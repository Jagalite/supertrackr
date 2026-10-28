//! Open-loop HTTP(S) generator. Unbounded worker queues; delayed offers and drain time are explicit.
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use reqwest::Client;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
#[derive(Parser)]
struct Args {
    #[arg(long)]
    url: String,
    #[arg(long)]
    ca: Option<String>,
    #[arg(long, default_value = "verify")]
    mode: String,
    #[arg(long, default_value_t = 5000)]
    rate: usize,
    #[arg(long, default_value_t = 10)]
    seconds: usize,
    #[arg(long, default_value_t = 32)]
    workers: usize,
    #[arg(long, default_value_t = 1000)]
    population: usize,
    #[arg(long, default_value_t = 20)]
    peer_limit: usize,
}
#[derive(Default)]
struct Stats {
    success: usize,
    errors: usize,
    statuses: std::collections::BTreeMap<u16, usize>,
    lat: Vec<u64>,
    service_lat: Vec<u64>,
    queue_lat: Vec<u64>,
    response_bytes: usize,
}
#[derive(serde::Deserialize)]
struct PeerResponse {
    public_key: String,
    endpoint: String,
    remaining_seconds: u64,
    #[serde(default)]
    verified: bool,
}
#[derive(serde::Deserialize)]
struct RegistrationResponse {
    token: String,
    expires_in_seconds: u64,
}
fn key(seed: u64, n: usize) -> String {
    hex::encode(Sha256::digest(format!("{seed}/{n}")))
}
async fn register(c: &Client, url: &str, k: &str) -> Result<String, Box<dyn std::error::Error>> {
    let r: Value = c
        .post(format!("{url}/v1/register"))
        .json(&json!({"public_key":k,"endpoint":"127.0.0.1:51820"}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(r["token"].as_str().ok_or("missing token")?.into())
}
fn client(ca: Option<&str>) -> Result<Client, Box<dyn std::error::Error>> {
    let mut builder = Client::builder()
        .http1_only()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .pool_max_idle_per_host(1);
    if let Some(ca) = ca {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
    }
    Ok(builder.build()?)
}
type LoadError = Box<dyn std::error::Error + Send + Sync>;
type Direct = hyper::client::conn::http1::SendRequest<Full<Bytes>>;
async fn send(
    req: reqwest::RequestBuilder,
    direct: &mut Option<Direct>,
) -> Result<(u16, Bytes), LoadError> {
    if let Some(sender) = direct {
        let req = req.build()?;
        let mut out = hyper::Request::builder()
            .method(req.method().clone())
            .uri(format!(
                "{}{}",
                req.url().path(),
                req.url()
                    .query()
                    .map(|q| format!("?{q}"))
                    .unwrap_or_default()
            ))
            .header("host", req.url().authority());
        for (name, value) in req.headers() {
            out = out.header(name, value);
        }
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or_default();
        sender.ready().await?;
        let response = sender
            .send_request(out.body(Full::new(Bytes::copy_from_slice(body)))?)
            .await?;
        let status = response.status().as_u16();
        Ok((status, response.into_body().collect().await?.to_bytes()))
    } else {
        let response = req.send().await?;
        Ok((response.status().as_u16(), response.bytes().await?))
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = Args::parse();
    if !["register", "refresh", "peers", "verify", "aquatic"].contains(&a.mode.as_str())
        || a.rate == 0
        || a.rate > 1_000_000
        || a.seconds == 0
        || a.seconds > 60
        || a.workers == 0
        || a.workers > 256
        || a.population > 50000
        || a.population < a.workers * 2
        || (a.mode == "peers"
            && (a.peer_limit == 0 || a.peer_limit > 100 || a.peer_limit >= a.population))
    {
        return Err("invalid load settings".into());
    }
    let endpoint = reqwest::Url::parse(&a.url)?;
    if endpoint.scheme() == "http"
        && !endpoint
            .host_str()
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
    {
        return Err("plaintext benchmark target must be a loopback IP".into());
    }
    let c = client(a.ca.as_deref())?;
    let seed = rand::random::<u64>();
    let mut identities = Vec::new();
    // Setup and the expected discovery-key set are outside the measured interval.
    for i in 0..a.population {
        let k = key(seed, i);
        let t = if a.mode == "aquatic" {
            let response = c
                .get(announce_url(&a.url, i))
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await?;
            let _: Announce = serde_bencode::from_bytes(&response)?;
            String::new()
        } else {
            register(&c, &a.url, &k).await?
        };
        identities.push((k, t));
    }
    let known_keys: Arc<std::collections::HashSet<String>> =
        Arc::new(identities.iter().map(|(k, _)| k.clone()).collect());
    let identities = Arc::new(identities);
    let mut senders = Vec::new();
    let mut handles = Vec::new();
    for worker in 0..a.workers {
        let (tx, mut rx) = mpsc::unbounded_channel::<(usize, Instant, Instant)>();
        senders.push(tx);
        // Each sequential worker owns its connection pool; no shared checkout lock.
        let c = client(a.ca.as_deref())?;
        let ids = identities.clone();
        let known_keys = known_keys.clone();
        let peer_limit = a.peer_limit;
        let url = a.url.clone();
        let mode = a.mode.clone();
        let population = a.population;
        // Validate lookup credentials before timing; setup connections are separate.
        let caller = &ids[worker];
        let target = &ids[(worker + a.workers) % population];
        if mode != "register" && mode != "aquatic" {
            c.post(format!("{url}/v1/verify"))
                .json(&json!({"public_key":target.0,"endpoint":"127.0.0.1:51820"}))
                .header("x-peer-key", &caller.0)
                .bearer_auth(&caller.1)
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await?;
        }
        let mut direct = if endpoint.scheme() == "http" {
            let stream = tokio::net::TcpStream::connect((
                endpoint.host_str().unwrap(),
                endpoint.port_or_known_default().unwrap(),
            ))
            .await?;
            stream.set_nodelay(true)?;
            let (sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Some(sender)
        } else {
            None
        };
        handles.push(tokio::spawn(async move {
            let mut s = Stats::default();
            while let Some((i, planned, enqueued)) = rx.recv().await {
                s.queue_lat.push(enqueued.elapsed().as_micros() as u64);
                let (caller, target) = (
                    &ids[i % population],
                    &ids[(i + i / population + 1) % population],
                );
                let req = match mode.as_str() {
                    "aquatic" => c.get(announce_url(&url, i % population)),
                    "register" => c.post(format!("{url}/v1/register")).json(
                        &json!({"public_key":key(seed,population+i),"endpoint":"127.0.0.1:51820"}),
                    ),
                    "refresh" => c
                        .post(format!("{url}/v1/register"))
                        .json(&json!({"public_key":caller.0,"endpoint":"127.0.0.1:51820"}))
                        .header("x-peer-key", &caller.0)
                        .bearer_auth(&caller.1),
                    "peers" => c
                        .get(format!("{url}/v1/peers?limit={peer_limit}"))
                        .header("x-peer-key", &caller.0)
                        .bearer_auth(&caller.1),
                    _ => c
                        .post(format!("{url}/v1/verify"))
                        .json(&json!({"public_key":target.0,"endpoint":"127.0.0.1:51820"}))
                        .header("x-peer-key", &caller.0)
                        .bearer_auth(&caller.1),
                };
                let sent = Instant::now();
                match tokio::time::timeout(Duration::from_secs(3), send(req, &mut direct)).await {
                    Ok(Ok((status, bytes))) => {
                        *s.statuses.entry(status).or_default() += 1;
                        let good = match status {
                            200 => {
                                s.response_bytes += bytes.len();
                                if mode == "aquatic" {
                                    valid_announce(&bytes, i % population, population)
                                } else if mode == "register" || mode == "refresh" {
                                    serde_json::from_slice::<RegistrationResponse>(&bytes)
                                        .is_ok_and(|v| {
                                            v.token.len() == 64
                                                && v.expires_in_seconds > 0
                                                && (mode != "refresh" || v.token == caller.1)
                                        })
                                } else if mode == "peers" {
                                    serde_json::from_slice::<Vec<PeerResponse>>(&bytes).is_ok_and(
                                        |peers| {
                                            let mut seen = std::collections::HashSet::with_capacity(
                                                peers.len(),
                                            );
                                            peers.len() == peer_limit
                                                && peers.iter().all(|p| {
                                                    p.public_key != caller.0
                                                        && known_keys.contains(&p.public_key)
                                                        && p.endpoint == "127.0.0.1:51820"
                                                        && p.remaining_seconds > 0
                                                        && seen.insert(&p.public_key)
                                                })
                                        },
                                    )
                                } else {
                                    serde_json::from_slice::<PeerResponse>(&bytes).is_ok_and(|v| {
                                        v.verified
                                            && v.public_key == target.0
                                            && v.endpoint == "127.0.0.1:51820"
                                            && v.remaining_seconds > 0
                                    })
                                }
                            }
                            _ => false,
                        };
                        if good {
                            s.success += 1;
                            s.service_lat.push(sent.elapsed().as_micros() as u64);
                            s.lat.push(planned.elapsed().as_micros() as u64);
                        } else {
                            s.errors += 1;
                        }
                    }
                    _ => s.errors += 1,
                }
            }
            s
        }));
    }
    let total = a.rate * a.seconds;
    let start = Instant::now() + Duration::from_millis(100);
    let rate = a.rate;
    let workers = a.workers;
    let seconds = a.seconds;
    // Dedicated pacing avoids competing with network tasks for Tokio timer wakes.
    // Sleep to the END of each 250us slice: no request is offered before its due time.
    let (late, closed, accepted, offer_ms) = tokio::task::spawn_blocking(move || {
        let mut late = 0;
        let mut closed = 0;
        let mut accepted = 0;
        for slice in 0..seconds * 4000 {
            let wake = start + Duration::from_micros((slice as u64 + 1) * 250);
            std::thread::sleep(wake.saturating_duration_since(Instant::now()));
            for i in (slice * rate).div_ceil(4000)..((slice + 1) * rate).div_ceil(4000) {
                let planned =
                    start + Duration::from_nanos((i as u64) * 1_000_000_000 / rate as u64);
                if Instant::now().saturating_duration_since(planned) > Duration::from_millis(10) {
                    late += 1;
                    continue;
                }
                if senders[i % workers]
                    .send((i, planned, Instant::now()))
                    .is_ok()
                {
                    accepted += 1;
                } else {
                    closed += 1;
                }
            }
        }
        (late, closed, accepted, start.elapsed().as_millis())
    })
    .await?;
    let mut all = Stats::default();
    for h in handles {
        let s = h.await?;
        all.success += s.success;
        all.errors += s.errors;
        all.lat.extend(s.lat);
        all.service_lat.extend(s.service_lat);
        all.queue_lat.extend(s.queue_lat);
        all.response_bytes += s.response_bytes;
        for (k, v) in s.statuses {
            *all.statuses.entry(k).or_default() += v;
        }
    }
    let elapsed = start.elapsed();
    all.lat.sort_unstable();
    all.service_lat.sort_unstable();
    all.queue_lat.sort_unstable();
    let percentile = |p: usize| {
        all.lat
            .get(all.lat.len().saturating_sub(1) * p / 100)
            .copied()
            .unwrap_or(0)
    };
    let passed = accepted == total && all.success == total && all.errors == 0;
    println!(
        "{}",
        json!({"pacing":"dedicated-thread-250us","mode":a.mode,"peer_limit":a.peer_limit,"response_bytes":all.response_bytes,"service_p99_us":all.service_lat.get(all.service_lat.len().saturating_sub(1)*99/100).copied().unwrap_or(0),"target_rps":a.rate,"duration_seconds":a.seconds,"population":a.population,"workers":a.workers,"queue_mode":"unbounded","queue_per_worker":null,"queue_wait_p99_us":all.queue_lat.get(all.queue_lat.len().saturating_sub(1)*99/100).copied().unwrap_or(0),"queue_wait_max_us":all.queue_lat.last().copied().unwrap_or(0),"offered":total,"accepted":accepted,"late":late,"queue_dropped":0,"channel_closed":closed,"success":all.success,"errors":all.errors,"statuses":all.statuses,"e2e_p50_us":percentile(50),"e2e_p95_us":percentile(95),"e2e_p99_us":percentile(99),"offer_ms":offer_ms,"elapsed_ms":elapsed.as_millis(),"drain_ms":elapsed.as_millis().saturating_sub(offer_ms),"passed":passed,"latency_scope":"successful requests, from scheduled offer through complete validated response","transport":if endpoint.scheme() == "http" {"http HTTP/1.1 worker-owned hyper"} else {"https HTTP/1.1 reqwest"}})
    );
    if !passed {
        std::process::exit(2);
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct Announce {
    interval: u64,
    complete: usize,
    incomplete: usize,
    peers: serde_bytes::ByteBuf,
}
fn announce_url(base: &str, index: usize) -> String {
    format!(
        "{base}/announce?info_hash=abcdefghijklmnopqrst&peer_id={index:020}&port={}&uploaded=0&downloaded=0&left=1&compact=1&numwant=1",
        10000 + index
    )
}
fn valid_announce(bytes: &[u8], index: usize, population: usize) -> bool {
    let Ok(r) = serde_bencode::from_bytes::<Announce>(bytes) else {
        return false;
    };
    if r.interval == 0 || r.complete != 0 || r.incomplete != population - 1 || r.peers.len() != 6 {
        return false;
    }
    let port = u16::from_be_bytes([r.peers[4], r.peers[5]]) as usize;
    r.peers[..4] == [127, 0, 0, 1]
        && (10000..10000 + population).contains(&port)
        && port != 10000 + index
}
