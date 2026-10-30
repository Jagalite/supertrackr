//! Loopback tracker adapter for ordinary clients using this companion.
use super::control::TrackerAccess;
use axum::{
    Router,
    body::Body,
    extract::{RawQuery, State},
    http::{Response, header},
    routing::get,
};
use serde::Deserialize;
use std::{
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use supertrackr::CandidatePeer;
use supertrackr_bittorrent::{
    http,
    standard::{Counts, Event, Peer, PeerId},
};

#[derive(Clone)]
pub struct Bridge {
    pub access: TrackerAccess,
    pub upstream: Option<reqwest::Url>,
    pub udp: Arc<crate::udp_upstream::Announcements>,
    pub ordering: Arc<[tokio::sync::Mutex<()>; 64]>,
    pub permits: Arc<tokio::sync::Semaphore>,
    pub selection: Arc<std::sync::atomic::AtomicU64>,
}
#[derive(Deserialize)]
struct OverlayPeer {
    public_key: String,
    #[serde(default)]
    application_id: Option<String>,
    port: u16,
    complete: bool,
    remaining_seconds: u64,
}
#[derive(Deserialize)]
struct OverlayResponse {
    interval: u64,
    seeders: usize,
    leechers: usize,
    peers: Vec<OverlayPeer>,
}
#[derive(Deserialize)]
struct UpstreamResponse {
    #[serde(default)]
    complete: u64,
    #[serde(default)]
    incomplete: u64,
    interval: u64,
    peers: UpstreamPeers,
    #[serde(default, with = "serde_bytes")]
    peers6: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum UpstreamPeers {
    Compact(serde_bytes::ByteBuf),
    Expanded(Vec<UpstreamPeer>),
}
#[derive(Deserialize)]
struct UpstreamPeer {
    ip: String,
    port: u16,
    #[serde(rename = "peer id", default)]
    peer_id: Option<serde_bytes::ByteBuf>,
}
#[derive(Deserialize)]
struct UpstreamScrape {
    files: std::collections::BTreeMap<serde_bytes::ByteBuf, UpstreamCounts>,
}
#[derive(Deserialize)]
struct UpstreamCounts {
    complete: u64,
    incomplete: u64,
    downloaded: u64,
}
fn result(data: Vec<u8>) -> Response<Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(data))
        .unwrap()
}
fn append_query(url: &mut reqwest::Url, query: &str) {
    let combined = match url.query() {
        Some(existing) if !existing.is_empty() => format!("{existing}&{query}"),
        _ => query.to_owned(),
    };
    url.set_query(Some(&combined));
}
async fn retry_http_stop(
    bridge: &Bridge,
    upstream: &reqwest::Url,
    query: &str,
    request: &http::Announce,
) {
    if let Ok(upstream_query) = http::upstream_query(
        query,
        request.compact || request.no_peer_id,
        request.no_peer_id,
    ) {
        let mut url = upstream.clone();
        append_query(&mut url, &upstream_query);
        let _ = tokio::time::timeout(
            Duration::from_millis(1500),
            bridge.access.http.get(url).send(),
        )
        .await;
    }
}
fn internet_address(ip: IpAddr, port: u16) -> Option<SocketAddr> {
    let ip = ip.to_canonical();
    if port == 0 || ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    if supertrackr::exit::is_overlay(ip) || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast()) {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}
async fn bounded_bytes(mut response: reqwest::Response) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if bytes.len().saturating_add(chunk.len()) > 65_536 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
async fn resolve_overlay_peer(access: TrackerAccess, peer: OverlayPeer) -> Option<(Peer, bool)> {
    if peer.port == 0 || peer.remaining_seconds == 0 {
        return None;
    }
    let response = access
        .auth(access.http.post(access.base.join("v1/binding").ok()?))
        .json(&serde_json::json!({"public_key":peer.public_key}))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?;
    let binding: CandidatePeer =
        serde_json::from_slice(&bounded_bytes(response).await.ok()?).ok()?;
    if binding.public_key != peer.public_key
        || !supertrackr::peer_manager::overlay(binding.virtual_ip)
        || binding.remaining_seconds == 0
    {
        return None;
    }
    let decoded = hex::decode(&peer.public_key).ok()?;
    if decoded.len() != 32 {
        return None;
    }
    let mut id = [0; 20];
    let missing_id = if let Some(application) = peer.application_id {
        hex::decode_to_slice(application, &mut id).ok()?;
        false
    } else {
        id.copy_from_slice(&decoded[..20]);
        true
    };
    Some((
        Peer {
            id: PeerId(id),
            address: SocketAddr::new(IpAddr::V4(binding.virtual_ip), peer.port),
            complete: peer.complete,
            expires: 0,
        },
        missing_id,
    ))
}
async fn announce(State(bridge): State<Arc<Bridge>>, RawQuery(query): RawQuery) -> Response<Body> {
    let _permit = match bridge.permits.try_acquire() {
        Ok(p) => p,
        Err(_) => return result(http::failure("tracker busy")),
    };
    let query = query.unwrap_or_default();
    let request = match http::announce(&query) {
        Ok(q) => q,
        Err(_) => return result(http::failure("invalid announce")),
    };
    // Serialize requests for a peer before contacting either tracker. Without
    // this, a slow earlier announce can reach the upstream after a later stop.
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    request.info_hash.hash(&mut hasher);
    request.peer_id.hash(&mut hasher);
    let slot = hasher.finish() as usize % bridge.ordering.len();
    let _order =
        // Four handlers can be admitted. Allow a queued stop to outlast the
        // bounded UDP wait, overlay operation, and HTTP stop fallback of the
        // earlier handlers instead of timing out first.
        match tokio::time::timeout(Duration::from_secs(35), bridge.ordering[slot].lock()).await {
            Ok(guard) => guard,
            Err(_) => return result(http::failure("tracker busy")),
        };
    let event = if request.event == Event::Stopped {
        "stopped"
    } else {
        "announce"
    };
    let body = if event == "stopped" {
        serde_json::json!({"event":event,"info_hash":hex::encode(request.info_hash),"application_id":hex::encode(request.peer_id.0)})
    } else {
        serde_json::json!({"event":event,"info_hash":hex::encode(request.info_hash),"application_id":hex::encode(request.peer_id.0),"port":request.port,"complete":request.left==0,"limit":20})
    };
    // Register the upstream operation before the overlay request, so an
    // overlay outage cannot leave a previous upstream announce retrying after
    // a stop. The manager bounds the synchronous wait and continues retries.
    let udp_result =
        if let Some(upstream) = bridge.upstream.as_ref().filter(|url| url.scheme() == "udp") {
            let udp_request = supertrackr_bittorrent::udp::Announce {
                info_hash: request.info_hash,
                peer_id: request.peer_id,
                downloaded: request.downloaded,
                left: request.left,
                uploaded: request.uploaded,
                event: request.event,
                key: bridge.udp.key(&request.info_hash, request.peer_id),
                numwant: request.numwant.min(200) as i32,
                port: request.port,
            };
            bridge.udp.announce(upstream, udp_request).await
        } else {
            None
        };
    let operation = async {
        let response = bridge
            .access
            .auth(
                bridge
                    .access
                    .http
                    .post(bridge.access.base.join("v1/bittorrent").map_err(|_| ())?),
            )
            .json(&body)
            .send()
            .await
            .map_err(|_| ())?
            .error_for_status()
            .map_err(|_| ())?;
        let overlay: OverlayResponse =
            serde_json::from_slice(&bounded_bytes(response).await?).map_err(|_| ())?;
        if overlay.peers.len() > 50 || overlay.interval == 0 {
            return Err(());
        }
        let mut peers = Vec::new();
        let mut missing_peer_ids = false;
        let mut tasks = tokio::task::JoinSet::new();
        let slots = Arc::new(tokio::sync::Semaphore::new(8));
        for peer in overlay.peers {
            let access = bridge.access.clone();
            let slots = slots.clone();
            tasks.spawn(async move {
                let _permit = slots.acquire_owned().await.ok()?;
                resolve_overlay_peer(access, peer).await
            });
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(result) = tasks.join_next().await {
                if let Ok(Some((peer, missing_id))) = result {
                    peers.push(peer);
                    missing_peer_ids |= missing_id;
                }
            }
        })
        .await;
        tasks.abort_all();
        let mut counts = Counts {
            complete: overlay.seeders,
            incomplete: overlay.leechers,
            downloaded: 0,
        };
        let mut interval = overlay.interval;
        let overlay_count = peers.len();
        let mut upstream_unavailable = false;
        if let Some(upstream) = &bridge.upstream {
            if upstream.scheme() == "udp" {
                if let Some(remote) = udp_result {
                    counts.complete = counts.complete.saturating_add(remote.seeders as usize);
                    counts.incomplete = counts.incomplete.saturating_add(remote.leechers as usize);
                    interval = interval.min(u64::from(remote.interval.max(1)));
                    missing_peer_ids |= !remote.peers.is_empty();
                    for address in remote.peers {
                        if let Some(address) = internet_address(address.ip(), address.port()) {
                            peers.push(Peer {
                                id: PeerId([0; 20]),
                                address,
                                complete: false,
                                expires: 0,
                            });
                        }
                    }
                } else {
                    upstream_unavailable = true;
                }
            } else {
                let overlay_counts = counts;
                let overlay_interval = interval;
                let overlay_missing_ids = missing_peer_ids;
                let upstream_result = tokio::time::timeout(Duration::from_millis(1500), async {
                    let mut upstream_url = upstream.clone();
                    // Strip compact options after parsing, then request compact responses.
                    let compact_upstream = request.compact || request.no_peer_id;
                    let upstream_query =
                        http::upstream_query(&query, compact_upstream, request.no_peer_id)
                            .map_err(|_| ())?;
                    append_query(&mut upstream_url, &upstream_query);
                    let response = bridge
                        .access
                        .http
                        .get(upstream_url)
                        .send()
                        .await
                        .map_err(|_| ())?
                        .error_for_status()
                        .map_err(|_| ())?;
                    let remote: UpstreamResponse =
                        serde_bencode::from_bytes(&bounded_bytes(response).await?)
                            .map_err(|_| ())?;
                    let peer_count = match &remote.peers {
                        UpstreamPeers::Compact(peers) => {
                            if peers.len() % 6 != 0 {
                                return Err(());
                            }
                            peers.len() / 6
                        }
                        UpstreamPeers::Expanded(peers) => peers.len(),
                    };
                    if !remote.peers6.len().is_multiple_of(18)
                        || peer_count + remote.peers6.len() / 18 > 200
                    {
                        return Err(());
                    }
                    counts.complete = counts
                        .complete
                        .saturating_add(remote.complete.min(usize::MAX as u64) as usize);
                    counts.incomplete = counts
                        .incomplete
                        .saturating_add(remote.incomplete.min(usize::MAX as u64) as usize);
                    interval = interval.min(remote.interval.max(1));
                    if let UpstreamPeers::Compact(ref raw_peers) = remote.peers {
                        missing_peer_ids |= !raw_peers.is_empty();
                        for raw in raw_peers.as_chunks::<6>().0 {
                            let ip = Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
                            let port = u16::from_be_bytes([raw[4], raw[5]]);
                            if let Some(address) = internet_address(IpAddr::V4(ip), port) {
                                peers.push(Peer {
                                    id: PeerId([0; 20]),
                                    address,
                                    complete: false,
                                    expires: 0,
                                });
                            }
                        }
                    } else if let UpstreamPeers::Expanded(raw_peers) = remote.peers {
                        for raw in raw_peers {
                            let Ok(ip) = raw.ip.parse::<IpAddr>() else {
                                continue;
                            };
                            let Some(address) = internet_address(ip, raw.port) else {
                                continue;
                            };
                            let mut id = [0; 20];
                            if let Some(peer_id) = raw.peer_id {
                                if peer_id.len() != 20 {
                                    return Err(());
                                }
                                id.copy_from_slice(&peer_id);
                            } else {
                                missing_peer_ids = true;
                            }
                            peers.push(Peer {
                                id: PeerId(id),
                                address,
                                complete: false,
                                expires: 0,
                            });
                        }
                    }
                    missing_peer_ids |= !remote.peers6.is_empty();
                    for raw in remote.peers6.as_chunks::<18>().0 {
                        let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[..16]).unwrap());
                        let port = u16::from_be_bytes([raw[16], raw[17]]);
                        if let Some(address) = internet_address(IpAddr::V6(ip), port) {
                            peers.push(Peer {
                                id: PeerId([0; 20]),
                                address,
                                complete: false,
                                expires: 0,
                            });
                        }
                    }
                    Ok::<(), ()>(())
                })
                .await;
                if !matches!(upstream_result, Ok(Ok(()))) {
                    peers.truncate(overlay_count);
                    counts = overlay_counts;
                    interval = overlay_interval;
                    missing_peer_ids = overlay_missing_ids;
                    upstream_unavailable = true;
                    if request.event == Event::Stopped {
                        retry_http_stop(&bridge, upstream, &query, &request).await;
                    }
                }
            }
        }
        let internet = peers.split_off(overlay_count);
        let mut overlay = peers.into_iter();
        let mut internet = internet.into_iter();
        let mut peers = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut use_overlay = bridge
            .selection
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % 2
            == 0;
        while peers.len() < request.numwant.min(50) {
            let candidate = if use_overlay {
                overlay.next().or_else(|| internet.next())
            } else {
                internet.next().or_else(|| overlay.next())
            };
            let Some(peer) = candidate else { break };
            if seen.insert(peer.address) {
                peers.push(peer);
            }
            use_overlay = !use_overlay;
        }
        let mut response = http::announce_response(
            &peers,
            counts,
            interval,
            request.compact,
            request.no_peer_id || missing_peer_ids,
        );
        if upstream_unavailable {
            response.pop();
            response.extend_from_slice(b"15:warning message20:upstream unavailablee");
        }
        Ok::<_, ()>(response)
    };
    match tokio::time::timeout(Duration::from_secs(7), operation).await {
        Ok(Ok(response)) => result(response),
        _ => {
            // Overlay failures must not prevent an HTTP upstream stop. The
            // timeout may also have interrupted a stop already sent, so this
            // retry can duplicate a stop; stops are idempotent.
            if request.event == Event::Stopped {
                if let Some(upstream) = bridge
                    .upstream
                    .as_ref()
                    .filter(|url| matches!(url.scheme(), "http" | "https"))
                {
                    retry_http_stop(&bridge, upstream, &query, &request).await;
                }
            }
            result(http::failure("tracker unavailable"))
        }
    }
}
async fn scrape(State(bridge): State<Arc<Bridge>>, RawQuery(query): RawQuery) -> Response<Body> {
    let _permit = match bridge.permits.try_acquire() {
        Ok(p) => p,
        Err(_) => return result(http::failure("tracker busy")),
    };
    let query = query.unwrap_or_default();
    let mut hashes = match http::scrape(&query) {
        Ok(hashes) => hashes,
        Err(_) => return result(http::failure("invalid scrape")),
    };
    let mut seen = std::collections::HashSet::new();
    hashes.retain(|hash| seen.insert(*hash));
    let operation = async {
        let mut tasks = tokio::task::JoinSet::new();
        let slots = Arc::new(tokio::sync::Semaphore::new(8));
        let mut entries = vec![None; hashes.len()];
        for (index, hash) in hashes.into_iter().enumerate() {
            let access = bridge.access.clone();
            let slots = slots.clone();
            tasks.spawn(async move {
                let _permit = slots.acquire_owned().await.map_err(|_| ())?;
                let response = access
                    .auth(
                        access
                            .http
                            .post(access.base.join("v1/bittorrent").map_err(|_| ())?),
                    )
                    .json(&serde_json::json!({"event":"scrape","info_hash":hex::encode(hash)}))
                    .send()
                    .await
                    .map_err(|_| ())?
                    .error_for_status()
                    .map_err(|_| ())?;
                let overlay: OverlayResponse =
                    serde_json::from_slice(&bounded_bytes(response).await?).map_err(|_| ())?;
                Ok::<_, ()>((
                    index,
                    (
                        hash,
                        Counts {
                            complete: overlay.seeders,
                            incomplete: overlay.leechers,
                            downloaded: 0,
                        },
                    ),
                ))
            });
        }
        while let Some(result) = tasks.join_next().await {
            let (index, entry) = result.map_err(|_| ())??;
            entries[index] = Some(entry);
        }
        let mut entries: Vec<_> = entries.into_iter().collect::<Option<_>>().ok_or(())?;
        let mut upstream_unavailable = false;
        if let Some(upstream) = &bridge.upstream {
            if upstream.scheme() == "udp" {
                // Canonicalize the key so permutations of the same scrape do
                // not consume independent worker/cache entries.
                entries.sort_unstable_by_key(|(hash, _)| *hash);
                let hashes = entries.iter().map(|(hash, _)| *hash).collect();
                if let Some(remote) = bridge.udp.scrape(upstream, hashes).await {
                    for ((_, counts), remote) in entries.iter_mut().zip(remote) {
                        counts.complete = counts.complete.saturating_add(remote.seeders as usize);
                        counts.incomplete =
                            counts.incomplete.saturating_add(remote.leechers as usize);
                        counts.downloaded = u64::from(remote.downloaded);
                    }
                } else {
                    upstream_unavailable = true;
                }
            } else {
                let overlay_entries = entries.clone();
                let upstream_result = tokio::time::timeout(Duration::from_millis(1500), async {
                    let mut url = upstream.clone();
                    let path = url.path().strip_suffix("announce").ok_or(())?.to_owned() + "scrape";
                    url.set_path(&path);
                    append_query(&mut url, &query);
                    let response = bridge
                        .access
                        .http
                        .get(url)
                        .send()
                        .await
                        .map_err(|_| ())?
                        .error_for_status()
                        .map_err(|_| ())?;
                    let remote: UpstreamScrape =
                        serde_bencode::from_bytes(&bounded_bytes(response).await?)
                            .map_err(|_| ())?;
                    if remote.files.len() > 32 {
                        return Err(());
                    }
                    for (hash, counts) in &mut entries {
                        if let Some(remote) =
                            remote.files.get(&serde_bytes::ByteBuf::from(hash.to_vec()))
                        {
                            counts.complete = counts
                                .complete
                                .saturating_add(remote.complete.min(usize::MAX as u64) as usize);
                            counts.incomplete = counts
                                .incomplete
                                .saturating_add(remote.incomplete.min(usize::MAX as u64) as usize);
                            counts.downloaded = remote.downloaded;
                        }
                    }
                    Ok::<(), ()>(())
                })
                .await;
                if !matches!(upstream_result, Ok(Ok(()))) {
                    entries = overlay_entries;
                    upstream_unavailable = true;
                }
            }
        }
        let mut response = http::scrape_response(&entries);
        if upstream_unavailable {
            response.pop();
            response.extend_from_slice(b"15:warning message20:upstream unavailablee");
        }
        Ok::<_, ()>(response)
    };
    match tokio::time::timeout(Duration::from_secs(11), operation).await {
        Ok(Ok(response)) => result(response),
        _ => result(http::failure("tracker unavailable")),
    }
}
pub fn router(bridge: Bridge) -> Router {
    Router::new()
        .route("/announce", get(announce))
        .route("/scrape", get(scrape))
        .with_state(Arc::new(bridge))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use boringtun::x25519::{PublicKey, StaticSecret};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    const BAD_PEER_RESPONSE: &[u8] = b"d8:completei99e10:incompletei99e8:intervali1e5:peersld2:ip9:127.0.0.17:peer id20:111111111111111111114:porti6881eed2:ip9:127.0.0.27:peer id3:bad4:porti6882eeee";

    #[derive(Deserialize)]
    struct ClientResponse {
        #[serde(with = "serde_bytes")]
        peers: Vec<u8>,
        complete: u64,
        incomplete: u64,
    }
    #[derive(Deserialize)]
    struct ExpandedResponse {
        complete: u64,
        incomplete: u64,
        interval: u64,
        peers: Vec<UpstreamPeer>,
        #[serde(rename = "warning message")]
        warning: Option<String>,
    }
    #[test]
    fn upstream_query_keeps_configured_tracker_credentials() {
        let mut url: reqwest::Url = "https://tracker.example/announce?passkey=abc%2Bdef"
            .parse()
            .unwrap();
        append_query(&mut url, "info_hash=%00%ff");
        assert_eq!(url.query(), Some("passkey=abc%2Bdef&info_hash=%00%ff"));
    }
    #[test]
    fn upstream_addresses_cannot_inject_overlay_routes() {
        for address in [
            "10.203.1.2",
            "::ffff:10.203.1.2",
            "fdcb::ac1:2",
            "0.0.0.0",
            "ff02::1",
        ] {
            assert!(internet_address(address.parse().unwrap(), 6881).is_none());
        }
        assert_eq!(
            internet_address("::ffff:192.0.2.1".parse().unwrap(), 6881),
            Some("192.0.2.1:6881".parse().unwrap())
        );
        assert!(internet_address("192.0.2.1".parse().unwrap(), 0).is_none());
    }
    #[tokio::test]
    async fn failed_http_stop_is_retried_even_when_overlay_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let internet = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}/announce", internet.local_addr().unwrap())
            .parse()
            .unwrap();
        let internet_routes = Router::new().route(
            "/announce",
            get(move || {
                let counter = counter.clone();
                async move {
                    if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        axum::http::StatusCode::OK
                    }
                }
            }),
        );
        let internet_server =
            tokio::spawn(async move { axum::serve(internet, internet_routes).await.unwrap() });
        let overlay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", overlay.local_addr().unwrap())
            .parse()
            .unwrap();
        let routes = Router::new().route(
            "/v1/bittorrent",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({"interval":100,"seeders":0,"leechers":0,"peers":[]}))
            }),
        );
        let overlay_server =
            tokio::spawn(async move { axum::serve(overlay, routes).await.unwrap() });
        let app = router(Bridge {
            access: TrackerAccess {
                http: reqwest::Client::new(),
                base,
                public: "test".into(),
                token: "test".into(),
            },
            upstream: Some(upstream),
            udp: Arc::new(crate::udp_upstream::Announcements::new()),
            ordering: Arc::new(std::array::from_fn(|_| tokio::sync::Mutex::new(()))),
            permits: Arc::new(tokio::sync::Semaphore::new(4)),
            selection: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        let _response = app.oneshot(Request::builder().uri("/announce?info_hash=11111111111111111111&peer_id=22222222222222222222&port=6881&uploaded=0&downloaded=0&left=1&event=stopped").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        internet_server.abort();
        overlay_server.abort();
    }
    #[tokio::test]
    async fn overlay_failure_does_not_prevent_http_stop() {
        let (sent, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let internet = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!(
            "http://{}/announce?passkey=secret",
            internet.local_addr().unwrap()
        )
        .parse()
        .unwrap();
        let internet_routes = Router::new().route(
            "/announce",
            get(move |RawQuery(query): RawQuery| {
                let sent = sent.clone();
                async move {
                    sent.send(query.unwrap_or_default()).unwrap();
                    "ok"
                }
            }),
        );
        let internet_server =
            tokio::spawn(async move { axum::serve(internet, internet_routes).await.unwrap() });
        let overlay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", overlay.local_addr().unwrap())
            .parse()
            .unwrap();
        let overlay_routes = Router::new().route(
            "/v1/bittorrent",
            axum::routing::post(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
        );
        let overlay_server =
            tokio::spawn(async move { axum::serve(overlay, overlay_routes).await.unwrap() });
        let app = router(Bridge {
            access: TrackerAccess {
                http: reqwest::Client::new(),
                base,
                public: "test".into(),
                token: "test".into(),
            },
            upstream: Some(upstream),
            udp: Arc::new(crate::udp_upstream::Announcements::new()),
            ordering: Arc::new(std::array::from_fn(|_| tokio::sync::Mutex::new(()))),
            permits: Arc::new(tokio::sync::Semaphore::new(4)),
            selection: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        let response = app.oneshot(Request::builder().uri("/announce?info_hash=11111111111111111111&peer_id=22222222222222222222&port=6881&uploaded=0&downloaded=0&left=1&event=stopped").body(Body::empty()).unwrap()).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            body.windows(b"tracker unavailable".len())
                .any(|part| part == b"tracker unavailable")
        );
        let query = tokio::time::timeout(Duration::from_secs(2), observed.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(query.contains("event=stopped"));
        assert!(query.contains("passkey=secret"));
        internet_server.abort();
        overlay_server.abort();
    }
    #[tokio::test]
    async fn bridge_merges_udp_announce_and_scrape() {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("udp://{}/announce", udp.local_addr().unwrap())
            .parse()
            .unwrap();
        let tracker = tokio::spawn(async move {
            let mut packet = [0u8; 2048];
            for action in [1u32, 2] {
                let (_, peer) = udp.recv_from(&mut packet).await.unwrap();
                let mut connect = 0u32.to_be_bytes().to_vec();
                connect.extend_from_slice(&packet[12..16]);
                connect.extend_from_slice(&[1; 8]);
                udp.send_to(&connect, peer).await.unwrap();
                let (len, peer) = udp.recv_from(&mut packet).await.unwrap();
                assert_eq!(
                    u32::from_be_bytes(packet[8..12].try_into().unwrap()),
                    action
                );
                let mut reply = action.to_be_bytes().to_vec();
                reply.extend_from_slice(&packet[12..16]);
                if action == 1 {
                    assert!(len >= 98);
                    for value in [120u32, 3, 2] {
                        reply.extend_from_slice(&value.to_be_bytes());
                    }
                    reply.extend_from_slice(&[127, 0, 0, 2, 0x1a, 0xe1]);
                } else {
                    assert_eq!(len, 36);
                    for value in [2u32, 4, 3] {
                        reply.extend_from_slice(&value.to_be_bytes());
                    }
                }
                udp.send_to(&reply, peer).await.unwrap();
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let routes = Router::new().route(
            "/v1/bittorrent",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({"interval":100,"seeders":1,"leechers":2,"peers":[]}))
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        let app = router(Bridge {
            access: TrackerAccess {
                http: reqwest::Client::new(),
                base,
                public: "test".into(),
                token: "test".into(),
            },
            upstream: Some(upstream),
            udp: Arc::new(crate::udp_upstream::Announcements::new()),
            ordering: Arc::new(std::array::from_fn(|_| tokio::sync::Mutex::new(()))),
            permits: Arc::new(tokio::sync::Semaphore::new(4)),
            selection: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        let response = app.clone().oneshot(Request::builder().uri("/announce?info_hash=11111111111111111111&peer_id=22222222222222222222&port=6881&uploaded=0&downloaded=0&left=1&compact=1").body(Body::empty()).unwrap()).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let announce: ClientResponse = serde_bencode::from_bytes(&body).unwrap();
        assert_eq!((announce.complete, announce.incomplete), (3, 5));
        assert_eq!(announce.peers, [127, 0, 0, 2, 0x1a, 0xe1]);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/scrape?info_hash=11111111111111111111")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let scrape: UpstreamScrape = serde_bencode::from_bytes(&body).unwrap();
        let counts = &scrape.files[&serde_bytes::ByteBuf::from(vec![b'1'; 20])];
        assert_eq!(
            (counts.complete, counts.incomplete, counts.downloaded),
            (3, 5, 4)
        );
        tracker.await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn overlay_failure_does_not_prevent_udp_stop() {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("udp://{}/announce", udp.local_addr().unwrap())
            .parse()
            .unwrap();
        let received = tokio::spawn(async move {
            let mut packet = [0u8; 2048];
            let (_, peer) = udp.recv_from(&mut packet).await.unwrap();
            let mut connect = 0u32.to_be_bytes().to_vec();
            connect.extend_from_slice(&packet[12..16]);
            connect.extend_from_slice(&[1; 8]);
            udp.send_to(&connect, peer).await.unwrap();
            let (len, peer) = udp.recv_from(&mut packet).await.unwrap();
            assert!(len >= 98);
            assert_eq!(u32::from_be_bytes(packet[80..84].try_into().unwrap()), 3);
            let mut response = 1u32.to_be_bytes().to_vec();
            response.extend_from_slice(&packet[12..16]);
            for value in [60u32, 0, 0] {
                response.extend_from_slice(&value.to_be_bytes());
            }
            udp.send_to(&response, peer).await.unwrap();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let routes = Router::new().route(
            "/v1/bittorrent",
            axum::routing::post(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        let app = router(Bridge {
            access: TrackerAccess {
                http: reqwest::Client::new(),
                base,
                public: "test".into(),
                token: "test".into(),
            },
            upstream: Some(upstream),
            udp: Arc::new(crate::udp_upstream::Announcements::new()),
            ordering: Arc::new(std::array::from_fn(|_| tokio::sync::Mutex::new(()))),
            permits: Arc::new(tokio::sync::Semaphore::new(4)),
            selection: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        let response = app.oneshot(Request::builder().uri("/announce?info_hash=11111111111111111111&peer_id=22222222222222222222&port=6881&uploaded=0&downloaded=0&left=1&event=stopped").body(Body::empty()).unwrap()).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            body.windows(b"tracker unavailable".len())
                .any(|part| part == b"tracker unavailable")
        );
        tokio::time::timeout(Duration::from_secs(2), received)
            .await
            .unwrap()
            .unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn announce_and_stop_reach_overlay_in_request_order() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let handler_release = release.clone();
        let routes = Router::new().route(
            "/v1/bittorrent",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let events = events.clone();
                let release = handler_release.clone();
                async move {
                    let event = body["event"].as_str().unwrap().to_owned();
                    events.send(event.clone()).unwrap();
                    if event == "announce" {
                        release.notified().await;
                    }
                    axum::Json(
                        serde_json::json!({"interval":100,"seeders":0,"leechers":0,"peers":[]}),
                    )
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        let app = router(Bridge {
            access: TrackerAccess {
                http: reqwest::Client::new(),
                base,
                public: "test".into(),
                token: "test".into(),
            },
            upstream: None,
            udp: Arc::new(crate::udp_upstream::Announcements::new()),
            ordering: Arc::new(std::array::from_fn(|_| tokio::sync::Mutex::new(()))),
            permits: Arc::new(tokio::sync::Semaphore::new(4)),
            selection: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        let query = "info_hash=11111111111111111111&peer_id=22222222222222222222&port=6881&uploaded=0&downloaded=0&left=1";
        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(
                    Request::builder()
                        .uri(format!("/announce?{query}&event=started"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), observed.recv())
                .await
                .unwrap()
                .as_deref(),
            Some("announce")
        );
        let second = tokio::spawn(async move {
            app.oneshot(
                Request::builder()
                    .uri(format!("/announce?{query}&event=stopped"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), observed.recv())
                .await
                .is_err()
        );
        release.notify_one();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), observed.recv())
                .await
                .unwrap()
                .as_deref(),
            Some("stopped")
        );
        assert!(first.await.is_ok());
        assert!(second.await.is_ok());
        server.abort();
    }
    #[tokio::test]
    async fn multi_scrape_is_bounded_concurrent_and_fails_without_partial_results() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));
        let handler_active = active.clone();
        let handler_peak = peak.clone();
        let handler_calls = calls.clone();
        let handler_fail = fail.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let routes = Router::new().route(
            "/v1/bittorrent",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let active = handler_active.clone();
                let peak = handler_peak.clone();
                let calls = handler_calls.clone();
                let fail = handler_fail.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    let status = if fail.load(Ordering::SeqCst)
                        && body["info_hash"] == hex::encode([b'0'; 20])
                    {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        axum::http::StatusCode::OK
                    };
                    (
                        status,
                        axum::Json(
                            serde_json::json!({"interval":100,"seeders":1,"leechers":2,"peers":[]}),
                        ),
                    )
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        let app = router(Bridge {
            access: TrackerAccess {
                http: reqwest::Client::new(),
                base,
                public: "test".into(),
                token: "test".into(),
            },
            upstream: None,
            udp: std::sync::Arc::new(crate::udp_upstream::Announcements::new()),
            ordering: std::sync::Arc::new(std::array::from_fn(|_| tokio::sync::Mutex::new(()))),
            permits: Arc::new(tokio::sync::Semaphore::new(4)),
            selection: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        let query = b"0123456789ABCDEFGHIJKLMNOPQRSTUV"
            .iter()
            .map(|b| format!("info_hash={}", char::from(*b).to_string().repeat(20)))
            .collect::<Vec<_>>()
            .join("&");
        let request = || {
            Request::builder()
                .uri(format!("/scrape?{query}"))
                .body(Body::empty())
                .unwrap()
        };
        let response = app.clone().oneshot(request()).await.unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response: UpstreamScrape = serde_bencode::from_bytes(&bytes).unwrap();
        assert_eq!(response.files.len(), 32);
        assert!(
            response
                .files
                .values()
                .all(|counts| counts.complete == 1 && counts.incomplete == 2)
        );
        assert!((2..=8).contains(&peak.load(Ordering::SeqCst)));
        let before = calls.load(Ordering::SeqCst);
        let duplicates = std::iter::repeat_n("info_hash=00000000000000000000", 32)
            .collect::<Vec<_>>()
            .join("&");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/scrape?{duplicates}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response: UpstreamScrape = serde_bencode::from_bytes(&bytes).unwrap();
        assert_eq!(response.files.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst) - before, 1);
        fail.store(true, Ordering::SeqCst);
        let response = app.oneshot(request()).await.unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.as_ref(), http::failure("tracker unavailable"));
        server.abort();
    }
    #[tokio::test]
    async fn binding_resolution_limits_concurrency_and_keeps_completed_peers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let handler_active = active.clone();
        let handler_peak = peak.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let routes = Router::new()
            .route("/v1/bittorrent", axum::routing::post(|| async {
                let peers: Vec<_> = (1u8..=10).map(|n| serde_json::json!({"public_key":hex::encode([n;32]),"application_id":hex::encode([n;20]),"port":6881,"complete":false,"remaining_seconds":100})).collect();
                axum::Json(serde_json::json!({"interval":100,"seeders":0,"leechers":10,"peers":peers}))
            }))
            .route("/v1/binding", axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let active = handler_active.clone();
                let peak = handler_peak.clone();
                async move {
                    let n = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(n, Ordering::SeqCst);
                    let key = body["public_key"].as_str().unwrap().to_owned();
                    let first = hex::decode(&key).unwrap()[0];
                    tokio::time::sleep(if first <= 2 { Duration::from_secs(3) } else { Duration::from_millis(150) }).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({"public_key":key,"endpoint":"127.0.0.1:1234","candidates":[],"virtual_ip":format!("10.203.1.{first}"),"remaining_seconds":100}))
                }
            }));
        let server = tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        let app = router(Bridge {
            access: TrackerAccess {
                http: reqwest::Client::new(),
                base,
                public: "test".into(),
                token: "test".into(),
            },
            upstream: None,
            udp: std::sync::Arc::new(crate::udp_upstream::Announcements::new()),
            ordering: std::sync::Arc::new(std::array::from_fn(|_| tokio::sync::Mutex::new(()))),
            permits: Arc::new(tokio::sync::Semaphore::new(4)),
            selection: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        let query = "info_hash=abcdefghijklmnopqrst&peer_id=22222222222222222222&port=6883&uploaded=0&downloaded=0&left=1&compact=1";
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/announce?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response: ClientResponse = serde_bencode::from_bytes(&bytes).unwrap();
        assert_eq!(response.peers.len(), 8 * 6);
        assert!((2..=8).contains(&peak.load(Ordering::SeqCst)));
        server.abort();
    }
    #[tokio::test]
    async fn bridge_combines_authenticated_overlay_and_internet_peers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let state = supertrackr::Coordinator::with_audience(
            supertrackr::Config {
                open_registration: true,
                ..Default::default()
            },
            base.to_string(),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, supertrackr::router(state))
                .await
                .unwrap()
        });
        let internet_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let internet_address = internet_listener.local_addr().unwrap();
        let internet = tokio::spawn(async move {
            axum::serve(
                internet_listener,
                supertrackr::standard_tracker::router(
                    supertrackr::standard_tracker::TrackerState::new(),
                )
                .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap()
        });
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let mut identities = Vec::new();
        for n in [31u8, 32] {
            let secret = StaticSecret::from([n; 32]);
            let key = hex::encode(PublicKey::from(&secret).as_bytes());
            let endpoint: SocketAddr = format!("127.0.0.1:{}", 10000 + n as u16).parse().unwrap();
            let registration = supertrackr::enrollment::register(&http, &base, &secret, endpoint)
                .await
                .unwrap();
            http.post(base.join("v1/candidates").unwrap())
                .header("x-peer-key", &key)
                .bearer_auth(&registration.token)
                .json(&serde_json::json!({"candidates":[endpoint]}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
            identities.push((key, registration.token));
        }
        let hash = "abcdefghijklmnopqrst";
        let hash_hex = hex::encode(hash);
        http.post(base.join("v1/bittorrent").unwrap()).header("x-peer-key",&identities[1].0).bearer_auth(&identities[1].1).json(&serde_json::json!({"event":"announce","info_hash":hash_hex,"application_id":hex::encode(b"33333333333333333333"),"port":6882,"complete":true})).send().await.unwrap().error_for_status().unwrap();
        let upstream: reqwest::Url = format!("http://{internet_address}/announce")
            .parse()
            .unwrap();
        let query = format!(
            "info_hash={hash}&peer_id=11111111111111111111&port=6881&uploaded=0&downloaded=0&left=1&compact=1"
        );
        http.get(format!("{upstream}?{query}"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let access = TrackerAccess {
            http: http.clone(),
            base: base.clone(),
            public: identities[0].0.clone(),
            token: identities[0].1.clone(),
        };
        let app = router(Bridge {
            access: access.clone(),
            upstream: Some(upstream),
            udp: std::sync::Arc::new(crate::udp_upstream::Announcements::new()),
            ordering: std::sync::Arc::new(std::array::from_fn(|_| tokio::sync::Mutex::new(()))),
            permits: Arc::new(tokio::sync::Semaphore::new(4)),
            selection: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        let query2 = format!(
            "info_hash={hash}&peer_id=22222222222222222222&port=6883&uploaded=0&downloaded=0&left=1&compact=1"
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/announce?{query2}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response: ClientResponse = serde_bencode::from_bytes(&bytes).unwrap();
        assert_eq!(response.peers.len(), 12);
        assert!(
            response
                .peers
                .as_chunks::<6>()
                .0
                .iter()
                .any(|peer| peer[..4] == [127, 0, 0, 1] && peer[4..] == 6881u16.to_be_bytes())
        );
        assert!(
            response
                .peers
                .as_chunks::<6>()
                .0
                .iter()
                .any(|peer| peer[..2] == [10, 203] && peer[4..] == 6882u16.to_be_bytes())
        );
        assert_eq!((response.complete, response.incomplete), (1, 3));
        let mut selected = Vec::new();
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/announce?{query2}&numwant=1"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let response: ClientResponse = serde_bencode::from_bytes(&bytes).unwrap();
            assert_eq!(response.peers.len(), 6);
            selected.push(response.peers[..2].to_vec());
        }
        assert!(selected.contains(&vec![127, 0]));
        assert!(selected.contains(&vec![10, 203]));
        let expanded = query2.replace("compact=1", "compact=0");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/announce?{expanded}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let _: serde_bencode::value::Value = serde_bencode::from_bytes(&bytes).unwrap();
        assert!(
            bytes
                .windows(20)
                .any(|part| part == b"11111111111111111111")
        );
        assert!(
            bytes
                .windows(20)
                .any(|part| part == b"33333333333333333333")
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/scrape?info_hash={hash}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let decoded: UpstreamScrape = serde_bencode::from_bytes(&bytes).unwrap();
        let counts = decoded
            .files
            .get(&serde_bytes::ByteBuf::from(hash.as_bytes().to_vec()))
            .unwrap();
        assert_eq!((counts.complete, counts.incomplete), (1, 3));
        internet.abort();
        let _ = internet.await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/announce?{query2}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response: ClientResponse = serde_bencode::from_bytes(&bytes).unwrap();
        assert!(
            response
                .peers
                .as_chunks::<6>()
                .0
                .iter()
                .any(|peer| peer[..2] == [10, 203])
        );
        assert!(
            bytes
                .windows(20)
                .any(|part| part == b"upstream unavailable")
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/scrape?info_hash={hash}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response: UpstreamScrape = serde_bencode::from_bytes(&bytes).unwrap();
        assert_eq!(
            response.files[&serde_bytes::ByteBuf::from(hash.as_bytes().to_vec())].complete,
            1
        );
        assert!(
            bytes
                .windows(20)
                .any(|part| part == b"upstream unavailable")
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_address = listener.local_addr().unwrap();
        let decoded: UpstreamResponse = serde_bencode::from_bytes(BAD_PEER_RESPONSE).unwrap();
        assert!(
            matches!(decoded.peers, UpstreamPeers::Expanded(ref peers) if peers.len() == 2 && peers[0].peer_id.as_ref().unwrap().len() == 20 && peers[1].peer_id.as_ref().unwrap().len() == 3)
        );
        let mock = tokio::spawn(async move {
            let routes = Router::new()
                .route(
                    "/announce",
                    get(|| async {
                        // One valid expanded peer followed by a malformed peer ID: the
                        // response is rejected after counts and the first peer were read.
                        BAD_PEER_RESPONSE
                    }),
                )
                .route(
                    "/slow/announce",
                    get(|| async {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        &b"d8:intervali1e5:peers0:e"[..]
                    }),
                );
            axum::serve(listener, routes).await.unwrap();
        });
        for path in ["announce", "slow/announce"] {
            let app = router(Bridge {
                access: access.clone(),
                upstream: Some(format!("http://{mock_address}/{path}").parse().unwrap()),
                udp: std::sync::Arc::new(crate::udp_upstream::Announcements::new()),
                ordering: std::sync::Arc::new(std::array::from_fn(|_| tokio::sync::Mutex::new(()))),
                permits: Arc::new(tokio::sync::Semaphore::new(4)),
                selection: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            });
            let response = app
                .oneshot(
                    Request::builder()
                        .uri(format!("/announce?{expanded}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let response: ExpandedResponse = serde_bencode::from_bytes(&bytes).unwrap();
            assert_eq!((response.complete, response.incomplete), (1, 1));
            assert!(response.interval > 1);
            assert_eq!(response.warning.as_deref(), Some("upstream unavailable"));
            assert_eq!(response.peers.len(), 1);
            assert!(response.peers[0].ip.starts_with("10.203."));
        }
        mock.abort();
        server.abort();
    }
}
