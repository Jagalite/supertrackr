//! Single-peer WireGuard traversal lab. Real encrypted packets; no OS TUN or routes.
mod control;
mod identity;
mod mapping;
mod packet;
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use clap::Parser;
use serde_json::json;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};
use supertrackr::stun;
use supertrackr::{CandidatePeer, Peer};
use tokio::{net::UdpSocket, time::Instant};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Parser)]
struct Args {
    #[arg(long)]
    server: String,
    #[arg(long)]
    key_file: PathBuf,
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    #[arg(long)]
    tunnel_ip: Ipv4Addr,
    #[arg(long)]
    peer_ip: Ipv4Addr,
    /// Optional expected public key; otherwise pin the first verified discovery result.
    #[arg(long)]
    peer_key: Option<String>,
    #[arg(long, default_value_t = 30)]
    run_seconds: u64,
    /// Requested application packets per second (emitted in 100 ms batches).
    #[arg(long, default_value_t = 1)]
    packets_per_second: usize,
    /// Total inner IPv4 packet size including the test payload.
    #[arg(long, default_value_t = 44)]
    packet_size: usize,
    /// Request UDP port mapping using PCP, NAT-PMP, or UPnP (requires router-mapping feature).
    #[arg(long)]
    portmap: bool,
    /// STUN servers (numeric UDP endpoints); up to two, queried on the WireGuard socket.
    #[arg(long)]
    stun: Vec<SocketAddr>,
    /// Explicit advertised candidate(s), useful for port forwarding and NAT labs.
    #[arg(long)]
    candidate: Vec<SocketAddr>,
    /// Wait for a tracker connection request rather than choosing a discovery result.
    #[arg(long)]
    passive: bool,
    /// Disable direct UDP for relay testing.
    #[arg(long)]
    relay_only: bool,
    /// Permit non-loopback peer addresses. Control still requires HTTPS off loopback.
    #[arg(long)]
    allow_network: bool,
    /// Permit plaintext coordinator HTTP on a numeric loopback address only.
    #[arg(long)]
    lab_http: bool,
}
fn key(s: &str) -> Result<[u8; 32]> {
    let mut raw = [0; 32];
    hex::decode_to_slice(s, &mut raw).map_err(|_| "invalid public key")?;
    if raw == [0; 32] {
        return Err("zero public key".into());
    }
    Ok(raw)
}
fn validate_server(url: &str, lab_http: bool) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(url)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("server must be an origin URL without credentials, query, or path".into());
    }
    let local = url
        .host_str()
        .and_then(|h| {
            h.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|ip| ip.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && lab_http && local) {
        return Err("server requires HTTPS, or explicit --lab-http on numeric loopback".into());
    }
    Ok(url)
}
enum Action {
    None,
    Network(Vec<u8>),
    Packet(Vec<u8>, Ipv4Addr),
    Rejected,
}
fn action(result: TunnResult<'_>) -> Action {
    match result {
        TunnResult::Done => Action::None,
        TunnResult::WriteToNetwork(bytes) => Action::Network(bytes.to_vec()),
        TunnResult::WriteToTunnelV4(bytes, src) => Action::Packet(bytes.to_vec(), src),
        TunnResult::WriteToTunnelV6(..) | TunnResult::Err(_) => Action::Rejected,
    }
}
struct Tunnel {
    tunn: Tunn,
    binding: Peer,
    expires: Instant,
}
impl Tunnel {
    fn new(secret: &StaticSecret, binding: Peer, expires: Instant) -> Result<Self> {
        let public = PublicKey::from(key(&binding.public_key)?);
        Ok(Self {
            tunn: Tunn::new(
                secret.clone(),
                public,
                None,
                Some(5),
                (rand::random::<u32>() & 0xffffff).max(1),
                None,
            ),
            binding,
            expires,
        })
    }
    fn send(&mut self, packet: &[u8]) -> Action {
        let mut out = [0u8; 65536];
        action(self.tunn.encapsulate(packet, &mut out))
    }
    fn timer(&mut self) -> Action {
        let mut out = [0u8; 65536];
        action(self.tunn.update_timers(&mut out))
    }
    #[cfg(test)]
    fn receive(&mut self, data: &[u8]) -> Vec<Action> {
        self.receive_from(data, Some(self.binding.endpoint.ip()))
    }
    fn receive_from(&mut self, data: &[u8], source: Option<std::net::IpAddr>) -> Vec<Action> {
        let mut out = [0u8; 65536];
        let mut actions = Vec::new();
        let mut a = action(self.tunn.decapsulate(source, data, &mut out));
        loop {
            let more = matches!(a, Action::Network(_));
            actions.push(a);
            if !more {
                break;
            }
            a = action(self.tunn.decapsulate(None, &[], &mut out));
        }
        actions
    }
}
#[derive(Default)]
struct Stats {
    encrypted_sent: u64,
    encrypted_received: u64,
    pings_received: u64,
    pongs_received: u64,
    pings_generated: u64,
    timed_out: u64,
    inner_bytes_generated: u64,
    rejected: u64,
    relay_sent: u64,
    relay_received: u64,
    relay_dropped: u64,
    udp_errors: u64,
    refreshes: u64,
    direct_validated: u64,
}
struct Session {
    tunnel: Tunnel,
    candidates: Vec<SocketAddr>,
    direct: Option<(SocketAddr, Instant)>,
}
impl Session {
    fn active(&self, now: Instant) -> Option<SocketAddr> {
        self.direct
            .filter(|(_, at)| now.duration_since(*at) < Duration::from_secs(5))
            .map(|(a, _)| a)
    }
}
async fn transmit(
    socket: &UdpSocket,
    relay: &tokio::sync::mpsc::Sender<control::Relay>,
    s: &Session,
    output: Action,
    destination: Option<Option<SocketAddr>>,
    relay_only: bool,
    stats: &mut Stats,
) -> Result<()> {
    match output {
        Action::Network(data) => {
            if data.len() > supertrackr::core::traversal::MAX_DATAGRAM {
                stats.rejected += 1;
                return Ok(());
            }
            let active = s.active(Instant::now());
            let addresses: Vec<_> = match destination {
                Some(Some(addr)) if !relay_only => vec![addr],
                Some(_) => vec![],
                None if relay_only => vec![],
                None => active.map_or_else(|| s.candidates.clone(), |addr| vec![addr]),
            };
            for addr in addresses {
                match socket.send_to(&data, addr).await {
                    Ok(_) => stats.encrypted_sent += 1,
                    Err(_) => stats.udp_errors += 1,
                }
            }
            let use_relay = matches!(destination, Some(None))
                || (destination.is_none() && (relay_only || active.is_none()));
            if use_relay {
                match relay.try_send(control::Relay {
                    target: s.tunnel.binding.public_key.clone(),
                    data,
                }) {
                    Ok(()) => stats.relay_sent += 1,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        stats.relay_dropped += 1
                    }
                    Err(_) => return Err("control worker closed".into()),
                }
            }
        }
        Action::Rejected => stats.rejected += 1,
        _ => {}
    }
    Ok(())
}
fn allowed(addr: SocketAddr, a: &Args) -> bool {
    supertrackr::core::traversal::valid_endpoint(addr)
        && addr.is_ipv4() == a.listen.is_ipv4()
        && (a.allow_network || addr.ip().is_loopback())
}
#[allow(clippy::too_many_arguments)]
async fn incoming(
    data: &[u8],
    source: Option<SocketAddr>,
    s: &mut Session,
    a: &Args,
    socket: &UdpSocket,
    relay: &tokio::sync::mpsc::Sender<control::Relay>,
    pending: &mut HashMap<u64, Instant>,
    stats: &mut Stats,
) -> Result<()> {
    if data.len() > supertrackr::core::traversal::MAX_DATAGRAM || Instant::now() >= s.tunnel.expires
    {
        stats.rejected += 1;
        return Ok(());
    }
    stats.encrypted_received += 1;
    if source.is_none() {
        stats.relay_received += 1;
    }
    for output in s.tunnel.receive_from(data, source.map(|s| s.ip())) {
        if let Action::Packet(bytes, src) = output {
            let decoded = if src == a.peer_ip {
                packet::decode(&bytes, a.peer_ip, a.tunnel_ip)
            } else {
                None
            };
            if decoded.is_none() {
                stats.rejected += 1;
                continue;
            }
            if let Some(addr) = source {
                if s.active(Instant::now()) != Some(addr) {
                    stats.direct_validated += 1;
                    println!("{}", json!({"event":"direct_path","endpoint":addr}));
                }
                s.direct = Some((addr, Instant::now()));
            }
            match decoded.unwrap() {
                (1, nonce) => {
                    stats.pings_received += 1;
                    let output = s.tunnel.send(&packet::encode_sized(
                        a.tunnel_ip,
                        a.peer_ip,
                        2,
                        nonce,
                        bytes.len(),
                    ));
                    transmit(socket, relay, s, output, Some(source), a.relay_only, stats).await?;
                }
                (2, nonce) if pending.remove(&nonce).is_some() => {
                    stats.pongs_received += 1;
                    println!(
                        "{}",
                        json!({"event":"roundtrip","transport":if source.is_some(){"udp"}else{"relay"},"at_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis()})
                    );
                }
                _ => stats.rejected += 1,
            }
        } else {
            transmit(socket, relay, s, output, Some(source), a.relay_only, stats).await?;
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
    if (!a.allow_network && !a.listen.ip().is_loopback())
        || a.tunnel_ip == a.peer_ip
        || !a.tunnel_ip.is_private()
        || !a.peer_ip.is_private()
        || !(1..=3600).contains(&a.run_seconds)
        || !(1..=1000).contains(&a.packets_per_second)
        || !(44..=1400).contains(&a.packet_size)
        || a.stun.len() > 2
        || a.candidate.len() > 5
        || a.candidate
            .iter()
            .chain(&a.stun)
            .any(|&addr| !allowed(addr, &a))
    {
        return Err("invalid addresses/duration; non-loopback UDP requires --allow-network; max 2 STUN servers and 5 explicit candidates".into());
    }
    if a.portmap && (!a.allow_network || !a.listen.is_ipv4() || a.listen.ip().is_loopback()) {
        return Err("--portmap requires --allow-network and a non-loopback IPv4 bind".into());
    }
    let base = validate_server(&a.server, a.lab_http)?;
    let wanted = a.peer_key.as_deref().map(key).transpose()?.map(hex::encode);
    let secret = identity::load_or_create(&a.key_file)?;
    let public = hex::encode(PublicKey::from(&secret).as_bytes());
    if wanted.as_deref() == Some(&public) {
        return Err("peer key must differ from own key".into());
    }
    let socket = UdpSocket::bind(a.listen).await?;
    let bound = socket.local_addr()?;
    let endpoint = if !bound.ip().is_unspecified() {
        bound
    } else {
        let route = a.stun.first().or(a.candidate.first()).ok_or(
            "wildcard bind needs a STUN server or explicit candidate to choose a local route",
        )?;
        let probe = std::net::UdpSocket::bind(SocketAddr::new(bound.ip(), 0))?;
        probe.connect(route)?;
        SocketAddr::new(probe.local_addr()?.ip(), bound.port())
    };
    let host_candidates = if a.candidate.is_empty() {
        vec![endpoint]
    } else {
        a.candidate.clone()
    };
    let mapping = mapping::Mapping::new(a.portmap, endpoint.port())?;
    let control = control::Control::register(base, public.clone(), endpoint).await?;
    let mut expires = control.expires();
    let (candidate_tx, candidate_rx) = tokio::sync::watch::channel(host_candidates.clone());
    let (relay_tx, relay_rx) = tokio::sync::mpsc::channel(32);
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(64);
    let mut worker =
        tokio::spawn(control.run(wanted.clone(), a.passive, candidate_rx, relay_rx, event_tx));
    println!(
        "{}",
        json!({"event":"ready","public_key":public,"endpoint":endpoint,"tunnel_ip":a.tunnel_ip})
    );
    let result = run(
        &a,
        &secret,
        &socket,
        &relay_tx,
        &candidate_tx,
        &mut event_rx,
        &mut worker,
        &mut expires,
        host_candidates,
        &mapping,
    )
    .await;
    if !worker.is_finished() {
        worker.abort();
        let _ = worker.await;
    }
    mapping.shutdown().await;
    result
}
#[allow(clippy::too_many_arguments)]
async fn run(
    a: &Args,
    secret: &StaticSecret,
    socket: &UdpSocket,
    relay: &tokio::sync::mpsc::Sender<control::Relay>,
    candidate_tx: &tokio::sync::watch::Sender<Vec<SocketAddr>>,
    events: &mut tokio::sync::mpsc::Receiver<control::Event>,
    worker: &mut tokio::task::JoinHandle<Result<()>>,
    expires: &mut Instant,
    host_candidates: Vec<SocketAddr>,
    mapping: &mapping::Mapping,
) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(a.run_seconds);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut discovery = stun::Discovery::new(&a.stun);
    let mut session: Option<Session> = None;
    let mut pinned = a.peer_key.as_deref().map(key).transpose()?.map(hex::encode);
    let mut packet_credit = 0usize;
    let mut probe_at = Instant::now();
    let mut mapping_at = Instant::now();
    let mut pending = HashMap::<u64, Instant>::new();
    let mut stats = Stats::default();
    let mut recv = [0; 65536];
    loop {
        let now = Instant::now();
        if now >= end {
            break;
        }
        if now >= *expires {
            return Err("local registration expired".into());
        }
        if session.as_ref().is_some_and(|s| now >= s.tunnel.expires) {
            session = None;
            stats.timed_out += pending.len() as u64;
            pending.clear();
        }
        tokio::select! {
            _=tokio::time::sleep_until(end)=>break,
            _=tokio::signal::ctrl_c()=>break,
            result=&mut *worker=>{result??;return Err("control worker stopped".into());},
            event=events.recv()=>match event.ok_or("control events closed")? {
                control::Event::Lease(until,refreshes)=>{*expires=until;stats.refreshes=refreshes;},
                control::Event::RelayDropped=>stats.relay_dropped+=1,
                control::Event::Peer(p,until)=>{
                    if key(&p.public_key).is_err() || p.candidates.is_empty() || p.candidates.len()>8
                        || p.candidates.iter().any(|&addr|!allowed(addr,a)) || pinned.as_ref().is_some_and(|k|*k!=p.public_key) {stats.rejected+=1;continue;}
                    pinned=Some(p.public_key.clone());
                    if let Some(s)=&mut session {s.tunnel.expires=until;s.candidates=p.candidates;}
                    else {
                        println!("{}",json!({"event":"peer_verified","public_key":p.public_key,"endpoint":p.endpoint,"candidates":p.candidates}));
                        let binding=Peer {public_key:p.public_key,endpoint:p.endpoint,remaining_seconds:p.remaining_seconds};
                        session=Some(Session {tunnel:Tunnel::new(secret,binding,until)?,candidates:p.candidates,direct:None});
                    }
                },
                control::Event::Packet(public,data)=>{
                    if Instant::now()>=*expires {return Err("local registration expired".into());}
                    if let Some(s)=session.as_mut().filter(|s|s.tunnel.binding.public_key==public) {
                        incoming(&data,None,s,a,socket,relay,&mut pending,&mut stats).await?;
                    } else {stats.rejected+=1;}
                },
            },
            _=tick.tick()=>{
                let now=Instant::now();
                if now>=mapping_at {mapping.retry();mapping_at=now+Duration::from_secs(15);}
                for (server,request) in discovery.due(now) {if socket.send_to(&request,server).await.is_err(){stats.udp_errors+=1;}}
                let mut candidates=host_candidates.clone();
                if let Some(addr)=mapping.address() && allowed(addr,a) && !candidates.contains(&addr) {candidates.push(addr);}
                for addr in discovery.candidates(now) {if allowed(addr,a) && !candidates.contains(&addr){candidates.push(addr);}}
                if *candidate_tx.borrow()!=candidates {println!("{}",json!({"event":"candidates","addresses":candidates}));candidate_tx.send_replace(candidates);}
                if let Some(s)=session.as_mut().filter(|s|now<s.tunnel.expires) {
                    let out=s.tunnel.timer();transmit(socket,relay,s,out,None,a.relay_only,&mut stats).await?;
                    let before=pending.len();pending.retain(|_,at|now.duration_since(*at)<Duration::from_secs(5));stats.timed_out+=(before-pending.len()) as u64;
                    {
                        packet_credit+=a.packets_per_second;
                        let count=packet_credit/10;packet_credit%=10;
                        for _ in 0..count {
                            if pending.len()>=1024 {break;}
                            let nonce=rand::random();pending.insert(nonce,now);
                            stats.pings_generated+=1;stats.inner_bytes_generated+=a.packet_size as u64;
                            let out=s.tunnel.send(&packet::encode_sized(a.tunnel_ip,a.peer_ip,1,nonce,a.packet_size));
                            transmit(socket,relay,s,out,None,a.relay_only,&mut stats).await?;
                        }

                    }
                    if now>=probe_at && !a.relay_only {
                        // Unique WireGuard packet per direct candidate avoids replay races with relay delivery.
                        for addr in s.candidates.clone() {
                            if pending.len()>=1024 {break;}
                            let nonce=rand::random();pending.insert(nonce,now);
                            stats.pings_generated+=1;stats.inner_bytes_generated+=44;
                            let out=s.tunnel.send(&packet::encode(a.tunnel_ip,a.peer_ip,1,nonce));
                            transmit(socket,relay,s,out,Some(Some(addr)),false,&mut stats).await?;
                        }
                        probe_at=now+Duration::from_secs(2);
                    }
                }
            },
            data=socket.recv_from(&mut recv)=>{
                let (n,source)=match data {Ok(v)=>v,Err(_)=>{stats.udp_errors+=1;continue;}};
                let now=Instant::now();
                if discovery.receive(source,&recv[..n],now){continue;}
                if now>=*expires {return Err("local registration expired".into());}
                if !allowed(source,a) || a.relay_only {stats.rejected+=1;continue;}
                if let Some(s)=&mut session {incoming(&recv[..n],Some(source),s,a,socket,relay,&mut pending,&mut stats).await?;}
                else {stats.rejected+=1;}
            },
        }
    }
    println!(
        "{}",
        json!({"event":"summary","refreshes":stats.refreshes,"encrypted_sent":stats.encrypted_sent,"encrypted_received":stats.encrypted_received,
        "pings_received":stats.pings_received,"pongs_received":stats.pongs_received,"rejected":stats.rejected,
        "relay_sent":stats.relay_sent,"relay_received":stats.relay_received,"relay_dropped":stats.relay_dropped,
        "udp_errors":stats.udp_errors,"direct_validated":stats.direct_validated,
        "pings_generated":stats.pings_generated,"inner_bytes_generated":stats.inner_bytes_generated,"timed_out":stats.timed_out,"pending_at_exit":pending.len(),"requested_packets_per_second":a.packets_per_second,"packet_size":a.packet_size})
    );
    if stats.pongs_received == 0 {
        return Err("no authenticated round trip completed".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plaintext_control_requires_explicit_loopback_opt_in() {
        assert!(validate_server("http://127.0.0.1:8443", false).is_err());
        assert!(validate_server("http://192.0.2.1", true).is_err());
        assert!(validate_server("http://127.0.0.1:8443", true).is_ok());
        assert!(validate_server("http://[::1]:8443", true).is_ok());
        assert!(validate_server("https://example.com", false).is_ok());
        assert!(validate_server("https://user:pass@example.com", false).is_err());
    }
    #[test]
    fn wrong_private_key_cannot_complete_handshake() {
        let expected = StaticSecret::from([1; 32]);
        let responder = StaticSecret::from([2; 32]);
        let impostor = StaticSecret::from([3; 32]);
        let binding = |public_key| Peer {
            public_key,
            endpoint: "127.0.0.1:51820".parse().unwrap(),
            remaining_seconds: 60,
        };
        let expires = Instant::now() + Duration::from_secs(60);
        let mut a = Tunnel::new(
            &impostor,
            binding(hex::encode(PublicKey::from(&responder).as_bytes())),
            expires,
        )
        .unwrap();
        let mut b = Tunnel::new(
            &responder,
            binding(hex::encode(PublicKey::from(&expected).as_bytes())),
            expires,
        )
        .unwrap();
        let plain = packet::encode(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            1,
            42,
        );
        let Action::Network(init) = a.send(&plain) else {
            panic!("handshake expected")
        };
        assert!(
            b.receive(&init)
                .iter()
                .all(|r| matches!(r, Action::Rejected | Action::None))
        );
        assert!(b.tunn.stats().0.is_none());
    }
    #[test]
    fn real_handshake_encryption_tamper_and_replay() {
        let sa = StaticSecret::from([1; 32]);
        let sb = StaticSecret::from([2; 32]);
        let pa = hex::encode(PublicKey::from(&sa).as_bytes());
        let pb = hex::encode(PublicKey::from(&sb).as_bytes());
        let binding = |public_key| Peer {
            public_key,
            endpoint: "127.0.0.1:51820".parse().unwrap(),
            remaining_seconds: 60,
        };
        let mut a =
            Tunnel::new(&sa, binding(pb), Instant::now() + Duration::from_secs(60)).unwrap();
        let mut b =
            Tunnel::new(&sb, binding(pa), Instant::now() + Duration::from_secs(60)).unwrap();
        let plain = packet::encode(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            1,
            42,
        );
        let Action::Network(init) = a.send(&plain) else {
            panic!("handshake expected")
        };
        let response = b
            .receive(&init)
            .into_iter()
            .find_map(|x| {
                if let Action::Network(v) = x {
                    Some(v)
                } else {
                    None
                }
            })
            .unwrap();
        let encrypted = a
            .receive(&response)
            .into_iter()
            .find_map(|x| {
                if let Action::Network(v) = x {
                    (v.len() > 32).then_some(v)
                } else {
                    None
                }
            })
            .unwrap();
        assert!(!encrypted.windows(plain.len()).any(|w| w == plain));
        let mut corrupt = encrypted.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(
            !b.receive(&corrupt)
                .iter()
                .any(|x| matches!(x, Action::Packet(..)))
        );
        assert!(
            b.receive(&encrypted)
                .iter()
                .any(|x| matches!(x,Action::Packet(v,_) if v==&plain))
        );
        assert!(
            !b.receive(&encrypted)
                .iter()
                .any(|x| matches!(x, Action::Packet(..)))
        );
    }
}
