//! Native macOS utun companion. Packet-socket mode is an unprivileged test adapter.
use boringtun::x25519::PublicKey;
use clap::{Parser, ValueEnum};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};
use supertrackr::peer_manager::{Effect, MTU, Manager};
use tokio::{
    net::{UdpSocket, UnixDatagram},
    sync::{mpsc, watch},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
mod control;
mod delivery;
mod exit;
#[path = "../client/identity.rs"]
mod identity;
mod interface;
mod introduction;
#[path = "../client/mapping.rs"]
mod mapping;
mod punch;
#[cfg(feature = "bittorrent")]
mod tracker_bridge;
#[cfg(feature = "bittorrent")]
mod udp_upstream;
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum IntroductionMode {
    Direct,
    Server,
}
#[derive(Parser)]
struct Args {
    /// Local HTTP tracker adapter for interface-bound standard torrent clients.
    #[cfg(feature = "bittorrent")]
    #[arg(long)]
    tracker_bridge_listen: Option<SocketAddr>,
    /// Optional ordinary HTTP(S) or UDP tracker URL for Internet peers.
    #[cfg(feature = "bittorrent")]
    #[arg(long, requires = "tracker_bridge_listen")]
    tracker_upstream: Option<reqwest::Url>,
    /// Ordinary destinations: block, exit locally, or tunnel to an authorized gateway.
    #[arg(long, value_enum, default_value_t=exit::Mode::OverlayOnly)]
    exit_mode: exit::Mode,
    #[arg(long, requires = "exit_gateway_key")]
    exit_gateway: Option<Ipv4Addr>,
    #[arg(long, requires = "exit_gateway")]
    exit_gateway_key: Option<String>,
    /// Explicit peer public keys permitted to use this machine as an exit (maximum 8).
    #[arg(long)]
    serve_exit_for: Vec<String>,
    /// Also permit private/local destinations, including test echo servers.
    #[arg(long)]
    exit_allow_private: bool,
    /// Local inbound mapping: tcp|udp,listen-address:port,application-port.
    #[arg(long)]
    exit_forward: Vec<supertrackr::exit::Forward>,
    /// Gateway mapping: client-public-key,tcp|udp,listen-address:port,application-port.
    #[arg(long)]
    exit_forward_for: Vec<exit::PeerForward>,
    #[arg(long)]
    server: reqwest::Url,
    /// Preferred outbound introduction. Both modes are accepted on inbound connections.
    #[arg(long,value_enum,default_value_t=IntroductionMode::Direct)]
    introduction: IntroductionMode,
    #[arg(long)]
    key_file: PathBuf,
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    #[arg(long)]
    lab_http: bool,
    #[arg(long)]
    allow_network: bool,
    /// Opt-in PCP/NAT-PMP/UPnP mapping; requires router-mapping build feature.
    #[arg(long)]
    portmap: bool,
    #[arg(long)]
    stun: Vec<SocketAddr>,
    #[arg(long)]
    candidate: Vec<SocketAddr>,
    /// Test adapter only: receive raw IPv4 datagrams here instead of opening utun.
    #[arg(long, requires = "packet_peer")]
    packet_socket: Option<PathBuf>,
    #[arg(long, requires = "packet_socket")]
    packet_peer: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    run_seconds: u64,
}
fn allowed(addr: SocketAddr, network: bool) -> bool {
    supertrackr::core::traversal::valid_endpoint(addr)
        && (network || addr.ip().is_loopback())
        && !matches!(addr.ip().to_canonical(),std::net::IpAddr::V4(ip) if ip.octets()[..2]==[10,203])
}
#[cfg(feature = "bittorrent")]
fn valid_tracker_upstream(url: &reqwest::Url) -> bool {
    udp_upstream::valid_url(url)
        || (matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.path().ends_with("/announce"))
}
#[cfg(all(test, feature = "bittorrent"))]
mod tracker_url_tests {
    use super::valid_tracker_upstream;

    #[test]
    fn accepts_query_credentials_but_rejects_userinfo_and_fragments() {
        for (url, valid) in [
            ("https://tracker.example/announce?passkey=secret", true),
            ("http://tracker.example/announce", true),
            ("https://user:secret@tracker.example/announce", false),
            ("https://tracker.example/announce#fragment", false),
            ("udp://tracker.example/announce", false),
            ("udp://tracker.example:6969/announce", true),
            ("udp://[::1]:6969/announce?passkey=secret", true),
            ("udp://user:secret@tracker.example:6969/announce", false),
            ("https://tracker.example/scrape?passkey=secret", false),
        ] {
            assert_eq!(valid_tracker_upstream(&url.parse().unwrap()), valid);
        }
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
    #[cfg(feature = "bittorrent")]
    if a.tracker_bridge_listen
        .is_some_and(|address| !address.ip().is_loopback())
        || a.tracker_upstream
            .as_ref()
            .is_some_and(|url| !valid_tracker_upstream(url))
    {
        return Err("tracker bridge must bind loopback and upstream must be a valid HTTP(S) announce or UDP tracker URL without userinfo or fragment".into());
    }
    if !a.server.username().is_empty()
        || a.server.password().is_some()
        || a.server.query().is_some()
        || a.server.fragment().is_some()
        || a.server.path() != "/"
    {
        return Err("server must be an origin URL".into());
    }
    let host = a.server.host_str().unwrap_or("");
    if a.server.scheme() != "https"
        && !(a.lab_http
            && a.server.scheme() == "http"
            && host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()))
    {
        return Err("HTTPS required; --lab-http permits numeric loopback only".into());
    }
    if host
        .parse::<Ipv4Addr>()
        .is_ok_and(|ip| ip.octets()[..2] == [10, 203])
    {
        return Err("tracker must be outside overlay".into());
    }
    if a.stun.len() > 2
        || a.candidate.len() > if a.portmap { 4 } else { 5 }
        || a.listen.ip().is_unspecified()
        || (!a.allow_network && !a.listen.ip().is_loopback())
        || a.stun
            .iter()
            .chain(&a.candidate)
            .any(|&v| !allowed(v, a.allow_network))
    {
        return Err("invalid endpoint or missing --allow-network; bind a concrete local IP".into());
    }
    if a.portmap && (!a.allow_network || !a.listen.is_ipv4() || a.listen.ip().is_loopback()) {
        return Err("--portmap requires --allow-network and a non-loopback IPv4 bind".into());
    }
    if (a.exit_mode == exit::Mode::Remote) != a.exit_gateway.is_some()
        || a.exit_gateway
            .is_some_and(|ip| !supertrackr::peer_manager::overlay(ip))
        || a.serve_exit_for.len() > 8
        || a.serve_exit_for
            .iter()
            .chain(a.exit_gateway_key.iter())
            .any(|key| {
                key.len() != 64 || hex::decode(key).is_err() || key != &key.to_ascii_lowercase()
            })
    {
        return Err("remote exit requires an overlay gateway IP and lowercase public key; at most eight gateway clients".into());
    }
    if a.exit_forward.len() > 16
        || (!a.exit_forward.is_empty() && a.exit_mode != exit::Mode::Local)
        || a.exit_forward_for.len() > 128
        || a.exit_forward_for
            .iter()
            .any(|f| !a.serve_exit_for.contains(&f.key))
        || a.serve_exit_for
            .iter()
            .any(|key| a.exit_forward_for.iter().filter(|f| &f.key == key).count() > 16)
    {
        return Err("inbound mappings require local mode or an explicitly allowed gateway client; at most 16 per client".into());
    }
    if a.packet_socket.is_none() {
        interface::preflight()?;
    }
    let secret = identity::load_or_create(&a.key_file)?;
    let public = hex::encode(PublicKey::from(&secret).as_bytes());
    let socket = UdpSocket::bind(a.listen).await?;
    let endpoint = socket.local_addr()?;
    if !allowed(endpoint, a.allow_network) {
        return Err("invalid bind endpoint".into());
    }
    let mapping = mapping::Mapping::new(a.portmap, endpoint.port())?;
    let mut mapping_at = Instant::now();
    let mut initial = vec![endpoint];
    for &c in &a.candidate {
        if !initial.contains(&c) {
            initial.push(c);
        }
    }
    let (control, info) = control::Control::new(
        a.server.clone(),
        public.clone(),
        endpoint,
        initial.clone(),
        a.introduction,
        &secret,
    )
    .await?;
    #[cfg(feature = "bittorrent")]
    let bridge_server = if let Some(address) = a.tracker_bridge_listen {
        let listener = tokio::net::TcpListener::bind(address).await?;
        let bridge = tracker_bridge::Bridge {
            access: control.tracker_access(),
            upstream: a.tracker_upstream.clone(),
            udp: std::sync::Arc::new(udp_upstream::Announcements::new()),
            ordering: std::sync::Arc::new(std::array::from_fn(|_| tokio::sync::Mutex::new(()))),
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
            selection: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        Some(tokio::spawn(async move {
            axum::serve(listener, tracker_bridge::router(bridge)).await
        }))
    } else {
        None
    };
    let adapter = interface::Adapter::new(
        info.virtual_ip,
        a.packet_socket.as_deref(),
        a.packet_peer.as_deref(),
        a.exit_mode != exit::Mode::OverlayOnly,
    )
    .await?;
    if a.exit_gateway == Some(info.virtual_ip) {
        return Err("exit gateway cannot be self".into());
    }
    let mut exits = exit::Exits::new(&a, info.virtual_ip)?;
    let mut lease = control.expires();
    let intro_key = *PublicKey::from(&secret).as_bytes();
    let mut manager = Manager::new(secret, info.virtual_ip);
    let mut introductions =
        introduction::Introductions::new(a.server.as_str(), intro_key, Instant::now());
    let (requests, rx) = mpsc::channel(128);
    let (tx, mut events) = mpsc::channel(128);
    // Proactively establish gateway/client bindings so inbound listeners do not
    // depend on the application first initiating an Internet flow.
    for key in a.serve_exit_for.iter().chain(a.exit_gateway_key.iter()) {
        requests.try_send(control::Request::Peer(key.clone()))?;
    }

    let (candidates, candidate_rx) = watch::channel(initial.clone());
    let mut worker = tokio::spawn(control.run(rx, tx, candidate_rx));
    let mut discovery = supertrackr::stun::Discovery::new(&a.stun);
    let mut tick = tokio::time::interval(Duration::from_millis(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let stop = tokio::time::sleep(Duration::from_secs(if a.run_seconds == 0 {
        u64::from(u32::MAX)
    } else {
        a.run_seconds
    }));
    tokio::pin!(stop);
    let mut udp = [0; 2049];
    let mut ip = [0; 2049];
    let mut io_dropped = 0u64;
    let mut delivery = delivery::Queue::default();
    let mut puncher = punch::Puncher::new();
    let mut punch_sent = 0u64;
    let mut server_bindings_received = 0u64;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    println!(
        "{}",
        serde_json::json!({"event":"ready","public_key":public,"virtual_ip":info.virtual_ip,"interface":adapter.name(),"endpoint":endpoint,"exit_mode":format!("{:?}",a.exit_mode),"exit_ipv6":supertrackr::exit::ipv6(info.virtual_ip).to_string()})
    );
    let result:Result<()>=async {loop {
        if Instant::now()>=lease {return Err("local registration expired".into());}
        let mut actions=Vec::new();
        let mut effects=tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            _=&mut stop=>break,
            r=&mut worker=>{r??;return Err("control worker stopped".into());},
            sent=delivery.send(lease, |p|adapter.send(p))=>{delivery.pop();if !sent {io_dropped+=1;}vec![]},
            _=tick.tick()=>{
                let now=Instant::now();
                if now>=mapping_at {mapping.retry();mapping_at=now+Duration::from_secs(15);}
                for (to,p) in discovery.due(now.into()) {if socket.send_to(&p,to).await.is_err(){io_dropped+=1;}}
                let mut list=initial.clone();for e in discovery.candidates(now.into()) {if allowed(e,a.allow_network)&&!list.contains(&e){list.push(e);}}
                if let Some(addr)=mapping.address() && allowed(addr,a.allow_network) && !list.contains(&addr){list.push(addr);}
                candidates.send_if_modified(|old|if *old!=list {*old=list;true}else{false});
                for (to,p) in puncher.due(now) {if socket.send_to(&p,to).await.is_ok(){punch_sent+=1;}else{io_dropped+=1;}}
                actions.extend(introductions.tick(now));
                let (local,remote)=exits.poll(Instant::now()).await;
                for p in local {if !delivery.push(p,lease,Instant::now()){io_dropped+=1;}}
                let mut effects=manager.tick(Instant::now());for p in remote {effects.extend(manager.send(p,Instant::now()));}effects
            },
            r=adapter.recv(&mut ip)=>{let n=r?;if let Some(p)=exits.outbound(ip[..n].to_vec(),Instant::now()){manager.send(p,Instant::now())}else{vec![]}},
            r=socket.recv_from(&mut udp)=>{let(n,from)=r?;if !allowed(from,a.allow_network){io_dropped+=1;continue;}
                if discovery.receive(from,&udp[..n],Instant::now().into()){continue;}
                if punch::Puncher::is_probe(&udp[..n]){continue;}
                if introduction::Introductions::is_introduction(&udp[..n]) {actions.extend(introductions.receive(&udp[..n],from,Instant::now()));vec![]}
                else {manager.receive(&udp[..n],Some(from),None,Instant::now())}
            },
            event=events.recv()=>match event.ok_or("control events closed")? {
                control::Event::Punch(hints,at)=>{
                    for mut h in hints {
                        if let Some(p)=h.binding.take() {
                            if (2..=5).contains(&h.remaining_seconds) && at+Duration::from_secs(h.remaining_seconds-1)>Instant::now()
                                && (2..=86400).contains(&p.remaining_seconds) && p.candidates==h.candidates && p.candidates.iter().all(|&v|allowed(v,a.allow_network)) {
                                let until=at+Duration::from_secs(p.remaining_seconds-1);
                                actions.push(introduction::Action::Install(p,until));server_bindings_received+=1;
                            }else{io_dropped+=1;}
                        }
                        puncher.add(h,at,Instant::now(),a.allow_network);
                    }vec![]
                },
                control::Event::RendezvousUnavailable=>{puncher.dropped+=1;vec![]},
                control::Event::Lease(until)=>{lease=until;vec![]},
                control::Event::Discovered(p,until)=>{
                    if p.candidates.iter().any(|&v|!allowed(v,a.allow_network)){io_dropped+=1;continue;}
                    if a.introduction==IntroductionMode::Server {actions.push(introduction::Action::Install(p,until));server_bindings_received+=1;}
                    else {actions.extend(introductions.begin(p,until,Instant::now()));}vec![]
                },
                control::Event::Verified(ticket,p,until)=>{
                    if p.candidates.iter().any(|&v|!allowed(v,a.allow_network)){io_dropped+=1;continue;}
                    actions.extend(introductions.verified(ticket,p,until,Instant::now()));vec![]
                },
                control::Event::Refreshed(p,until)=>{
                    if until<=Instant::now() || p.candidates.iter().any(|&v|!allowed(v,a.allow_network)){continue;}
                    if !exits.install(&p,until){io_dropped+=1;continue;}
                    manager.install(p,until,Instant::now()).unwrap_or_else(|_|{io_dropped+=1;vec![]})
                },
            }
        };
        if Instant::now()>=lease {return Err("local registration expired".into());}
        for action in actions {match action {
            introduction::Action::Send(to,p)=>{if socket.send_to(&p,to).await.is_err(){io_dropped+=1;}},
            introduction::Action::Verify(ticket)=>{if requests.try_send(control::Request::Verify(ticket)).is_err(){io_dropped+=1;}},
            introduction::Action::Install(p,until)=>{
                let key=p.public_key.clone();
                if !exits.install(&p,until){io_dropped+=1;continue;}
                match manager.install(p,until,Instant::now()) {
                    Ok(e)=>{effects.extend(e);if requests.try_send(control::Request::Track(key,until)).is_err(){io_dropped+=1;}},
                    Err(_)=>{io_dropped+=1;},
                }
            }
        }}
        for effect in effects {match effect {
            Effect::Network {to:Some(to),data,..}=>{if socket.send_to(&data,to).await.is_err(){io_dropped+=1;}},
            Effect::Network {to:None,..}=>{}, // Direct companion never calls the legacy HTTP relay.
            Effect::Resolve(ip)=>{if requests.try_send(control::Request::Resolve(ip)).is_err(){io_dropped+=1;}},
            Effect::Deliver(p)=>{
                let until=supertrackr::peer_manager::addresses(&p).and_then(|(src,_)|manager.peer_deadline(src)).unwrap_or_else(Instant::now).min(lease);
                let Some(p)=exits.inbound(p,Instant::now()) else {continue;};
                if !delivery.push(p,until,Instant::now()){io_dropped+=1;}
            },
        }}
    } Ok(())}.await;
    worker.abort();
    #[cfg(feature = "bittorrent")]
    if let Some(bridge) = bridge_server {
        bridge.abort();
    }
    mapping.shutdown().await;
    println!(
        "{}",
        serde_json::json!({"event":"summary","delivered":manager.delivered,"direct_delivered":manager.direct_delivered,"relay_delivered":manager.relay_delivered,"rejected":manager.rejected,"queue_dropped":manager.dropped,"io_dropped":io_dropped,"introductions_completed":introductions.completed,"server_bindings_received":server_bindings_received,"introductions_rejected":introductions.rejected,"punch_hints":puncher.hints,"punch_sent":punch_sent,"punch_dropped":puncher.dropped,"validated_pongs":manager.validated_pongs,"rejected_pongs":manager.rejected_pongs,"path_changes":manager.path_changes,"mapping_varies_by_destination":discovery.mapping_varies_by_destination(tokio::time::Instant::now())})
    );
    result
}
