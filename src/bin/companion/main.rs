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
#[path = "../client/identity.rs"]
mod identity;
mod interface;
mod introduction;
#[path = "../client/mapping.rs"]
mod mapping;
mod punch;
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum IntroductionMode {
    Direct,
    Server,
}
#[derive(Parser)]
struct Args {
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
#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
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
    let adapter = interface::Adapter::new(
        info.virtual_ip,
        a.packet_socket.as_deref(),
        a.packet_peer.as_deref(),
    )
    .await?;
    let mut lease = control.expires();
    let intro_key = *PublicKey::from(&secret).as_bytes();
    let mut manager = Manager::new(secret, info.virtual_ip);
    let mut introductions =
        introduction::Introductions::new(a.server.as_str(), intro_key, Instant::now());
    let (requests, rx) = mpsc::channel(128);
    let (tx, mut events) = mpsc::channel(128);
    let (candidates, candidate_rx) = watch::channel(initial.clone());
    let mut worker = tokio::spawn(control.run(rx, tx, candidate_rx));
    let mut discovery = supertrackr::stun::Discovery::new(&a.stun);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
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
    let mut puncher = punch::Puncher::new();
    let mut punch_sent = 0u64;
    let mut server_bindings_received = 0u64;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    println!(
        "{}",
        serde_json::json!({"event":"ready","public_key":public,"virtual_ip":info.virtual_ip,"interface":adapter.name(),"endpoint":endpoint})
    );
    let result:Result<()>=async {loop {
        if Instant::now()>=lease {return Err("local registration expired".into());}
        let mut actions=Vec::new();
        let mut effects=tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            _=&mut stop=>break,
            r=&mut worker=>{r??;return Err("control worker stopped".into());},
            _=tick.tick()=>{
                let now=Instant::now();
                if now>=mapping_at {mapping.retry();mapping_at=now+Duration::from_secs(15);}
                for (to,p) in discovery.due(now.into()) {if socket.send_to(&p,to).await.is_err(){io_dropped+=1;}}
                let mut list=initial.clone();for e in discovery.candidates(now.into()) {if allowed(e,a.allow_network)&&!list.contains(&e){list.push(e);}}
                if let Some(addr)=mapping.address() && allowed(addr,a.allow_network) && !list.contains(&addr){list.push(addr);}
                candidates.send_if_modified(|old|if *old!=list {*old=list;true}else{false});
                for (to,p) in puncher.due(now) {if socket.send_to(&p,to).await.is_ok(){punch_sent+=1;}else{io_dropped+=1;}}
                actions.extend(introductions.tick(now));
                manager.tick(now)
            },
            r=adapter.recv(&mut ip)=>{let n=r?;manager.send(ip[..n].to_vec(),Instant::now())},
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
            Effect::Deliver(p)=>{match tokio::time::timeout(Duration::from_millis(20),adapter.send(&p)).await {Ok(Ok(n)) if n==p.len()=>(),_=>io_dropped+=1}},
        }}
    } Ok(())}.await;
    worker.abort();
    mapping.shutdown().await;
    println!(
        "{}",
        serde_json::json!({"event":"summary","delivered":manager.delivered,"direct_delivered":manager.direct_delivered,"relay_delivered":manager.relay_delivered,"rejected":manager.rejected,"queue_dropped":manager.dropped,"io_dropped":io_dropped,"introductions_completed":introductions.completed,"server_bindings_received":server_bindings_received,"introductions_rejected":introductions.rejected,"punch_hints":puncher.hints,"punch_sent":punch_sent,"punch_dropped":puncher.dropped,"validated_pongs":manager.validated_pongs,"rejected_pongs":manager.rejected_pongs,"path_changes":manager.path_changes,"mapping_varies_by_destination":discovery.mapping_varies_by_destination(tokio::time::Instant::now())})
    );
    result
}
