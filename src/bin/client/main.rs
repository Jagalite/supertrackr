//! Single-peer loopback client lab. Real WireGuard packets; no OS TUN or routes.
mod identity;
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
use supertrackr::{Peer, RegistrationResponse, Verification};
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
struct Control {
    http: reqwest::Client,
    base: reqwest::Url,
    public: String,
    token: String,
    expires: Instant,
    refresh_at: Instant,
    refreshes: u64,
}
impl Control {
    async fn register(base: reqwest::Url, public: String, endpoint: SocketAddr) -> Result<Self> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()?;
        let start = Instant::now();
        let r: RegistrationResponse = http
            .post(base.join("v1/register")?)
            .json(&json!({"public_key":public,"endpoint":endpoint}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut raw = [0; 32];
        if !(1..=86400).contains(&r.expires_in_seconds)
            || hex::decode_to_slice(&r.token, &mut raw).is_err()
        {
            return Err("invalid registration response".into());
        }
        let ttl = Duration::from_secs(r.expires_in_seconds);
        Ok(Self {
            http,
            base,
            public,
            token: r.token,
            expires: start + ttl,
            refresh_at: start + ttl / 2,
            refreshes: 0,
        })
    }
    fn authenticated(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        r.header("x-peer-key", &self.public)
            .bearer_auth(&self.token)
    }
    async fn refresh(&mut self, endpoint: SocketAddr) -> Result<()> {
        let start = Instant::now();
        let r: RegistrationResponse = self
            .authenticated(self.http.post(self.base.join("v1/register")?))
            .json(&json!({"public_key":self.public,"endpoint":endpoint}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if r.token != self.token || !(1..=86400).contains(&r.expires_in_seconds) {
            return Err("invalid refresh response".into());
        }
        let ttl = Duration::from_secs(r.expires_in_seconds);
        self.expires = start + ttl;
        self.refresh_at = start + ttl / 2;
        self.refreshes += 1;
        Ok(())
    }
    async fn discover(&self, wanted: Option<&str>, ipv4: bool) -> Result<Option<(Peer, Instant)>> {
        let peers: Vec<Peer> = self
            .authenticated(self.http.get(self.base.join("v1/peers?limit=100")?))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        for p in peers {
            if p.public_key == self.public
                || wanted.is_some_and(|k| k != p.public_key)
                || !p.endpoint.ip().is_loopback()
                || p.endpoint.port() == 0
                || p.endpoint.is_ipv4() != ipv4
            {
                continue;
            }
            if key(&p.public_key).is_err() {
                continue;
            }
            let start = Instant::now();
            let response = self
                .authenticated(self.http.post(self.base.join("v1/verify")?))
                .json(&json!({"public_key":p.public_key,"endpoint":p.endpoint}))
                .send()
                .await?;
            if response.status() == reqwest::StatusCode::NOT_FOUND
                || response.status() == reqwest::StatusCode::CONFLICT
            {
                continue;
            }
            let v: Verification = response.error_for_status()?.json().await?;
            if !v.verified
                || v.peer.public_key != p.public_key
                || v.peer.endpoint != p.endpoint
                || !(1..=86400).contains(&v.peer.remaining_seconds)
            {
                return Err("invalid verification response".into());
            }
            let expires = start + Duration::from_secs(v.peer.remaining_seconds);
            return Ok(Some((v.peer, expires)));
        }
        Ok(None)
    }
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
    fn receive(&mut self, data: &[u8]) -> Vec<Action> {
        let mut out = [0u8; 65536];
        let mut actions = Vec::new();
        let mut a = action(
            self.tunn
                .decapsulate(Some(self.binding.endpoint.ip()), data, &mut out),
        );
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
    rejected: u64,
}
async fn network(
    socket: &UdpSocket,
    endpoint: SocketAddr,
    a: Action,
    stats: &mut Stats,
) -> Result<()> {
    match a {
        Action::Network(bytes) => {
            socket.send_to(&bytes, endpoint).await?;
            stats.encrypted_sent += 1;
        }
        Action::Rejected => stats.rejected += 1,
        _ => {}
    }
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
    if !a.listen.ip().is_loopback()
        || a.tunnel_ip == a.peer_ip
        || !a.tunnel_ip.is_private()
        || !a.peer_ip.is_private()
        || !(1..=3600).contains(&a.run_seconds)
    {
        return Err("lab requires loopback UDP, distinct private IPv4 tunnel addresses, and duration 1..3600".into());
    }
    let base = validate_server(&a.server, a.lab_http)?;
    let mut wanted = a.peer_key.as_deref().map(key).transpose()?.map(hex::encode);
    let secret = identity::load_or_create(&a.key_file)?;
    let public = hex::encode(PublicKey::from(&secret).as_bytes());
    if wanted.as_deref() == Some(&public) {
        return Err("peer key must differ from own key".into());
    }
    let socket = UdpSocket::bind(a.listen).await?;
    let endpoint = socket.local_addr()?;
    let mut control = Control::register(base, public.clone(), endpoint).await?;
    println!(
        "{}",
        json!({"event":"ready","public_key":public,"endpoint":endpoint,"tunnel_ip":a.tunnel_ip})
    );
    let end = Instant::now() + Duration::from_secs(a.run_seconds);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut discover_at = Instant::now();
    let mut ping_at = Instant::now();
    let mut tunnel: Option<Tunnel> = None;
    let mut pending = HashMap::<u64, Instant>::new();
    let mut stats = Stats::default();
    let mut recv = [0u8; 65536];
    loop {
        let now = Instant::now();
        if now >= end {
            break;
        }
        if now >= control.expires {
            return Err("local registration expired".into());
        }
        if tunnel.as_ref().is_some_and(|t| now >= t.expires) {
            tunnel = None;
            pending.clear();
        }
        tokio::select! {
            _=tokio::time::sleep_until(end)=>break,
            _=tokio::signal::ctrl_c()=>break,
            _=tick.tick()=>{
                if Instant::now()>=control.refresh_at {control.refresh(endpoint).await?;}
                if Instant::now()>=discover_at {
                    if let Some((binding,expires))=control.discover(wanted.as_deref(),endpoint.is_ipv4()).await? {
                        if let Some(t)=tunnel.as_mut().filter(|t|t.binding.public_key==binding.public_key && t.binding.endpoint==binding.endpoint) {t.expires=expires;}
                        else {
                            wanted=Some(binding.public_key.clone());
                            println!("{}",json!({"event":"peer_verified","public_key":binding.public_key,"endpoint":binding.endpoint}));
                            tunnel=Some(Tunnel::new(&secret,binding,expires)?);pending.clear();
                        }
                    }
                    discover_at=Instant::now()+Duration::from_millis(500);
                }
                let now=Instant::now();
                if now>=end {break;}
                if now>=control.expires {return Err("local registration expired".into());}
                if let Some(t)=tunnel.as_mut().filter(|t|now<t.expires) {
                    let output=t.timer();network(&socket,t.binding.endpoint,output,&mut stats).await?;
                    pending.retain(|_,at|now.duration_since(*at)<Duration::from_secs(5));
                    if now>=ping_at && pending.len()<8 {
                        let nonce=rand::random::<u64>();pending.insert(nonce,now);
                        let output=t.send(&packet::encode(a.tunnel_ip,a.peer_ip,1,nonce));
                        network(&socket,t.binding.endpoint,output,&mut stats).await?;
                        ping_at=now+Duration::from_secs(1);
                    }
                }
            },
            incoming=socket.recv_from(&mut recv)=>{
                let (len,source)=incoming?;
                if Instant::now()>=control.expires {return Err("local registration expired".into());}
                let Some(t)=tunnel.as_mut().filter(|t|source==t.binding.endpoint && Instant::now()<t.expires) else {stats.rejected+=1;continue;};
                stats.encrypted_received+=1;
                for output in t.receive(&recv[..len]) {
                    if let Action::Packet(bytes,src)=output {
                        let decoded=if src==a.peer_ip {packet::decode(&bytes,a.peer_ip,a.tunnel_ip)} else {None};
                        match decoded {
                            Some((1,nonce))=>{stats.pings_received+=1;let output=t.send(&packet::encode(a.tunnel_ip,a.peer_ip,2,nonce));network(&socket,t.binding.endpoint,output,&mut stats).await?;},
                            Some((2,nonce)) if pending.remove(&nonce).is_some()=>{stats.pongs_received+=1;},
                            _=>stats.rejected+=1,
                        }
                    } else {network(&socket,t.binding.endpoint,output,&mut stats).await?;}
                }
            },
        }
    }
    println!(
        "{}",
        json!({"event":"summary","public_key":public,"refreshes":control.refreshes,"encrypted_sent":stats.encrypted_sent,
        "encrypted_received":stats.encrypted_received,"pings_received":stats.pings_received,"pongs_received":stats.pongs_received,"rejected":stats.rejected})
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
