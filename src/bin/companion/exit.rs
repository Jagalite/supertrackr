use super::*;
use std::collections::HashMap;
use supertrackr::{
    CandidatePeer,
    exit::{Engine, Forward, is_overlay, owns, packet_addresses, unwrap, wrap},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    OverlayOnly,
    Local,
    Remote,
}
#[derive(Clone, Debug)]
pub struct PeerForward {
    pub key: String,
    pub forward: Forward,
}
impl std::str::FromStr for PeerForward {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        let (key, rest) = s
            .split_once(',')
            .ok_or("expected public-key,tcp|udp,listen-address:port,target-port")?;
        if key.len() != 64 || hex::decode(key).is_err() || key != key.to_ascii_lowercase() {
            return Err("invalid client public key".into());
        }
        Ok(Self {
            key: key.into(),
            forward: rest.parse()?,
        })
    }
}
pub struct Exits {
    mode: Mode,
    local: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    gateway_key: Option<String>,
    allowed: Vec<String>,
    private: bool,
    bindings: HashMap<Ipv4Addr, (String, Instant)>,
    engines: HashMap<Ipv4Addr, Engine>,
    forwards: Vec<PeerForward>,
}
impl Exits {
    pub fn new(a: &Args, local: Ipv4Addr) -> Result<Self> {
        let mut engines = HashMap::new();
        if a.exit_mode == Mode::Local {
            let mut engine = Engine::new(local, a.exit_allow_private);
            for f in &a.exit_forward {
                engine.add_forward(f)?;
            }
            engines.insert(local, engine);
        }
        Ok(Self {
            mode: a.exit_mode,
            local,
            gateway: a.exit_gateway,
            gateway_key: a.exit_gateway_key.clone(),
            allowed: a.serve_exit_for.clone(),
            private: a.exit_allow_private,
            bindings: HashMap::new(),
            engines,
            forwards: a.exit_forward_for.clone(),
        })
    }
    pub fn install(&mut self, p: &CandidatePeer, until: Instant) -> bool {
        if until <= Instant::now()
            || !supertrackr::peer_manager::overlay(p.virtual_ip)
            || p.virtual_ip == self.local
        {
            return false;
        }
        if Some(p.virtual_ip) == self.gateway && Some(&p.public_key) != self.gateway_key.as_ref() {
            return false;
        }
        if self.allowed.contains(&p.public_key) || Some(p.virtual_ip) == self.gateway {
            // One engine per authenticated key, even if re-enrollment changes its IP.
            let stale: Vec<_> = self
                .bindings
                .iter()
                .filter(|(ip, (key, _))| **ip != p.virtual_ip && key == &p.public_key)
                .map(|(ip, _)| *ip)
                .collect();
            for ip in stale {
                self.bindings.remove(&ip);
                self.engines.remove(&ip);
            }

            if self
                .bindings
                .get(&p.virtual_ip)
                .is_some_and(|(key, until)| key != &p.public_key || *until <= Instant::now())
            {
                self.engines.remove(&p.virtual_ip);
            }
            if self.allowed.contains(&p.public_key) && !self.engines.contains_key(&p.virtual_ip) {
                let mut engine = Engine::new(p.virtual_ip, self.private);
                for mapping in self.forwards.iter().filter(|f| f.key == p.public_key) {
                    if let Err(error) = engine.add_forward(&mapping.forward) {
                        eprintln!("exit listener failed for {}: {error}", p.public_key);
                        return false;
                    }
                }
                self.engines.insert(p.virtual_ip, engine);
            }
            self.bindings
                .insert(p.virtual_ip, (p.public_key.clone(), until));
        }
        true
    }
    pub fn outbound(&mut self, p: Vec<u8>, now: Instant) -> Option<Vec<u8>> {
        let (src, dst) = packet_addresses(&p)?;
        if !owns(self.local, src) {
            return None;
        }
        if is_overlay(dst) {
            return Some(p);
        }
        match self.mode {
            Mode::OverlayOnly => None,
            Mode::Local => {
                let _ = self
                    .engines
                    .entry(self.local)
                    .or_insert_with(|| Engine::new(self.local, self.private))
                    .ingest(p, now);
                None
            }
            Mode::Remote => wrap(self.local, self.gateway?, false, &p),
        }
    }
    /// Called only on authenticated WireGuard plaintext delivered by Manager.
    pub fn inbound(&mut self, p: Vec<u8>, now: Instant) -> Option<Vec<u8>> {
        if p.get(9) != Some(&252) {
            return Some(p);
        }
        let (src, dst, response, inner) = unwrap(&p)?;
        if dst != self.local {
            return None;
        }
        let (inner_src, inner_dst) = packet_addresses(&inner)?;
        if response {
            if self.mode == Mode::Remote
                && Some(src) == self.gateway
                && owns(self.local, inner_dst)
                && !is_overlay(inner_src)
                && self.bindings.get(&src).is_some_and(|(key, until)| {
                    Some(key) == self.gateway_key.as_ref() && *until > now
                })
            {
                return Some(inner);
            }
        } else if owns(src, inner_src)
            && self
                .bindings
                .get(&src)
                .is_some_and(|(key, until)| self.allowed.contains(key) && *until > now)
            && (self.engines.len() < 8 || self.engines.contains_key(&src))
        {
            let _ = self
                .engines
                .entry(src)
                .or_insert_with(|| Engine::new(src, self.private))
                .ingest(inner, now);
        }
        None
    }
    pub async fn poll(&mut self, now: Instant) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        self.bindings.retain(|_, (_, until)| *until > now);
        self.engines.retain(|ip, _| {
            (*ip == self.local && self.mode == Mode::Local) || self.bindings.contains_key(ip)
        });
        let mut local = vec![];
        let mut remote = vec![];
        for (ip, engine) in &mut self.engines {
            for p in engine.poll(now).await {
                if *ip == self.local {
                    local.push(p);
                } else if let Some(p) = wrap(self.local, *ip, true, &p) {
                    remote.push(p);
                }
            }
        }
        (local, remote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::StaticSecret;
    fn exits(
        mode: Mode,
        local: Ipv4Addr,
        gateway: Option<(Ipv4Addr, String)>,
        allowed: Vec<String>,
    ) -> Exits {
        Exits {
            mode,
            local,
            gateway: gateway.as_ref().map(|g| g.0),
            gateway_key: gateway.map(|g| g.1),
            allowed,
            private: true,
            bindings: HashMap::new(),
            engines: HashMap::new(),
            forwards: vec![],
        }
    }
    fn packet(src: Ipv4Addr, dst: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 32];
        p[0] = 0x45;
        p[3] = 32;
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&4000u16.to_be_bytes());
        p[22..24].copy_from_slice(&port.to_be_bytes());
        p[25] = 12;
        p[28..].copy_from_slice(b"echo");
        let mut s: u32 = p[..20]
            .chunks(2)
            .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
            .sum();
        while s > 65535 {
            s = (s & 65535) + (s >> 16);
        }
        p[10..12].copy_from_slice(&(!(s as u16)).to_be_bytes());
        p
    }
    fn packet6(source: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut p = vec![0; 52];
        p[0] = 0x60;
        p[5] = 12;
        p[6] = 17;
        p[7] = 64;
        p[8..24].copy_from_slice(&supertrackr::exit::ipv6(source).octets());
        p[24..40].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        p[40..42].copy_from_slice(&4000u16.to_be_bytes());
        p[42..44].copy_from_slice(&port.to_be_bytes());
        p[45] = 12;
        p[48..].copy_from_slice(b"echo");
        let mut pseudo = p[8..40].to_vec();
        pseudo.extend_from_slice(&[0, 0, 0, 12, 0, 0, 0, 17]);
        pseudo.extend_from_slice(&p[40..]);
        let mut sum: u32 = pseudo
            .chunks(2)
            .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
            .sum();
        while sum > 65535 {
            sum = (sum & 65535) + (sum >> 16);
        }
        let sum = !(sum as u16);
        p[46..48].copy_from_slice(&(if sum == 0 { 65535 } else { sum }).to_be_bytes());
        p
    }
    fn peer(n: u8) -> (Manager, CandidatePeer) {
        let secret = StaticSecret::from([n; 32]);
        let ip = Ipv4Addr::new(10, 203, 0, n);
        let key = hex::encode(PublicKey::from(&secret).as_bytes());
        let ep = format!("127.0.0.1:{}", 2000 + u16::from(n))
            .parse()
            .unwrap();
        (
            Manager::new(secret, ip),
            CandidatePeer {
                public_key: key,
                virtual_ip: ip,
                endpoint: ep,
                candidates: vec![ep],
                remaining_seconds: 30,
            },
        )
    }
    fn exchange(
        a: &mut Manager,
        b: &mut Manager,
        ae: SocketAddr,
        be: SocketAddr,
        initial: Vec<Effect>,
        now: Instant,
    ) -> Vec<Vec<u8>> {
        let mut queue = std::collections::VecDeque::from([(false, initial)]);
        let mut packets = vec![];
        for _ in 0..100 {
            let Some((from_b, effects)) = queue.pop_front() else {
                break;
            };
            for effect in effects {
                match effect {
                    Effect::Network { data, .. } => {
                        let next = if from_b {
                            a.receive(&data, Some(be), None, now)
                        } else {
                            b.receive(&data, Some(ae), None, now)
                        };
                        queue.push_back((!from_b, next));
                    }
                    Effect::Deliver(p) => packets.push(p),
                    _ => {}
                }
            }
        }
        packets
    }
    #[tokio::test]
    async fn remote_exit_over_wireguard_and_fail_closed_policy() {
        remote_roundtrip(false).await;
        remote_roundtrip(true).await;
    }
    async fn remote_roundtrip(v6: bool) {
        let (mut client_manager, client) = peer(2);
        let (mut gateway_manager, gateway) = peer(3);
        let now = Instant::now();
        let until = now + Duration::from_secs(30);
        client_manager.install(gateway.clone(), until, now).unwrap();
        gateway_manager.install(client.clone(), until, now).unwrap();
        let mut c = exits(
            Mode::Remote,
            client.virtual_ip,
            Some((gateway.virtual_ip, gateway.public_key.clone())),
            vec![],
        );
        let mut g = exits(
            Mode::OverlayOnly,
            gateway.virtual_ip,
            None,
            vec![client.public_key.clone()],
        );
        assert!(c.install(&gateway, until));
        assert!(g.install(&client, until));
        let echo = tokio::net::UdpSocket::bind(if v6 { "[::1]:0" } else { "127.0.0.1:0" })
            .await
            .unwrap();
        let p = if v6 {
            packet6(client.virtual_ip, echo.local_addr().unwrap().port())
        } else {
            packet(
                client.virtual_ip,
                Ipv4Addr::LOCALHOST,
                echo.local_addr().unwrap().port(),
            )
        };
        let envelope = c.outbound(p.clone(), now).unwrap();
        assert!(c.engines.is_empty());
        let effects = client_manager.send(envelope, now);
        let incoming = exchange(
            &mut client_manager,
            &mut gateway_manager,
            client.endpoint,
            gateway.endpoint,
            effects,
            now,
        );
        assert_eq!(incoming.len(), 1);
        assert!(g.inbound(incoming[0].clone(), now).is_none());
        let mut b = [0; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[..n], b"echo");
        echo.send_to(&b[..n], from).await.unwrap();
        let mut replies = vec![];
        for _ in 0..100 {
            replies.extend(g.poll(Instant::now()).await.1);
            if !replies.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(replies.len(), 1);
        let effects = gateway_manager.send(replies.remove(0), Instant::now());
        let incoming = exchange(
            &mut gateway_manager,
            &mut client_manager,
            gateway.endpoint,
            client.endpoint,
            effects,
            Instant::now(),
        );
        assert_eq!(incoming.len(), 1);
        let response = incoming[0].clone();
        let inner = c.inbound(response.clone(), Instant::now()).unwrap();
        assert_eq!(&inner[if v6 { 48 } else { 28 }..], b"echo");
        assert!(c.inbound(response, until).is_none());
        c.poll(until).await;
        assert!(c.engines.is_empty());
        assert!(c.outbound(p.clone(), until).is_some());
        assert!(c.engines.is_empty()); // Only encrypted gateway envelopes, never local egress.
        let mut denied = exits(Mode::OverlayOnly, gateway.virtual_ip, None, vec![]);
        denied.inbound(
            wrap(client.virtual_ip, gateway.virtual_ip, false, &p).unwrap(),
            now,
        );
        assert!(denied.engines.is_empty());
        let mut wrong = gateway.clone();
        wrong.public_key = client.public_key;
        assert!(!c.install(&wrong, until));
        let mut off = exits(Mode::OverlayOnly, client.virtual_ip, None, vec![]);
        assert!(off.outbound(p, now).is_none());
        assert!(off.engines.is_empty());
    }
}

#[cfg(test)]
mod inbound_tests {
    use super::*;
    #[tokio::test]
    async fn gateway_listener_requires_live_authorized_binding_and_closes_on_expiry() {
        let key = "01".repeat(32);
        let ip = Ipv4Addr::new(10, 203, 0, 2);
        let local = Ipv4Addr::new(10, 203, 0, 3);
        // Reserve then release a concrete test port; production configuration rejects port zero.
        let reserve = std::net::UdpSocket::bind("[::1]:0").unwrap();
        let addr = reserve.local_addr().unwrap();
        drop(reserve);
        let mut gateway = Exits {
            mode: Mode::OverlayOnly,
            local,
            gateway: None,
            gateway_key: None,
            allowed: vec![key.clone()],
            private: false,
            bindings: HashMap::new(),
            engines: HashMap::new(),
            forwards: vec![PeerForward {
                key: key.clone(),
                forward: Forward {
                    listen: addr,
                    target_port: 6881,
                    tcp: false,
                },
            }],
        };
        let now = Instant::now();
        let until = now + Duration::from_secs(10);
        let mut peer = CandidatePeer {
            public_key: "02".repeat(32),
            virtual_ip: ip,
            endpoint: "127.0.0.1:1000".parse().unwrap(),
            candidates: vec!["127.0.0.1:1000".parse().unwrap()],
            remaining_seconds: 10,
        };
        assert!(gateway.install(&peer, until));
        assert!(gateway.engines.is_empty());
        peer.public_key = key;
        assert!(gateway.install(&peer, until));
        assert!(std::net::UdpSocket::bind(addr).is_err());
        let external = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        external.send_to(b"hello", addr).await.unwrap();
        let mut packets = vec![];
        for _ in 0..100 {
            packets.extend(gateway.poll(Instant::now()).await.1);
            if !packets.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(packets.len(), 1);
        let (src, dst, response, inner) = unwrap(&packets[0]).unwrap();
        assert_eq!((src, dst, response), (local, ip, true));
        assert!(owns(ip, packet_addresses(&inner).unwrap().1));
        gateway.poll(until).await;
        assert!(gateway.engines.is_empty());
        assert!(std::net::UdpSocket::bind(addr).is_ok());
    }
}
