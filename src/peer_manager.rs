//! Bounded multi-peer WireGuard routing engine. No sockets or OS route changes.
use crate::CandidatePeer;
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};
pub const MTU: usize = 1280;
const MAX_PEERS: usize = 64;
#[derive(Debug)]
pub enum Effect {
    Network {
        key: String,
        to: Option<SocketAddr>,
        data: Vec<u8>,
    },
    Deliver(Vec<u8>),
    Resolve(Ipv4Addr),
}
struct Peer {
    tunn: Tunn,
    binding: CandidatePeer,
    until: Instant,
    paths: crate::path_selection::Paths,
    probe_at: Instant,
}
struct Waiting {
    packets: Vec<Vec<u8>>,
    until: Instant,
}
pub struct Manager {
    secret: StaticSecret,
    local: Ipv4Addr,
    peers: HashMap<String, Peer>,
    waiting: HashMap<Ipv4Addr, Waiting>,
    next_index: u32,
    pub rejected: u64,
    pub dropped: u64,
    pub delivered: u64,
    pub direct_delivered: u64,
    pub relay_delivered: u64,
    pub relay_only: bool,
    pub validated_pongs: u64,
    pub rejected_pongs: u64,
    pub path_changes: u64,
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u16::from_be_bytes([v[0], v[1]]) as u32)
        .sum::<u32>();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
pub fn addresses(p: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if p.len() < 20
        || p[0] >> 4 != 4
        || (p.len() > MTU
            && !(p.len() <= crate::exit::MTU + 24
                && p.len() >= 24
                && p[0] == 0x45
                && p[9] == 252
                && &p[20..23] == b"EX1"))
    {
        return None;
    }
    let header = usize::from(p[0] & 15) * 4;
    if header < 20
        || header > p.len()
        || usize::from(u16::from_be_bytes([p[2], p[3]])) != p.len()
        || checksum(&p[..header]) != 0
    {
        return None;
    }
    Some((
        Ipv4Addr::new(p[12], p[13], p[14], p[15]),
        Ipv4Addr::new(p[16], p[17], p[18], p[19]),
    ))
}
#[cfg(test)]
fn probe(src: Ipv4Addr, dst: Ipv4Addr, kind: u8) -> Vec<u8> {
    probe_nonce(src, dst, kind, rand::random())
}
fn probe_nonce(src: Ipv4Addr, dst: Ipv4Addr, kind: u8, nonce: u64) -> Vec<u8> {
    let mut p = vec![0; 36];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&36u16.to_be_bytes());
    p[8] = 64;
    p[9] = 253;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let c = checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[20..24].copy_from_slice(b"STP1");
    p[24] = kind;
    p[28..36].copy_from_slice(&nonce.to_be_bytes());
    p
}
enum Output {
    None,
    Network(Vec<u8>),
    Ip(Vec<u8>),
    Reject,
}
fn output(result: TunnResult<'_>) -> Output {
    match result {
        TunnResult::Done => Output::None,
        TunnResult::WriteToNetwork(p) => Output::Network(p.to_vec()),
        TunnResult::WriteToTunnelV4(p, _) => Output::Ip(p.to_vec()),
        _ => Output::Reject,
    }
}
impl Peer {
    fn route(&mut self, data: Vec<u8>, now: Instant, relay_only: bool) -> Vec<Effect> {
        if !relay_only && let Some(addr) = self.paths.best(now) {
            return vec![Effect::Network {
                key: self.binding.public_key.clone(),
                to: Some(addr),
                data,
            }];
        }
        let mut out = Vec::new();
        if !relay_only {
            for addr in self.paths.targets(now) {
                out.push(Effect::Network {
                    key: self.binding.public_key.clone(),
                    to: Some(addr),
                    data: data.clone(),
                });
            }
        }
        out.push(Effect::Network {
            key: self.binding.public_key.clone(),
            to: None,
            data,
        });
        out
    }
}
impl Manager {
    pub fn new(secret: StaticSecret, local: Ipv4Addr) -> Self {
        Self {
            secret,
            local,
            peers: HashMap::new(),
            waiting: HashMap::new(),
            next_index: 1,
            rejected: 0,
            dropped: 0,
            delivered: 0,
            direct_delivered: 0,
            relay_delivered: 0,
            relay_only: false,
            validated_pongs: 0,
            rejected_pongs: 0,
            path_changes: 0,
        }
    }
    pub fn install(
        &mut self,
        binding: CandidatePeer,
        until: Instant,
        now: Instant,
    ) -> Result<Vec<Effect>, &'static str> {
        let mut raw = [0; 32];
        if hex::decode_to_slice(&binding.public_key, &mut raw).is_err()
            || raw == [0; 32]
            || raw == *PublicKey::from(&self.secret).as_bytes()
            || binding.virtual_ip == self.local
            || !overlay(binding.virtual_ip)
            || until <= now
            || binding.candidates.is_empty()
            || binding.candidates.len() > 8
            || binding
                .candidates
                .iter()
                .any(|&e| !crate::core::traversal::valid_endpoint(e))
        {
            return Err("invalid peer binding");
        }
        if self.peers.iter().any(|(key, p)| {
            *key != binding.public_key
                && p.binding.virtual_ip == binding.virtual_ip
                && p.until > now
        }) {
            return Err("conflicting peer address");
        }
        self.peers.retain(|_, p| p.until > now);
        if let Some(p) = self
            .peers
            .get_mut(&binding.public_key)
            .filter(|p| p.binding.virtual_ip == binding.virtual_ip)
        {
            p.until = until;
            p.paths.configure(&binding.candidates, now);
            p.binding = binding.clone();
        } else {
            if self.peers.len() >= MAX_PEERS || self.next_index >= 0xffffff {
                return Err("peer capacity");
            }
            let tunn = Tunn::new(
                self.secret.clone(),
                PublicKey::from(raw),
                None,
                Some(5),
                self.next_index,
                None,
            );
            self.next_index += 1;
            let mut paths = crate::path_selection::Paths::default();
            paths.configure(&binding.candidates, now);
            self.peers.insert(
                binding.public_key.clone(),
                Peer {
                    tunn,
                    binding: binding.clone(),
                    until,
                    paths,
                    probe_at: now,
                },
            );
        }
        let mut out = Vec::new();
        if let Some(w) = self.waiting.remove(&binding.virtual_ip) {
            if now < w.until {
                for p in w.packets {
                    out.extend(self.send(p, now));
                }
            } else {
                self.dropped += w.packets.len() as u64;
            }
        }
        Ok(out)
    }
    /// Current authenticated deadline for queued application delivery.
    pub fn peer_deadline(&self, ip: Ipv4Addr) -> Option<Instant> {
        self.peers
            .values()
            .find(|peer| peer.binding.virtual_ip == ip)
            .map(|peer| peer.until)
    }
    pub fn send(&mut self, packet: Vec<u8>, now: Instant) -> Vec<Effect> {
        let Some((src, dst)) = addresses(&packet) else {
            self.rejected += 1;
            return vec![];
        };
        if src != self.local || !overlay(dst) || dst == self.local {
            self.rejected += 1;
            return vec![];
        }
        if let Some(p) = self
            .peers
            .values_mut()
            .find(|p| p.binding.virtual_ip == dst && p.until > now)
        {
            let mut buf = [0; 2048];
            return match output(p.tunn.encapsulate(&packet, &mut buf)) {
                Output::Network(data) => p.route(data, now, self.relay_only),
                Output::Reject => {
                    self.rejected += 1;
                    vec![]
                }
                _ => vec![],
            };
        }
        if let Some(w) = self.waiting.get_mut(&dst) {
            if w.packets.len() < 4 {
                w.packets.push(packet);
            } else {
                self.dropped += 1;
            }
            return vec![];
        }
        if self.waiting.len() >= 64 {
            self.dropped += 1;
            return vec![];
        }
        self.waiting.insert(
            dst,
            Waiting {
                packets: vec![packet],
                until: now + Duration::from_secs(3),
            },
        );
        vec![Effect::Resolve(dst)]
    }
    pub fn receive(
        &mut self,
        data: &[u8],
        source: Option<SocketAddr>,
        relay_key: Option<&str>,
        now: Instant,
    ) -> Vec<Effect> {
        if data.len() > 2048 || (source.is_some() && self.relay_only) {
            self.rejected += 1;
            return vec![];
        }
        let mut result = Vec::new();
        let mut buf = [0; 2048];
        for (key, p) in &mut self.peers {
            if p.until <= now || relay_key.is_some_and(|k| k != key) {
                continue;
            }
            let mut o = output(p.tunn.decapsulate(source.map(|s| s.ip()), data, &mut buf));
            if matches!(o, Output::Reject) {
                continue;
            }
            loop {
                match o {
                    Output::Network(data) => result.push(Effect::Network {
                        key: key.clone(),
                        to: source,
                        data,
                    }),
                    Output::Ip(packet) => {
                        if addresses(&packet) != Some((p.binding.virtual_ip, self.local)) {
                            self.rejected += 1;
                            break;
                        }
                        if let Some(addr) = source {
                            p.paths.learn(addr, now);
                        }
                        if packet[9] == 253 && packet.len() == 36 && &packet[20..24] == b"STP1" {
                            let nonce = u64::from_be_bytes(packet[28..36].try_into().unwrap());
                            if packet[24] == 1 {
                                let reply = probe_nonce(self.local, p.binding.virtual_ip, 2, nonce);
                                if let Output::Network(data) =
                                    output(p.tunn.encapsulate(&reply, &mut buf))
                                {
                                    result.push(Effect::Network {
                                        key: key.clone(),
                                        to: source,
                                        data,
                                    });
                                }
                            } else if packet[24] == 2
                                && let Some(addr) = source
                            {
                                let previous = p.paths.best(now);
                                if p.paths.confirm(addr, nonce, now) {
                                    self.validated_pongs += 1;
                                    if previous != p.paths.best(now) {
                                        self.path_changes += 1;
                                    }
                                } else {
                                    self.rejected_pongs += 1;
                                }
                            }
                        } else {
                            self.delivered += 1;
                            if source.is_some() {
                                self.direct_delivered += 1;
                            } else {
                                self.relay_delivered += 1;
                            }
                            result.push(Effect::Deliver(packet));
                        }
                        break;
                    }
                    Output::Reject => {
                        self.rejected += 1;
                        break;
                    }
                    Output::None => break,
                }
                o = output(p.tunn.decapsulate(None, &[], &mut buf));
            }
            return result;
        }
        self.rejected += 1;
        result
    }
    pub fn tick(&mut self, now: Instant) -> Vec<Effect> {
        self.peers.retain(|_, p| p.until > now);
        self.waiting.retain(|_, w| {
            if now >= w.until {
                self.dropped += w.packets.len() as u64;
                false
            } else {
                true
            }
        });
        let mut out = Vec::new();
        let mut buf = [0; 2048];
        for p in self.peers.values_mut() {
            if let Output::Network(data) = output(p.tunn.update_timers(&mut buf)) {
                out.extend(p.route(data, now, self.relay_only));
            }
            if now >= p.probe_at {
                // Probe each candidate with a distinct authenticated WireGuard packet.
                if !self.relay_only {
                    for addr in p.paths.targets(now) {
                        let nonce = p.paths.challenge(addr, now).expect("known path");
                        if let Output::Network(data) = output(p.tunn.encapsulate(
                            &probe_nonce(self.local, p.binding.virtual_ip, 1, nonce),
                            &mut buf,
                        )) {
                            out.push(Effect::Network {
                                key: p.binding.public_key.clone(),
                                to: Some(addr),
                                data,
                            });
                        }
                    }
                }
                p.probe_at = now + Duration::from_secs(2);
            }
        }
        out
    }
}
pub fn overlay(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10
        && o[1] == 203
        && u16::from_be_bytes([o[2], o[3]]) != 0
        && u16::from_be_bytes([o[2], o[3]]) != 65535
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make(n: u8, now: Instant) -> (Manager, CandidatePeer) {
        let secret = StaticSecret::from([n; 32]);
        let ip = Ipv4Addr::new(10, 203, 0, n);
        let binding = CandidatePeer {
            public_key: hex::encode(PublicKey::from(&secret).as_bytes()),
            virtual_ip: ip,
            endpoint: format!("127.0.0.1:{}", 2000 + u16::from(n))
                .parse()
                .unwrap(),
            candidates: vec![
                format!("127.0.0.1:{}", 2000 + u16::from(n))
                    .parse()
                    .unwrap(),
            ],
            remaining_seconds: 30,
        };
        let _ = now;
        (Manager::new(secret, ip), binding)
    }
    fn data(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut p = probe(src, dst, 0);
        p[9] = 17;
        p[10..12].fill(0);
        let c = checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p
    }
    fn pump(
        a: &mut Manager,
        b: &mut Manager,
        mut effects: Vec<Effect>,
        now: Instant,
    ) -> Vec<Vec<u8>> {
        let mut delivered = vec![];
        for _ in 0..20 {
            let mut next = vec![];
            for e in effects {
                match e {
                    Effect::Network { to: None, data, .. } => {
                        next.extend(b.receive(&data, None, None, now))
                    }
                    Effect::Deliver(p) => delivered.push(p),
                    _ => (),
                }
            }
            if next.is_empty() {
                return delivered;
            }
            effects = vec![];
            for e in next {
                match e {
                    Effect::Network { to: None, data, .. } => {
                        effects.extend(a.receive(&data, None, None, now))
                    }
                    Effect::Deliver(p) => delivered.push(p),
                    _ => (),
                }
            }
        }
        panic!("handshake did not settle")
    }
    #[test]
    fn multiple_tunnels_authenticate_inner_source_and_expire() {
        let now = Instant::now();
        let (mut a, aa) = make(1, now);
        let (mut b, bb) = make(2, now);
        let (mut c, cc) = make(3, now);
        for m in [&mut a, &mut b, &mut c] {
            m.relay_only = true;
        }
        a.install(bb.clone(), now + Duration::from_secs(30), now)
            .unwrap();
        a.install(cc.clone(), now + Duration::from_secs(30), now)
            .unwrap();
        b.install(aa.clone(), now + Duration::from_secs(30), now)
            .unwrap();
        c.install(aa.clone(), now + Duration::from_secs(30), now)
            .unwrap();
        for (remote, ip) in [(&mut b, bb.virtual_ip), (&mut c, cc.virtual_ip)] {
            let p = data(aa.virtual_ip, ip);
            let e = a.send(p.clone(), now);
            assert_eq!(pump(&mut a, remote, e, now), vec![p]);
        }
        // An authenticated WireGuard peer still cannot impersonate a different inner IP.
        let bad = data(cc.virtual_ip, aa.virtual_ip);
        let mut buf = [0; 2048];
        let Output::Network(wire) = output(
            b.peers
                .get_mut(&aa.public_key)
                .unwrap()
                .tunn
                .encapsulate(&bad, &mut buf),
        ) else {
            panic!("no packet")
        };
        assert!(a.receive(&wire, None, Some(&bb.public_key), now).is_empty());
        assert_eq!(a.rejected, 1);
        let later = now + Duration::from_secs(31);
        a.tick(later);
        assert!(matches!(
            a.send(data(aa.virtual_ip, bb.virtual_ip), later).as_slice(),
            [Effect::Resolve(_)]
        ));
    }
    #[test]
    fn pending_packets_are_bounded_and_address_conflicts_rejected() {
        let now = Instant::now();
        let (mut a, aa) = make(1, now);
        let (_, bb) = make(2, now);
        let (_, mut cc) = make(3, now);
        for _ in 0..10 {
            a.send(data(aa.virtual_ip, bb.virtual_ip), now);
        }
        assert_eq!(a.waiting[&bb.virtual_ip].packets.len(), 4);
        assert_eq!(a.dropped, 6);
        a.tick(now + Duration::from_secs(4));
        assert_eq!(a.dropped, 10);
        a.install(bb.clone(), now + Duration::from_secs(30), now)
            .unwrap();
        cc.virtual_ip = bb.virtual_ip;
        assert_eq!(
            a.install(cc, now + Duration::from_secs(30), now)
                .unwrap_err(),
            "conflicting peer address"
        );
    }
}
