//! Lazy, bounded rendezvous and ciphertext mailboxes. Owned exclusively by Registry.
use super::*;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, net::Ipv4Addr};
pub const MAX_CONNECTIONS: usize = 64;
pub const OVERLAY_NETWORK: &str = "10.203.0.0/16";
pub const MAX_CANDIDATES: usize = 8;
pub const MAX_TRAVERSAL_PEERS: usize = 4096;
pub const MAX_DATAGRAM: usize = 2048;
const MAX_PACKETS: usize = 4096;
const PER_PEER_PACKETS: usize = 32;
const MAX_REQUESTS: usize = 8;
const MESSAGE_TTL: u64 = 10;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidatePeer {
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub candidates: Vec<SocketAddr>,
    pub virtual_ip: Ipv4Addr,
    pub remaining_seconds: u64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PunchHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<CandidatePeer>,
    pub candidates: Vec<SocketAddr>,
    pub remaining_seconds: u64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RelayPacket {
    pub public_key: String,
    pub packet: String,
}
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Events {
    pub requests: Vec<CandidatePeer>,
    pub packets: Vec<RelayPacket>,
}
struct Message<T> {
    sender: Credentials,
    until: u64,
    data: T,
}
pub(super) struct Mailbox {
    pub(super) candidates: Vec<SocketAddr>,
    virtual_ip: Ipv4Addr,
    selected: HashMap<Key, Key>,
    requests: VecDeque<Message<()>>,
    punches: VecDeque<Message<bool>>,
    punch_budget: (u64, u8),
    packets: VecDeque<Message<Vec<u8>>>,
}
#[derive(Default)]
pub(super) struct Traversal {
    pub(super) peers: HashMap<Key, Mailbox>,
    packets: usize,
    addresses: HashMap<Ipv4Addr, Key>,
    next_address: u32,
}
impl Traversal {
    pub(super) fn maintain(&mut self, key: &Key, now: u64) {
        if let Some(m) = self.peers.get_mut(key) {
            let before = m.packets.len();
            m.packets.retain(|p| now < p.until);
            self.packets -= before - m.packets.len();
            m.requests.retain(|r| now < r.until);
            m.punches.retain(|r| now < r.until);
        }
    }
    pub(super) fn remove(&mut self, key: &Key) {
        if let Some(m) = self.peers.remove(key) {
            self.packets -= m.packets.len();
            self.addresses.remove(&m.virtual_ip);
        }
    }
}
pub fn valid_endpoint(endpoint: SocketAddr) -> bool {
    endpoint.port() != 0
        && !endpoint.ip().is_unspecified()
        && !endpoint.ip().is_multicast()
        && !matches!(endpoint.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
}
impl Registry {
    fn mutual(&self, who: Credentials, target: Key, now: u64) -> bool {
        let Some(record) = self.records.get(&target) else {
            return false;
        };
        let Some(caller) = self.records.get(&who.key) else {
            return false;
        };
        if caller.identity == record.identity
            || caller.endpoint_expires <= now
            || record.endpoint_expires <= now
        {
            return false;
        }
        self.traversal
            .peers
            .get(&who.key)
            .and_then(|m| m.selected.get(&target))
            == Some(&record.token_hash)
            && self
                .traversal
                .peers
                .get(&target)
                .and_then(|m| m.selected.get(&who.key))
                == Some(&who.token_hash)
    }
    pub fn interface(&self, who: Credentials, now: u64) -> Result<InterfaceInfo> {
        let lease = self.authenticate(who, now)?;
        let m = self.traversal.peers.get(&who.key).ok_or(Error::NotFound)?;
        let remaining_seconds = decision(Access.decide(&AccessInput {
            now,
            caller: Some(lease),
            token_matches: true,
            query: AccessQuery::Caller,
        }))?;
        Ok(InterfaceInfo {
            public_key: hex::encode(who.key),
            virtual_ip: m.virtual_ip,
            network: OVERLAY_NETWORK.into(),
            remaining_seconds,
        })
    }
    pub fn resolve(&mut self, who: Credentials, ip: Ipv4Addr, now: u64) -> Result<CandidatePeer> {
        self.authenticate(who, now)?;
        let key = *self.traversal.addresses.get(&ip).ok_or(Error::NotFound)?;
        self.connect(who, key, now)
    }
    /// Read-only resolution: never selects peers or queues an introduction.
    pub fn lookup(&self, who: Credentials, ip: Ipv4Addr, now: u64) -> Result<CandidatePeer> {
        self.authenticate(who, now)?;
        let key = *self.traversal.addresses.get(&ip).ok_or(Error::NotFound)?;
        self.binding(who, key, now)
    }
    pub fn binding(&self, who: Credentials, key: Key, now: u64) -> Result<CandidatePeer> {
        self.candidate_peer(who, key, now)
    }
    /// Endpoint-only by default; optional bindings are rebuilt from live registration state.
    pub fn rendezvous(&mut self, who: Credentials, target: Key, now: u64) -> Result<()> {
        self.rendezvous_with_binding(who, target, false, now)
    }
    pub fn rendezvous_with_binding(
        &mut self,
        who: Credentials,
        target: Key,
        include_binding: bool,
        now: u64,
    ) -> Result<()> {
        let peer = self.candidate_peer(who, target, now)?;
        let caller_until = self.records[&who.key].endpoint_expires;
        if caller_until <= now {
            return Err(Error::Conflict);
        }
        let until = now
            .saturating_add(5)
            .min(caller_until)
            .min(now.saturating_add(peer.remaining_seconds));
        let caller = self
            .traversal
            .peers
            .get_mut(&who.key)
            .ok_or(Error::Conflict)?;
        if caller.punch_budget.0 != now {
            caller.punch_budget = (now, 0);
        }
        if caller.punch_budget.1 >= 8 {
            return Err(Error::Unavailable);
        }
        caller.punch_budget.1 += 1;
        let target = self
            .traversal
            .peers
            .get_mut(&target)
            .ok_or(Error::NotFound)?;
        target
            .punches
            .retain(|m| m.until > now && m.sender.key != who.key);
        if target.punches.len() >= MAX_REQUESTS {
            return Err(Error::Unavailable);
        }
        target.punches.push_back(Message {
            sender: who,
            until,
            data: include_binding,
        });
        Ok(())
    }
    pub fn punch_hints(&mut self, who: Credentials, now: u64) -> Result<Vec<PunchHint>> {
        self.authenticate(who, now)?;
        let mailbox = self
            .traversal
            .peers
            .get_mut(&who.key)
            .ok_or(Error::NotFound)?;
        let messages = std::mem::take(&mut mailbox.punches);
        let mut hints = Vec::new();
        for m in messages {
            if m.until > now
                && self.authenticate(m.sender, now).is_ok()
                && let Ok(peer) = self.candidate_peer(who, m.sender.key, now)
            {
                hints.push(PunchHint {
                    candidates: peer.candidates.clone(),
                    remaining_seconds: peer.remaining_seconds.min(m.until - now),
                    binding: m.data.then_some(peer),
                });
            }
        }
        Ok(hints)
    }
    pub fn set_candidates(
        &mut self,
        who: Credentials,
        candidates: Vec<SocketAddr>,
        now: u64,
    ) -> Result<()> {
        self.authenticate(who, now)?;
        if candidates.is_empty()
            || candidates.len() > MAX_CANDIDATES
            || candidates.iter().any(|&e| !valid_endpoint(e))
            || candidates
                .iter()
                .enumerate()
                .any(|(i, e)| candidates[..i].contains(e))
        {
            return Err(Error::BadRequest);
        }
        if !self.traversal.peers.contains_key(&who.key)
            && self.traversal.peers.len() >= MAX_TRAVERSAL_PEERS
        {
            return Err(Error::Unavailable);
        }
        if let Some(m) = self.traversal.peers.get_mut(&who.key) {
            m.candidates = candidates;
        } else {
            if self.traversal.next_address >= 65534 {
                return Err(Error::Unavailable);
            }
            self.traversal.next_address += 1;
            let ip = Ipv4Addr::from(0x0acb0000 + self.traversal.next_address);
            self.traversal.addresses.insert(ip, who.key);
            self.traversal.peers.insert(
                who.key,
                Mailbox {
                    virtual_ip: ip,
                    candidates,
                    selected: HashMap::new(),
                    requests: VecDeque::new(),
                    punches: VecDeque::new(),
                    punch_budget: (0, 0),
                    packets: VecDeque::new(),
                },
            );
        }
        Ok(())
    }
    fn candidate_peer(&self, who: Credentials, target: Key, now: u64) -> Result<CandidatePeer> {
        let lease = self.authenticate(who, now)?;
        let p = self.peer(who.key, lease, target, None, now)?;
        let m = self.traversal.peers.get(&target).ok_or(Error::NotFound)?;
        if m.candidates.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(CandidatePeer {
            public_key: hex::encode(target),
            endpoint: p.endpoint,
            candidates: m.candidates.clone(),
            virtual_ip: m.virtual_ip,
            remaining_seconds: p.remaining_seconds,
        })
    }
    pub fn connect(&mut self, who: Credentials, target: Key, now: u64) -> Result<CandidatePeer> {
        let peer = self.candidate_peer(who, target, now)?;
        let caller_until = self.records[&who.key].endpoint_expires;
        if caller_until <= now {
            return Err(Error::Conflict);
        }
        let until = now
            .saturating_add(MESSAGE_TTL)
            .min(caller_until)
            .min(now.saturating_add(peer.remaining_seconds));
        if !self.traversal.peers.contains_key(&who.key) {
            return Err(Error::Conflict);
        }
        let target_hash = self.records.get(&target).unwrap().token_hash;
        let selected = &mut self.traversal.peers.get_mut(&who.key).unwrap().selected;
        selected.retain(|key, hash| {
            self.records
                .get(key)
                .is_some_and(|r| valid(r.lease, now) && r.token_hash == *hash)
        });
        if !selected.contains_key(&target) && selected.len() >= MAX_CONNECTIONS {
            return Err(Error::Unavailable);
        }
        if self.mutual(who, target, now) {
            return Ok(peer);
        }
        let m = self.traversal.peers.get_mut(&target).unwrap();
        m.requests
            .retain(|r| now < r.until && r.sender.key != who.key);
        if m.requests.len() >= MAX_REQUESTS {
            return Err(Error::Unavailable);
        }
        m.requests.push_back(Message {
            sender: who,
            until,
            data: (),
        });
        self.traversal
            .peers
            .get_mut(&who.key)
            .unwrap()
            .selected
            .insert(target, target_hash);
        Ok(peer)
    }
    pub fn relay(
        &mut self,
        who: Credentials,
        target: Key,
        packet: Vec<u8>,
        now: u64,
    ) -> Result<()> {
        let lease = self.authenticate(who, now)?;
        self.peer(who.key, lease, target, None, now)?;
        if packet.is_empty() || packet.len() > MAX_DATAGRAM {
            return Err(Error::BadRequest);
        }
        if !self.mutual(who, target, now) {
            return Err(Error::Conflict);
        }
        let until = now
            .saturating_add(MESSAGE_TTL)
            .min(self.records[&who.key].endpoint_expires)
            .min(self.records[&target].endpoint_expires);
        let m = self.traversal.peers.get_mut(&target).unwrap();
        let before = m.packets.len();
        m.packets.retain(|p| now < p.until);
        self.traversal.packets -= before - m.packets.len();
        if m.packets.len() >= PER_PEER_PACKETS || self.traversal.packets >= MAX_PACKETS {
            return Err(Error::Unavailable);
        }
        m.packets.push_back(Message {
            sender: who,
            until,
            data: packet,
        });
        self.traversal.packets += 1;
        Ok(())
    }
    pub fn events(&mut self, who: Credentials, now: u64) -> Result<Events> {
        self.authenticate(who, now)?;
        let m = self
            .traversal
            .peers
            .get_mut(&who.key)
            .ok_or(Error::NotFound)?;
        let requests = std::mem::take(&mut m.requests);
        let packets = std::mem::take(&mut m.packets);
        self.traversal.packets -= packets.len();

        let mut events = Events::default();
        for r in requests {
            if now < r.until
                && self.authenticate(r.sender, now).is_ok()
                && let Ok(peer) = self.candidate_peer(who, r.sender.key, now)
            {
                events.requests.push(peer);
            }
        }
        for p in packets {
            if now < p.until
                && self.mutual(who, p.sender.key, now)
                && self.authenticate(p.sender, now).is_ok()
            {
                events.packets.push(RelayPacket {
                    public_key: hex::encode(p.sender.key),
                    packet: hex::encode(p.data),
                });
            }
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (Registry, Credentials, Credentials, SocketAddr) {
        let mut r = Registry::new(Config {
            capacity: 10,
            ttl_seconds: 20,
            open_registration: true,
        });
        let a = Credentials {
            key: [1; 32],
            token_hash: [11; 32],
        };
        let b = Credentials {
            key: [2; 32],
            token_hash: [22; 32],
        };
        let addr = "127.0.0.1:1234".parse().unwrap();
        for c in [a, b] {
            r.register_or_refresh(c.key, addr, None, c.token_hash, 0)
                .unwrap();
            r.set_candidates(c, vec![addr], 0).unwrap();
        }
        (r, a, b, addr)
    }
    #[test]
    fn rendezvous_requires_auth_and_reciprocal_selection_for_relay() {
        let (mut r, a, b, addr) = setup();
        assert!(matches!(
            r.connect(
                Credentials {
                    token_hash: [0; 32],
                    ..a
                },
                b.key,
                0
            ),
            Err(Error::Unauthorized)
        ));
        r.connect(a, b.key, 0).unwrap();
        assert_eq!(r.relay(a, b.key, vec![1], 0), Err(Error::Conflict));
        let events = r.events(b, 0).unwrap();
        assert_eq!(events.requests.len(), 1);
        assert_eq!(events.requests[0].public_key, hex::encode(a.key));
        r.connect(b, a.key, 0).unwrap();
        r.relay(a, b.key, vec![1, 2, 3], 0).unwrap();
        let events = r.events(b, 1).unwrap();
        assert_eq!(events.packets.len(), 1);
        assert_eq!(events.packets[0].packet, "010203");
        assert!(r.events(b, 1).unwrap().packets.is_empty());
        assert_eq!(r.traversal.packets, 0);
        assert_eq!(
            r.set_candidates(a, vec![addr; 9], 0),
            Err(Error::BadRequest)
        );
        assert_eq!(
            r.set_candidates(a, vec![addr, addr], 0),
            Err(Error::BadRequest)
        );
        for invalid in [
            "0.0.0.0:1",
            "224.0.0.1:1",
            "127.0.0.1:0",
            "255.255.255.255:1",
        ] {
            assert_eq!(
                r.set_candidates(a, vec![invalid.parse().unwrap()], 0),
                Err(Error::BadRequest)
            );
        }
        assert_eq!(
            r.relay(a, b.key, vec![0; MAX_DATAGRAM + 1], 0),
            Err(Error::BadRequest)
        );
    }
    #[test]
    fn endpoint_expiry_caps_queued_relay_even_if_endpoint_is_renewed() {
        let (mut r, a, b, addr) = setup();
        r.publish_endpoint(a, addr, 2, 0).unwrap();
        r.connect(a, b.key, 0).unwrap();
        r.connect(b, a.key, 0).unwrap();
        r.relay(a, b.key, vec![1], 0).unwrap();
        assert_eq!(r.relay(a, b.key, vec![2], 2), Err(Error::Conflict));
        r.publish_endpoint(a, addr, 10, 2).unwrap();
        r.set_candidates(a, vec![addr], 2).unwrap();
        assert!(r.events(b, 2).unwrap().packets.is_empty());
        r.relay(a, b.key, vec![3], 2).unwrap();
        assert_eq!(r.events(b, 3).unwrap().packets.len(), 1);
        r.relay(a, b.key, vec![4], 3).unwrap();
        r.publish_endpoint(a, addr, 1, 3).unwrap();
        // The previous message was already issued under a longer endpoint lease;
        // renewal never extends the deadline that was assigned on enqueue.
        r.publish_endpoint(a, addr, 10, 4).unwrap();
        r.set_candidates(a, vec![addr], 4).unwrap();
        assert_eq!(r.events(b, 4).unwrap().packets.len(), 1);
    }
    #[test]
    fn explicit_endpoint_requires_fresh_candidates_after_change_or_expiry() {
        let (mut r, a, b, _) = setup();
        let changed = "127.0.0.1:4321".parse().unwrap();
        r.publish_endpoint(b, changed, 2, 1).unwrap();
        assert!(matches!(r.binding(a, b.key, 1), Err(Error::NotFound)));
        r.set_candidates(b, vec![changed], 1).unwrap();
        assert_eq!(r.binding(a, b.key, 1).unwrap().candidates, vec![changed]);
        r.publish_endpoint(b, changed, 5, 3).unwrap();
        assert!(matches!(r.binding(a, b.key, 3), Err(Error::NotFound)));
        r.set_candidates(b, vec![changed], 3).unwrap();
        assert_eq!(r.binding(a, b.key, 3).unwrap().candidates, vec![changed]);
    }
    #[test]
    fn relay_is_bounded_expires_and_rechecks_source_session() {
        let (mut r, a, b, addr) = setup();
        r.connect(a, b.key, 0).unwrap();
        r.connect(b, a.key, 0).unwrap();
        for _ in 0..PER_PEER_PACKETS {
            r.relay(a, b.key, vec![0; MAX_DATAGRAM], 0).unwrap();
        }
        assert_eq!(r.relay(a, b.key, vec![1], 0), Err(Error::Unavailable));
        r.cleanup_batch(10, 10);
        assert_eq!(r.traversal.packets, 0);
        assert!(r.events(b, 10).unwrap().packets.is_empty());
        r.relay(a, b.key, vec![3], 15).unwrap();
        r.register_or_refresh(b.key, addr, Some(b), [0; 32], 15)
            .unwrap();
        // Expired source packets are rejected before physical cleanup.
        assert!(r.events(b, 20).unwrap().packets.is_empty());
        r.cleanup(20);
        assert!(!r.traversal.peers.contains_key(&a.key));
        let newer = Credentials {
            token_hash: [33; 32],
            ..a
        };
        r.register_or_refresh(a.key, addr, None, newer.token_hash, 20)
            .unwrap();
        assert!(matches!(r.events(a, 20), Err(Error::Unauthorized)));
        r.set_candidates(newer, vec![addr], 20).unwrap();
        assert!(r.events(newer, 20).unwrap().requests.is_empty());
    }
    #[test]
    fn refresh_replaces_candidates_and_delivery_uses_current_metadata() {
        let (mut r, a, b, addr) = setup();
        r.connect(a, b.key, 0).unwrap();
        let changed = "127.0.0.1:4321".parse().unwrap();
        r.set_candidates(a, vec![changed], 1).unwrap();
        assert_eq!(
            r.events(b, 1).unwrap().requests[0].candidates,
            vec![changed]
        );
        assert_eq!(
            r.verify_peer(b, a.key, changed, 1).unwrap_err(),
            Error::Conflict
        );
        assert_eq!(r.verify_peer(b, a.key, addr, 1).unwrap().endpoint, addr);
        r.connect(b, a.key, 1).unwrap();
        r.relay(a, b.key, vec![9], 1).unwrap();
        r.traversal.peers.get_mut(&a.key).unwrap().selected.clear();
        assert!(r.events(b, 1).unwrap().packets.is_empty());
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    #[test]
    fn global_relay_capacity_is_reclaimed_and_old_session_cannot_deliver() {
        let mut r = Registry::new(Config {
            capacity: 300,
            ttl_seconds: 20,
            open_registration: true,
        });
        let addr = "127.0.0.1:1234".parse().unwrap();
        let c = |n: u16| {
            let mut k = [1; 32];
            k[..2].copy_from_slice(&n.to_be_bytes());
            Credentials {
                key: k,
                token_hash: k,
            }
        };
        for n in 0..258 {
            let who = c(n);
            r.register_or_refresh(who.key, addr, None, who.token_hash, 0)
                .unwrap();
            r.set_candidates(who, vec![addr], 0).unwrap();
        }
        for n in 0..129 {
            let a = c(2 * n);
            let b = c(2 * n + 1);
            r.connect(a, b.key, 0).unwrap();
            r.connect(b, a.key, 0).unwrap();
        }
        for n in 0..128 {
            for _ in 0..32 {
                r.relay(c(2 * n), c(2 * n + 1).key, vec![1], 0).unwrap();
            }
        }
        assert_eq!(r.traversal.packets, MAX_PACKETS);
        assert_eq!(
            r.relay(c(256), c(257).key, vec![1], 0),
            Err(Error::Unavailable)
        );
        r.events(c(1), 0).unwrap();
        r.relay(c(256), c(257).key, vec![1], 0).unwrap();
        r.cleanup_batch(10, 300);
        assert_eq!(r.traversal.packets, 0);
        let a = c(0);
        let b = c(1);
        r.register_or_refresh(b.key, addr, Some(b), [0; 32], 15)
            .unwrap();
        r.relay(a, b.key, vec![3], 19).unwrap();
        r.cleanup(20);
        let fresh = Credentials {
            token_hash: [5; 32],
            ..a
        };
        r.register_or_refresh(a.key, addr, None, fresh.token_hash, 20)
            .unwrap();
        r.set_candidates(fresh, vec![addr], 20).unwrap();
        r.connect(fresh, b.key, 20).unwrap();
        assert!(r.events(b, 20).unwrap().packets.is_empty());
        assert_eq!(r.traversal.packets, 0);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub public_key: String,
    pub virtual_ip: Ipv4Addr,
    pub network: String,
    pub remaining_seconds: u64,
}

#[cfg(test)]
mod address_tests {
    use super::*;
    #[test]
    fn addresses_are_not_reused_and_exhaustion_is_atomic() {
        let mut r = Registry::new(Config {
            capacity: 10,
            ttl_seconds: 10,
            open_registration: true,
        });
        let endpoint = "127.0.0.1:1000".parse().unwrap();
        let a = Credentials {
            key: [1; 32],
            token_hash: [2; 32],
        };
        r.register_or_refresh(a.key, endpoint, None, a.token_hash, 0)
            .unwrap();
        r.set_candidates(a, vec![endpoint], 0).unwrap();
        let old = r.interface(a, 0).unwrap().virtual_ip;
        r.cleanup(10);
        let b = Credentials {
            token_hash: [3; 32],
            ..a
        };
        r.register_or_refresh(b.key, endpoint, None, b.token_hash, 10)
            .unwrap();
        r.set_candidates(b, vec![endpoint], 10).unwrap();
        assert_ne!(old, r.interface(b, 10).unwrap().virtual_ip);
        assert!(matches!(r.interface(a, 10), Err(Error::Unauthorized)));
        assert!(matches!(r.resolve(b, old, 10), Err(Error::NotFound)));
        let c = Credentials {
            key: [4; 32],
            token_hash: [5; 32],
        };
        r.register_or_refresh(c.key, endpoint, None, c.token_hash, 10)
            .unwrap();
        r.traversal.next_address = 65534;
        assert_eq!(
            r.set_candidates(c, vec![endpoint], 10),
            Err(Error::Unavailable)
        );
        assert!(!r.traversal.peers.contains_key(&c.key));
        assert_eq!(r.traversal.addresses.len(), 1);
    }
}

#[cfg(test)]
mod punch_tests {
    use super::*;
    #[test]
    fn rendezvous_is_bounded_and_drops_stale_sessions() {
        let mut r = Registry::new(Config {
            capacity: 20,
            ttl_seconds: 10,
            open_registration: true,
        });
        let addr = "127.0.0.1:1000".parse().unwrap();
        let creds: Vec<_> = (1..=10)
            .map(|n| Credentials {
                key: [n; 32],
                token_hash: [n + 20; 32],
            })
            .collect();
        for &c in &creds {
            r.register_or_refresh(c.key, addr, None, c.token_hash, 0)
                .unwrap();
            r.set_candidates(c, vec![addr], 0).unwrap();
        }
        let a = creds[0];
        let b = creds[1];
        for _ in 0..8 {
            r.rendezvous(a, b.key, 0).unwrap();
        }
        assert_eq!(r.rendezvous(a, b.key, 0), Err(Error::Unavailable));
        assert_eq!(r.punch_hints(b, 0).unwrap().len(), 1);
        for &c in creds.iter().skip(1).take(8) {
            r.rendezvous(c, a.key, 1).unwrap();
        }
        assert_eq!(r.rendezvous(creds[9], a.key, 1), Err(Error::Unavailable));
        assert!(r.punch_hints(a, 6).unwrap().is_empty());
        r.rendezvous_with_binding(a, b.key, true, 7).unwrap();
        r.register_or_refresh(b.key, addr, Some(b), b.token_hash, 8)
            .unwrap();
        r.cleanup(10);
        let fresh = Credentials {
            token_hash: [99; 32],
            ..a
        };
        r.register_or_refresh(a.key, addr, None, fresh.token_hash, 10)
            .unwrap();
        r.set_candidates(fresh, vec![addr], 10).unwrap();
        assert!(r.punch_hints(b, 10).unwrap().is_empty());
    }
}
