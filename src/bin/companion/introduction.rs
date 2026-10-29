//! Bounded plaintext introduction, followed by tracker verification and WireGuard authentication.
//! No URL fetching, peer trust or IP assignment is derived from these datagrams.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use supertrackr::CandidatePeer;
const SIZE: usize = 104;
const CAP: usize = 64;
const TTL: Duration = Duration::from_secs(5);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub source: SocketAddr,
    pub key: [u8; 32],
    a: [u8; 16],
    b: [u8; 16],
}
struct Incoming {
    ticket: Ticket,
    until: Instant,
    verifying: bool,
    accepted: bool,
}
struct Outgoing {
    peer: CandidatePeer,
    until: Instant,
    expires: Instant,
    a: [u8; 16],
    b: Option<(SocketAddr, [u8; 16])>,
    next: Instant,
}
pub enum Action {
    Send(SocketAddr, Vec<u8>),
    Verify(Ticket),
    Install(CandidatePeer, Instant),
}
pub struct Introductions {
    authority: [u8; 32],
    key: [u8; 32],
    incoming: HashMap<(SocketAddr, [u8; 32]), Incoming>,
    outgoing: HashMap<[u8; 32], Outgoing>,
    window: Instant,
    count: u32,
    pub rejected: u64,
    pub completed: u64,
}
impl Introductions {
    pub fn new(origin: &str, key: [u8; 32], now: Instant) -> Self {
        Self {
            authority: Sha256::digest(origin.as_bytes()).into(),
            key,
            incoming: HashMap::new(),
            outgoing: HashMap::new(),
            window: now,
            count: 0,
            rejected: 0,
            completed: 0,
        }
    }
    fn wire(&self, kind: u8, a: [u8; 16], b: [u8; 16]) -> Vec<u8> {
        let mut p = vec![0; SIZE];
        p[..4].copy_from_slice(b"STI1");
        p[4] = kind;
        p[8..40].copy_from_slice(&self.authority);
        p[40..72].copy_from_slice(&self.key);
        p[72..88].copy_from_slice(&a);
        p[88..104].copy_from_slice(&b);
        p
    }
    fn prune(&mut self, now: Instant) {
        self.incoming.retain(|_, v| v.until > now);
        self.outgoing
            .retain(|_, v| v.expires > now && v.until > now);
    }
    pub fn begin(&mut self, peer: CandidatePeer, until: Instant, now: Instant) -> Vec<Action> {
        self.prune(now);
        let mut key = [0; 32];
        if until <= now
            || hex::decode_to_slice(&peer.public_key, &mut key).is_err()
            || key == self.key
            || peer.candidates.len() > 8
            || peer.candidates.is_empty()
        {
            self.rejected += 1;
            return vec![];
        }
        if self.outgoing.contains_key(&key) {
            return vec![];
        }
        if self.outgoing.len() >= CAP {
            self.rejected += 1;
            return vec![];
        }
        self.outgoing.insert(
            key,
            Outgoing {
                peer,
                until,
                expires: now + TTL,
                a: rand::random(),
                b: None,
                next: now,
            },
        );
        self.tick(now)
    }
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        self.prune(now);
        let mut sends = vec![];
        for o in self.outgoing.values_mut() {
            if o.next <= now {
                if let Some((addr, b)) = o.b {
                    sends.push((addr, 3, o.a, b));
                } else {
                    for &addr in &o.peer.candidates {
                        sends.push((addr, 1, o.a, [0; 16]));
                    }
                }
                o.next = now + Duration::from_millis(500);
            }
        }
        sends
            .into_iter()
            .map(|(addr, k, a, b)| Action::Send(addr, self.wire(k, a, b)))
            .collect()
    }
    pub fn is_introduction(p: &[u8]) -> bool {
        p.starts_with(b"STI1")
    }
    pub fn receive(&mut self, p: &[u8], source: SocketAddr, now: Instant) -> Vec<Action> {
        self.prune(now);
        if p.len() != SIZE || p[..4] != *b"STI1" || p[5..8] != [0; 3] || p[8..40] != self.authority
        {
            self.rejected += 1;
            return vec![];
        }
        let key: [u8; 32] = p[40..72].try_into().unwrap();
        let a = p[72..88].try_into().unwrap();
        let b = p[88..104].try_into().unwrap();
        if key == self.key || key == [0; 32] {
            self.rejected += 1;
            return vec![];
        }
        // Global budget bounds responses and HTTP admissions, independent of source cardinality.
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            self.window = now;
            self.count = 0;
        }
        if self.count >= 64 {
            self.rejected += 1;
            return vec![];
        }
        self.count += 1;
        match p[4] {
            1 => {
                if b != [0; 16] {
                    self.rejected += 1;
                    return vec![];
                }
                if let Some(old) = self.incoming.get(&(source, key)) {
                    if old.ticket.a == a {
                        return vec![Action::Send(source, self.wire(2, a, old.ticket.b))];
                    }
                    return vec![];
                }
                if self.incoming.len() >= CAP {
                    self.rejected += 1;
                    return vec![];
                }
                let b = rand::random();
                let ticket = Ticket { source, key, a, b };
                self.incoming.insert(
                    (source, key),
                    Incoming {
                        ticket,
                        until: now + TTL,
                        verifying: false,
                        accepted: false,
                    },
                );
                vec![Action::Send(source, self.wire(2, a, b))]
            }
            2 => {
                let Some(o) = self.outgoing.get_mut(&key) else {
                    self.rejected += 1;
                    return vec![];
                };
                if o.a != a
                    || !o.peer.candidates.contains(&source)
                    || o.b.is_some_and(|v| v != (source, b))
                {
                    self.rejected += 1;
                    return vec![];
                }
                o.b = Some((source, b));
                o.next = now + Duration::from_millis(500);
                vec![Action::Send(source, self.wire(3, a, b))]
            }
            3 => {
                let Some(i) = self.incoming.get_mut(&(source, key)) else {
                    self.rejected += 1;
                    return vec![];
                };
                if i.ticket.a != a || i.ticket.b != b {
                    self.rejected += 1;
                    return vec![];
                }
                if i.accepted {
                    return vec![Action::Send(source, self.wire(4, a, b))];
                }
                if i.verifying {
                    return vec![];
                }
                i.verifying = true;
                vec![Action::Verify(i.ticket)]
            }
            4 => {
                let Some(o) = self.outgoing.get(&key) else {
                    self.rejected += 1;
                    return vec![];
                };
                if o.a != a || o.b != Some((source, b)) {
                    self.rejected += 1;
                    return vec![];
                }
                let o = self.outgoing.remove(&key).unwrap();
                self.completed += 1;
                vec![Action::Install(o.peer, o.until)]
            }
            _ => {
                self.rejected += 1;
                vec![]
            }
        }
    }
    pub fn verified(
        &mut self,
        ticket: Ticket,
        mut peer: CandidatePeer,
        until: Instant,
        now: Instant,
    ) -> Vec<Action> {
        self.prune(now);
        let Some(i) = self.incoming.get_mut(&(ticket.source, ticket.key)) else {
            return vec![];
        };
        if i.ticket != ticket
            || !i.verifying
            || i.accepted
            || until <= now
            || peer.public_key != hex::encode(ticket.key)
        {
            self.rejected += 1;
            return vec![];
        }
        i.accepted = true;
        i.until = i.until.min(until);
        // The source proved return reachability, not identity; WireGuard still authenticates it.
        peer.candidates.retain(|&v| v != ticket.source);
        peer.candidates.insert(0, ticket.source);
        peer.candidates.truncate(8);
        self.completed += 1;
        vec![
            Action::Install(peer, until),
            Action::Send(ticket.source, self.wire(4, ticket.a, ticket.b)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer(key: u8, port: u16) -> CandidatePeer {
        CandidatePeer {
            public_key: hex::encode([key; 32]),
            virtual_ip: Ipv4Addr::new(10, 203, 0, key),
            endpoint: format!("127.0.0.1:{port}").parse().unwrap(),
            candidates: vec![format!("127.0.0.1:{port}").parse().unwrap()],
            remaining_seconds: 30,
        }
    }
    fn sent(actions: Vec<Action>) -> Vec<u8> {
        let Action::Send(_, p) = actions.into_iter().next().expect("send") else {
            panic!("not send")
        };
        p
    }
    #[test]
    fn return_path_then_registration_then_wireguard_admission() {
        let now = Instant::now();
        let pa = peer(1, 1001);
        let pb = peer(2, 1002);
        let mut a = Introductions::new("https://tracker/", [1; 32], now);
        let mut b = Introductions::new("https://tracker/", [2; 32], now);
        let hello = sent(a.begin(pb.clone(), now + Duration::from_secs(30), now));
        let challenge = sent(b.receive(&hello, pa.endpoint, now));
        // A forged confirmation cannot trigger a tracker lookup.
        let mut forged = a.wire(3, [9; 16], [8; 16]);
        assert!(b.receive(&forged, pa.endpoint, now).is_empty());
        let confirm = sent(a.receive(&challenge, pb.endpoint, now));
        let actions = b.receive(&confirm, pa.endpoint, now);
        let Action::Verify(ticket) = actions[0] else {
            panic!("verification required")
        };
        assert!(b.receive(&confirm, pa.endpoint, now).is_empty()); // deduplicated while HTTP is pending
        let verified = b.verified(ticket, pa.clone(), now + Duration::from_secs(30), now);
        assert!(matches!(verified[0], Action::Install(..)));
        let accept = sent(verified.into_iter().skip(1).collect());
        assert!(matches!(
            a.receive(&accept, pb.endpoint, now).as_slice(),
            [Action::Install(..)]
        ));
        assert!(a.receive(&accept, pb.endpoint, now).is_empty()); // no stale replay install
        assert!(matches!(
            b.receive(&confirm, pa.endpoint, now).as_slice(),
            [Action::Send(..)]
        )); // lost ACCEPT retry
        forged[8] ^= 1;
        assert!(b.receive(&forged, pa.endpoint, now).is_empty());
        assert!(
            b.verified(ticket, pa, now + Duration::from_secs(30), now + TTL)
                .is_empty()
        );
    }
    #[test]
    fn rejects_other_authorities_wrong_sources_and_expired_challenges() {
        let now = Instant::now();
        let pa = peer(1, 1001);
        let pb = peer(2, 1002);
        let mut a = Introductions::new("https://tracker/", [1; 32], now);
        let mut b = Introductions::new("https://tracker/", [2; 32], now);
        let mut other = Introductions::new("https://evil/", [2; 32], now);
        let hello = sent(a.begin(pb.clone(), now + Duration::from_secs(30), now));
        assert!(other.receive(&hello, pa.endpoint, now).is_empty());
        assert!(other.incoming.is_empty());
        let challenge = sent(b.receive(&hello, pa.endpoint, now));
        assert!(a.receive(&challenge, pa.endpoint, now).is_empty());
        let confirm = sent(a.receive(&challenge, pb.endpoint, now));
        assert!(b.receive(&confirm, pa.endpoint, now + TTL).is_empty());
        assert!(b.receive(&hello[..40], pa.endpoint, now).is_empty());
    }
    #[test]
    fn pending_state_and_responses_are_bounded() {
        let now = Instant::now();
        let mut b = Introductions::new("https://tracker/", [2; 32], now);
        for n in 0..100u16 {
            let a = Introductions::new("https://tracker/", [1; 32], now);
            let addr = format!("127.0.0.1:{}", 1000 + n).parse().unwrap();
            let actions = b.receive(&a.wire(1, [3; 16], [0; 16]), addr, now);
            assert!(actions.iter().all(|a| matches!(a, Action::Send(..))));
        }
        assert_eq!(b.incoming.len(), 64);
        assert_eq!(b.rejected, 36);
        b.tick(now + TTL);
        assert!(b.incoming.is_empty());
    }
}
