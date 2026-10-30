//! Bounded in-memory state for ordinary Internet tracker endpoints.
//! Source addresses must be obtained from the actual transport, never client headers.
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerId(pub [u8; 20]);
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    pub id: PeerId,
    pub address: SocketAddr,
    pub complete: bool,
    pub expires: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    pub complete: usize,
    pub incomplete: usize,
    pub downloaded: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Started,
    Update,
    Completed,
    Stopped,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidAddress,
    Capacity,
}
struct Swarm {
    peers: HashMap<(PeerId, IpAddr), Peer>,
    downloaded: u64,
    idle_since: Option<u64>,
}
pub struct Tracker {
    swarms: HashMap<[u8; 20], Swarm>,
    peer_expirations: BTreeSet<(u64, [u8; 20], PeerId, IpAddr)>,
    idle_expirations: BTreeSet<(u64, [u8; 20])>,
    memberships: usize,
    max_swarms: usize,
    max_memberships: usize,
    max_per_swarm: usize,
    ttl: u64,
}
impl Tracker {
    pub fn new(
        max_swarms: usize,
        max_memberships: usize,
        max_per_swarm: usize,
        ttl: u64,
    ) -> Option<Self> {
        if max_swarms == 0 || max_memberships == 0 || max_per_swarm == 0 || ttl == 0 {
            return None;
        }
        Some(Self {
            swarms: HashMap::new(),
            peer_expirations: BTreeSet::new(),
            idle_expirations: BTreeSet::new(),
            memberships: 0,
            max_swarms,
            max_memberships,
            max_per_swarm,
            ttl,
        })
    }
    pub fn expire(&mut self, now: u64) {
        while let Some(&(deadline, hash, id, ip)) = self.peer_expirations.first() {
            if deadline > now {
                break;
            }
            self.peer_expirations.pop_first();
            let swarm = self
                .swarms
                .get_mut(&hash)
                .expect("expiry index points to swarm");
            let removed = swarm
                .peers
                .remove(&(id, ip))
                .expect("expiry index points to peer");
            debug_assert_eq!(removed.expires, deadline);
            self.memberships -= 1;
            self.empty_swarm(hash, now);
        }
        while let Some(&(deadline, hash)) = self.idle_expirations.first() {
            if deadline > now {
                break;
            }
            self.idle_expirations.pop_first();
            let swarm = self
                .swarms
                .remove(&hash)
                .expect("idle index points to swarm");
            debug_assert!(swarm.peers.is_empty());
        }
    }
    fn empty_swarm(&mut self, hash: [u8; 20], now: u64) {
        let Some(swarm) = self.swarms.get_mut(&hash) else {
            return;
        };
        if !swarm.peers.is_empty() {
            return;
        }
        // Completed swarms retain statistics, not their former peer-table allocation.
        swarm.peers = HashMap::new();
        if swarm.downloaded == 0 {
            self.swarms.remove(&hash);
        } else if swarm.idle_since.is_none() {
            swarm.idle_since = Some(now);
            if let Some(deadline) = now.checked_add(86_400) {
                self.idle_expirations.insert((deadline, hash));
            }
        }
    }
    pub fn announce(
        &mut self,
        hash: [u8; 20],
        id: PeerId,
        address: SocketAddr,
        left: u64,
        event: Event,
        now: u64,
    ) -> Result<(), Error> {
        if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
            return Err(Error::InvalidAddress);
        }
        self.expire(now);
        let key = (id, address.ip());
        if event == Event::Stopped {
            if let Some(swarm) = self.swarms.get_mut(&hash)
                && let Some(peer) = swarm.peers.remove(&key)
            {
                self.peer_expirations
                    .remove(&(peer.expires, hash, id, address.ip()));
                self.memberships -= 1;
                self.empty_swarm(hash, now);
            }
            return Ok(());
        }
        let swarm = self.swarms.get(&hash);
        let exists = swarm.is_some_and(|s| s.peers.contains_key(&key));
        if !exists
            && (self.memberships >= self.max_memberships
                || swarm.is_some_and(|s| s.peers.len() >= self.max_per_swarm)
                || (swarm.is_none() && self.swarms.len() >= self.max_swarms))
        {
            return Err(Error::Capacity);
        }
        let swarm = self.swarms.entry(hash).or_insert_with(|| Swarm {
            peers: HashMap::new(),
            downloaded: 0,
            idle_since: None,
        });
        if let Some(since) = swarm.idle_since.take()
            && let Some(deadline) = since.checked_add(86_400)
        {
            self.idle_expirations.remove(&(deadline, hash));
        }
        // Only count a transition from a previously observed incomplete membership.
        if event == Event::Completed
            && left == 0
            && swarm.peers.get(&key).is_some_and(|p| !p.complete)
        {
            swarm.downloaded = swarm.downloaded.saturating_add(1);
        }
        let old = swarm.peers.insert(
            key,
            Peer {
                id,
                address,
                complete: left == 0,
                expires: now.saturating_add(self.ttl),
            },
        );
        if let Some(old) = old {
            self.peer_expirations
                .remove(&(old.expires, hash, id, address.ip()));
        }
        self.peer_expirations
            .insert((now.saturating_add(self.ttl), hash, id, address.ip()));
        if !exists {
            self.memberships += 1;
        }
        Ok(())
    }
    pub fn scrape(&self, hash: [u8; 20], now: u64) -> Counts {
        let mut result = Counts::default();
        if let Some(swarm) = self.swarms.get(&hash) {
            result.downloaded = swarm.downloaded;
            for peer in swarm.peers.values().filter(|p| p.expires > now) {
                if peer.complete {
                    result.complete += 1;
                } else {
                    result.incomplete += 1;
                }
            }
        }
        result
    }
    pub fn peers(&self, hash: [u8; 20], requester: PeerId, limit: usize, now: u64) -> Vec<Peer> {
        self.swarms
            .get(&hash)
            .into_iter()
            .flat_map(|s| s.peers.values())
            .filter(|p| p.expires > now && p.id != requester)
            .take(limit.min(50))
            .copied()
            .collect()
    }
    pub fn peers_for_family(
        &self,
        hash: [u8; 20],
        requester: PeerId,
        ipv4: bool,
        limit: usize,
        now: u64,
    ) -> Vec<Peer> {
        self.swarms
            .get(&hash)
            .into_iter()
            .flat_map(|s| s.peers.values())
            .filter(|p| p.expires > now && p.id != requester && p.address.is_ipv4() == ipv4)
            .take(limit.min(50))
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct ScanOracle {
        swarms: HashMap<[u8; 20], Swarm>,
        memberships: usize,
    }
    impl ScanOracle {
        fn expire(&mut self, now: u64) {
            self.swarms.retain(|_, swarm| {
                let before = swarm.peers.len();
                swarm.peers.retain(|_, peer| peer.expires > now);
                self.memberships -= before - swarm.peers.len();
                if !swarm.peers.is_empty() {
                    swarm.idle_since = None;
                    true
                } else if swarm.downloaded == 0 {
                    false
                } else {
                    now.saturating_sub(*swarm.idle_since.get_or_insert(now)) < 86_400
                }
            });
        }
        fn announce(
            &mut self,
            hash: [u8; 20],
            id: PeerId,
            address: SocketAddr,
            left: u64,
            event: Event,
            now: u64,
        ) -> Result<(), Error> {
            if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
                return Err(Error::InvalidAddress);
            }
            self.expire(now);
            let key = (id, address.ip());
            if event == Event::Stopped {
                if let Some(swarm) = self.swarms.get_mut(&hash)
                    && swarm.peers.remove(&key).is_some()
                {
                    self.memberships -= 1;
                }
                self.expire(now);
                return Ok(());
            }
            let swarm = self.swarms.get(&hash);
            let exists = swarm.is_some_and(|swarm| swarm.peers.contains_key(&key));
            if !exists
                && (self.memberships >= 24
                    || swarm.is_some_and(|s| s.peers.len() >= 8)
                    || (swarm.is_none() && self.swarms.len() >= 8))
            {
                return Err(Error::Capacity);
            }
            let swarm = self.swarms.entry(hash).or_insert_with(|| Swarm {
                peers: HashMap::new(),
                downloaded: 0,
                idle_since: None,
            });
            swarm.idle_since = None;
            if event == Event::Completed
                && left == 0
                && swarm.peers.get(&key).is_some_and(|peer| !peer.complete)
            {
                swarm.downloaded = swarm.downloaded.saturating_add(1);
            }
            swarm.peers.insert(
                key,
                Peer {
                    id,
                    address,
                    complete: left == 0,
                    expires: now.saturating_add(13),
                },
            );
            if !exists {
                self.memberships += 1;
            }
            Ok(())
        }
    }
    #[test]
    fn indexed_tracker_matches_persistent_scan_oracle() {
        let mut actual = Tracker::new(8, 24, 8, 13).unwrap();
        let mut expected = ScanOracle {
            swarms: HashMap::new(),
            memberships: 0,
        };
        let mut rng = 21u64;
        let mut now = 0u64;
        for step in 0..10_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            now += if step % 1000 == 999 {
                86_400
            } else {
                (rng >> 60) % 3
            };
            let hash = [(rng >> 32) as u8 % 10; 20];
            let id = PeerId([(rng >> 40) as u8 % 12; 20]);
            let ip = std::net::Ipv4Addr::new(127, 0, 0, 1 + ((rng >> 52) as u8 % 3));
            let address = SocketAddr::new(ip.into(), 6000 + (rng as u16 % 10));
            let event = match (rng >> 48) % 6 {
                0 => Event::Stopped,
                1 => Event::Completed,
                2 => Event::Started,
                _ => Event::Update,
            };
            let left = u64::from(event != Event::Completed);
            assert_eq!(
                actual.announce(hash, id, address, left, event, now),
                expected.announce(hash, id, address, left, event, now),
                "step {step}"
            );
            assert_eq!(actual.memberships, expected.memberships, "step {step}");
            assert_eq!(actual.swarms.len(), expected.swarms.len(), "step {step}");
            for (hash, oracle) in &expected.swarms {
                let current = &actual.swarms[hash];
                assert_eq!(
                    (current.downloaded, current.idle_since),
                    (oracle.downloaded, oracle.idle_since),
                    "step {step}"
                );
                assert_eq!(current.peers.len(), oracle.peers.len(), "step {step}");
                for (key, peer) in &oracle.peers {
                    let got = &current.peers[key];
                    assert_eq!(
                        (got.id, got.address, got.complete, got.expires),
                        (peer.id, peer.address, peer.complete, peer.expires),
                        "step {step}"
                    );
                }
            }
        }
    }
    #[test]
    fn indexed_expiry_matches_full_scan_oracle() {
        let mut tracker = Tracker::new(8, 24, 8, 13).unwrap();
        let addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let mut random = 7u64;
        for now in 0..500u64 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let hash = [(random >> 32) as u8 % 8; 20];
            let id = PeerId([(random >> 40) as u8 % 10; 20]);
            let event = match (random >> 48) % 5 {
                0 => Event::Stopped,
                1 => Event::Completed,
                _ => Event::Update,
            };
            let _ = tracker.announce(
                hash,
                id,
                addr,
                u64::from(event != Event::Completed),
                event,
                now,
            );
            let expected_index: BTreeSet<_> = tracker
                .swarms
                .iter()
                .flat_map(|(hash, swarm)| {
                    swarm
                        .peers
                        .iter()
                        .map(move |((id, ip), peer)| (peer.expires, *hash, *id, *ip))
                })
                .collect();
            assert_eq!(tracker.peer_expirations, expected_index);
            let expected_idle: BTreeSet<_> = tracker
                .swarms
                .iter()
                .filter_map(|(hash, swarm)| {
                    swarm
                        .idle_since
                        .and_then(|since| since.checked_add(86_400))
                        .map(|deadline| (deadline, *hash))
                })
                .collect();
            assert_eq!(tracker.idle_expirations, expected_idle);
            let mut indexed = Tracker {
                swarms: tracker
                    .swarms
                    .iter()
                    .map(|(hash, s)| {
                        (
                            *hash,
                            Swarm {
                                peers: s.peers.clone(),
                                downloaded: s.downloaded,
                                idle_since: s.idle_since,
                            },
                        )
                    })
                    .collect(),
                peer_expirations: tracker.peer_expirations.clone(),
                idle_expirations: tracker.idle_expirations.clone(),
                memberships: tracker.memberships,
                max_swarms: tracker.max_swarms,
                max_memberships: tracker.max_memberships,
                max_per_swarm: tracker.max_per_swarm,
                ttl: tracker.ttl,
            };
            let mut oracle: HashMap<_, _> = tracker
                .swarms
                .iter()
                .map(|(hash, s)| {
                    (
                        *hash,
                        Swarm {
                            peers: s.peers.clone(),
                            downloaded: s.downloaded,
                            idle_since: s.idle_since,
                        },
                    )
                })
                .collect();
            let later = now + (random % 100_000);
            oracle.retain(|_, swarm| {
                swarm.peers.retain(|_, peer| peer.expires > later);
                if !swarm.peers.is_empty() {
                    swarm.idle_since = None;
                    true
                } else if swarm.downloaded == 0 {
                    false
                } else {
                    later.saturating_sub(*swarm.idle_since.get_or_insert(later)) < 86_400
                }
            });
            indexed.expire(later);
            assert_eq!(indexed.swarms.len(), oracle.len());
            for (hash, expected) in oracle {
                let actual = &indexed.swarms[&hash];
                assert_eq!(
                    (actual.downloaded, actual.idle_since),
                    (expected.downloaded, expected.idle_since)
                );
                assert_eq!(actual.peers.len(), expected.peers.len());
                for (key, peer) in expected.peers {
                    assert_eq!(actual.peers[&key].expires, peer.expires);
                }
            }
            assert_eq!(indexed.peer_expirations.len(), indexed.memberships);
        }
    }
    #[test]
    fn expiry_index_tracks_refresh_stop_and_idle_revival() {
        let mut tracker = Tracker::new(1, 2, 2, 10).unwrap();
        let hash = [7; 20];
        let id = PeerId([1; 20]);
        let addr = "127.0.0.1:1000".parse().unwrap();
        tracker
            .announce(hash, id, addr, 1, Event::Started, 1)
            .unwrap();
        for now in 2..100 {
            tracker
                .announce(hash, id, addr, 1, Event::Update, now)
                .unwrap();
            assert_eq!(tracker.peer_expirations.len(), 1);
        }
        tracker
            .announce(hash, id, addr, 0, Event::Completed, 100)
            .unwrap();
        tracker
            .announce(hash, id, addr, 0, Event::Stopped, 101)
            .unwrap();
        assert_eq!(tracker.peer_expirations.len(), 0);
        assert_eq!(tracker.swarms[&hash].peers.capacity(), 0);
        assert_eq!(tracker.idle_expirations.len(), 1);
        assert_eq!(
            tracker.announce([8; 20], id, addr, 1, Event::Started, 102),
            Err(Error::Capacity)
        );
        tracker
            .announce(hash, id, addr, 1, Event::Started, 103)
            .unwrap();
        assert!(tracker.idle_expirations.is_empty());
        tracker.expire(113);
        assert_eq!(tracker.scrape(hash, 113).downloaded, 1);
        tracker.expire(86_512);
        assert_eq!(tracker.scrape(hash, 86_512).downloaded, 1);
        tracker.expire(86_513);
        assert_eq!(tracker.scrape(hash, 86_513), Counts::default());
        tracker
            .announce([8; 20], id, addr, 1, Event::Started, 86_513)
            .unwrap();
    }
    #[test]
    fn expiration_index_handles_colliding_deadlines_and_timestamp_limits() {
        let mut tracker = Tracker::new(2, 3, 2, 10).unwrap();
        let first = [1; 20];
        let second = [2; 20];
        let id = PeerId([1; 20]);
        let other = PeerId([2; 20]);
        let a: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let b: SocketAddr = "127.0.0.2:2222".parse().unwrap();
        tracker
            .announce(first, id, a, 1, Event::Started, 10)
            .unwrap();
        tracker
            .announce(first, id, b, 1, Event::Started, 10)
            .unwrap();
        tracker
            .announce(second, other, a, 1, Event::Started, 10)
            .unwrap();
        tracker
            .announce(first, id, a, 1, Event::Update, 10)
            .unwrap();
        assert_eq!(tracker.peer_expirations.len(), 3);
        assert_eq!(
            tracker.announce(first, other, b, 1, Event::Started, 19),
            Err(Error::Capacity)
        );
        tracker
            .announce(first, id, a, 0, Event::Completed, 19)
            .unwrap();
        tracker.expire(20);
        assert_eq!(tracker.memberships, 1);
        assert_eq!(tracker.scrape(first, 20).downloaded, 1);
        tracker
            .announce(first, id, a, 0, Event::Stopped, 20)
            .unwrap();
        tracker
            .announce(first, id, a, 0, Event::Stopped, 20)
            .unwrap();
        tracker
            .announce(second, other, a, 1, Event::Started, u64::MAX - 5)
            .unwrap();
        tracker.expire(u64::MAX);
        assert_eq!(tracker.memberships, 0);
        assert!(tracker.peer_expirations.is_empty());
        assert!(!tracker.swarms.contains_key(&second));
    }
    #[test]
    fn bounded_membership_expiry_and_completion() {
        let mut tracker = Tracker::new(2, 2, 2, 10).unwrap();
        let hash = [1; 20];
        let a = PeerId([1; 20]);
        let b = PeerId([2; 20]);
        let addr = "127.0.0.1:6881".parse().unwrap();
        tracker
            .announce(hash, a, addr, 1, Event::Started, 0)
            .unwrap();
        tracker
            .announce(hash, a, addr, 0, Event::Completed, 1)
            .unwrap();
        tracker
            .announce(hash, a, addr, 0, Event::Completed, 2)
            .unwrap();
        tracker
            .announce(hash, b, addr, 1, Event::Started, 2)
            .unwrap();
        let moved = "127.0.0.1:6889".parse().unwrap();
        tracker
            .announce(hash, b, moved, 1, Event::Update, 2)
            .unwrap();
        assert_eq!(tracker.peers(hash, a, 50, 3)[0].address, moved);
        assert_eq!(
            tracker.scrape(hash, 3),
            Counts {
                complete: 1,
                incomplete: 1,
                downloaded: 1
            }
        );
        assert_eq!(tracker.peers(hash, a, 50, 3).len(), 1);
        assert_eq!(
            tracker.announce(hash, PeerId([3; 20]), addr, 1, Event::Started, 3),
            Err(Error::Capacity)
        );
        tracker
            .announce(hash, b, addr, 1, Event::Stopped, 3)
            .unwrap();
        tracker.expire(12);
        assert_eq!(
            tracker.scrape(hash, 12),
            Counts {
                complete: 0,
                incomplete: 0,
                downloaded: 1
            }
        );
        tracker.expire(86_412);
        assert_eq!(tracker.scrape(hash, 86_412), Counts::default());
    }
}
