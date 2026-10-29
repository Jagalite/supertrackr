//! Bounded overlay swarm membership. No networking or torrent metadata storage.
//!
//! The caller MUST authenticate peer keys and supply their current lease deadline.
//! All times use the same monotonic seconds clock. Revalidate returned keys against
//! the coordinator before connecting: revocation is owned by the coordinator.
use std::{collections::HashMap, num::NonZeroU16};

pub type PeerKey = [u8; 32];

/// Full hashes, with separate namespaces for v1 and v2 torrents.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum InfoHash {
    V1([u8; 20]),
    V2([u8; 32]),
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub max_swarms: usize,
    pub max_memberships: usize,
    pub max_peers_per_swarm: usize,
    pub max_response_peers: usize,
    pub ttl_seconds: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_swarms: 10_000,
            max_memberships: 100_000,
            max_peers_per_swarm: 1_000,
            max_response_peers: 50,
            ttl_seconds: 300,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfig,
    ExpiredLease,
    Capacity,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub key: PeerKey,
    pub port: NonZeroU16,
    pub complete: bool,
    pub expires_at: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct Announce {
    pub info_hash: InfoHash,
    pub key: PeerKey,
    pub port: NonZeroU16,
    /// Self-reported completion; not proof of possession.
    pub complete: bool,
    pub lease_expires_at: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub seeders: usize,
    pub leechers: usize,
}

pub struct Tracker {
    config: Config,
    swarms: HashMap<InfoHash, HashMap<PeerKey, Peer>>,
    memberships: usize,
}
impl Tracker {
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.max_swarms == 0
            || config.max_memberships == 0
            || config.max_peers_per_swarm == 0
            || config.max_response_peers == 0
            || config.ttl_seconds == 0
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            config,
            swarms: HashMap::new(),
            memberships: 0,
        })
    }
    /// Insert or refresh one membership after external authentication.
    /// Expiry cleanup scans bounded stored state; this is not a high-rate index.
    pub fn announce(&mut self, input: Announce, now: u64) -> Result<(), Error> {
        if input.lease_expires_at <= now {
            return Err(Error::ExpiredLease);
        }
        self.expire(now);
        let swarm = self.swarms.get(&input.info_hash);
        let exists = swarm.is_some_and(|s| s.contains_key(&input.key));
        if !exists
            && (self.memberships >= self.config.max_memberships
                || swarm.is_some_and(|s| s.len() >= self.config.max_peers_per_swarm)
                || (swarm.is_none() && self.swarms.len() >= self.config.max_swarms))
        {
            return Err(Error::Capacity);
        }
        let peer = Peer {
            key: input.key,
            port: input.port,
            complete: input.complete,
            expires_at: input
                .lease_expires_at
                .min(now.saturating_add(self.config.ttl_seconds)),
        };
        self.swarms
            .entry(input.info_hash)
            .or_default()
            .insert(input.key, peer);
        if !exists {
            self.memberships += 1;
        }
        Ok(())
    }
    /// Caller authenticates the departing key before invoking this operation.
    pub fn stop(&mut self, hash: InfoHash, key: PeerKey) {
        if let Some(swarm) = self.swarms.get_mut(&hash) {
            if swarm.remove(&key).is_some() {
                self.memberships -= 1;
            }
            if swarm.is_empty() {
                self.swarms.remove(&hash);
            }
        }
    }
    /// Remove all memberships for a revoked identity.
    pub fn remove_peer(&mut self, key: PeerKey) {
        self.swarms.retain(|_, swarm| {
            if swarm.remove(&key).is_some() {
                self.memberships -= 1;
            }
            !swarm.is_empty()
        });
    }
    pub fn expire(&mut self, now: u64) {
        self.swarms.retain(|_, swarm| {
            let before = swarm.len();
            swarm.retain(|_, p| p.expires_at > now);
            self.memberships -= before - swarm.len();
            !swarm.is_empty()
        });
    }
    /// Bounded arbitrary subset, excluding the requester. No fairness guarantee.
    pub fn peers(&self, hash: InfoHash, requester: PeerKey, limit: usize, now: u64) -> Vec<Peer> {
        self.swarms
            .get(&hash)
            .into_iter()
            .flat_map(|s| s.values())
            .filter(|p| p.key != requester && p.expires_at > now)
            .take(limit.min(self.config.max_response_peers))
            .copied()
            .collect()
    }
    pub fn stats(&self, hash: InfoHash, now: u64) -> Stats {
        let mut stats = Stats::default();
        for p in self
            .swarms
            .get(&hash)
            .into_iter()
            .flat_map(|s| s.values())
            .filter(|p| p.expires_at > now)
        {
            if p.complete {
                stats.seeders += 1;
            } else {
                stats.leechers += 1;
            }
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(key: u8) -> Announce {
        Announce {
            info_hash: InfoHash::V1([1; 20]),
            key: [key; 32],
            port: NonZeroU16::new(6881).unwrap(),
            complete: false,
            lease_expires_at: 20,
        }
    }
    #[test]
    fn expiry_refresh_completion_and_response_bounds() {
        let mut t = Tracker::new(Config {
            max_response_peers: 1,
            ttl_seconds: 10,
            ..Config::default()
        })
        .unwrap();
        t.announce(input(1), 0).unwrap();
        t.announce(input(2), 0).unwrap();
        let mut a = input(1);
        a.complete = true;
        t.announce(a, 5).unwrap();
        assert_eq!(
            t.stats(a.info_hash, 9),
            Stats {
                seeders: 1,
                leechers: 1
            }
        );
        assert_eq!(t.peers(a.info_hash, a.key, 100, 9)[0].key, [2; 32]);
        assert_eq!(t.peers(a.info_hash, [9; 32], 100, 9).len(), 1);
        assert!(t.peers(a.info_hash, a.key, 100, 10).is_empty());
        assert_eq!(t.stats(a.info_hash, 15), Stats::default());
        a.lease_expires_at = 16;
        t.announce(a, 15).unwrap();
        assert_eq!(t.stats(a.info_hash, 16), Stats::default());
        assert_eq!(t.announce(a, 16), Err(Error::ExpiredLease));
    }
    #[test]
    fn capacity_recovery_stop_revocation_and_hash_isolation() {
        let mut t = Tracker::new(Config {
            max_swarms: 1,
            max_memberships: 1,
            max_peers_per_swarm: 1,
            ..Config::default()
        })
        .unwrap();
        let a = input(1);
        t.announce(a, 0).unwrap();
        t.announce(a, 1).unwrap();
        assert_eq!(t.announce(input(2), 1), Err(Error::Capacity));
        let mut b = input(2);
        b.info_hash = InfoHash::V2([1; 32]);
        assert_eq!(t.stats(b.info_hash, 1), Stats::default());
        assert_eq!(t.announce(b, 1), Err(Error::Capacity));
        t.stop(a.info_hash, a.key);
        t.stop(a.info_hash, a.key);
        t.announce(b, 1).unwrap();
        t.remove_peer(b.key);
        t.announce(a, 1).unwrap();
        b.lease_expires_at = 40;
        t.announce(b, 20).unwrap();
        assert_eq!(t.memberships, 1);
        t.expire(40);
        assert!(t.swarms.is_empty());
        assert_eq!(t.memberships, 0);
    }
}
