//! Synchronous registry owned by one task. No locks, atomics, channels, clocks or I/O.
use crate::model::{
    Access, AccessInput, AccessQuery, Binding, Decision, Input, Lease, Operation, Registration,
    valid,
};
use stateless::Model;
use std::{collections::HashMap, net::SocketAddr};
use subtle::ConstantTimeEq;

pub type Key = [u8; 32];
pub type Result<T> = std::result::Result<T, Error>;
pub const MAX_PEERS: usize = 100;
const SCAN_BUDGET: usize = 4096;
#[derive(Clone)]
pub struct Config {
    pub capacity: usize,
    pub ttl_seconds: u64,
    pub open_registration: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            capacity: 100_000,
            ttl_seconds: 300,
            open_registration: false,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unauthorized,
    BadRequest,
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
}
#[derive(Clone, Copy)]
pub struct Credentials {
    pub key: Key,
    pub token_hash: Key,
}
#[derive(Clone, Copy, Debug)]
pub struct PeerInfo {
    pub key: Key,
    pub endpoint: SocketAddr,
    pub remaining_seconds: u64,
}
struct Record {
    token_hash: Key,
    endpoint: SocketAddr,
    lease: Lease,
}
pub struct Registry {
    records: HashMap<Key, Record>,
    discovery_keys: Vec<Key>,
    cursor: usize,
    cleanup_cursor: usize,
    config: Config,
}
fn decision(value: Decision) -> Result<u64> {
    match value {
        Decision::Allowed { remaining_seconds } => Ok(remaining_seconds),
        Decision::Unauthorized => Err(Error::Unauthorized),
        Decision::SelfPeer => Err(Error::BadRequest),
        Decision::Unavailable => Err(Error::NotFound),
        Decision::EndpointMismatch => Err(Error::Conflict),
    }
}
impl Registry {
    pub fn new(config: Config) -> Self {
        assert!(config.capacity > 0 && (1..=86400).contains(&config.ttl_seconds));
        Self {
            records: HashMap::with_capacity(config.capacity),
            discovery_keys: Vec::with_capacity(config.capacity),
            cursor: 0,
            cleanup_cursor: 0,
            config,
        }
    }
    fn authenticate(&self, credentials: Credentials, now: u64) -> Result<Lease> {
        let record = self.records.get(&credentials.key);
        decision(Access.decide(&AccessInput {
            now,
            caller: record.map(|r| r.lease),
            token_matches:
                record.is_some_and(|r| bool::from(r.token_hash.ct_eq(&credentials.token_hash))),
            query: AccessQuery::Caller,
        }))?;
        Ok(record.expect("model allowed existing caller").lease)
    }
    fn peer(
        &self,
        caller: Key,
        lease: Lease,
        target: Key,
        claimed_endpoint: Option<SocketAddr>,
        now: u64,
    ) -> Result<PeerInfo> {
        let record = self.records.get(&target);
        let remaining_seconds = decision(Access.decide(&AccessInput {
            now,
            caller: Some(lease),
            token_matches: true,
            query: AccessQuery::Peer {
                same_peer: caller == target,
                target: record.map(|r| Binding {
                    lease: r.lease,
                    endpoint: r.endpoint,
                }),
                claimed_endpoint,
            },
        }))?;
        Ok(PeerInfo {
            key: target,
            endpoint: record.expect("model allowed existing peer").endpoint,
            remaining_seconds,
        })
    }
    pub fn register_or_refresh(
        &mut self,
        key: Key,
        endpoint: SocketAddr,
        credentials: Option<Credentials>,
        new_token_hash: Key,
        now: u64,
    ) -> Result<u64> {
        if key == [0; 32]
            || endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || endpoint.ip().is_multicast()
        {
            return Err(Error::BadRequest);
        }
        if let Some(credentials) = credentials {
            if credentials.key != key {
                return Err(Error::Unauthorized);
            }
            let lease = self.authenticate(credentials, now)?;
            let next = Registration
                .step(
                    &lease,
                    &Input {
                        now,
                        op: Operation::Refresh {
                            ttl: self.config.ttl_seconds,
                        },
                    },
                )
                .map_err(|_| Error::BadRequest)?
                .state;
            let record = self.records.get_mut(&key).expect("authenticated record");
            record.lease = next;
            record.endpoint = endpoint;
        } else {
            if !self.config.open_registration {
                return Err(Error::Forbidden);
            }
            if self.records.contains_key(&key) {
                return Err(Error::Conflict);
            }
            if self.records.len() >= self.config.capacity {
                return Err(Error::Unavailable);
            }
            let lease = Registration
                .step(
                    &Lease::default(),
                    &Input {
                        now,
                        op: Operation::Register {
                            ttl: self.config.ttl_seconds,
                        },
                    },
                )
                .map_err(|_| Error::BadRequest)?
                .state;
            self.records.insert(
                key,
                Record {
                    token_hash: new_token_hash,
                    endpoint,
                    lease,
                },
            );
            self.discovery_keys.push(key);
        }
        Ok(self.config.ttl_seconds)
    }
    pub fn get_peers(
        &mut self,
        credentials: Credentials,
        limit: usize,
        now: u64,
    ) -> Result<Vec<PeerInfo>> {
        if !(1..=MAX_PEERS).contains(&limit) {
            return Err(Error::BadRequest);
        }
        let lease = self.authenticate(credentials, now)?;
        let len = self.discovery_keys.len();
        let mut peers = Vec::with_capacity(limit);
        for _ in 0..len.min(SCAN_BUDGET) {
            let key = self.discovery_keys[self.cursor];
            self.cursor = (self.cursor + 1) % len;
            if let Ok(peer) = self.peer(credentials.key, lease, key, None, now) {
                peers.push(peer);
                if peers.len() == limit {
                    break;
                }
            }
        }
        Ok(peers)
    }
    pub fn verify_peer(
        &self,
        credentials: Credentials,
        target: Key,
        endpoint: SocketAddr,
        now: u64,
    ) -> Result<PeerInfo> {
        let lease = self.authenticate(credentials, now)?;
        self.peer(credentials.key, lease, target, Some(endpoint), now)
    }
    /// Explicit full cleanup for callers that require all expired storage reclaimed now.
    pub fn cleanup(&mut self, now: u64) {
        let before = self.records.len();
        self.records.retain(|_, r| valid(r.lease, now));
        if self.records.len() != before {
            self.discovery_keys
                .retain(|key| self.records.contains_key(key));
            self.cleanup_cursor = 0;
            self.normalize_cursor();
        }
    }
    /// Bounded maintenance for the owner loop. Authorization checks expiry independently.
    /// Swap removal avoids rebuilding or shifting the entire discovery index.
    pub fn cleanup_batch(&mut self, now: u64, budget: usize) {
        for _ in 0..budget.min(self.discovery_keys.len()) {
            if self.discovery_keys.is_empty() {
                break;
            }
            self.cleanup_cursor %= self.discovery_keys.len();
            let key = self.discovery_keys[self.cleanup_cursor];
            if self.records.get(&key).is_some_and(|r| valid(r.lease, now)) {
                self.cleanup_cursor += 1;
            } else {
                self.records.remove(&key);
                self.discovery_keys.swap_remove(self.cleanup_cursor);
            }
        }
        self.normalize_cursor();
    }
    fn normalize_cursor(&mut self) {
        self.cursor = if self.discovery_keys.is_empty() {
            0
        } else {
            self.cursor % self.discovery_keys.len()
        };
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_cleanup_preserves_refresh_discovery_and_reuse() {
        let mut core = Registry::new(Config {
            capacity: 100,
            ttl_seconds: 10,
            open_registration: true,
        });
        let endpoint = "127.0.0.1:51820".parse().unwrap();
        for i in 1..=100u8 {
            core.register_or_refresh([i; 32], endpoint, None, [7; 32], 0)
                .unwrap();
            if i % 2 == 1 {
                core.register_or_refresh(
                    [i; 32],
                    endpoint,
                    Some(Credentials {
                        key: [i; 32],
                        token_hash: [7; 32],
                    }),
                    [0; 32],
                    5,
                )
                .unwrap();
            }
        }
        let caller = Credentials {
            key: [1; 32],
            token_hash: [7; 32],
        };
        assert!(matches!(
            core.verify_peer(caller, [2; 32], endpoint, 10),
            Err(Error::NotFound)
        ));
        assert_eq!(core.len(), 100); // Expiry blocks access before reclamation.
        core.cleanup_batch(10, 0);
        assert_eq!(core.len(), 100);
        for _ in 0..100 {
            let before = core.len();
            core.cleanup_batch(10, 3);
            assert!(before - core.len() <= 3);
            assert_eq!(core.records.len(), core.discovery_keys.len());
            assert!(
                core.discovery_keys
                    .iter()
                    .all(|key| core.records.contains_key(key))
            );
        }
        assert_eq!(core.len(), 50);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            for peer in core.get_peers(caller, 7, 10).unwrap() {
                seen.insert(peer.key);
            }
        }
        assert_eq!(seen.len(), 49);
        assert!(seen.iter().all(|key| key[0] % 2 == 1 && key[0] != 1));
        core.register_or_refresh([2; 32], endpoint, None, [8; 32], 10)
            .unwrap();
        // Refresh an existing survivor while the maintenance cursor is mid-cycle.
        core.cleanup_batch(10, 7);
        core.register_or_refresh(
            [3; 32],
            endpoint,
            Some(Credentials {
                key: [3; 32],
                token_hash: [7; 32],
            }),
            [0; 32],
            14,
        )
        .unwrap();
        for _ in 0..100 {
            core.cleanup_batch(15, 3);
        }
        assert_eq!(core.len(), 2);
        assert!(core.records.contains_key(&[2; 32]) && core.records.contains_key(&[3; 32]));
        for _ in 0..3 {
            core.cleanup_batch(24, 1);
        }
        assert!(core.is_empty());
        core.register_or_refresh([4; 32], endpoint, None, [9; 32], 24)
            .unwrap();
        core.cleanup_batch(24, 4096);
        assert_eq!(core.len(), 1);
    }
    #[test]
    fn registry_lifecycle_without_runtime_or_shared_state() {
        let mut core = Registry::new(Config {
            capacity: 2,
            ttl_seconds: 2,
            open_registration: true,
        });
        let endpoint = "127.0.0.1:51820".parse().unwrap();
        let changed = "127.0.0.1:51821".parse().unwrap();
        let caller = Credentials {
            key: [1; 32],
            token_hash: [11; 32],
        };
        core.register_or_refresh(caller.key, endpoint, None, caller.token_hash, 10)
            .unwrap();
        core.register_or_refresh([2; 32], endpoint, None, [22; 32], 10)
            .unwrap();
        assert_eq!(
            core.register_or_refresh([3; 32], endpoint, None, [33; 32], 10),
            Err(Error::Unavailable)
        );
        core.register_or_refresh(caller.key, changed, Some(caller), [0; 32], 11)
            .unwrap();
        assert_eq!(core.get_peers(caller, 10, 11).unwrap().len(), 1);
        assert!(matches!(
            core.verify_peer(caller, [2; 32], changed, 11),
            Err(Error::Conflict)
        ));
        assert!(matches!(
            core.verify_peer(caller, [2; 32], endpoint, 12),
            Err(Error::NotFound)
        ));
        core.cleanup(12);
        assert_eq!(core.len(), 1);
        assert!(core.get_peers(caller, 10, 12).unwrap().is_empty());
        assert_eq!(
            core.register_or_refresh(caller.key, endpoint, Some(caller), [0; 32], 13),
            Err(Error::Unauthorized)
        );
        core.cleanup(13);
        assert!(core.is_empty());
        core.register_or_refresh(caller.key, endpoint, None, [44; 32], 13)
            .unwrap();
        assert!(matches!(
            core.get_peers(caller, 10, 13),
            Err(Error::Unauthorized)
        ));
    }
}
