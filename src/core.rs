//! Synchronous registry owned by one task. No locks, atomics, channels, clocks or I/O.
use crate::model::{
    Access, AccessInput, AccessQuery, Binding, Decision, Input, Lease, Operation, Registration,
    valid,
};
use sha2::{Digest, Sha256};
use stateless::Model;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};
use subtle::ConstantTimeEq;
#[path = "traversal.rs"]
pub mod traversal;

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
    identity: Key,
    token_hash: Key,
    endpoint: SocketAddr,
    endpoint_expires: u64,
    endpoint_explicit: bool,
    lease: Lease,
}
/// Credential namespace is distinct from the logical peer ID. New transports
/// must add their own variant and proof-of-possession protocol before linking.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum CredentialId {
    WireGuard(Key),
}
struct PendingLink {
    owner_identity: Key,
    added: Credentials,
    proof: crate::enrollment::Pending,
}
pub struct Registry {
    records: HashMap<Key, Record>,
    identity_members: HashMap<Key, HashSet<CredentialId>>,
    enrollments: HashMap<Key, crate::enrollment::Pending>,
    enrollment_expiry: std::collections::BTreeSet<(u64, Key)>,
    links: HashMap<Key, PendingLink>,
    link_expiry: std::collections::BTreeSet<(u64, Key)>,
    discovery_keys: Vec<Key>,
    cursor: usize,
    cleanup_cursor: usize,
    config: Config,
    traversal: traversal::Traversal,
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
    #[cfg(feature = "bittorrent")]
    pub(crate) fn live_identity_for_key(&self, key: Key, now: u64) -> Option<Key> {
        self.records
            .get(&key)
            .filter(|record| valid(record.lease, now))
            .map(|record| record.identity)
    }
    #[cfg(feature = "bittorrent")]
    pub(crate) fn endpoint_remaining_for_key(&self, key: Key, now: u64) -> Option<u64> {
        self.records
            .get(&key)
            .filter(|record| valid(record.lease, now) && record.endpoint_expires > now)
            .filter(|_| {
                self.traversal
                    .peers
                    .get(&key)
                    .is_some_and(|peer| !peer.candidates.is_empty())
            })
            .map(|record| record.endpoint_expires.min(record.lease.expires) - now)
    }
    pub(crate) fn prepare_link(
        &mut self,
        owner: Credentials,
        expected_identity: Key,
        id: Key,
        mut proof: crate::enrollment::Pending,
        now: u64,
    ) -> Result<()> {
        self.expire_links(now);
        let owner_identity = self.identity(owner, now)?;
        if owner_identity != expected_identity {
            return Err(Error::Conflict);
        }
        let added = self.records.get(&proof.key).ok_or(Error::NotFound)?;
        if !valid(added.lease, now)
            || added.endpoint_expires <= now
            || added.endpoint != proof.endpoint
        {
            return Err(Error::Conflict);
        }
        if added.identity == owner_identity
            || self
                .identity_members
                .get(&added.identity)
                .map_or(0, HashSet::len)
                != 1
        {
            return Err(Error::Conflict);
        }
        if self
            .identity_members
            .get(&owner_identity)
            .map_or(0, HashSet::len)
            >= 8
            || self.links.len() >= 4096
            || self
                .links
                .values()
                .filter(|link| link.owner_identity == owner_identity)
                .count()
                >= 8
        {
            return Err(Error::Unavailable);
        }
        if self.links.contains_key(&id) {
            return Err(Error::Conflict);
        }
        let added = Credentials {
            key: proof.key,
            token_hash: added.token_hash,
        };
        proof.until = now.saturating_add(30);
        self.link_expiry.insert((proof.until, id));
        self.links.insert(
            id,
            PendingLink {
                owner_identity,
                added,
                proof,
            },
        );
        Ok(())
    }
    pub(crate) fn finish_link(
        &mut self,
        owner: Credentials,
        id: Key,
        answer_hash: Key,
        now: u64,
    ) -> Result<Key> {
        self.expire_links(now);
        let identity = self.identity(owner, now)?;
        let pending = self.links.get(&id).ok_or(Error::Unauthorized)?;
        if pending.proof.until <= now
            || pending.owner_identity != identity
            || !bool::from(pending.proof.answer_hash.ct_eq(&answer_hash))
        {
            return Err(Error::Unauthorized);
        }
        let added = pending.added;
        let until = pending.proof.until;
        let endpoint = pending.proof.endpoint;
        // Consume before attempting the mutation, including on conflict.
        self.links.remove(&id);
        self.link_expiry.remove(&(until, id));
        if !self
            .records
            .get(&added.key)
            .is_some_and(|record| record.endpoint == endpoint && record.endpoint_expires > now)
        {
            return Err(Error::Conflict);
        }
        self.link_credentials(owner, added, now)
    }
    fn expire_links(&mut self, now: u64) {
        for _ in 0..64 {
            let Some(&(until, id)) = self.link_expiry.first() else {
                break;
            };
            if until > now {
                break;
            }
            self.link_expiry.remove(&(until, id));
            self.links.remove(&id);
        }
    }
    /// Return the logical identity associated with an authenticated live credential.
    pub fn identity(&self, credentials: Credentials, now: u64) -> Result<Key> {
        self.authenticate(credentials, now)?;
        Ok(self.records[&credentials.key].identity)
    }

    /// Publish a shorter-lived endpoint without refreshing the credential lease.
    /// Endpoint validity never outlives its credential.
    pub fn publish_endpoint(
        &mut self,
        who: Credentials,
        endpoint: SocketAddr,
        ttl: u64,
        now: u64,
    ) -> Result<u64> {
        let lease = self.authenticate(who, now)?;
        if !traversal::valid_endpoint(endpoint) || !(1..=86400).contains(&ttl) {
            return Err(Error::BadRequest);
        }
        let expires = now
            .checked_add(ttl)
            .ok_or(Error::BadRequest)?
            .min(lease.expires);
        let record = self
            .records
            .get_mut(&who.key)
            .expect("authenticated record");
        let invalidate_candidates = record.endpoint != endpoint || record.endpoint_expires <= now;
        record.endpoint = endpoint;
        record.endpoint_expires = expires;
        record.endpoint_explicit = true;
        if invalidate_candidates && let Some(peer) = self.traversal.peers.get_mut(&who.key) {
            peer.candidates.clear();
        }
        Ok(expires - now)
    }

    /// List live transport credentials belonging to the authenticated identity.
    pub fn identity_credentials(
        &self,
        credentials: Credentials,
        now: u64,
    ) -> Result<(Key, Vec<Key>)> {
        let identity = self.identity(credentials, now)?;
        let mut keys: Vec<_> = self
            .identity_members
            .get(&identity)
            .into_iter()
            .flatten()
            .filter_map(|credential| match credential {
                CredentialId::WireGuard(key) => self
                    .records
                    .get(key)
                    .filter(|record| valid(record.lease, now))
                    .map(|_| *key),
            })
            .collect();
        keys.sort_unstable();
        Ok((identity, keys))
    }

    /// Join two independently authenticated registrations. The second identity must
    /// have only one credential: merging whole groups requires a separate protocol.
    /// Both credentials retain their own leases, bearer tokens and transport state.
    fn link_credentials(
        &mut self,
        owner: Credentials,
        added: Credentials,
        now: u64,
    ) -> Result<Key> {
        let identity = self.identity(owner, now)?;
        let other = self.identity(added, now)?;
        if identity == other {
            return Err(Error::Conflict);
        }
        if self.identity_members.get(&other).map_or(0, HashSet::len) != 1 {
            return Err(Error::Conflict);
        }
        if self.identity_members.get(&identity).map_or(0, HashSet::len) >= 8 {
            return Err(Error::Unavailable);
        }
        self.identity_members.remove(&other);
        self.identity_members
            .entry(identity)
            .or_default()
            .insert(CredentialId::WireGuard(added.key));
        self.records
            .get_mut(&added.key)
            .expect("authenticated credential")
            .identity = identity;
        Ok(identity)
    }

    /// Revoke another credential of the same identity. Self-revocation is
    /// forbidden, so an authenticated credential always remains for recovery.
    pub fn revoke_credential(&mut self, owner: Credentials, target: Key, now: u64) -> Result<()> {
        let identity = self.identity(owner, now)?;
        if target == owner.key {
            return Err(Error::BadRequest);
        }
        let record = self.records.get(&target).ok_or(Error::NotFound)?;
        if record.identity != identity {
            return Err(Error::Forbidden);
        }
        self.remove_record(&target);
        self.traversal.remove(&target);
        self.discovery_keys.retain(|key| *key != target);
        self.cleanup_cursor = 0;
        self.normalize_cursor();
        Ok(())
    }
    pub fn new(config: Config) -> Self {
        assert!(config.capacity > 0 && (1..=86400).contains(&config.ttl_seconds));
        Self {
            records: HashMap::with_capacity(config.capacity),
            identity_members: HashMap::new(),
            enrollments: HashMap::new(),
            enrollment_expiry: std::collections::BTreeSet::new(),
            links: HashMap::new(),
            link_expiry: std::collections::BTreeSet::new(),
            discovery_keys: Vec::with_capacity(config.capacity),
            cursor: 0,
            cleanup_cursor: 0,
            config,
            traversal: traversal::Traversal::default(),
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
        let remaining_seconds = decision(
            Access.decide(&AccessInput {
                now,
                caller: Some(lease),
                token_matches: true,
                query: AccessQuery::Peer {
                    same_peer: caller == target
                        || self
                            .records
                            .get(&caller)
                            .zip(record)
                            .is_some_and(|(a, b)| a.identity == b.identity),
                    target: record.map(|r| Binding {
                        lease: Lease {
                            expires: r.lease.expires.min(r.endpoint_expires),
                            ..r.lease
                        },
                        endpoint: r.endpoint,
                    }),
                    claimed_endpoint,
                },
            }),
        )?;
        Ok(PeerInfo {
            key: target,
            endpoint: record.expect("model allowed existing peer").endpoint,
            remaining_seconds,
        })
    }
    fn expire_enrollments(&mut self, now: u64) {
        for _ in 0..64 {
            let Some(&(until, id)) = self.enrollment_expiry.first() else {
                break;
            };
            if until > now {
                break;
            }
            self.enrollment_expiry.remove(&(until, id));
            self.enrollments.remove(&id);
        }
    }
    pub fn prepare_enrollment(
        &mut self,
        id: Key,
        mut pending: crate::enrollment::Pending,
        now: u64,
    ) -> Result<()> {
        self.expire_enrollments(now);
        if !self.config.open_registration {
            return Err(Error::Forbidden);
        }
        if self.records.contains_key(&pending.key) {
            return Err(Error::Conflict);
        }
        if self.records.len() >= self.config.capacity || self.enrollments.len() >= 4096 {
            return Err(Error::Unavailable);
        }
        if pending.endpoint.port() == 0
            || pending.endpoint.ip().is_unspecified()
            || pending.endpoint.ip().is_multicast()
        {
            return Err(Error::BadRequest);
        }
        if self.enrollments.contains_key(&id) {
            return Err(Error::Conflict);
        }
        pending.until = now.saturating_add(30);
        self.enrollment_expiry.insert((pending.until, id));
        self.enrollments.insert(id, pending);
        Ok(())
    }
    pub fn finish_enrollment(
        &mut self,
        key: Key,
        endpoint: SocketAddr,
        id: Key,
        answer_hash: Key,
        token_hash: Key,
        now: u64,
    ) -> Result<u64> {
        self.expire_enrollments(now);
        let pending = self.enrollments.get(&id).ok_or(Error::Unauthorized)?;
        if pending.until <= now
            || pending.key != key
            || pending.endpoint != endpoint
            || !bool::from(pending.answer_hash.ct_eq(&answer_hash))
        {
            return Err(Error::Unauthorized);
        }
        let until = pending.until;
        self.enrollments.remove(&id);
        self.enrollment_expiry.remove(&(until, id));
        self.register_or_refresh(key, endpoint, None, token_hash, now)
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
            if !record.endpoint_explicit {
                record.endpoint = endpoint;
                record.endpoint_expires = next.expires;
            }
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
            let identity: Key = Sha256::digest(
                [
                    b"supertrackr/identity/v1\0".as_slice(),
                    &key,
                    &new_token_hash,
                ]
                .concat(),
            )
            .into();
            // Never attach a fresh registration to an existing identity, even on collision.
            if self.identity_members.contains_key(&identity) {
                return Err(Error::Conflict);
            }
            self.identity_members
                .entry(identity)
                .or_default()
                .insert(CredentialId::WireGuard(key));
            self.records.insert(
                key,
                Record {
                    identity,
                    token_hash: new_token_hash,
                    endpoint,
                    endpoint_expires: lease.expires,
                    endpoint_explicit: false,
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
        let expired: Vec<_> = self
            .records
            .iter()
            .filter_map(|(key, record)| (!valid(record.lease, now)).then_some(*key))
            .collect();
        for key in expired {
            self.remove_record(&key);
        }
        if self.records.len() != before {
            let removed: Vec<_> = self
                .traversal
                .peers
                .keys()
                .filter(|k| !self.records.contains_key(*k))
                .copied()
                .collect();
            for key in removed {
                self.traversal.remove(&key);
            }
            self.discovery_keys
                .retain(|key| self.records.contains_key(key));
            self.cleanup_cursor = 0;
            self.normalize_cursor();
        }
    }
    /// Bounded maintenance for the owner loop. Authorization checks expiry independently.
    /// Swap removal avoids rebuilding or shifting the entire discovery index.
    pub fn cleanup_batch(&mut self, now: u64, budget: usize) {
        self.expire_enrollments(now);
        self.expire_links(now);
        for _ in 0..budget.min(self.discovery_keys.len()) {
            if self.discovery_keys.is_empty() {
                break;
            }
            self.cleanup_cursor %= self.discovery_keys.len();
            let key = self.discovery_keys[self.cleanup_cursor];
            if self.records.get(&key).is_some_and(|r| valid(r.lease, now)) {
                self.traversal.maintain(&key, now);
                self.cleanup_cursor += 1;
            } else {
                self.remove_record(&key);
                self.traversal.remove(&key);
                self.discovery_keys.swap_remove(self.cleanup_cursor);
            }
        }
        self.normalize_cursor();
    }
    fn remove_record(&mut self, key: &Key) {
        if let Some(record) = self.records.remove(key)
            && let Some(members) = self.identity_members.get_mut(&record.identity)
        {
            members.remove(&CredentialId::WireGuard(*key));
            if members.is_empty() {
                self.identity_members.remove(&record.identity);
            }
        }
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
    fn endpoint_expiry_is_independent_and_cannot_extend_credential() {
        let mut r = Registry::new(Config {
            open_registration: true,
            ttl_seconds: 20,
            ..Config::default()
        });
        let endpoint = "127.0.0.1:51820".parse().unwrap();
        let changed = "127.0.0.1:51821".parse().unwrap();
        let a = Credentials {
            key: [1; 32],
            token_hash: [11; 32],
        };
        let b = Credentials {
            key: [2; 32],
            token_hash: [22; 32],
        };
        for who in [a, b] {
            r.register_or_refresh(who.key, endpoint, None, who.token_hash, 0)
                .unwrap();
        }
        let identity = r.identity(b, 1).unwrap();
        assert_eq!(
            r.publish_endpoint(
                Credentials {
                    token_hash: [0; 32],
                    ..b
                },
                changed,
                3,
                1
            ),
            Err(Error::Unauthorized)
        );
        assert_eq!(r.publish_endpoint(b, changed, 0, 1), Err(Error::BadRequest));
        assert_eq!(r.publish_endpoint(b, changed, 3, 1), Ok(3));
        r.register_or_refresh(b.key, endpoint, Some(b), [0; 32], 2)
            .unwrap();
        assert_eq!(
            r.verify_peer(a, b.key, changed, 2)
                .unwrap()
                .remaining_seconds,
            2
        );
        assert_eq!(
            r.verify_peer(a, b.key, changed, 4).unwrap_err(),
            Error::NotFound
        );
        assert_eq!(r.identity(b, 4), Ok(identity));
        assert_eq!(r.publish_endpoint(b, changed, 100, 4), Ok(18));
        assert_eq!(
            r.verify_peer(a, b.key, changed, 19)
                .unwrap()
                .remaining_seconds,
            3
        );
        assert!(matches!(r.identity(b, 22), Err(Error::Unauthorized)));
    }
    #[test]
    fn identity_capacity_and_competing_links_are_atomic() {
        let mut r = Registry::new(Config {
            open_registration: true,
            ttl_seconds: 120,
            ..Config::default()
        });
        let endpoint = "127.0.0.1:51820".parse().unwrap();
        let credentials = |i| Credentials {
            key: [i; 32],
            token_hash: [i + 32; 32],
        };
        for i in 1..=10 {
            let c = credentials(i);
            r.register_or_refresh(c.key, endpoint, None, c.token_hash, 0)
                .unwrap();
        }
        let a = credentials(1);
        for i in 2..=8 {
            r.link_credentials(a, credentials(i), 1).unwrap();
        }
        assert_eq!(
            r.link_credentials(a, credentials(9), 1),
            Err(Error::Unavailable)
        );
        assert_ne!(r.identity(a, 1), r.identity(credentials(9), 1));
        let b = credentials(9);
        let identity = r.identity(b, 1).unwrap();
        let proof = || crate::enrollment::Pending {
            key: credentials(10).key,
            endpoint,
            answer_hash: [99; 32],
            until: 0,
        };
        r.prepare_link(b, identity, [41; 32], proof(), 1).unwrap();
        r.prepare_link(b, identity, [42; 32], proof(), 1).unwrap();
        assert_eq!(r.finish_link(b, [41; 32], [99; 32], 1), Ok(identity));
        assert_eq!(
            r.finish_link(b, [42; 32], [99; 32], 1),
            Err(Error::Conflict)
        );
        assert_eq!(
            r.finish_link(b, [42; 32], [99; 32], 1),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn link_challenge_is_bound_expiring_and_cannot_attach_a_replaced_registration() {
        let mut r = Registry::new(Config {
            open_registration: true,
            ttl_seconds: 120,
            ..Config::default()
        });
        let endpoint = "127.0.0.1:51820".parse().unwrap();
        let a = Credentials {
            key: [1; 32],
            token_hash: [11; 32],
        };
        let b = Credentials {
            key: [2; 32],
            token_hash: [22; 32],
        };
        let c = Credentials {
            key: [3; 32],
            token_hash: [33; 32],
        };
        for who in [a, b, c] {
            r.register_or_refresh(who.key, endpoint, None, who.token_hash, 0)
                .unwrap();
        }
        let identity = r.identity(a, 1).unwrap();
        let pending = || crate::enrollment::Pending {
            key: b.key,
            endpoint,
            answer_hash: [8; 32],
            until: 0,
        };
        r.prepare_link(a, identity, [4; 32], pending(), 1).unwrap();
        assert_eq!(
            r.finish_link(c, [4; 32], [8; 32], 1),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            r.finish_link(a, [4; 32], [7; 32], 1),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            r.finish_link(a, [4; 32], [8; 32], 31),
            Err(Error::Unauthorized)
        );
        r.prepare_link(a, identity, [6; 32], pending(), 32).unwrap();
        let changed = "127.0.0.1:51821".parse().unwrap();
        r.register_or_refresh(b.key, changed, Some(b), [0; 32], 32)
            .unwrap();
        assert_eq!(r.finish_link(a, [6; 32], [8; 32], 32), Err(Error::Conflict));
        r.register_or_refresh(b.key, endpoint, Some(b), [0; 32], 32)
            .unwrap();
        r.prepare_link(a, identity, [5; 32], pending(), 32).unwrap();
        r.remove_record(&b.key);
        r.traversal.remove(&b.key);
        r.discovery_keys.retain(|key| *key != b.key);
        r.register_or_refresh(b.key, endpoint, None, [44; 32], 32)
            .unwrap();
        assert_eq!(
            r.finish_link(a, [5; 32], [8; 32], 32),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            r.finish_link(a, [5; 32], [8; 32], 32),
            Err(Error::Unauthorized)
        );
        assert_ne!(
            r.identity(a, 32),
            r.identity(
                Credentials {
                    token_hash: [44; 32],
                    ..b
                },
                32
            )
        );
    }
    #[test]
    fn linked_credentials_require_both_tokens_and_remain_separate_leases() {
        let mut registry = Registry::new(Config {
            open_registration: true,
            ttl_seconds: 10,
            ..Config::default()
        });
        let endpoint = "127.0.0.1:51820".parse().unwrap();
        let a = Credentials {
            key: [1; 32],
            token_hash: [11; 32],
        };
        let b = Credentials {
            key: [2; 32],
            token_hash: [22; 32],
        };
        registry
            .register_or_refresh(a.key, endpoint, None, a.token_hash, 0)
            .unwrap();
        registry
            .register_or_refresh(b.key, endpoint, None, b.token_hash, 1)
            .unwrap();
        let first = registry.identity(a, 1).unwrap();
        assert_ne!(first, registry.identity(b, 1).unwrap());
        assert_eq!(
            registry.link_credentials(
                a,
                Credentials {
                    token_hash: [0; 32],
                    ..b
                },
                1
            ),
            Err(Error::Unauthorized)
        );
        assert_eq!(registry.link_credentials(a, b, 1), Ok(first));
        assert_eq!(registry.identity(b, 1), Ok(first));
        assert_eq!(registry.link_credentials(a, b, 1), Err(Error::Conflict));
        assert!(matches!(
            registry.verify_peer(a, b.key, endpoint, 1),
            Err(Error::BadRequest)
        ));
        assert!(matches!(registry.identity(a, 10), Err(Error::Unauthorized)));
        assert_eq!(registry.identity(b, 10), Ok(first));
        registry.cleanup(10);
        assert_eq!(registry.identity(b, 10), Ok(first));
        assert_eq!(registry.identity_members[&first].len(), 1);
        registry.cleanup(11);
        assert!(registry.is_empty());
        assert!(registry.identity_members.is_empty());
    }
    #[test]
    fn revocation_removes_only_authorized_credential_and_state() {
        let mut r = Registry::new(Config {
            open_registration: true,
            ttl_seconds: 30,
            ..Config::default()
        });
        let endpoint = "127.0.0.1:51820".parse().unwrap();
        let a = Credentials {
            key: [1; 32],
            token_hash: [11; 32],
        };
        let b = Credentials {
            key: [2; 32],
            token_hash: [22; 32],
        };
        let c = Credentials {
            key: [3; 32],
            token_hash: [33; 32],
        };
        for who in [a, b, c] {
            r.register_or_refresh(who.key, endpoint, None, who.token_hash, 0)
                .unwrap();
        }
        r.link_credentials(a, b, 1).unwrap();
        assert_eq!(r.revoke_credential(c, b.key, 1), Err(Error::Forbidden));
        assert_eq!(r.revoke_credential(a, a.key, 1), Err(Error::BadRequest));
        assert_eq!(r.revoke_credential(a, b.key, 1), Ok(()));
        assert!(matches!(r.identity(b, 1), Err(Error::Unauthorized)));
        assert!(r.identity(a, 1).is_ok());
        assert!(!r.discovery_keys.contains(&b.key));
        assert_eq!(r.revoke_credential(a, b.key, 1), Err(Error::NotFound));
    }
    #[test]
    fn enrollment_expiry_replay_and_resource_bounds() {
        let mut core = Registry::new(Config {
            open_registration: true,
            ttl_seconds: 1,
            ..Config::default()
        });
        let endpoint = "127.0.0.1:10".parse().unwrap();
        let pending = || crate::enrollment::Pending {
            key: [1; 32],
            endpoint,
            answer_hash: [2; 32],
            until: 0,
        };
        core.prepare_enrollment([3; 32], pending(), 0).unwrap();
        assert_eq!(
            core.finish_enrollment([1; 32], endpoint, [3; 32], [2; 32], [4; 32], 30),
            Err(Error::Unauthorized)
        );
        assert!(core.is_empty());
        core.prepare_enrollment([3; 32], pending(), 31).unwrap();
        core.finish_enrollment([1; 32], endpoint, [3; 32], [2; 32], [4; 32], 31)
            .unwrap();
        core.cleanup_batch(32, 4096);
        assert!(core.is_empty());
        assert_eq!(
            core.finish_enrollment([1; 32], endpoint, [3; 32], [2; 32], [4; 32], 32),
            Err(Error::Unauthorized)
        );
        for n in 0..4096u64 {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&n.to_be_bytes());
            core.prepare_enrollment(id, pending(), 40).unwrap();
        }
        assert_eq!(
            core.prepare_enrollment([9; 32], pending(), 40),
            Err(Error::Unavailable)
        );
        assert!(core.is_empty());
        for _ in 0..64 {
            core.cleanup_batch(70, 0);
        }
        assert!(core.enrollments.is_empty());
        assert!(core.enrollment_expiry.is_empty());
        core.prepare_enrollment([9; 32], pending(), 70).unwrap();
    }
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
