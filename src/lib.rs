pub mod model;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use model::{
    Access, AccessInput, AccessQuery, Binding, Decision, Input, Lease, Operation, Registration,
    valid,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stateless::Model;
use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
use subtle::ConstantTimeEq;
type Key = [u8; 32];
type Result<T> = std::result::Result<T, StatusCode>;
const SHARDS: usize = 64;
const MAX_PEERS: usize = 100;
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
struct Record {
    token: Key,
    endpoint: SocketAddr,
    lease: Lease,
}
#[derive(Default)]
struct Shard {
    records: HashMap<Key, Record>,
    discovery_keys: Vec<Key>,
    cursor: AtomicUsize,
}
pub struct Coordinator {
    shards: [RwLock<Shard>; SHARDS],
    count: AtomicUsize,
    discovery_cursor: AtomicUsize,
    shard_hash: RandomState,
    config: Config,
    start: Instant,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub public_key: String,
    pub endpoint: SocketAddr,
}
#[derive(Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub token: String,
    pub expires_in_seconds: u64,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Peer {
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub remaining_seconds: u64,
}
fn parse_key(s: &str) -> Result<Key> {
    let mut key = [0; 32];
    hex::decode_to_slice(s, &mut key).map_err(|_| StatusCode::BAD_REQUEST)?;
    if key == [0; 32] {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(key)
}
fn credentials(h: &HeaderMap) -> Result<(Key, Key)> {
    let key = parse_key(
        h.get("x-peer-key")
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?,
    )?;
    let token = h
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if token.len() != 64 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut raw = [0; 32];
    hex::decode_to_slice(token, &mut raw).map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok((key, Sha256::digest(raw).into()))
}
fn http_decision(decision: Decision) -> Result<u64> {
    match decision {
        Decision::Allowed { remaining_seconds } => Ok(remaining_seconds),
        Decision::Unauthorized => Err(StatusCode::UNAUTHORIZED),
        Decision::SelfPeer => Err(StatusCode::BAD_REQUEST),
        Decision::Unavailable => Err(StatusCode::NOT_FOUND),
        Decision::EndpointMismatch => Err(StatusCode::CONFLICT),
    }
}
fn authenticate(record: Option<&Record>, token: &Key, now: u64) -> Result<Lease> {
    http_decision(Access.decide(&AccessInput {
        now,
        caller: record.map(|r| r.lease),
        token_matches: record.is_some_and(|r| bool::from(r.token.ct_eq(token))),
        query: AccessQuery::Caller,
    }))?;
    Ok(record.expect("model allowed an existing caller").lease)
}
#[derive(Clone, Copy)]
struct PeerSnapshot {
    key: Key,
    endpoint: SocketAddr,
    remaining_seconds: u64,
}
impl PeerSnapshot {
    fn encode(self) -> Peer {
        Peer {
            public_key: hex::encode(self.key),
            endpoint: self.endpoint,
            remaining_seconds: self.remaining_seconds,
        }
    }
}
fn eligible_peer(
    caller: Key,
    caller_lease: Lease,
    target: Key,
    record: Option<&Record>,
    claimed_endpoint: Option<SocketAddr>,
    now: u64,
) -> Result<PeerSnapshot> {
    let remaining_seconds = http_decision(Access.decide(&AccessInput {
        now,
        caller: Some(caller_lease),
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
    Ok(PeerSnapshot {
        key: target,
        endpoint: record.expect("model allowed an existing target").endpoint,
        remaining_seconds,
    })
}
impl Coordinator {
    pub fn new(config: Config) -> Arc<Self> {
        assert!(config.capacity > 0 && config.ttl_seconds > 0);
        Arc::new(Self {
            shards: std::array::from_fn(|_| RwLock::new(Shard::default())),
            count: AtomicUsize::new(0),
            discovery_cursor: AtomicUsize::new(0),
            shard_hash: RandomState::new(),
            config,
            start: Instant::now(),
        })
    }
    fn shard(&self, key: &Key) -> usize {
        self.shard_hash.hash_one(key) as usize % SHARDS
    }
    fn now(&self) -> u64 {
        self.start.elapsed().as_secs()
    }
    pub fn cleanup(&self) {
        let now = self.now();
        for shard in &self.shards {
            let mut entries = shard.write().unwrap();
            let before = entries.records.len();
            entries.records.retain(|_, r| valid(r.lease, now));
            let Shard {
                records,
                discovery_keys,
                cursor,
            } = &mut *entries;
            discovery_keys.retain(|key| records.contains_key(key));
            *cursor.get_mut() = if discovery_keys.is_empty() {
                0
            } else {
                *cursor.get_mut() % discovery_keys.len()
            };
            self.count
                .fetch_sub(before - entries.records.len(), Ordering::Relaxed);
        }
    }
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    // Lock both shards in a stable order: caller authentication and target lookup
    // are one atomic observation relative to removal/registration.
    fn with_shard<T>(
        &self,
        caller: Key,
        token: &Key,
        target_shard: usize,
        f: impl FnOnce(&Shard, Lease, u64) -> Result<T>,
    ) -> Result<T> {
        let caller_shard = self.shard(&caller);
        let inspect = |left: &Shard, right: &Shard| {
            let now = self.now();
            let lease = authenticate(left.records.get(&caller), token, now)?;
            f(right, lease, now)
        };
        if caller_shard == target_shard {
            let shard = self.shards[caller_shard].read().unwrap();
            inspect(&shard, &shard)
        } else {
            let low = self.shards[caller_shard.min(target_shard)].read().unwrap();
            let high = self.shards[caller_shard.max(target_shard)].read().unwrap();
            if caller_shard < target_shard {
                inspect(&low, &high)
            } else {
                inspect(&high, &low)
            }
        }
    }
}
#[allow(deprecated)] // AtomicUsize::fetch_update supports the declared Rust 1.90 MSRV.
async fn register(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<RegisterRequest>,
) -> Result<Json<RegistrationResponse>> {
    let key = parse_key(&q.public_key)?;
    if q.endpoint.port() == 0 || q.endpoint.ip().is_unspecified() || q.endpoint.ip().is_multicast()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if headers.contains_key("authorization") || headers.contains_key("x-peer-key") {
        let (caller, token) = credentials(&headers)?;
        if caller != key {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let mut entries = s.shards[s.shard(&key)].write().unwrap();
        let record = entries
            .records
            .get_mut(&key)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let now = s.now();
        authenticate(Some(record), &token, now)?;
        record.lease = Registration
            .step(
                &record.lease,
                &Input {
                    now,
                    op: Operation::Refresh {
                        ttl: s.config.ttl_seconds,
                    },
                },
            )
            .map_err(|_| StatusCode::UNAUTHORIZED)?
            .state;
        record.endpoint = q.endpoint;
        // Retain the existing token so concurrent refreshes cannot invalidate one another.
        drop(entries);
        return Ok(Json(RegistrationResponse {
            token: headers["authorization"].to_str().unwrap()[7..].to_owned(),
            expires_in_seconds: s.config.ttl_seconds,
        }));
    }
    if !s.config.open_registration {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut raw = [0; 32];
    OsRng.fill_bytes(&mut raw);
    let token_hash = Sha256::digest(raw).into();
    let mut entries = s.shards[s.shard(&key)].write().unwrap();
    if entries.records.contains_key(&key) {
        return Err(StatusCode::CONFLICT);
    }
    s.count
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < s.config.capacity).then_some(n + 1)
        })
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let lease = Registration
        .step(
            &Lease::default(),
            &Input {
                now: s.now(),
                op: Operation::Register {
                    ttl: s.config.ttl_seconds,
                },
            },
        )
        .unwrap()
        .state;
    entries.discovery_keys.push(key);
    entries.records.insert(
        key,
        Record {
            token: token_hash,
            endpoint: q.endpoint,
            lease,
        },
    );
    drop(entries);
    Ok(Json(RegistrationResponse {
        token: hex::encode(raw),
        expires_in_seconds: s.config.ttl_seconds,
    }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    20
}
#[derive(Serialize, Deserialize)]
pub struct Verification {
    pub verified: bool,
    #[serde(flatten)]
    pub peer: Peer,
}
async fn get_peers(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Query(q): Query<PeerQuery>,
) -> Result<Json<Vec<Peer>>> {
    if q.limit == 0 || q.limit > MAX_PEERS {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (caller, token) = credentials(&headers)?;
    let check_caller = || s.with_shard(caller, &token, s.shard(&caller), |_, _, _| Ok(()));
    check_caller()?;
    let start = s.discovery_cursor.fetch_add(1, Ordering::Relaxed) % SHARDS;
    let mut snapshots = Vec::with_capacity(q.limit);
    let mut examined = 0;
    for offset in 0..SHARDS {
        s.with_shard(
            caller,
            &token,
            (start + offset) % SHARDS,
            |shard, caller_lease, now| {
                let len = shard.discovery_keys.len();
                let visits = len.min(SCAN_BUDGET - examined);
                let begin = if len == 0 {
                    0
                } else {
                    shard.cursor.load(Ordering::Relaxed) % len
                };
                let mut consumed = 0;
                for index in 0..visits {
                    let key = shard.discovery_keys[(begin + index) % len];
                    consumed += 1;
                    if let Ok(p) = eligible_peer(
                        caller,
                        caller_lease,
                        key,
                        shard.records.get(&key),
                        None,
                        now,
                    ) {
                        snapshots.push(p);
                        if snapshots.len() == q.limit {
                            break;
                        }
                    }
                }
                // Concurrent samples may overlap, but each sample visits a key at most once.
                // Advance only by examined entries so stable peers do not starve.
                shard.cursor.fetch_add(consumed, Ordering::Relaxed);
                examined += consumed;
                Ok(())
            },
        )?;
        if snapshots.len() == q.limit || examined == SCAN_BUDGET {
            break;
        }
    }
    check_caller()?;
    Ok(Json(
        snapshots.into_iter().map(PeerSnapshot::encode).collect(),
    ))
}

async fn verify_peer(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<RegisterRequest>,
) -> Result<Json<Verification>> {
    let (caller, token) = credentials(&headers)?;
    let target = parse_key(&q.public_key)?;
    let snapshot = s.with_shard(
        caller,
        &token,
        s.shard(&target),
        |shard, caller_lease, now| {
            eligible_peer(
                caller,
                caller_lease,
                target,
                shard.records.get(&target),
                Some(q.endpoint),
                now,
            )
        },
    )?;
    Ok(Json(Verification {
        verified: true,
        peer: snapshot.encode(),
    }))
}

pub fn router(s: Arc<Coordinator>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/register", post(register))
        .route("/v1/peers", get(get_peers))
        .route("/v1/verify", post(verify_peer))
        .layer(DefaultBodyLimit::max(2048))
        .with_state(s)
}
