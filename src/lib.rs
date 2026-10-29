pub mod async_userspace;
mod coordinator;
pub mod core;
pub mod enrollment;
pub mod model;
mod path_selection;
pub mod peer_manager;
pub mod stun;
pub mod userspace;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
pub use coordinator::Coordinator;
pub use core::Config;
use core::{Credentials, Error, Key, PeerInfo};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
type Result<T> = std::result::Result<T, StatusCode>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    #[serde(default)]
    pub proof: Option<enrollment::Proof>,
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
impl From<PeerInfo> for Peer {
    fn from(p: PeerInfo) -> Self {
        Self {
            public_key: hex::encode(p.key),
            endpoint: p.endpoint,
            remaining_seconds: p.remaining_seconds,
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct Verification {
    pub verified: bool,
    #[serde(flatten)]
    pub peer: Peer,
}
fn status(error: Error) -> StatusCode {
    match error {
        Error::Unauthorized => StatusCode::UNAUTHORIZED,
        Error::BadRequest => StatusCode::BAD_REQUEST,
        Error::Forbidden => StatusCode::FORBIDDEN,
        Error::NotFound => StatusCode::NOT_FOUND,
        Error::Conflict => StatusCode::CONFLICT,
        Error::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}
fn parse_key(s: &str) -> Result<Key> {
    let mut key = [0; 32];
    hex::decode_to_slice(s, &mut key).map_err(|_| StatusCode::BAD_REQUEST)?;
    if key == [0; 32] {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(key)
}
fn credentials(h: &HeaderMap) -> Result<Credentials> {
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
    Ok(Credentials {
        key,
        token_hash: Sha256::digest(raw).into(),
    })
}
async fn register(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<RegisterRequest>,
) -> Result<Json<RegistrationResponse>> {
    let key = parse_key(&q.public_key)?;
    let (credentials, token, token_hash) =
        if headers.contains_key("authorization") || headers.contains_key("x-peer-key") {
            let credentials = credentials(&headers)?;
            (
                Some(credentials),
                headers["authorization"].to_str().unwrap()[7..].to_owned(),
                [0; 32],
            )
        } else {
            let mut raw = [0; 32];
            OsRng.fill_bytes(&mut raw);
            (None, hex::encode(raw), Sha256::digest(raw).into())
        };
    let expires_in_seconds = if let Some(credentials) = credentials {
        s.register_or_refresh(key, q.endpoint, Some(credentials), token_hash)
            .await
            .map_err(status)?
    } else {
        let proof = q.proof.ok_or(StatusCode::UNAUTHORIZED)?;
        let id = parse_key(&proof.id)?;
        let response = parse_key(&proof.response)?;
        s.finish_enrollment(
            key,
            q.endpoint,
            id,
            Sha256::digest(response).into(),
            token_hash,
        )
        .await
        .map_err(status)?
    };
    Ok(Json(RegistrationResponse {
        token,
        expires_in_seconds,
    }))
}
async fn challenge(
    State(s): State<Arc<Coordinator>>,
    Json(q): Json<enrollment::ChallengeRequest>,
) -> Result<Json<enrollment::Challenge>> {
    let key = parse_key(&q.public_key)?;
    let nonce = parse_key(&q.client_nonce)?;
    let (challenge, pending) = enrollment::issue(key, q.endpoint, nonce, &s.registration_audience)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    s.prepare_enrollment(parse_key(&challenge.id)?, pending)
        .await
        .map_err(status)?;
    Ok(Json(challenge))
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
async fn get_peers(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Query(q): Query<PeerQuery>,
) -> Result<Json<Vec<Peer>>> {
    let peers = s
        .get_peers(credentials(&headers)?, q.limit)
        .await
        .map_err(status)?;
    Ok(Json(peers.into_iter().map(Peer::from).collect()))
}
async fn verify_peer(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<RegisterRequest>,
) -> Result<Json<Verification>> {
    let peer = s
        .verify_peer(
            credentials(&headers)?,
            parse_key(&q.public_key)?,
            q.endpoint,
        )
        .await
        .map_err(status)?;
    Ok(Json(Verification {
        verified: true,
        peer: peer.into(),
    }))
}
pub use core::traversal::{CandidatePeer, Events, InterfaceInfo, PunchHint, RelayPacket};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateRequest {
    candidates: Vec<SocketAddr>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectRequest {
    public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayRequest {
    public_key: String,
    packet: String,
}
async fn candidates(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<CandidateRequest>,
) -> Result<StatusCode> {
    s.set_candidates(credentials(&headers)?, q.candidates)
        .await
        .map_err(status)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn connect(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<ConnectRequest>,
) -> Result<Json<CandidatePeer>> {
    Ok(Json(
        s.connect(credentials(&headers)?, parse_key(&q.public_key)?)
            .await
            .map_err(status)?,
    ))
}
async fn relay(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<RelayRequest>,
) -> Result<StatusCode> {
    let who = credentials(&headers)?;
    if q.packet.len() > core::traversal::MAX_DATAGRAM * 2 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let packet = hex::decode(q.packet).map_err(|_| StatusCode::BAD_REQUEST)?;
    s.relay(who, parse_key(&q.public_key)?, packet)
        .await
        .map_err(status)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn events(State(s): State<Arc<Coordinator>>, headers: HeaderMap) -> Result<Json<Events>> {
    Ok(Json(
        s.events(credentials(&headers)?).await.map_err(status)?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveRequest {
    virtual_ip: std::net::Ipv4Addr,
}
async fn interface(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
) -> Result<Json<InterfaceInfo>> {
    Ok(Json(
        s.interface(credentials(&headers)?).await.map_err(status)?,
    ))
}
async fn resolve(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<ResolveRequest>,
) -> Result<Json<CandidatePeer>> {
    Ok(Json(
        s.resolve(credentials(&headers)?, q.virtual_ip)
            .await
            .map_err(status)?,
    ))
}
async fn lookup(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<ResolveRequest>,
) -> Result<Json<CandidatePeer>> {
    Ok(Json(
        s.lookup(credentials(&headers)?, q.virtual_ip)
            .await
            .map_err(status)?,
    ))
}
async fn binding(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<ConnectRequest>,
) -> Result<Json<CandidatePeer>> {
    Ok(Json(
        s.binding(credentials(&headers)?, parse_key(&q.public_key)?)
            .await
            .map_err(status)?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RendezvousRequest {
    public_key: String,
    #[serde(default)]
    include_binding: bool,
}
async fn rendezvous(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(q): Json<RendezvousRequest>,
) -> Result<StatusCode> {
    s.rendezvous(
        credentials(&headers)?,
        parse_key(&q.public_key)?,
        q.include_binding,
    )
    .await
    .map_err(status)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn punch_hints(
    State(s): State<Arc<Coordinator>>,
    headers: HeaderMap,
) -> Result<Json<Vec<PunchHint>>> {
    Ok(Json(
        s.punch_hints(credentials(&headers)?)
            .await
            .map_err(status)?,
    ))
}
pub fn router(s: Arc<Coordinator>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/register", post(register))
        .route("/v1/register/challenge", post(challenge))
        .route("/v1/peers", get(get_peers))
        .route("/v1/verify", post(verify_peer))
        .route("/v1/candidates", post(candidates))
        .route("/v1/connect", post(connect))
        .route("/v1/events", get(events))
        .route("/v1/relay", post(relay))
        .route("/v1/interface", get(interface))
        .route("/v1/resolve", post(resolve))
        .route("/v1/lookup", post(lookup))
        .route("/v1/binding", post(binding))
        .route("/v1/rendezvous", post(rendezvous).get(punch_hints))
        .layer(DefaultBodyLimit::max(8192))
        .with_state(s)
}
