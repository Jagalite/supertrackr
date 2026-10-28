mod coordinator;
pub mod core;
pub mod model;
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
    let expires_in_seconds = s
        .register_or_refresh(key, q.endpoint, credentials, token_hash)
        .await
        .map_err(status)?;
    Ok(Json(RegistrationResponse {
        token,
        expires_in_seconds,
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
pub fn router(s: Arc<Coordinator>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/register", post(register))
        .route("/v1/peers", get(get_peers))
        .route("/v1/verify", post(verify_peer))
        .layer(DefaultBodyLimit::max(2048))
        .with_state(s)
}
