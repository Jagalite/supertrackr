//! Response-shape calibration only; this fixture does not authenticate registrations.
use axum::{
    Json, Router,
    extract::{Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use clap::Parser;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use supertrackr::RegisterRequest;
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8444")]
    listen: SocketAddr,
}
#[derive(Deserialize)]
struct Limit {
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    20
}
type Keys = Arc<Mutex<Vec<String>>>;
async fn register(State(keys): State<Keys>, Json(q): Json<RegisterRequest>) -> Json<Value> {
    let mut keys = keys.lock().unwrap();
    // Only a small fixture for peer-list response shape, never a full registry.
    if keys.len() < 101 && !keys.contains(&q.public_key) {
        keys.push(q.public_key);
    }
    Json(json!({"token":"00".repeat(32),"expires_in_seconds":300}))
}
async fn peers(
    State(keys): State<Keys>,
    headers: HeaderMap,
    Query(q): Query<Limit>,
) -> Json<Value> {
    let caller = headers
        .get("x-peer-key")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let peers: Vec<_> = keys
        .lock()
        .unwrap()
        .iter()
        .filter(|k| k.as_str() != caller)
        .take(q.limit.min(100))
        .map(|key| json!({"public_key":key,"endpoint":"127.0.0.1:51820","remaining_seconds":300}))
        .collect();
    Json(json!(peers))
}
async fn verify(Json(q): Json<RegisterRequest>) -> Json<Value> {
    Json(
        json!({"verified":true,"public_key":q.public_key,"endpoint":q.endpoint,"remaining_seconds":300}),
    )
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = Args::parse();
    if !a.listen.ip().is_loopback() {
        return Err("calibration is loopback only".into());
    }
    let app = Router::new()
        .route("/v1/register", post(register))
        .route("/v1/peers", get(peers))
        .route("/v1/verify", post(verify))
        .with_state(Arc::new(Mutex::new(Vec::<String>::new())));
    axum::serve(tokio::net::TcpListener::bind(a.listen).await?, app).await?;
    Ok(())
}
