//! Optional standard HTTP tracker listener. Ordinary Internet state is separate
//! from authenticated overlay state. Never trust proxy or client IP headers.
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, RawQuery, State},
    http::{Response, header},
    routing::get,
};
use std::{net::SocketAddr, sync::Arc, time::Instant};
use supertrackr_bittorrent::{http, standard};
use tokio::sync::Mutex;

pub struct TrackerState {
    tracker: Mutex<standard::Tracker>,
    start: Instant,
}
impl TrackerState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tracker: Mutex::new(
                standard::Tracker::new(10_000, 100_000, 1_000, 1_800)
                    .expect("valid tracker bounds"),
            ),
            start: Instant::now(),
        })
    }
    fn now(&self) -> u64 {
        self.start.elapsed().as_secs()
    }
}
fn result(bytes: Vec<u8>) -> Response<Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
        .expect("valid response")
}
async fn announce(
    State(state): State<Arc<TrackerState>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    RawQuery(query): RawQuery,
) -> Response<Body> {
    let request = match http::announce(query.as_deref().unwrap_or("")) {
        Ok(request) => request,
        Err(_) => return result(http::failure("invalid announce")),
    };
    let mut tracker = state.tracker.lock().await;
    let now = state.now();
    let endpoint = SocketAddr::new(source.ip().to_canonical(), request.port);
    if tracker
        .announce(
            request.info_hash,
            request.peer_id,
            endpoint,
            request.left,
            request.event,
            now,
        )
        .is_err()
    {
        return result(http::failure("tracker capacity or invalid address"));
    }
    let peers = tracker.peers(request.info_hash, request.peer_id, request.numwant, now);
    result(http::announce_response(
        &peers,
        tracker.scrape(request.info_hash, now),
        900,
        request.compact,
        request.no_peer_id,
    ))
}
async fn scrape(
    State(state): State<Arc<TrackerState>>,
    RawQuery(query): RawQuery,
) -> Response<Body> {
    let hashes = match http::scrape(query.as_deref().unwrap_or("")) {
        Ok(hashes) => hashes,
        Err(_) => return result(http::failure("invalid scrape")),
    };
    let tracker = state.tracker.lock().await;
    let now = state.now();
    let entries: Vec<_> = hashes
        .into_iter()
        .map(|hash| (hash, tracker.scrape(hash, now)))
        .collect();
    result(http::scrape_response(&entries))
}
pub fn router(state: Arc<TrackerState>) -> Router {
    Router::new()
        .route("/announce", get(announce))
        .route("/scrape", get(scrape))
        .with_state(state)
}

fn udp_cookie(secret: &[u8; 32], source: SocketAddr, issued_at: u64) -> [u8; 8] {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret).expect("valid HMAC key");
    mac.update(b"supertrackr/udp-tracker/v1\0");
    match source {
        SocketAddr::V4(addr) => {
            mac.update(&[4]);
            mac.update(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            mac.update(&[6]);
            mac.update(&addr.ip().octets());
            mac.update(&addr.scope_id().to_be_bytes());
        }
    }
    mac.update(&source.port().to_be_bytes());
    mac.update(&issued_at.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut token = [0u8; 8];
    token[0] = issued_at as u8;
    token[1..].copy_from_slice(&digest[..7]);
    token
}
fn valid_udp_cookie(secret: &[u8; 32], source: SocketAddr, provided: &[u8; 8], now: u64) -> bool {
    use subtle::ConstantTimeEq;
    let age = (now as u8).wrapping_sub(provided[0]) as u64;
    age <= 120 && age <= now && bool::from(provided.ct_eq(&udp_cookie(secret, source, now - age)))
}

/// BEP 15 UDP tracker. Connection IDs are authenticated and bound to the
/// observed source socket, with a bounded 120-second validity window.
pub async fn serve_udp(
    socket: tokio::net::UdpSocket,
    state: Arc<TrackerState>,
) -> std::io::Result<()> {
    use tokio::net::UdpSocket;
    async fn respond(socket: &UdpSocket, source: SocketAddr, data: &[u8]) {
        // A route or per-datagram send failure must not stop the listener for
        // every other client. Receive failures still terminate the task.
        let _ = socket.send_to(data, source).await;
    }
    fn error(tx: &[u8], reason: &[u8]) -> Vec<u8> {
        let mut out = 3u32.to_be_bytes().to_vec();
        out.extend_from_slice(tx);
        out.extend_from_slice(reason);
        out
    }
    let secret: [u8; 32] = rand::random();
    let mut buf = [0u8; 2048];
    loop {
        let (len, source) = socket.recv_from(&mut buf).await?;
        if len < 16 {
            continue;
        }
        let packet = &buf[..len];
        let action = u32::from_be_bytes(packet[8..12].try_into().unwrap());
        let tx = &packet[12..16];
        let now = state.now();
        if action == 0 {
            if len != 16 || packet[..8] != 0x41727101980u64.to_be_bytes() {
                continue;
            }
            let mut out = 0u32.to_be_bytes().to_vec();
            out.extend_from_slice(tx);
            out.extend_from_slice(&udp_cookie(&secret, source, now));
            respond(&socket, source, &out).await;
            continue;
        }
        let provided: &[u8; 8] = packet[..8].try_into().unwrap();
        if !valid_udp_cookie(&secret, source, provided, now) {
            continue;
        }
        match action {
            1 if len >= 98 => {
                let hash: [u8; 20] = packet[16..36].try_into().unwrap();
                let id = standard::PeerId(packet[36..56].try_into().unwrap());
                let left = u64::from_be_bytes(packet[64..72].try_into().unwrap());
                let event = match u32::from_be_bytes(packet[80..84].try_into().unwrap()) {
                    0 => standard::Event::Update,
                    1 => standard::Event::Completed,
                    2 => standard::Event::Started,
                    3 => standard::Event::Stopped,
                    _ => {
                        respond(&socket, source, &error(tx, b"invalid event")).await;
                        continue;
                    }
                };
                let numwant = i32::from_be_bytes(packet[92..96].try_into().unwrap());
                let limit = if numwant < 0 {
                    50
                } else {
                    (numwant as usize).min(50)
                };
                let port = u16::from_be_bytes(packet[96..98].try_into().unwrap());
                let mut tracker = state.tracker.lock().await;
                if tracker
                    .announce(
                        hash,
                        id,
                        SocketAddr::new(source.ip().to_canonical(), port),
                        left,
                        event,
                        now,
                    )
                    .is_err()
                {
                    drop(tracker);
                    respond(
                        &socket,
                        source,
                        &error(tx, b"tracker capacity or invalid address"),
                    )
                    .await;
                    continue;
                }
                let counts = tracker.scrape(hash, now);
                let peers = tracker.peers_for_family(
                    hash,
                    id,
                    source.ip().to_canonical().is_ipv4(),
                    limit,
                    now,
                );
                drop(tracker);
                let mut out = 1u32.to_be_bytes().to_vec();
                out.extend_from_slice(tx);
                out.extend_from_slice(&900u32.to_be_bytes());
                out.extend_from_slice(&(counts.incomplete as u32).to_be_bytes());
                out.extend_from_slice(&(counts.complete as u32).to_be_bytes());
                for peer in peers {
                    match peer.address.ip() {
                        std::net::IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
                        std::net::IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
                    }
                    out.extend_from_slice(&peer.address.port().to_be_bytes());
                }
                respond(&socket, source, &out).await;
            }
            2 if len > 16 && (len - 16) % 20 == 0 && (len - 16) / 20 <= 32 => {
                let tracker = state.tracker.lock().await;
                let mut out = 2u32.to_be_bytes().to_vec();
                out.extend_from_slice(tx);
                for hash in packet[16..].as_chunks::<20>().0 {
                    let counts = tracker.scrape(*hash, now);
                    out.extend_from_slice(&(counts.complete as u32).to_be_bytes());
                    out.extend_from_slice(
                        &(counts.downloaded.min(u32::MAX as u64) as u32).to_be_bytes(),
                    );
                    out.extend_from_slice(&(counts.incomplete as u32).to_be_bytes());
                }
                drop(tracker);
                respond(&socket, source, &out).await;
            }
            _ => {
                respond(&socket, source, &error(tx, b"invalid request")).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_cookie_binds_source_and_expires_across_clock_wraps() {
        let secret = [7; 32];
        let source: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let token = udp_cookie(&secret, source, 100);
        assert!(valid_udp_cookie(&secret, source, &token, 100));
        assert!(valid_udp_cookie(&secret, source, &token, 220));
        assert!(!valid_udp_cookie(&secret, source, &token, 221));
        assert!(!valid_udp_cookie(&secret, source, &token, 356));
        assert!(!valid_udp_cookie(&secret, source, &token, 99));
        assert!(!valid_udp_cookie(
            &secret,
            "127.0.0.1:1235".parse().unwrap(),
            &token,
            100
        ));
        let ip = "fe80::1".parse().unwrap();
        let v6a = SocketAddr::V6(std::net::SocketAddrV6::new(ip, 1234, 0, 1));
        let v6b = SocketAddr::V6(std::net::SocketAddrV6::new(ip, 1234, 0, 2));
        assert!(!valid_udp_cookie(
            &secret,
            v6b,
            &udp_cookie(&secret, v6a, 100),
            100
        ));
    }
}
