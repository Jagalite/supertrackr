//! Optional JSON overlay tracker adapter. Mutations share the coordinator owner task.
use crate::{
    Coordinator,
    core::{Credentials, Error, Registry},
};
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU16, sync::Arc};
use supertrackr_bittorrent::{Announce, InfoHash, Tracker};

#[derive(Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Announce {
        info_hash: String,
        port: NonZeroU16,
        complete: bool,
        #[serde(default = "crate::default_limit")]
        limit: usize,
    },
    Stopped {
        info_hash: String,
    },
    Scrape {
        info_hash: String,
    },
}
#[derive(Serialize)]
pub(crate) struct Peer {
    public_key: String,
    port: u16,
    complete: bool,
    remaining_seconds: u64,
}
#[derive(Serialize)]
pub(crate) struct Response {
    interval: u64,
    seeders: usize,
    leechers: usize,
    peers: Vec<Peer>,
}
fn hash(text: &str) -> Result<InfoHash, Error> {
    match text.len() {
        40 => {
            let mut h = [0; 20];
            hex::decode_to_slice(text, &mut h).map_err(|_| Error::BadRequest)?;
            Ok(InfoHash::V1(h))
        }
        64 => {
            let mut h = [0; 32];
            hex::decode_to_slice(text, &mut h).map_err(|_| Error::BadRequest)?;
            Ok(InfoHash::V2(h))
        }
        _ => Err(Error::BadRequest),
    }
}
pub(crate) fn execute(
    registry: &Registry,
    tracker: &mut Tracker,
    who: Credentials,
    request: Request,
    now: u64,
) -> crate::core::Result<Response> {
    // Requires a live authenticated overlay identity. No client-supplied identity or deadline.
    let interface = registry.interface(who, now)?;
    let (text, limit) = match &request {
        Request::Announce {
            info_hash, limit, ..
        } => (info_hash, *limit),
        Request::Stopped { info_hash } | Request::Scrape { info_hash } => (info_hash, 0),
    };
    let info_hash = hash(text)?;
    tracker.expire(now);
    match request {
        Request::Announce { port, complete, .. } => tracker
            .announce(
                Announce {
                    info_hash,
                    key: who.key,
                    port,
                    complete,
                    lease_expires_at: now.saturating_add(interface.remaining_seconds),
                },
                now,
            )
            .map_err(|e| match e {
                supertrackr_bittorrent::Error::Capacity => Error::Unavailable,
                supertrackr_bittorrent::Error::ExpiredLease => Error::Unauthorized,
                supertrackr_bittorrent::Error::InvalidConfig => Error::BadRequest,
            })?,
        Request::Stopped { .. } => tracker.stop(info_hash, who.key),
        Request::Scrape { .. } => {}
    }
    let peers = tracker
        .peers(info_hash, who.key, limit, now)
        .into_iter()
        .map(|p| Peer {
            public_key: hex::encode(p.key),
            port: p.port.get(),
            complete: p.complete,
            remaining_seconds: p.expires_at - now,
        })
        .collect();
    let stats = tracker.stats(info_hash, now);
    Ok(Response {
        interval: interface.remaining_seconds.clamp(1, 150),
        seeders: stats.seeders,
        leechers: stats.leechers,
        peers,
    })
}
async fn handle(
    State(state): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> crate::Result<Json<Response>> {
    Ok(Json(
        state
            .torrent(crate::credentials(&headers)?, request)
            .await
            .map_err(crate::status)?,
    ))
}
pub(crate) fn routes() -> Router<Arc<Coordinator>> {
    Router::new().route("/v1/bittorrent", post(handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn membership_cannot_outlive_overlay_lease() {
        let mut registry = Registry::new(crate::Config {
            ttl_seconds: 2,
            open_registration: true,
            ..Default::default()
        });
        let who = Credentials {
            key: [1; 32],
            token_hash: [2; 32],
        };
        registry
            .register_or_refresh(
                who.key,
                "127.0.0.1:51820".parse().unwrap(),
                None,
                who.token_hash,
                0,
            )
            .unwrap();
        registry
            .set_candidates(who, vec!["127.0.0.1:51820".parse().unwrap()], 0)
            .unwrap();
        let mut tracker = Tracker::new(Default::default()).unwrap();
        let request = || Request::Announce {
            info_hash: "01".repeat(20),
            port: NonZeroU16::new(6881).unwrap(),
            complete: true,
            limit: 10,
        };
        assert_eq!(
            execute(&registry, &mut tracker, who, request(), 1)
                .unwrap()
                .seeders,
            1
        );
        assert!(matches!(
            execute(&registry, &mut tracker, who, request(), 2),
            Err(Error::Unauthorized)
        ));
        assert_eq!(tracker.stats(InfoHash::V1([1; 20]), 2).seeders, 0);
    }
}
