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
        #[serde(default)]
        application_id: Option<String>,
        port: NonZeroU16,
        complete: bool,
        #[serde(default = "crate::default_limit")]
        limit: usize,
    },
    Stopped {
        info_hash: String,
        #[serde(default)]
        application_id: Option<String>,
    },
    Scrape {
        info_hash: String,
    },
}
#[derive(Serialize)]
pub(crate) struct Peer {
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_id: Option<String>,
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
fn application(text: &str) -> Result<[u8; 20], Error> {
    let mut id = [0; 20];
    hex::decode_to_slice(text, &mut id).map_err(|_| Error::BadRequest)?;
    Ok(id)
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
        Request::Stopped { info_hash, .. } | Request::Scrape { info_hash } => (info_hash, 0),
    };
    let info_hash = hash(text)?;
    tracker.expire(now);
    match request {
        Request::Announce {
            port,
            complete,
            application_id,
            ..
        } => tracker
            .announce_application(
                Announce {
                    info_hash,
                    key: who.key,
                    port,
                    complete,
                    lease_expires_at: now.saturating_add(interface.remaining_seconds),
                },
                application_id.map(|id| application(&id)).transpose()?,
                now,
            )
            .map_err(|e| match e {
                supertrackr_bittorrent::Error::Capacity => Error::Unavailable,
                supertrackr_bittorrent::Error::ExpiredLease => Error::Unauthorized,
                supertrackr_bittorrent::Error::InvalidConfig => Error::BadRequest,
            })?,
        Request::Stopped { application_id, .. } => tracker.stop_application(
            info_hash,
            who.key,
            application_id.map(|id| application(&id)).transpose()?,
        ),
        Request::Scrape { .. } => {}
    }
    let requester = registry.identity(who, now)?;
    let mut identities = std::collections::HashMap::<_, bool>::new();
    let mut returned = std::collections::HashSet::new();
    let mut peers = Vec::new();
    for p in tracker.active_peers(info_hash, now) {
        let Some(identity) = registry.live_identity_for_key(p.key, now) else {
            continue;
        };
        let member = (identity, p.application);
        identities
            .entry(member)
            .and_modify(|complete| *complete |= p.complete)
            .or_insert(p.complete);
        let endpoint_remaining = registry.endpoint_remaining_for_key(p.key, now);
        if let Some(endpoint_remaining) = endpoint_remaining
            && identity != requester
            && peers.len() < limit.min(50)
            && returned.insert(member)
        {
            peers.push(Peer {
                public_key: hex::encode(p.key),
                application_id: p.application.map(hex::encode),
                port: p.port.get(),
                complete: p.complete,
                remaining_seconds: (p.expires_at - now).min(endpoint_remaining),
            });
        }
    }
    let seeders = identities.values().filter(|complete| **complete).count();
    Ok(Response {
        interval: interface.remaining_seconds.clamp(1, 150),
        seeders,
        leechers: identities.len() - seeders,
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
    fn expired_endpoint_is_not_advertised_and_lifetime_is_capped() {
        let mut registry = Registry::new(crate::Config {
            ttl_seconds: 20,
            open_registration: true,
            ..Default::default()
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
        for who in [a, b] {
            registry
                .register_or_refresh(who.key, endpoint, None, who.token_hash, 0)
                .unwrap();
            registry.set_candidates(who, vec![endpoint], 0).unwrap();
        }
        let mut tracker = Tracker::new(Default::default()).unwrap();
        let request = || Request::Announce {
            info_hash: "01".repeat(20),
            application_id: None,
            port: NonZeroU16::new(6881).unwrap(),
            complete: false,
            limit: 10,
        };
        execute(&registry, &mut tracker, b, request(), 0).unwrap();
        registry.publish_endpoint(b, endpoint, 2, 1).unwrap();
        let response = execute(&registry, &mut tracker, a, request(), 2).unwrap();
        assert_eq!(response.peers.len(), 1);
        assert_eq!(response.peers[0].remaining_seconds, 1);
        let response = execute(&registry, &mut tracker, a, request(), 3).unwrap();
        assert!(response.peers.is_empty());
        assert_eq!(response.leechers, 2);
        registry.publish_endpoint(b, endpoint, 5, 3).unwrap();
        assert!(
            execute(&registry, &mut tracker, a, request(), 3)
                .unwrap()
                .peers
                .is_empty()
        );
        registry.set_candidates(b, vec![endpoint], 3).unwrap();
        assert_eq!(
            execute(&registry, &mut tracker, a, request(), 3)
                .unwrap()
                .peers
                .len(),
            1
        );
    }
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
            application_id: None,
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
