use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use supertrackr::{Config, Coordinator, router};
use tower::ServiceExt;
fn secrets() -> &'static std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>> {
    static KEYS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
    > = std::sync::OnceLock::new();
    KEYS.get_or_init(Default::default)
}
fn key(n: u64) -> String {
    use sha2::Digest;
    let bytes: [u8; 32] = sha2::Sha256::digest(n.to_be_bytes()).into();
    let secret = boringtun::x25519::StaticSecret::from(bytes);
    let key = hex::encode(boringtun::x25519::PublicKey::from(&secret).as_bytes());
    secrets().lock().unwrap().insert(key.clone(), bytes);
    key
}
// Existing lifecycle tests use full proof-bearing enrollment through this helper.
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    who: Option<(&str, &str)>,
    mut body: Value,
) -> (StatusCode, Value) {
    if method == "POST" && path == "/v1/register" && who.is_none() && body.get("proof").is_none() {
        let bytes = body["public_key"]
            .as_str()
            .and_then(|key| secrets().lock().unwrap().get(key).copied());
        if let Some(bytes) = bytes {
            let nonce = rand::random::<[u8; 32]>();
            let(code,value)=call_raw(app,"POST","/v1/register/challenge",None,json!({"public_key":body["public_key"],"endpoint":body["endpoint"],"client_nonce":hex::encode(nonce)})).await;
            if code != StatusCode::OK {
                return (code, value);
            }
            let c = serde_json::from_value(value).unwrap();
            let endpoint = body["endpoint"].as_str().unwrap().parse().unwrap();
            body["proof"] = serde_json::to_value(
                supertrackr::enrollment::solve(
                    &c,
                    &boringtun::x25519::StaticSecret::from(bytes),
                    endpoint,
                    nonce,
                    "http://localhost/",
                )
                .unwrap(),
            )
            .unwrap();
        }
    }
    call_raw(app, method, path, who, body).await
}
async fn call_raw(
    app: &Router,
    method: &str,
    path: &str,
    who: Option<(&str, &str)>,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some((key, token)) = who {
        req = req
            .header("x-peer-key", key)
            .header("authorization", format!("Bearer {token}"));
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let code = res.status();
    let data = res.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&data).unwrap_or(Value::Null))
}
async fn reg(app: &Router, n: u64) -> (String, String) {
    let k = key(n);
    let (code, b) = call(
        app,
        "POST",
        "/v1/register",
        None,
        json!({"public_key": k, "endpoint": "127.0.0.1:51820"}),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    (k, b["token"].as_str().unwrap().to_owned())
}
#[tokio::test]
async fn discovery_verification_and_authenticated_refresh() {
    let state = Coordinator::new(Config {
        open_registration: true,
        ..Config::default()
    });
    let app = router(state.clone());
    let (a, at) = reg(&app, 1).await;
    let (b, bt) = reg(&app, 2).await;
    let claim = json!({"public_key": b, "endpoint":"127.0.0.1:51820"});
    assert_eq!(
        call(&app, "GET", "/v1/peers", None, Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "POST", "/v1/verify", Some((&a, &bt)), claim.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (code, peers) = call(
        &app,
        "GET",
        "/v1/peers?limit=1",
        Some((&a, &at)),
        Value::Null,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(peers.as_array().unwrap().len(), 1);
    assert_eq!(peers[0]["public_key"], b);
    assert_eq!(peers[0]["endpoint"], "127.0.0.1:51820");
    let (code, result) = call(&app, "POST", "/v1/verify", Some((&a, &at)), claim).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(result["verified"], true);
    let updated = json!({"public_key":b,"endpoint":"127.0.0.1:9999"});
    assert_eq!(
        call(&app, "POST", "/v1/register", None, updated.clone())
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/register",
            Some((&a, &at)),
            updated.clone()
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/register",
            Some((&b, &at)),
            updated.clone()
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (code, result) = call(
        &app,
        "POST",
        "/v1/register",
        Some((&b, &bt)),
        updated.clone(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(result["token"], bt);
    assert_eq!(state.len().await.unwrap(), 2);
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/verify",
            Some((&a, &at)),
            json!({"public_key":b,"endpoint":"127.0.0.1:51820"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(&app, "POST", "/v1/verify", Some((&a, &at)), updated)
            .await
            .0,
        StatusCode::OK
    );
    let (_, peers) = call(&app, "GET", "/v1/peers", Some((&a, &at)), Value::Null).await;
    assert_eq!(peers[0]["endpoint"], "127.0.0.1:9999");
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/verify",
            Some((&a, &at)),
            json!({"public_key":key(99),"endpoint":"127.0.0.1:51820"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/verify",
            Some((&a, &at)),
            json!({"public_key":a,"endpoint":"127.0.0.1:51820"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for (method, path) in [
        ("GET", "/v1/pending"),
        ("POST", "/v1/connect/test"),
        ("GET", "/v1/peers/test"),
        ("DELETE", "/v1/self"),
    ] {
        assert_eq!(
            call(&app, method, path, Some((&a, &at)), Value::Null)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
}
#[tokio::test]
async fn discovery_bounds_and_no_duplicates() {
    let state = Coordinator::new(Config {
        capacity: 120,
        open_registration: true,
        ..Config::default()
    });
    let app = router(state);
    let (a, at) = reg(&app, 1).await;
    for n in 2..=120 {
        reg(&app, n).await;
    }
    for limit in [1, 20, 100] {
        let (code, peers) = call(
            &app,
            "GET",
            &format!("/v1/peers?limit={limit}"),
            Some((&a, &at)),
            Value::Null,
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        let peers = peers.as_array().unwrap();
        assert_eq!(peers.len(), limit);
        let keys: std::collections::HashSet<_> = peers
            .iter()
            .map(|p| p["public_key"].as_str().unwrap())
            .collect();
        assert_eq!(keys.len(), limit);
        assert!(!keys.contains(a.as_str()));
    }
    // Repeated discovery must eventually expose every other peer, not just a fixed prefix.
    let mut discovered = std::collections::HashSet::new();
    for _ in 0..64 * 120 {
        let (code, peers) = call(
            &app,
            "GET",
            "/v1/peers?limit=1",
            Some((&a, &at)),
            Value::Null,
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        for peer in peers.as_array().unwrap() {
            discovered.insert(peer["public_key"].as_str().unwrap().to_owned());
        }
        if discovered.len() == 119 {
            break;
        }
    }
    assert_eq!(discovered.len(), 119);
    for limit in [0, 101] {
        assert_eq!(
            call(
                &app,
                "GET",
                &format!("/v1/peers?limit={limit}"),
                Some((&a, &at)),
                Value::Null
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/register",
            None,
            json!({"public_key":key(999),"endpoint":"127.0.0.1:51820"})
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // Refresh does not consume a slot, even when registration capacity is full.
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/register",
            Some((&a, &at)),
            json!({"public_key":a,"endpoint":"127.0.0.1:51821"})
        )
        .await
        .0,
        StatusCode::OK
    );
}
#[tokio::test]
async fn expiry_refresh_cannot_resurrect_and_old_tokens_fail() {
    let closed = router(Coordinator::new(Config::default()));
    assert_eq!(
        call(
            &closed,
            "POST",
            "/v1/register",
            None,
            json!({"public_key":key(1),"endpoint":"127.0.0.1:51820"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let state = Coordinator::new(Config {
        ttl_seconds: 1,
        open_registration: true,
        ..Config::default()
    });
    let app = router(state.clone());
    let (a, at) = reg(&app, 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (b, bt) = reg(&app, 2).await;
    assert_eq!(
        call(&app, "GET", "/v1/peers", Some((&a, &at)), Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (_, peers) = call(&app, "GET", "/v1/peers", Some((&b, &bt)), Value::Null).await;
    assert_eq!(peers, json!([]));
    let claim = json!({"public_key":a,"endpoint":"127.0.0.1:51820"});
    assert_eq!(
        call(&app, "POST", "/v1/verify", Some((&b, &bt)), claim.clone())
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "POST", "/v1/register", Some((&a, &at)), claim.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    state.cleanup().await.unwrap();
    let (_, new_token) = reg(&app, 1).await;
    assert_ne!(at, new_token);
    assert_eq!(
        call(&app, "POST", "/v1/register", Some((&a, &at)), claim)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/peers",
            Some((&a, &new_token)),
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_registration_obeys_capacity() {
    let state = Coordinator::new(Config {
        capacity: 32,
        open_registration: true,
        ..Config::default()
    });
    let app = router(state.clone());
    let mut jobs = Vec::new();
    for i in 1..=128 {
        let app = app.clone();
        jobs.push(tokio::spawn(async move {
            call(
                &app,
                "POST",
                "/v1/register",
                None,
                json!({"public_key":key(i),"endpoint":"127.0.0.1:51820"}),
            )
            .await
            .0
        }));
    }
    let mut admitted = 0;
    for j in jobs {
        let status = j.await.unwrap();
        if status == StatusCode::OK {
            admitted += 1;
        } else {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        }
    }
    assert_eq!(admitted, 32);
    assert_eq!(state.len().await.unwrap(), 32);
}

#[tokio::test]
async fn unauthenticated_verification_does_not_disclose_target_membership() {
    let app = router(Coordinator::new(Config {
        open_registration: true,
        ..Config::default()
    }));
    let (a, at) = reg(&app, 1).await;
    let (b, bt) = reg(&app, 2).await;
    // Existing, missing, and self targets must not change an invalid credential's result.
    for target in [&a, &b, &key(999)] {
        let claim = json!({"public_key":target,"endpoint":"127.0.0.1:51820"});
        assert_eq!(
            call(&app, "POST", "/v1/verify", Some((&a, &bt)), claim.clone())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, "POST", "/v1/verify", Some((&key(888), &at)), claim)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/verify",
            Some((&a, &at)),
            json!({"public_key":key(999),"endpoint":"127.0.0.1:51820"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_discovery_verification_refresh_and_cleanup() {
    let state = Coordinator::new(Config {
        open_registration: true,
        ..Config::default()
    });
    let app = router(state.clone());
    let mut identities = Vec::new();
    for i in 1..=64 {
        identities.push(reg(&app, i).await);
    }
    let mut tasks = Vec::new();
    for worker in 0..12 {
        let app = app.clone();
        let state = state.clone();
        let ids = identities.clone();
        tasks.push(tokio::spawn(async move {
            for i in 0..40 {
                let (caller, token) = &ids[(worker + i) % ids.len()];
                let (target, _) = &ids[(worker + i + 1) % ids.len()];
                match worker % 3 {
                    0 => {
                        let (status, peers) = call(
                            &app,
                            "GET",
                            "/v1/peers?limit=20",
                            Some((caller, token)),
                            Value::Null,
                        )
                        .await;
                        assert_eq!(status, StatusCode::OK);
                        let peers = peers.as_array().unwrap();
                        assert_eq!(peers.len(), 20);
                        let mut seen = std::collections::HashSet::new();
                        for p in peers {
                            let k = p["public_key"].as_str().unwrap();
                            assert_ne!(k, caller);
                            assert!(seen.insert(k));
                        }
                    }
                    1 => {
                        assert_eq!(
                            call(
                                &app,
                                "POST",
                                "/v1/register",
                                Some((caller, token)),
                                json!({"public_key":caller,"endpoint":"127.0.0.1:51820"})
                            )
                            .await
                            .0,
                            StatusCode::OK
                        );
                        state.cleanup().await.unwrap();
                    }
                    _ => {
                        assert_eq!(
                            call(
                                &app,
                                "POST",
                                "/v1/verify",
                                Some((caller, token)),
                                json!({"public_key":target,"endpoint":"127.0.0.1:51820"})
                            )
                            .await
                            .0,
                            StatusCode::OK
                        );
                    }
                }
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(state.len().await.unwrap(), 64);
}

#[tokio::test]
async fn traversal_http_candidates_rendezvous_and_ciphertext_relay() {
    let app = router(Coordinator::new(Config {
        open_registration: true,
        ..Config::default()
    }));
    let (a, at) = reg(&app, 1).await;
    let (b, bt) = reg(&app, 2).await;
    let candidates = json!({"candidates":["127.0.0.1:1234","127.0.0.1:4321"]});
    assert_eq!(
        call(&app, "POST", "/v1/candidates", None, candidates.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    for who in [(a.as_str(), at.as_str()), (b.as_str(), bt.as_str())] {
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/candidates",
                Some(who),
                candidates.clone()
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
    }
    let (code, peer) = call(
        &app,
        "POST",
        "/v1/connect",
        Some((&a, &at)),
        json!({"public_key":b}),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(peer["candidates"], candidates["candidates"]);
    let packet = json!({"public_key":b,"packet":"01020304"});
    assert_eq!(
        call(&app, "POST", "/v1/relay", Some((&a, &at)), packet.clone())
            .await
            .0,
        StatusCode::CONFLICT
    );
    let (_, events) = call(&app, "GET", "/v1/events", Some((&b, &bt)), Value::Null).await;
    assert_eq!(events["requests"][0]["public_key"], a);
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/connect",
            Some((&b, &bt)),
            json!({"public_key":a})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "POST", "/v1/relay", Some((&a, &bt)), packet.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "POST", "/v1/relay", Some((&a, &at)), packet)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let (_, events) = call(&app, "GET", "/v1/events", Some((&b, &bt)), Value::Null).await;
    assert_eq!(events["packets"][0]["public_key"], a);
    assert_eq!(events["packets"][0]["packet"], "01020304");
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/relay",
            Some((&a, &at)),
            json!({"public_key":b,"packet":"x"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn assigned_addresses_resolve_to_reciprocal_multi_peer_introductions() {
    let app = router(Coordinator::new(Config {
        open_registration: true,
        ..Config::default()
    }));
    let mut peers = Vec::new();
    for n in 1..=3 {
        let (k, t) = reg(&app, n).await;
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/candidates",
                Some((&k, &t)),
                json!({"candidates":["127.0.0.1:51820"]})
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        let (code, info) = call(&app, "GET", "/v1/interface", Some((&k, &t)), Value::Null).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(info["virtual_ip"], format!("10.203.0.{n}"));
        peers.push((k, t, info["virtual_ip"].clone()));
    }
    let (a, at, _) = &peers[0];
    for (b, bt, ip) in &peers[1..] {
        assert_eq!(
            call(&app, "POST", "/v1/resolve", None, json!({"virtual_ip":ip}))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let (code, p) = call(
            &app,
            "POST",
            "/v1/resolve",
            Some((a, at)),
            json!({"virtual_ip":ip}),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(p["public_key"], *b);
        let (_, events) = call(&app, "GET", "/v1/events", Some((b, bt)), Value::Null).await;
        assert_eq!(events["requests"][0]["public_key"], *a);
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/connect",
                Some((b, bt)),
                json!({"public_key":a})
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    for (b, bt, _) in &peers[1..] {
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/relay",
                Some((a, at)),
                json!({"public_key":b,"packet":"01"})
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        let (_, events) = call(&app, "GET", "/v1/events", Some((b, bt)), Value::Null).await;
        assert_eq!(events["packets"].as_array().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn read_only_binding_and_lookup_do_not_introduce_or_grant_relay() {
    let app = router(Coordinator::new(Config {
        open_registration: true,
        ..Config::default()
    }));
    let (a, at) = reg(&app, 1).await;
    let (b, bt) = reg(&app, 2).await;
    for (k, t) in [(&a, &at), (&b, &bt)] {
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/candidates",
                Some((k, t)),
                json!({"candidates":["127.0.0.1:1234"]})
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
    }
    let (_, info) = call(&app, "GET", "/v1/interface", Some((&b, &bt)), Value::Null).await;
    for (path, query) in [
        ("/v1/lookup", json!({"virtual_ip":info["virtual_ip"]})),
        ("/v1/binding", json!({"public_key":b})),
    ] {
        assert_eq!(
            call(&app, "POST", path, None, query.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (code, p) = call(&app, "POST", path, Some((&a, &at)), query).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(p["public_key"], b);
    }
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/binding",
            Some((&b, &bt)),
            json!({"public_key":a})
        )
        .await
        .0,
        StatusCode::OK
    );
    for (k, t) in [(&a, &at), (&b, &bt)] {
        let (_, events) = call(&app, "GET", "/v1/events", Some((k, t)), Value::Null).await;
        assert!(events["requests"].as_array().unwrap().is_empty());
    }
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/relay",
            Some((&a, &at)),
            json!({"public_key":b,"packet":"01"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn rendezvous_sends_only_endpoints_and_never_grants_relay() {
    let app = router(Coordinator::new(Config {
        open_registration: true,
        ..Config::default()
    }));
    let (a, at) = reg(&app, 1).await;
    let (b, bt) = reg(&app, 2).await;
    for (k, t) in [(&a, &at), (&b, &bt)] {
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/candidates",
                Some((k, t)),
                json!({"candidates":["127.0.0.1:1234"]})
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
    }
    let request = json!({"public_key":b});
    assert_eq!(
        call(&app, "POST", "/v1/rendezvous", None, request.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/v1/rendezvous", None, Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    for _ in 0..2 {
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/rendezvous",
                Some((&a, &at)),
                request.clone()
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
    }
    let (code, hints) = call(&app, "GET", "/v1/rendezvous", Some((&b, &bt)), Value::Null).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(hints.as_array().unwrap().len(), 1);
    assert_eq!(hints[0].as_object().unwrap().len(), 2);
    assert_eq!(hints[0]["candidates"], json!(["127.0.0.1:1234"]));
    assert!(hints[0]["remaining_seconds"].as_u64().unwrap() <= 5);
    let (_, hints) = call(&app, "GET", "/v1/rendezvous", Some((&b, &bt)), Value::Null).await;
    assert_eq!(hints, json!([]));
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/relay",
            Some((&a, &at)),
            json!({"public_key":b,"packet":"01"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (_, events) = call(&app, "GET", "/v1/events", Some((&b, &bt)), Value::Null).await;
    assert_eq!(events["requests"], json!([]));
}

#[tokio::test]
async fn optional_rendezvous_binding_is_server_owned_and_does_not_grant_relay() {
    let app = router(Coordinator::new(Config {
        open_registration: true,
        ..Config::default()
    }));
    let (a, at) = reg(&app, 1).await;
    let (b, bt) = reg(&app, 2).await;
    for (k, t) in [(&a, &at), (&b, &bt)] {
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/candidates",
                Some((k, t)),
                json!({"candidates":["127.0.0.1:1234"]})
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
    }
    // The caller may request inclusion, but cannot provide the binding itself.
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/rendezvous",
            Some((&a, &at)),
            json!({"public_key":b,"include_binding":true,"binding":{"public_key":b}})
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/rendezvous",
            Some((&a, &at)),
            json!({"public_key":b,"include_binding":true})
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    call(
        &app,
        "POST",
        "/v1/candidates",
        Some((&a, &at)),
        json!({"candidates":["127.0.0.1:2345"]}),
    )
    .await;
    let (_, own) = call(&app, "GET", "/v1/interface", Some((&a, &at)), Value::Null).await;
    let (_, hints) = call(&app, "GET", "/v1/rendezvous", Some((&b, &bt)), Value::Null).await;
    assert_eq!(hints.as_array().unwrap().len(), 1);
    let binding = &hints[0]["binding"];
    assert_eq!(binding["public_key"], a);
    assert_eq!(binding["virtual_ip"], own["virtual_ip"]);
    assert_eq!(binding["candidates"], json!(["127.0.0.1:2345"]));
    assert_eq!(binding["candidates"], hints[0]["candidates"]);
    assert!(binding["remaining_seconds"].as_u64().unwrap() > 0);
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/relay",
            Some((&a, &at)),
            json!({"public_key":b,"packet":"01"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (_, events) = call(&app, "GET", "/v1/events", Some((&b, &bt)), Value::Null).await;
    assert_eq!(events["requests"], json!([]));
}

#[tokio::test]
async fn anonymous_enrollment_requires_scoped_proof_and_never_overwrites() {
    use boringtun::x25519::StaticSecret;
    use supertrackr::enrollment::{Challenge, solve};
    let state = Coordinator::new(Config {
        open_registration: true,
        ..Config::default()
    });
    let app = router(state.clone());
    let k = key(9001);
    let secret = StaticSecret::from(*secrets().lock().unwrap().get(&k).unwrap());
    let endpoint = "127.0.0.1:51820".parse().unwrap();
    let request = json!({"public_key":k,"endpoint":endpoint});
    assert_eq!(
        call_raw(&app, "POST", "/v1/register", None, request.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let nonce = [5; 32];
    let mut challenges = Vec::new();
    for _ in 0..2 {
        let (status, body) = call_raw(
            &app,
            "POST",
            "/v1/register/challenge",
            None,
            json!({"public_key":k,"endpoint":endpoint,"client_nonce":hex::encode(nonce)}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        challenges.push(serde_json::from_value::<Challenge>(body).unwrap());
    }
    assert_eq!(state.len().await.unwrap(), 0); // A challenge cannot squat on a key.
    let c = &challenges[0];
    assert!(
        solve(
            c,
            &StaticSecret::from([99; 32]),
            endpoint,
            nonce,
            "http://localhost/"
        )
        .is_err()
    );
    let mut q = request.clone();
    q["proof"] =
        serde_json::to_value(solve(c, &secret, endpoint, nonce, "https://other.example/").unwrap())
            .unwrap();
    assert_eq!(
        call_raw(&app, "POST", "/v1/register", None, q.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    q["proof"] =
        serde_json::to_value(solve(c, &secret, endpoint, nonce, "http://localhost/").unwrap())
            .unwrap();
    let mut wrong = q.clone();
    wrong["endpoint"] = json!("127.0.0.1:51821");
    assert_eq!(
        call_raw(&app, "POST", "/v1/register", None, wrong).await.0,
        StatusCode::UNAUTHORIZED
    );
    let mut wrong = q.clone();
    wrong["public_key"] = json!(key(9002));
    assert_eq!(
        call_raw(&app, "POST", "/v1/register", None, wrong).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, registered) = call_raw(&app, "POST", "/v1/register", None, q.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        call_raw(&app, "POST", "/v1/register", None, q.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    q["proof"] = serde_json::to_value(
        solve(
            &challenges[1],
            &secret,
            endpoint,
            nonce,
            "http://localhost/",
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        call_raw(&app, "POST", "/v1/register", None, q).await.0,
        StatusCode::CONFLICT
    );
    let token = registered["token"].as_str().unwrap();
    assert_eq!(
        call_raw(&app, "POST", "/v1/register", Some((&k, token)), request)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(state.len().await.unwrap(), 1);
}
