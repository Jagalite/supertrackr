use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use supertrackr::{Config, Coordinator, router};
use tower::ServiceExt;
fn key(n: u64) -> String {
    format!("{n:064x}")
}
async fn call(
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
    assert_eq!(state.len(), 2);
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
    state.cleanup();
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
    assert_eq!(state.len(), 32);
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
                        state.cleanup();
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
    assert_eq!(state.len(), 64);
}
