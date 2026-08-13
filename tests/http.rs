//! HTTP-level tests over the axum router, plus the challenge lifecycle and
//! OAuth-state round-trip.

use std::{
    sync::Arc,
    time::Instant,
};

use axum::{
    body::Body,
    http::{
        header,
        Request,
        StatusCode,
    },
};
use http_body_util::BodyExt;
use tower::ServiceExt;

use identity_backend::{
    platform::Platform,
    routes::{
        self,
        challenge::{
            format_oauth_state,
            parse_link_wallet,
            parse_oauth_state,
            validate_compressed_pubkey,
        },
    },
    state::{
        AppState,
        FlowStatus,
        PendingChallenge,
        Runtime,
    },
    types::ChallengeResponse,
};

// The state carries no signing identity: the service holds no key.
fn test_state(ttl_secs: u64, app_url: Option<&str>) -> Arc<AppState> {
    Arc::new(AppState {
        runtime: Runtime {
            base_url: "http://127.0.0.1:8722".into(),
            app_url: app_url.map(|s| s.to_string()),
            notary_url: url::Url::parse("tcp://127.0.0.1:7047").unwrap(),
            notary_address: [0x11u8; 20],
            chain_id: 31337,
            verifier_contract: [0x42u8; 20],
            challenge_ttl_secs: ttl_secs,
        },
        github_oauth: identity_backend::oauth::OAuthCredentials {
            client_id: "test-client-id".into(),
            client_secret: "test-client-secret".into(),
            redirect_uri: "http://127.0.0.1:8722/auth/github/callback".into(),
        },
        challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        results: tokio::sync::RwLock::new(std::collections::HashMap::new()),
    })
}

fn app(state: Arc<AppState>) -> axum::Router {
    routes::build_router().with_state(state)
}

fn valid_pubkey() -> String {
    let (_, vk) = libid_crypto::generate_keypair();
    libid_crypto::pubkey_to_hex(&vk)
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn health_is_ok() {
    let resp = app(test_state(300, None))
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"OK");
}

#[tokio::test]
async fn challenge_happy_path() {
    let state = test_state(300, None);
    let pubkey = valid_pubkey();
    let req = Request::post("/auth/github/challenge")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "pubkey": pubkey,
                "link_wallet": "0x7777777777777777777777777777777777777777",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app(Arc::clone(&state)).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let challenge: ChallengeResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(challenge.expires_in, 300);
    assert_eq!(challenge.challenge.len(), 64);

    let auth_url = url::Url::parse(&challenge.auth_url).unwrap();
    assert_eq!(auth_url.host_str(), Some("github.com"));
    let pairs: std::collections::HashMap<_, _> =
        auth_url.query_pairs().into_owned().collect();
    assert_eq!(pairs["client_id"], "test-client-id");
    assert_eq!(
        pairs["redirect_uri"],
        "http://127.0.0.1:8722/auth/github/callback"
    );
    assert_eq!(
        pairs["state"],
        format!("{}:{}:api.github.com", challenge.challenge, pubkey)
    );

    // The pending challenge is stored and single-use.
    let pending = state.consume_challenge(&challenge.challenge).await.unwrap();
    assert_eq!(pending.pubkey_hex, pubkey);
    assert_eq!(pending.link_wallet, [0x77u8; 20]);
    assert!(state
        .consume_challenge(&challenge.challenge)
        .await
        .is_none());

    // Its result slot reports pending (202) meanwhile.
    let resp = app(state)
        .oneshot(
            Request::get(format!("/auth/github/result/{}", challenge.challenge))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "pending");
}

#[tokio::test]
async fn challenge_rejects_bad_input() {
    let state = test_state(300, None);

    // Invalid pubkey hex.
    let req = Request::post("/auth/github/challenge")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "pubkey": "zz",
                "link_wallet": "0x7777777777777777777777777777777777777777",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app(Arc::clone(&state)).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "invalid pubkey hex");

    // Uncompressed (65-byte) pubkey.
    let req = Request::post("/auth/github/challenge")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "pubkey": hex::encode([4u8; 65]),
                "link_wallet": "0x7777777777777777777777777777777777777777",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app(Arc::clone(&state)).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Zero link_wallet is refused — the bind contract would refuse it too.
    let req = Request::post("/auth/github/challenge")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "pubkey": valid_pubkey(),
                "link_wallet": format!("0x{}", hex::encode([0u8; 20])),
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app(Arc::clone(&state)).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // link_wallet absent entirely: the JSON body is rejected before the
    // handler runs (it is a required field by design).
    let req = Request::post("/auth/github/challenge")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "pubkey": valid_pubkey() }).to_string(),
        ))
        .unwrap();
    let resp = app(state).oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn result_states() {
    let state = test_state(300, None);

    // Unknown challenge → 404.
    let resp = app(Arc::clone(&state))
        .oneshot(
            Request::get("/auth/github/result/deadbeef")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Failed flow → 500 with the error.
    state
        .set_status(
            "abc",
            FlowStatus::Failed {
                error: "boom".into(),
            },
        )
        .await;
    let resp = app(Arc::clone(&state))
        .oneshot(
            Request::get("/auth/github/result/abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "boom");
}

#[tokio::test]
async fn challenge_ttl_sweep() {
    // ttl 0: everything is expired the moment it exists.
    let state = test_state(0, None);
    state
        .create_challenge(
            "old".into(),
            PendingChallenge {
                pubkey_hex: "aa".into(),
                code_verifier: "v".into(),
                platform: Platform::GitHub,
                link_wallet: [1u8; 20],
                created: Instant::now(),
            },
        )
        .await;
    // The next create sweeps the expired entry.
    state
        .create_challenge(
            "new".into(),
            PendingChallenge {
                pubkey_hex: "bb".into(),
                code_verifier: "v".into(),
                platform: Platform::GitHub,
                link_wallet: [1u8; 20],
                created: Instant::now(),
            },
        )
        .await;
    assert!(state.consume_challenge("old").await.is_none());
    // And an expired result slot reads as unknown.
    assert!(state.status_json("new").await.is_none());
}

#[test]
fn oauth_state_round_trips() {
    let s = format_oauth_state("deadbeef", "02abcd", "api.github.com");
    assert_eq!(s, "deadbeef:02abcd:api.github.com");
    let (challenge, pubkey) = parse_oauth_state(&s).unwrap();
    assert_eq!(challenge, "deadbeef");
    assert_eq!(pubkey, "02abcd");

    // Whitespace-mangled copies still parse; empty segments do not.
    let (challenge, _) = parse_oauth_state(" deadbeef:02ab cd:api.github.com ").unwrap();
    assert_eq!(challenge, "deadbeef");
    assert!(parse_oauth_state(":pubkey:x").is_none());
    assert!(parse_oauth_state("challenge").is_none());
}

#[test]
fn pubkey_and_wallet_validation() {
    assert!(validate_compressed_pubkey("not-hex").is_err());
    assert!(validate_compressed_pubkey(&hex::encode([2u8; 32])).is_err());
    assert!(validate_compressed_pubkey(&hex::encode([9u8; 33])).is_err());
    let (_, vk) = libid_crypto::generate_keypair();
    assert!(validate_compressed_pubkey(&libid_crypto::pubkey_to_hex(&vk)).is_ok());

    assert!(parse_link_wallet("0x00").is_err());
    assert!(parse_link_wallet(&hex::encode([0u8; 20])).is_err());
    assert_eq!(
        parse_link_wallet("0x7777777777777777777777777777777777777777").unwrap(),
        [0x77u8; 20]
    );
    assert_eq!(
        parse_link_wallet("7777777777777777777777777777777777777777").unwrap(),
        [0x77u8; 20]
    );
}

#[tokio::test]
async fn x_relay_bounces_the_code_to_the_app() {
    let state = test_state(300, Some("https://wallet.example"));
    let resp = app(state)
        .oneshot(
            Request::get(
                "/zk/x-popup?code=abc123&state=job7~n&redirect=https://evil.example",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_redirection());
    // APP_URL substituted, path forced, provider params forwarded, and the
    // attacker-supplied one dropped rather than carried into the app's URL.
    let location = resp.headers()["location"].to_str().unwrap();
    assert!(location.starts_with("https://wallet.example/zk/x-popup?"));
    assert!(location.contains("code=abc123"));
    assert!(location.contains("state=job7"));
    assert!(!location.contains("evil.example"));
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert_eq!(resp.headers()["referrer-policy"], "no-referrer");
}

#[tokio::test]
async fn x_relay_requires_app_url() {
    let state = test_state(300, None);
    let resp = app(state)
        .oneshot(
            Request::get("/zk/x-popup?code=c&state=s")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn gmail_relay_serves_csp_locked_forwarder() {
    let state = test_state(300, Some("https://wallet.example"));
    let resp = app(state)
        .oneshot(
            Request::get("/auth/gmail/callback")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-security-policy"],
        "default-src 'none'; script-src 'unsafe-inline'"
    );
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert_eq!(resp.headers()["referrer-policy"], "no-referrer");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&bytes).unwrap();
    // APP_URL substituted, path forced, fragment forwarded.
    assert!(html.contains("\"https://wallet.example/auth/gmail/callback\""));
    assert!(html.contains("location.replace"));
    assert!(html.contains("location.hash"));
}

#[tokio::test]
async fn gmail_relay_requires_app_url() {
    let state = test_state(300, None);
    let resp = app(state)
        .oneshot(
            Request::get("/auth/gmail/callback")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn callback_rejects_unknown_and_replayed_state() {
    let state = test_state(300, None);

    // Missing state param.
    let resp = app(Arc::clone(&state))
        .oneshot(
            Request::get("/auth/github/callback?code=abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Unknown challenge.
    let resp = app(Arc::clone(&state))
        .oneshot(
            Request::get("/auth/github/callback?code=abc&state=dead:02ab:api.github.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // A user-declined OAuth flow marks the challenge failed and serves the
    // popup-closing page (200 so the browser renders it).
    state
        .create_challenge(
            "c0ffee".into(),
            PendingChallenge {
                pubkey_hex: "02ab".into(),
                code_verifier: "v".into(),
                platform: Platform::GitHub,
                link_wallet: [1u8; 20],
                created: Instant::now(),
            },
        )
        .await;
    let resp = app(Arc::clone(&state))
        .oneshot(
            Request::get(
                "/auth/github/callback?error=access_denied&state=c0ffee:02ab:api.github.com",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains("c0ffee"));
    assert!(html.contains("failed"));

    // The challenge was consumed: a replay finds nothing.
    let resp = app(Arc::clone(&state))
        .oneshot(
            Request::get(
                "/auth/github/callback?error=access_denied&state=c0ffee:02ab:api.github.com",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // And the result endpoint reports the failure.
    let resp = app(state)
        .oneshot(
            Request::get("/auth/github/result/c0ffee")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
