//! `POST /auth/github/challenge` — start a handle-claim flow.

use std::{
    sync::Arc,
    time::Instant,
};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use crate::{
    oauth,
    platform::Platform,
    state::{
        AppState,
        PendingChallenge,
    },
    types::{
        ChallengeRequest,
        ChallengeResponse,
    },
};

/// Validate a compressed secp256k1 pubkey hex string (33 bytes, 02/03
/// prefix). Returns a human-readable error message on failure.
pub fn validate_compressed_pubkey(pubkey_hex: &str) -> Result<(), String> {
    let bytes = hex::decode(pubkey_hex).map_err(|_| "invalid pubkey hex".to_string())?;
    if bytes.len() != 33 || (bytes[0] != 0x02 && bytes[0] != 0x03) {
        return Err(format!(
            "pubkey must be 33 bytes compressed (02.../03...), got {} bytes",
            bytes.len()
        ));
    }
    Ok(())
}

/// Parse a required, non-zero 20-byte wallet address (with or without `0x`).
pub fn parse_link_wallet(wallet: &str) -> Result<[u8; 20], String> {
    let raw = wallet.strip_prefix("0x").unwrap_or(wallet);
    match hex::decode(raw) {
        // Reject the zero address: the bind contract treats it as "no
        // wallet" and refuses the proof.
        Ok(b) if b.len() == 20 && b != [0u8; 20] => {
            let mut a = [0u8; 20];
            a.copy_from_slice(&b);
            Ok(a)
        }
        _ => Err("link_wallet must be a non-zero 20-byte hex address".to_string()),
    }
}

/// Build the OAuth `state` parameter: `challenge:pubkey:api_domain`.
pub fn format_oauth_state(
    challenge_hex: &str,
    pubkey_hex: &str,
    api_domain: &str,
) -> String {
    format!("{challenge_hex}:{pubkey_hex}:{api_domain}")
}

/// Parse an OAuth `state` parameter back into `(challenge, pubkey)`.
/// Whitespace (a mangled copy-paste) is stripped first. The platform segment
/// is informational only — the pending challenge is the authority.
pub fn parse_oauth_state(state_param: &str) -> Option<(String, String)> {
    let clean: String = state_param.chars().filter(|c| !c.is_whitespace()).collect();
    let mut parts = clean.splitn(3, ':');
    let challenge = parts.next().filter(|s| !s.is_empty())?;
    let pubkey = parts.next().filter(|s| !s.is_empty())?;
    Some((challenge.to_string(), pubkey.to_string()))
}

/// `POST /auth/github/challenge` handler.
pub async fn challenge_github(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChallengeRequest>,
) -> axum::response::Response {
    let platform = Platform::GitHub;

    if let Err(msg) = validate_compressed_pubkey(&req.pubkey) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response();
    }

    let link_wallet = match parse_link_wallet(&req.link_wallet) {
        Ok(w) => w,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": msg })),
            )
                .into_response()
        }
    };

    let challenge_bytes: [u8; 32] = rand::random();
    let challenge_hex = hex::encode(challenge_bytes);

    let oauth_state =
        format_oauth_state(&challenge_hex, &req.pubkey, platform.api_domain());
    let (auth_url, code_verifier) =
        oauth::build_auth_url(platform.config(), &state.github_oauth, &oauth_state);

    let ttl = state.runtime.challenge_ttl_secs;
    state
        .create_challenge(
            challenge_hex.clone(),
            PendingChallenge {
                pubkey_hex: req.pubkey,
                code_verifier,
                platform,
                link_wallet,
                created: Instant::now(),
            },
        )
        .await;

    (
        StatusCode::OK,
        Json(ChallengeResponse {
            challenge: challenge_hex,
            auth_url,
            expires_in: ttl,
        }),
    )
        .into_response()
}
