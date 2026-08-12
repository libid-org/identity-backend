//! `GET /auth/github/callback` — GitHub redirects the user's browser here.
//!
//! The handler exchanges the authorization code server-side (PKCE +
//! client_secret), then spawns the MPC-TLS proving flow against the notary
//! in the background and immediately serves the popup-closing HTML. The UI
//! polls `GET /auth/github/result/{challenge}` for the proof.

use std::sync::Arc;

use axum::{
    extract::{
        Query,
        State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use tokio::net::TcpStream;
use tracing::{
    error,
    info,
};

use crate::{
    error::{
        Error,
        Result,
    },
    flow,
    oauth,
    state::{
        AppState,
        FlowStatus,
    },
};

use super::challenge::parse_oauth_state;

/// HTML served to the user's browser during the OAuth callback.
const CALLBACK_HTML: &str = include_str!("callback.html");

/// Query parameters GitHub sends to the callback.
#[derive(serde::Deserialize)]
pub struct CallbackParams {
    /// Authorization code (present on success).
    pub code: Option<String>,
    /// The opaque state we minted in the challenge step.
    pub state: Option<String>,
    /// OAuth error code (present on decline/failure).
    pub error: Option<String>,
    /// Human-readable OAuth error description.
    pub error_description: Option<String>,
}

fn callback_html(challenge_hex: &str, phase: &str, error: &str) -> String {
    CALLBACK_HTML
        .replace("__CHALLENGE__", challenge_hex)
        .replace("__INITIAL_PHASE__", phase)
        .replace("__INITIAL_ERROR__", error)
}

/// `GET /auth/github/callback` handler.
pub async fn callback_github(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let Some(state_param) = params.state else {
        return (StatusCode::BAD_REQUEST, "missing state parameter").into_response();
    };
    let Some((challenge_hex, pubkey_hex)) = parse_oauth_state(&state_param) else {
        return (StatusCode::BAD_REQUEST, "invalid state parameter").into_response();
    };
    info!(challenge = %challenge_hex, "callback received");

    // Single-use consume; a replayed callback finds nothing.
    let pending = match state.consume_challenge(&challenge_hex).await {
        Some(p) => {
            if p.created.elapsed().as_secs() >= state.runtime.challenge_ttl_secs {
                return (StatusCode::GONE, "challenge expired").into_response();
            }
            p
        }
        None => {
            return (StatusCode::NOT_FOUND, "unknown challenge on callback")
                .into_response();
        }
    };

    if pending.pubkey_hex != pubkey_hex {
        return (StatusCode::BAD_REQUEST, "pubkey mismatch").into_response();
    }

    if let Some(error_code) = params.error {
        let mut msg = format!("Authorization declined: {}", error_code);
        if let Some(description) = params.error_description {
            if !description.trim().is_empty() {
                msg.push_str(" (");
                msg.push_str(description.trim());
                msg.push(')');
            }
        }
        state
            .set_status(&challenge_hex, FlowStatus::Failed { error: msg.clone() })
            .await;
        let html = callback_html(&challenge_hex, "failed", &msg);
        return (StatusCode::OK, [("Content-Type", "text/html")], html).into_response();
    }

    let Some(code) = params.code else {
        let msg = "OAuth callback missing authorization code".to_string();
        state
            .set_status(&challenge_hex, FlowStatus::Failed { error: msg.clone() })
            .await;
        let html = callback_html(&challenge_hex, "failed", &msg);
        return (
            StatusCode::BAD_REQUEST,
            [("Content-Type", "text/html")],
            html,
        )
            .into_response();
    };

    let platform = pending.platform;
    let access_token = match oauth::exchange_code_server_side(
        platform.config(),
        &state.github_oauth,
        &code,
        &pending.code_verifier,
    )
    .await
    {
        Ok(token) => token,
        Err(e) => {
            let msg = format!("OAuth token exchange failed: {}", e);
            error!("{}", msg);
            state
                .set_status(&challenge_hex, FlowStatus::Failed { error: msg.clone() })
                .await;
            return (StatusCode::BAD_GATEWAY, msg).into_response();
        }
    };
    info!(platform = %platform, token_len = access_token.len(), "access token obtained");
    state
        .set_status(
            &challenge_hex,
            FlowStatus::Pending {
                phase: "oauth_complete",
            },
        )
        .await;

    // Drive MPC-TLS + verification in the background; the popup closes now
    // and the UI polls the result endpoint.
    let state_clone = Arc::clone(&state);
    let challenge_for_task = challenge_hex.clone();
    tokio::spawn(async move {
        let result = run_verification(
            &state_clone,
            &access_token,
            &pubkey_hex,
            pending.link_wallet,
        )
        .await;
        match result {
            Ok(resp) => {
                info!(challenge = %challenge_for_task, "verification complete");
                state_clone
                    .set_status(&challenge_for_task, FlowStatus::Complete(Box::new(resp)))
                    .await;
            }
            Err(e) => {
                let msg = format!("{}", e);
                error!(challenge = %challenge_for_task, "verification failed: {msg}");
                state_clone
                    .set_status(&challenge_for_task, FlowStatus::Failed { error: msg })
                    .await;
            }
        }
    });

    let html = callback_html(&challenge_hex, "oauth_complete", "");
    (StatusCode::OK, [("Content-Type", "text/html")], html).into_response()
}

/// Connect to the notary over TCP and run the proving flow.
async fn run_verification(
    state: &AppState,
    access_token: &str,
    pubkey_hex: &str,
    link_wallet: [u8; 20],
) -> Result<crate::types::VerifyResponse> {
    let notary_host =
        state
            .runtime
            .notary_url
            .host_str()
            .ok_or_else(|| Error::NotaryUrl {
                detail: "no host".into(),
            })?;
    let notary_port =
        state
            .runtime
            .notary_url
            .port()
            .ok_or_else(|| Error::NotaryUrl {
                detail: "no port".into(),
            })?;
    let notary_addr = format!("{}:{}", notary_host, notary_port);
    info!(addr = %notary_addr, "connecting to notary");
    let tcp_stream =
        TcpStream::connect(&notary_addr)
            .await
            .map_err(|e| Error::NotaryConnect {
                addr: notary_addr.clone(),
                detail: format!("{e}"),
            })?;

    let ctx = flow::FlowContext {
        platform: crate::platform::Platform::GitHub,
        chain_id: state.runtime.chain_id,
        verifier_contract: state.runtime.verifier_contract,
        notary_address: state.runtime.notary_address,
        signer: &state.signer,
    };
    flow::run(tcp_stream, access_token, pubkey_hex, link_wallet, &ctx).await
}
