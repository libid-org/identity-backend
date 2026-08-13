//! HTTP route table and CORS. The full endpoint surface, deliberately tiny:
//!
//! - `GET  /health`
//! - `POST /auth/github/challenge`
//! - `GET  /auth/github/callback`
//! - `GET  /auth/github/result/{challenge}`
//! - `GET  /auth/gmail/callback`
//! - `GET  /zk/x-popup`
//!
//! The last two are pure browser bounces, not part of any proving path: X and
//! Google are proven client-side and talk to the notary directly. They exist so
//! a provider's registered redirect URI can be a stable API host instead of
//! whichever origin serves the UI.

pub mod callback;
pub mod challenge;
pub mod gmail;
mod relay;
pub mod result;
pub mod x;

use std::sync::Arc;

use axum::{
    http::HeaderValue,
    routing::{
        get,
        post,
    },
    Router,
};
use tower_http::cors::CorsLayer;

use crate::state::AppState;

/// Liveness probe.
async fn health() -> &'static str {
    "OK"
}

/// Build the route table (no CORS applied; see [`cors_layer`]).
pub fn build_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health))
        .route("/auth/github/challenge", post(challenge::challenge_github))
        .route("/auth/github/callback", get(callback::callback_github))
        .route(
            "/auth/github/result/{challenge}",
            get(result::result_github),
        )
        .route("/auth/gmail/callback", get(gmail::gmail_callback))
        .route("/zk/x-popup", get(x::x_popup))
}

/// CORS layer from a list of origin patterns (supports `*.suffix` and
/// `prefix*` wildcards).
pub fn cors_layer(allowed_origins: Vec<String>) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(
            move |origin: &HeaderValue, _req: &axum::http::request::Parts| {
                let origin_str = match origin.to_str() {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                allowed_origins.iter().any(|pattern| {
                    if pattern.contains('*') {
                        if let Some(suffix) = pattern.strip_prefix("*.") {
                            origin_str.ends_with(&format!(".{suffix}"))
                                || origin_str == suffix
                        } else if let Some(prefix) = pattern.strip_suffix('*') {
                            origin_str.starts_with(prefix)
                        } else {
                            false
                        }
                    } else {
                        origin_str == pattern
                    }
                })
            },
        ))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT])
}
