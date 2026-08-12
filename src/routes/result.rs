//! `GET /auth/github/result/{challenge}` — poll for the finished proof.
//!
//! Unauthenticated BY DESIGN: the challenge id is a 32-byte random secret
//! shared only with the browser that started the flow, and the proof it
//! yields is only usable by the `link_wallet` it was made out to — knowing
//! the id gains an attacker nothing they could bind elsewhere.

use std::sync::Arc;

use axum::{
    extract::{
        Path,
        State,
    },
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use crate::state::{
    AppState,
    StatusView,
};

/// `GET /auth/github/result/{challenge}` handler.
///
/// - unknown / expired challenge → `404`
/// - flow still running → `202 {"status":"pending","phase":...}`
/// - flow failed → `500 {"status":"failed","error":...}`
/// - proof ready → `200` with the full [`crate::types::VerifyResponse`]
pub async fn result_github(
    State(state): State<Arc<AppState>>,
    Path(challenge): Path<String>,
) -> impl IntoResponse {
    match state.status_json(&challenge).await {
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown challenge" })),
        )
            .into_response(),
        Some(StatusView::Pending { phase }) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "pending", "phase": phase })),
        )
            .into_response(),
        Some(StatusView::Failed { error }) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "status": "failed", "error": error })),
        )
            .into_response(),
        Some(StatusView::Complete(json)) => (StatusCode::OK, Json(json)).into_response(),
    }
}
