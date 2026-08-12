//! Minimal identity/handles backend.
//!
//! Exactly the endpoints the OAuth handle-claim flow needs, and nothing
//! else: the UI does OAuth via this server, the server produces a
//! bind-ready proof via MPC-TLS with the notary, the UI submits the bind
//! on-chain itself. No database, no wallet routes, no sponsor pool, no
//! indexer, no JWKS rotator.

#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod flow;
pub mod oauth;
pub mod platform;
pub mod routes;
pub mod state;
pub mod types;

use std::sync::Arc;

use error::{
    Error,
    Result,
};
use state::{
    AppState,
    Runtime,
};

/// Build the shared [`AppState`] from parsed configuration. Parses the
/// addresses that must be well-formed for any proof to verify, so a typo
/// fails at startup rather than on the first claim.
///
/// This holds no key material of any kind: the service signs nothing.
pub async fn build_state(cfg: &config::Config) -> Result<Arc<AppState>> {
    let notary_address = libid_crypto::hex_to_address(&cfg.notary_address)?;
    let verifier_contract = libid_crypto::hex_to_address(&cfg.verifier_contract_address)?;

    if cfg.base_url.is_empty() {
        return Err(Error::Config {
            detail: "BASE_URL must be set — GitHub redirects the browser to \
                     {BASE_URL}/auth/github/callback"
                .into(),
        });
    }

    let app_url = if cfg.app_url.is_empty() {
        None
    } else {
        Some(cfg.app_url.clone())
    };

    let github_oauth = oauth::OAuthCredentials {
        client_id: cfg.gh_oauth_client_id.clone(),
        client_secret: cfg.gh_oauth_client_secret.clone(),
        redirect_uri: format!(
            "{}/auth/github/callback",
            cfg.base_url.trim_end_matches('/')
        ),
    };

    Ok(Arc::new(AppState {
        runtime: Runtime {
            base_url: cfg.base_url.clone(),
            app_url,
            notary_url: cfg.notary_url.clone(),
            notary_address,
            chain_id: cfg.chain_id,
            verifier_contract,
            challenge_ttl_secs: cfg.challenge_ttl_secs,
        },
        github_oauth,
        challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        results: tokio::sync::RwLock::new(std::collections::HashMap::new()),
    }))
}
