//! Application state shared across request handlers.
//!
//! Everything is in-memory by design: a pending challenge lives for
//! `challenge_ttl_secs`, its result for the same again, and nothing survives
//! a restart. There is no database in this backend.

use std::{
    collections::HashMap,
    time::Instant,
};

use tokio::sync::RwLock;
use url::Url;

use crate::{
    oauth::OAuthCredentials,
    platform::Platform,
    types::VerifyResponse,
};

/// Pending OAuth challenge awaiting callback.
pub struct PendingChallenge {
    /// The hex-encoded compressed public key.
    pub pubkey_hex: String,
    /// PKCE code verifier.
    pub code_verifier: String,
    /// The platform being authenticated.
    pub platform: Platform,
    /// Wallet the proof is made out to.
    pub link_wallet: [u8; 20],
    /// When this challenge was created.
    pub created: Instant,
}

/// Where a challenge's flow currently stands. Served by the result route.
pub enum FlowStatus {
    /// The flow is still running (OAuth done, MPC-TLS in progress, ...).
    Pending {
        /// Coarse phase label for the client ("oauth_complete", ...).
        phase: &'static str,
    },
    /// The flow finished; the proof bundle is ready.
    Complete(Box<VerifyResponse>),
    /// The flow failed.
    Failed {
        /// Human-readable error description.
        error: String,
    },
}

/// A [`FlowStatus`] plus its last-touched time, for TTL sweeping.
pub struct FlowEntry {
    /// Current status.
    pub status: FlowStatus,
    /// Last state change.
    pub updated: Instant,
}

/// Validated runtime configuration (addresses parsed, not raw strings).
pub struct Runtime {
    /// Public base URL of this server.
    pub base_url: String,
    /// Public web-app URL for the Gmail fragment relay. `None` disables it.
    pub app_url: Option<String>,
    /// Notary TCP URL.
    pub notary_url: Url,
    /// Expected notary Ethereum address.
    pub notary_address: [u8; 20],
    /// EVM chain id bound into the notary digest.
    pub chain_id: u64,
    /// Verifier contract address bound into the notary digest
    /// (`GitHubIdentityVerifier` for the naming deployment).
    pub verifier_contract: [u8; 20],
    /// Challenge / result TTL in seconds.
    pub challenge_ttl_secs: u64,
}

/// Shared application state.
///
/// No signing identity lives here: the service holds no key and signs
/// nothing. The only secret it handles is the GitHub OAuth client secret,
/// and the only long-lived trust root in a proof is the notary's key.
pub struct AppState {
    /// Validated runtime configuration.
    pub runtime: Runtime,
    /// GitHub OAuth credentials.
    pub github_oauth: OAuthCredentials,
    /// Pending OAuth challenges, keyed by challenge hex.
    pub challenges: RwLock<HashMap<String, PendingChallenge>>,
    /// Flow results, keyed by challenge hex.
    pub results: RwLock<HashMap<String, FlowEntry>>,
}

impl AppState {
    /// Create a challenge and its pending result slot, sweeping expired
    /// entries from both maps first.
    pub async fn create_challenge(
        &self,
        challenge_hex: String,
        pending: PendingChallenge,
    ) {
        let ttl = self.runtime.challenge_ttl_secs;
        {
            let mut challenges = self.challenges.write().await;
            challenges.retain(|_, v| v.created.elapsed().as_secs() < ttl);
            challenges.insert(challenge_hex.clone(), pending);
        }
        {
            let mut results = self.results.write().await;
            results.retain(|_, v| v.updated.elapsed().as_secs() < ttl);
            results.insert(
                challenge_hex,
                FlowEntry {
                    status: FlowStatus::Pending {
                        phase: "waiting_for_authorization",
                    },
                    updated: Instant::now(),
                },
            );
        }
    }

    /// Consume a pending challenge by ID. Single-use: a second consume (a
    /// replayed OAuth callback) returns `None`.
    pub async fn consume_challenge(
        &self,
        challenge_id: &str,
    ) -> Option<PendingChallenge> {
        let mut challenges = self.challenges.write().await;
        challenges.remove(challenge_id)
    }

    /// Update the flow status for a challenge.
    pub async fn set_status(&self, challenge_id: &str, status: FlowStatus) {
        let mut results = self.results.write().await;
        results.insert(
            challenge_id.to_string(),
            FlowEntry {
                status,
                updated: Instant::now(),
            },
        );
    }

    /// Read the flow status for a challenge, `None` if unknown or expired.
    /// Reads do not extend the TTL.
    pub async fn status_json(&self, challenge_id: &str) -> Option<StatusView> {
        let results = self.results.read().await;
        let entry = results.get(challenge_id)?;
        if entry.updated.elapsed().as_secs() >= self.runtime.challenge_ttl_secs {
            return None;
        }
        Some(match &entry.status {
            FlowStatus::Pending { phase } => StatusView::Pending { phase },
            FlowStatus::Complete(resp) => {
                StatusView::Complete(serde_json::to_value(resp.as_ref()).ok()?)
            }
            FlowStatus::Failed { error } => StatusView::Failed {
                error: error.clone(),
            },
        })
    }
}

/// A snapshot of a flow's status, detached from the state lock.
pub enum StatusView {
    /// Still running.
    Pending {
        /// Coarse phase label.
        phase: &'static str,
    },
    /// Finished — the serialized [`VerifyResponse`].
    Complete(serde_json::Value),
    /// Failed.
    Failed {
        /// Human-readable error description.
        error: String,
    },
}
