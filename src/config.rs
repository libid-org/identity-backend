//! Configuration, parsed from CLI args / environment variables via `clap`.

use clap::Parser;
use url::Url;

/// Configuration for the handles backend server.
///
/// Every flag has an environment-variable form; the env names are the
/// deployment contract.
#[derive(Debug, Parser)]
#[command(name = "identity-backend", version, about)]
pub struct Config {
    /// Host to bind. Use 0.0.0.0 in containers.
    #[arg(long, env = "HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind.
    #[arg(long, env = "PORT", default_value = "8722")]
    pub port: u16,

    /// Public base URL of THIS server. The GitHub OAuth callback URL is
    /// derived as `{BASE_URL}/auth/github/callback` and must match the OAuth
    /// App registration exactly.
    #[arg(long, env = "BASE_URL", default_value = "http://127.0.0.1:8722")]
    pub base_url: String,

    /// Public URL of the web app. The Gmail fragment-relay callback bounces
    /// the popup to `{APP_URL}/auth/gmail/callback`. Empty disables the
    /// relay (it responds 500 with a pointed message).
    #[arg(long, env = "APP_URL", default_value = "")]
    pub app_url: String,

    /// Comma-separated CORS allow-list. Supports `*.suffix` and `prefix*`
    /// wildcards.
    #[arg(long, env = "ALLOWED_ORIGINS", default_value = "http://localhost:3000")]
    pub allowed_origins: String,

    /// URL of the notary server (TCP), e.g. `tcp://notary.example:7047`.
    #[arg(long, env = "NOTARY_URL", default_value = "tcp://127.0.0.1:7047")]
    pub notary_url: Url,

    /// Ethereum address of the notary. Every proof's notary signature must
    /// recover to this address or the flow fails before countersigning.
    #[arg(long, env = "NOTARY_ADDRESS")]
    pub notary_address: String,

    /// EVM chain id of the target deployment. Bound into the notary digest
    /// as a domain separator — a proof for chain A does not verify on
    /// chain B.
    #[arg(long, env = "CHAIN_ID")]
    pub chain_id: u64,

    /// The contract address bound into the MPC-TLS notary digest.
    ///
    /// LOUD WARNING, learned the hard way: this is the address of the
    /// contract that VERIFIES the notary signature on-chain — for the naming
    /// deployment that is `GitHubIdentityVerifier`, NOT `IdentityNames`.
    /// dyaka called the same value `REGISTRY_CONTRACT_ADDRESS`, which
    /// misled operators into pointing it at the registry; every bind then
    /// reverts with a notary-signature failure because the digest is
    /// domain-separated by `(chainId, verifyingContract)`.
    #[arg(long, env = "VERIFIER_CONTRACT_ADDRESS")]
    pub verifier_contract_address: String,

    /// Backend countersigning key: a hex secp256k1 private key, or
    /// `kms:<key-id>` naming an AWS KMS key (alias/ARN/UUID) — see
    /// libid-signer. The verifier contract must trust the corresponding
    /// address.
    #[arg(long, env = "BACKEND_SIGNING_KEY")]
    pub backend_signing_key: String,

    /// GitHub OAuth App client ID (read-only app; no GitHub App needed).
    #[arg(long, env = "GH_OAUTH_CLIENT_ID")]
    pub gh_oauth_client_id: String,

    /// GitHub OAuth App client secret.
    #[arg(long, env = "GH_OAUTH_CLIENT_SECRET")]
    pub gh_oauth_client_secret: String,

    /// Seconds a challenge (and its finished result) stays available.
    #[arg(long, env = "CHALLENGE_TTL_SECS", default_value = "300")]
    pub challenge_ttl_secs: u64,
}

impl Config {
    /// The comma-separated origins as a vector of patterns.
    pub fn allowed_origin_patterns(&self) -> Vec<String> {
        self.allowed_origins
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}
