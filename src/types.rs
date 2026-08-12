//! Wire types: challenge request/response and the bind-ready proof bundle.
//!
//! The proof shapes mirror dyaka's byte-for-byte (same field names, same
//! alloy serde encodings), so a client — or dyaka's e2e test — that consumed
//! the dyaka backend's `/auth/github/result/{challenge}` payload consumes
//! this one unchanged.
//!
//! End-to-end coverage against real GitHub OAuth + a live notary is out of
//! scope here; dyaka's `tests/src/e2e/identity_bind.rs` exercises exactly
//! the three endpoints this server exposes (`/auth/github/challenge`,
//! `/auth/github/callback` via the browser, `/auth/github/result/{id}`)
//! with these payload shapes, so pointing its `backend_url` at this server
//! runs it unchanged.

use serde::{
    Deserialize,
    Serialize,
};

use crate::platform::{
    Platform,
    PlatformUser,
};

/// Request to initiate an OAuth challenge. The platform comes from the
/// scoped `/auth/{platform}/challenge` route — never the body.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// The user's compressed secp256k1 public key (33 bytes, hex-encoded,
    /// no `0x` prefix). This is the session key the proof is issued to.
    pub pubkey: String,
    /// The wallet (20-byte hex address) the proof is made out to.
    ///
    /// REQUIRED and load-bearing: the backend countersignature binds this
    /// address into the digest, and `IdentityNames` refuses a bind whose
    /// proof names a different (or zero) wallet. A proof without it would be
    /// unusable, so the request is rejected instead.
    pub link_wallet: String,
}

/// Response containing the challenge and OAuth URL.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The challenge identifier (32 random bytes, hex).
    pub challenge: String,
    /// The OAuth authorization URL to open in a popup.
    pub auth_url: String,
    /// Seconds until this challenge (and its authorization URL) expires.
    pub expires_in: u64,
}

// The Solidity struct the verifier contract consumes, kept ABI- and
// serde-identical to dyaka's `Registry::FullTlsProof` binding.
#[allow(missing_docs, clippy::too_many_arguments, unused_attributes)]
mod sol_types {
    alloy_sol_types::sol! {
        /// The on-chain TLS proof: notary + backend signatures over the
        /// transcript root, plus the Merkle paths for the revealed leaves.
        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct FullTlsProof {
            bytes notarySignature;
            bytes backendSignature;
            address userAddress;
            address walletAddress;
            bytes32 domainHash;
            bytes32 clientRandom;
            bytes32 serverRandom;
            bytes serverEphemeralKey;
            bytes32 transcriptRoot;
            uint256 timestamp;
            bytes32[] domainPath;
            bytes32[] usernamePath;
            bytes32[] endpointPath;
            bytes32[] idPath;
        }
    }
}

pub use sol_types::FullTlsProof;

/// Full registration proof returned to the client after OAuth + MPC-TLS.
/// The client ABI-encodes `tls_proof` into the verifier-contract bind call
/// and submits it on-chain itself — this backend never touches the chain.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistrationProof {
    /// The session Ethereum address (derived from the challenge pubkey).
    pub session_address: String,
    /// On-chain platform identifier (the API domain, e.g. "api.github.com").
    pub platform: String,
    /// Platform handle (username).
    pub handle: String,
    /// Immutable platform user-id — the on-chain receiver key derives from
    /// this, never the mutable handle.
    pub user_id: String,
    /// The full TLS proof struct ready for on-chain verification.
    pub tls_proof: FullTlsProof,
    /// Backend signature fields (redundant with `tls_proof` for clients that
    /// only re-verify the countersignature).
    pub backend_sig: BackendSigFields,
    /// The API domain verified in the TLS proof.
    pub domain: String,
    /// The API endpoint path verified in the TLS proof.
    pub endpoint: String,
    /// The verifier contract address the notary digest is bound to (hex,
    /// `0x`-prefixed). Named `registry_address` for dyaka wire
    /// compatibility; for the naming deployment this is the
    /// `GitHubIdentityVerifier` contract.
    pub registry_address: String,
    /// Base64-encoded TLSNotary presentation (independently verifiable
    /// off-chain).
    pub presentation: String,
    /// The verified platform user info.
    pub user: PlatformUser,
    /// The platform enum value.
    pub platform_enum: Platform,
}

/// Backend countersignature fields.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackendSigFields {
    /// Hex-encoded session address (the user address in the digest).
    pub user_address: String,
    /// Unix timestamp from the proof.
    pub timestamp: u64,
    /// Hex-encoded 65-byte ECDSA signature (Solidity v-byte 27/28).
    pub signature: String,
}

/// Final verification response served by `GET /auth/github/result/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Verified platform user.
    pub user: PlatformUser,
    /// The platform that was verified.
    pub platform: Platform,
    /// The session Ethereum address (hex, `0x`-prefixed).
    pub eth_address: String,
    /// Unix timestamp of proof generation.
    pub timestamp: u64,
    /// Base64-encoded TLSNotary presentation.
    pub presentation: String,
    /// The full registration proof for client-side submission.
    pub registration_proof: RegistrationProof,
    /// Always `None` here — this backend never deploys or resolves wallets.
    /// Kept so the payload deserializes into dyaka's `VerifyResponse`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
}
