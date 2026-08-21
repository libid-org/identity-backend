//! Wire types: challenge request/response and the bind-ready proof bundle.
//!
//! The proof shapes still mirror the original wallet backend's
//! field-for-field and use the same alloy serde encodings, with one
//! deliberate difference: the backend countersignature is gone, so the
//! payload no longer carries `backend_sig` and `tls_proof` no longer carries
//! `backendSignature`. That drops one `bytes` member from the head of the
//! ABI tuple, so a client built for the old shape does not encode a valid
//! call — it has to drop the field in step with `GitHubIdentityVerifier`,
//! which no longer reads it.
//!
//! End-to-end coverage against real GitHub OAuth + a live notary is out of
//! scope here; the upstream monorepo's `tests/src/e2e/identity_bind.rs`
//! exercises exactly the three endpoints this server exposes
//! (`/auth/github/challenge`, `/auth/github/callback` via the browser,
//! `/auth/github/result/{id}`), so pointing its `backend_url` here still
//! drives the whole flow — but its proof deserialization has to lose the
//! countersignature fields first, the same edit its on-chain encoder needs.

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
    /// REQUIRED: it travels as the proof's `walletAddress`, and
    /// `IdentityNames` refuses a bind whose proof names a different (or zero)
    /// wallet — it must be the caller of the bind transaction. A proof
    /// without it would be unusable, so the request is rejected instead.
    ///
    /// No signature binds it any more (the backend countersignature that used
    /// to is gone — see the `flow` module docs), so a proof, which is public
    /// calldata once submitted, can be replayed by a third party who swaps in
    /// their own wallet. The fix is to bind the wallet into the notarised
    /// transcript itself; until then this field is a routing instruction, not
    /// a cryptographic commitment.
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
// serde-identical to the original wallet backend's `Registry::FullTlsProof`
// binding.
#[allow(missing_docs, clippy::too_many_arguments, unused_attributes)]
mod sol_types {
    alloy_sol_types::sol! {
        /// The on-chain TLS proof: the notary's signature over the transcript
        /// root, plus the Merkle paths for the revealed leaves. Field order
        /// is the ABI — it must stay identical to `FullTlsProof` in
        /// `GitHubIdentityVerifier.sol`, which no longer carries a
        /// `backendSignature` OR a `userAddress` — both went with the
        /// countersignature, `userAddress` because nothing read it once it was
        /// no longer being signed over. Dropping a field from the head of a
        /// tuple shifts every offset after it, so an encoder one field out of
        /// step does not fail loudly: it produces calldata the verifier decodes
        /// into the wrong values.
        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct FullTlsProof {
            bytes notarySignature;
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
    /// The API domain verified in the TLS proof.
    pub domain: String,
    /// The API endpoint path verified in the TLS proof.
    pub endpoint: String,
    /// The verifier contract address the notary digest is bound to (hex,
    /// `0x`-prefixed). Named `registry_address` for wire compatibility
    /// with the original wallet backend; for the naming deployment this
    /// is the `GitHubIdentityVerifier` contract.
    pub registry_address: String,
    /// Base64-encoded TLSNotary presentation (independently verifiable
    /// off-chain).
    pub presentation: String,
    /// The verified platform user info.
    pub user: PlatformUser,
    /// The platform enum value.
    pub platform_enum: Platform,
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
    /// Kept so the payload deserializes into the original wallet backend's
    /// `VerifyResponse`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
}
