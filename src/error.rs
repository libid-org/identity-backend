//! Error types for the handles backend.

use crate::platform::Platform;

/// Errors from the handle-claim flow.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration was missing or malformed.
    #[error("config: {detail}")]
    Config {
        /// Human-readable failure detail.
        detail: String,
    },

    /// OAuth token exchange or authorization failed.
    #[error("OAuth failed for {platform}: {detail}")]
    OAuthFailed {
        /// The platform whose OAuth flow failed.
        platform: String,
        /// Human-readable failure detail.
        detail: String,
    },

    /// Parsing a platform API response failed.
    #[error("failed to parse {platform} API response: {detail}")]
    ApiParse {
        /// The platform whose response failed to parse.
        platform: Platform,
        /// Human-readable failure detail.
        detail: String,
    },

    /// A cryptographic operation failed.
    #[error("{op}: {detail}")]
    CryptoFailed {
        /// The operation that failed.
        op: String,
        /// Human-readable failure detail.
        detail: String,
    },

    /// Connecting to the notary failed.
    #[error("failed to connect to notary at {addr}: {detail}")]
    NotaryConnect {
        /// The notary address that was dialled.
        addr: String,
        /// Human-readable failure detail.
        detail: String,
    },

    /// The notary URL was malformed.
    #[error("invalid notary URL: {detail}")]
    NotaryUrl {
        /// Human-readable failure detail.
        detail: String,
    },

    /// The MPC-TLS protocol failed.
    #[error("MPC-TLS failed: {detail}")]
    MpcTlsFailed {
        /// Human-readable failure detail.
        detail: String,
    },

    /// The notary's attestation did not validate.
    #[error("attestation invalid: {detail}")]
    AttestationInvalid {
        /// Human-readable failure detail.
        detail: String,
    },

    /// The proof's domain did not match the platform's API host.
    #[error("domain mismatch: expected {expected}, got {got}")]
    DomainMismatch {
        /// The expected API host.
        expected: String,
        /// The domain the proof carried.
        got: String,
    },

    /// The notary's endpoint disagreed with the prover's request line.
    #[error("endpoint mismatch: notary said {notary}, prover sent {prover}")]
    EndpointMismatch {
        /// The endpoint from the notary's proof.
        notary: String,
        /// The endpoint from the prover's own transcript.
        prover: String,
    },

    /// The proof timestamp drifted too far from the current time.
    #[error("timestamp drift {drift_secs}s exceeds max {max_secs}s")]
    TimestampDrift {
        /// Observed drift in seconds.
        drift_secs: u64,
        /// Maximum allowed drift in seconds.
        max_secs: u64,
    },

    /// A TLS handshake field disagreed between prover and notary.
    #[error("TLS handshake mismatch: {field}")]
    TlsHandshakeMismatch {
        /// The handshake field that disagreed.
        field: String,
    },

    /// A Merkle leaf did not match its recomputed value.
    #[error("Merkle leaf mismatch: {leaf_type}")]
    MerkleLeafMismatch {
        /// Which leaf failed.
        leaf_type: String,
    },

    /// A required Merkle leaf was absent from the proof.
    #[error("missing Merkle leaf: {leaf_type}")]
    MissingMerkleLeaf {
        /// Which leaf was missing.
        leaf_type: String,
    },

    /// The proof carried fewer Merkle leaves than the minimum.
    #[error("too few Merkle leaves: got {got}, expected at least {expected}")]
    TooFewMerkleLeaves {
        /// The number of leaves in the proof.
        got: usize,
        /// The minimum required.
        expected: usize,
    },

    /// The recomputed Merkle root did not match the proof's transcript root.
    #[error("transcript root mismatch")]
    TranscriptRootMismatch,

    /// The notary signature recovered to an unexpected address.
    #[error("notary signature mismatch: recovered {recovered}, expected {expected}")]
    NotarySignatureMismatch {
        /// The address the signature recovered to.
        recovered: String,
        /// The configured notary address.
        expected: String,
    },

    /// The revealed HTTP request line could not be parsed.
    #[error("malformed request line: {detail}")]
    MalformedRequestLine {
        /// Human-readable failure detail.
        detail: String,
    },

    /// Building the TLSNotary presentation failed.
    #[error("presentation build failed: {detail}")]
    PresentationBuildFailed {
        /// Human-readable failure detail.
        detail: String,
    },

    /// Socket I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// The MPC-TLS session driver failed.
    #[error(transparent)]
    Tlsn(#[from] libid_tlsn::Error),

    /// Transcript parsing or the notary wire protocol failed.
    #[error(transparent)]
    Transcript(#[from] libid_transcript::Error),

    /// A libid-crypto primitive failed.
    #[error(transparent)]
    Crypto(#[from] libid_crypto::Error),
    // No signing variant: this service holds no key and signs nothing.
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
