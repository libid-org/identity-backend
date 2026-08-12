//! The MPC-TLS proving flow: prover session → notary response → independent
//! verification → Merkle paths → bind-ready proof.
//!
//! Ported from dyaka's `RegistrationFlow`, rebuilt on the libid-rs crates and
//! stripped of everything on-chain: the output is a bind-ready
//! [`VerifyResponse`] the UI submits itself.
//!
//! # The notary is the only trust root
//!
//! This backend runs the prover side of MPC-TLS, so it independently holds
//! the full TLS session data. After receiving the notary's signed attestation
//! it re-checks everything — attestation validity, handshake parameters,
//! domain, endpoint, timestamp, Merkle leaves, Merkle root, notary signature
//! — against its own session view, and refuses to emit a proof that
//! disagrees. That check is worth keeping: it turns a broken or lying notary
//! into a failed claim here instead of a revert on-chain. It is not a second
//! trust root, and this backend no longer pretends to be one.
//!
//! Until this commit it also countersigned `(userAddress, walletAddress,
//! transcriptRoot, timestamp)` with a key of its own, which read as "forging
//! a proof needs two keys". It did not. The backend IS that signer, so a
//! compromised backend signed whichever pairing it liked — and it holds the
//! user's OAuth access token and drives the MPC-TLS session besides, so it
//! could equally obtain a GENUINE transcript naming its own wallet. The
//! second signature never constrained the party it appeared to constrain,
//! while costing a key, an IAM grant and a rotation story.
//!
//! What it did do is stop a THIRD PARTY replaying somebody else's proof: the
//! verifier is a view and proofs arrive as public calldata, so a successful
//! claim is readable on-chain, and without the countersignature an attacker
//! can copy one, point `walletAddress` at themselves and submit it. **That
//! hole is open as of this commit**, deliberately: it is a protocol problem,
//! not a signature problem. The fix belongs in the notarised data — the
//! notary already commits the request path as an `endpoint:` Merkle leaf, so
//! proving `/user?bind=0xWALLET` puts the wallet inside the transcript and
//! the verifier can check that leaf the way it already checks the handle.
//! Moving GitHub proving into the browser, as X and Google already do, would
//! remove this backend from the trust model altogether.
//!
//! # Testability
//!
//! The notary transport is injectable: [`run`] takes any async socket, so a
//! test (or an alternative deployment) can hand it something other than a
//! TCP stream. The pure verification and assembly steps
//! ([`verify_common_checks`], [`verify_tls_handshake`],
//! [`assemble_registration_proof`]) take plain data and are unit-tested
//! against fake transcripts without any notary at all.

use std::time::SystemTime;

use tlsn::attestation::{
    Attestation,
    CryptoProvider,
    Secrets,
};
use tokio::io::{
    AsyncRead,
    AsyncWrite,
};
use tracing::info;

use libid_attestations::compute_notary_digest;
use libid_crypto::{
    build_merkle_tree,
    double_hash_leaf,
    keccak256,
    merkle_proof,
    pubkey_to_eth_address,
    recover_eth_claim,
};
use libid_tlsn::{
    ProverResult,
    UserInfoParams,
};
use libid_transcript::{
    find_json_snippet_range,
    find_presentation_commit_ranges,
    find_request_line_range,
    wire,
    EvmProof,
    NotaryResponse,
    TlsHandshakeData,
};

use crate::{
    error::{
        Error,
        Result,
    },
    platform::{
        Platform,
        PlatformUser,
    },
    types::{
        FullTlsProof,
        RegistrationProof,
        VerifyResponse,
    },
};

/// User-Agent sent on the MPC-TLS request (GitHub rejects agent-less
/// requests).
const USER_AGENT: &str = concat!("identity-backend/", env!("CARGO_PKG_VERSION"));

/// Maximum allowed drift between the notary's proof timestamp and this
/// server's clock, in seconds.
const MAX_TIMESTAMP_DRIFT_SECS: u64 = 30;

/// Everything the flow needs besides the socket and the access token.
pub struct FlowContext {
    /// The platform being proven.
    pub platform: Platform,
    /// EVM chain id bound into the notary digest.
    pub chain_id: u64,
    /// Verifier contract address bound into the notary digest.
    pub verifier_contract: [u8; 20],
    /// Expected notary Ethereum address.
    pub notary_address: [u8; 20],
}

/// Run the full proving flow over `socket` (the notary connection).
///
/// `pubkey_hex` is the compressed session pubkey from the challenge;
/// `link_wallet` is the wallet the proof is made out to.
pub async fn run<S>(
    socket: S,
    access_token: &str,
    pubkey_hex: &str,
    link_wallet: [u8; 20],
    ctx: &FlowContext,
) -> Result<VerifyResponse>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let eth_addr = pubkey_to_session_address(pubkey_hex)?;
    info!("session ETH address: 0x{}", hex::encode(eth_addr));

    let platform_config = ctx.platform.config();

    // ── MPC-TLS session + notary exchange ───────────────────────────────
    info!(platform = %ctx.platform, "starting MPC-TLS proof");
    let mut prover_result = libid_tlsn::prover(
        socket,
        access_token,
        &UserInfoParams {
            api_host: platform_config.api_host,
            user_info_path: platform_config.user_info_path,
            username_field: platform_config.username_field,
            id_field: platform_config.id_field,
            user_agent: USER_AGENT,
        },
        |_| {},
    )
    .await?;

    wire::write_msg(&mut prover_result.recovered_io, &prover_result.request).await?;
    info!("attestation request sent to notary");
    let notary_resp: NotaryResponse =
        wire::read_msg(&mut prover_result.recovered_io).await?;
    info!("NotaryResponse received from notary");

    // ── Independent verification ────────────────────────────────────────
    let provider = CryptoProvider::default();
    let (platform_user, attestation, recv_snippet) =
        verify(&prover_result, &notary_resp, ctx, &provider)?;

    // ── Presentation ────────────────────────────────────────────────────
    let presentation =
        build_presentation(prover_result.secrets, &attestation, &provider)?;

    // ── Assemble ────────────────────────────────────────────────────────
    // Nothing is signed here. The proof carries exactly one signature, the
    // notary's, made over a digest domain-separated by (chain id, verifying
    // contract); `link_wallet` travels as the proof's `walletAddress`.
    let evm_proof = &notary_resp.evm_proof;

    assemble_registration_proof(
        evm_proof,
        &platform_user,
        &recv_snippet,
        eth_addr,
        link_wallet,
        &ctx.verifier_contract,
        ctx.platform,
        presentation,
    )
}

/// Derive the session Ethereum address from a compressed pubkey hex string.
pub fn pubkey_to_session_address(pubkey_hex: &str) -> Result<[u8; 20]> {
    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|e| Error::CryptoFailed {
        op: "decode pubkey hex".into(),
        detail: format!("{e}"),
    })?;
    let user_vk =
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey_bytes).map_err(|e| {
            Error::CryptoFailed {
                op: "parse compressed pubkey".into(),
                detail: format!("{e}"),
            }
        })?;
    Ok(pubkey_to_eth_address(&user_vk))
}

/// Validate the attestation and run all verification checks on the notary
/// response. Returns the platform user, the attestation, and the raw JSON
/// snippet bytes the notary hashed into the username leaf.
fn verify<T>(
    prover_result: &ProverResult<T>,
    notary_resp: &NotaryResponse,
    ctx: &FlowContext,
    provider: &CryptoProvider,
) -> Result<(PlatformUser, Attestation, Vec<u8>)>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let evm_proof = &notary_resp.evm_proof;
    let platform_config = ctx.platform.config();

    let attestation: Attestation = serde_json::from_slice(&notary_resp.attestation)
        .map_err(|e| Error::AttestationInvalid {
            detail: format!("invalid attestation JSON: {e}"),
        })?;
    prover_result
        .request
        .validate(&attestation, provider)
        .map_err(|e| Error::AttestationInvalid {
            detail: format!("{e}"),
        })?;
    info!("attestation validated");

    let our_user = ctx.platform.extract_user(&prover_result.response_body)?;
    info!(username = %our_user.username, "user extracted from prover response");

    verify_tls_handshake(&prover_result.handshake, evm_proof)?;

    if evm_proof.domain != platform_config.api_host {
        return Err(Error::DomainMismatch {
            expected: platform_config.api_host.to_string(),
            got: evm_proof.domain.clone(),
        });
    }
    verify_timestamp_freshness(evm_proof)?;

    let transcript = prover_result.secrets.transcript();
    verify_common_checks(
        transcript.sent(),
        evm_proof,
        ctx.chain_id,
        &ctx.verifier_contract,
        &ctx.notary_address,
    )?;

    // Extract the raw JSON snippet bytes from the response body.
    // response_body is the decoded HTTP body (no headers), so search directly.
    let recv_snippet = find_json_snippet_range(
        &prover_result.response_body,
        platform_config.username_field,
    )
    .map(|range| prover_result.response_body[range].to_vec())
    .ok_or_else(|| Error::MpcTlsFailed {
        detail: format!(
            "username field '{}' not found in response body",
            platform_config.username_field
        ),
    })?;

    // The notary must have committed to exactly this snippet.
    let expected = double_hash_leaf("recv:", &recv_snippet);
    if !evm_proof
        .leaves
        .get(2..)
        .unwrap_or_default()
        .contains(&expected)
    {
        return Err(Error::MissingMerkleLeaf {
            leaf_type: "username recv snippet".into(),
        });
    }
    info!("Merkle leaves verified against transcript");

    Ok((our_user, attestation, recv_snippet))
}

/// Cross-check TLS handshake parameters between prover and notary.
pub fn verify_tls_handshake(
    handshake: &TlsHandshakeData,
    evm_proof: &EvmProof,
) -> Result<()> {
    if handshake.client_random != evm_proof.client_random {
        return Err(Error::TlsHandshakeMismatch {
            field: "client_random".into(),
        });
    }
    if handshake.server_random != evm_proof.server_random {
        return Err(Error::TlsHandshakeMismatch {
            field: "server_random".into(),
        });
    }
    if handshake.server_ephemeral_key != evm_proof.server_ephemeral_key {
        return Err(Error::TlsHandshakeMismatch {
            field: "server_ephemeral_key".into(),
        });
    }
    info!("TLS handshake data cross-checked");
    Ok(())
}

/// Verify the notary timestamp is within
/// [`MAX_TIMESTAMP_DRIFT_SECS`] of the current time.
pub fn verify_timestamp_freshness(evm_proof: &EvmProof) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let drift = now.abs_diff(evm_proof.timestamp);
    if drift >= MAX_TIMESTAMP_DRIFT_SECS {
        return Err(Error::TimestampDrift {
            drift_secs: drift,
            max_secs: MAX_TIMESTAMP_DRIFT_SECS,
        });
    }
    Ok(())
}

/// The independent transcript checks: endpoint agreement between the
/// prover's own request line and the notary's proof, domain/endpoint Merkle
/// leaves, Merkle root, and the notary signature (chain- and
/// deployment-bound digest). Returns the method-stripped endpoint path.
pub fn verify_common_checks(
    sent: &[u8],
    evm_proof: &EvmProof,
    chain_id: u64,
    verifier_contract: &[u8; 20],
    notary_address: &[u8; 20],
) -> Result<String> {
    let request_line = &sent[find_request_line_range(sent)];
    let request_line_str =
        std::str::from_utf8(request_line).map_err(|e| Error::MalformedRequestLine {
            detail: format!("not valid UTF-8: {e}"),
        })?;
    let (method_path, _version) =
        request_line_str
            .rsplit_once(' ')
            .ok_or_else(|| Error::MalformedRequestLine {
                detail: "missing HTTP version".into(),
            })?;
    // Strip the HTTP method prefix ("GET /path" → "/path") to match the
    // notary's endpoint encoding, which also strips the method.
    let method_path = method_path
        .split_once(' ')
        .map_or(method_path, |(_, path)| path);

    if evm_proof.endpoint != method_path {
        return Err(Error::EndpointMismatch {
            notary: evm_proof.endpoint.clone(),
            prover: method_path.to_string(),
        });
    }

    let expected_domain_leaf = double_hash_leaf("domain:", evm_proof.domain.as_bytes());
    let expected_endpoint_leaf = double_hash_leaf("endpoint:", method_path.as_bytes());
    if evm_proof.leaves.len() < 3 {
        return Err(Error::TooFewMerkleLeaves {
            got: evm_proof.leaves.len(),
            expected: 3,
        });
    }
    if evm_proof.leaves[0] != expected_domain_leaf {
        return Err(Error::MerkleLeafMismatch {
            leaf_type: "domain".into(),
        });
    }
    if evm_proof.leaves[1] != expected_endpoint_leaf {
        return Err(Error::MerkleLeafMismatch {
            leaf_type: "endpoint".into(),
        });
    }

    let recomputed_root = build_merkle_tree(&evm_proof.leaves);
    if recomputed_root != evm_proof.transcript_root {
        return Err(Error::TranscriptRootMismatch);
    }

    let notary_digest = compute_notary_digest(
        chain_id,
        verifier_contract,
        &evm_proof.domain,
        &evm_proof.client_random,
        &evm_proof.server_random,
        &evm_proof.server_ephemeral_key,
        &evm_proof.transcript_root,
        evm_proof.timestamp,
    );
    let recovered_vk = recover_eth_claim(&evm_proof.notary_signature, &notary_digest)
        .map_err(|e| Error::CryptoFailed {
            op: "recover notary public key".into(),
            detail: format!("{e}"),
        })?;
    let recovered_addr = pubkey_to_eth_address(&recovered_vk);
    if &recovered_addr != notary_address {
        return Err(Error::NotarySignatureMismatch {
            recovered: format!("0x{}", hex::encode(recovered_addr)),
            expected: format!("0x{}", hex::encode(notary_address)),
        });
    }
    info!("notary signature verified");

    Ok(method_path.to_string())
}

/// Build a TLSNotary presentation from prover secrets and attestation.
fn build_presentation(
    secrets: Secrets,
    attestation: &Attestation,
    provider: &CryptoProvider,
) -> Result<String> {
    let transcript = secrets.transcript();
    let sent = transcript.sent();
    let recv = transcript.received();
    let identity_proof = secrets.identity_proof();
    let mut tp_builder = secrets.transcript_proof_builder();
    for range in find_presentation_commit_ranges(sent) {
        tp_builder
            .reveal_sent(&range)
            .map_err(|e| Error::PresentationBuildFailed {
                detail: format!("reveal sent: {e}"),
            })?;
    }
    tp_builder.reveal_recv(&(0..recv.len())).map_err(|e| {
        Error::PresentationBuildFailed {
            detail: format!("reveal recv: {e}"),
        }
    })?;
    let transcript_proof =
        tp_builder
            .build()
            .map_err(|e| Error::PresentationBuildFailed {
                detail: format!("transcript proof: {e}"),
            })?;

    let mut pres_builder = attestation.presentation_builder(provider);
    pres_builder
        .identity_proof(identity_proof)
        .transcript_proof(transcript_proof);
    let presentation =
        pres_builder
            .build()
            .map_err(|e| Error::PresentationBuildFailed {
                detail: format!("{e}"),
            })?;
    let presentation_bytes = serde_json::to_vec(&presentation)?;
    info!("presentation built");
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &presentation_bytes,
    ))
}

/// Normalize a 65-byte signature's v-byte to the EVM convention (27/28).
/// Idempotent: signatures already carrying 27/28 pass through; tlsn-supplied
/// notary signatures arrive with v=0/1 and get the bump.
pub fn solidity_sig(mut sig: Vec<u8>) -> Vec<u8> {
    sig[64] = match sig[64] {
        0 => 27,
        1 => 28,
        27 | 28 => sig[64],
        v => panic!("unexpected v-byte: {v}"),
    };
    sig
}

/// Assemble the bind-ready [`VerifyResponse`] from a verified proof. Pure —
/// no I/O, and nothing to sign — so tests can drive it with a fake
/// transcript.
#[allow(clippy::too_many_arguments)]
pub fn assemble_registration_proof(
    evm_proof: &EvmProof,
    platform_user: &PlatformUser,
    recv_snippet: &[u8],
    eth_addr: [u8; 20],
    link_wallet: [u8; 20],
    verifier_contract: &[u8; 20],
    platform: Platform,
    presentation: String,
) -> Result<VerifyResponse> {
    use alloy_primitives::{
        Address,
        FixedBytes,
        U256,
    };

    let session_address = format!("0x{}", hex::encode(eth_addr));
    let verifier_address = format!("0x{}", hex::encode(verifier_contract));

    // Merkle proofs for the on-chain FullTlsProof.
    let leaves = &evm_proof.leaves;
    let domain_path: Vec<FixedBytes<32>> = merkle_proof(leaves, 0)
        .into_iter()
        .map(FixedBytes::from)
        .collect();
    let endpoint_path: Vec<FixedBytes<32>> = merkle_proof(leaves, 1)
        .into_iter()
        .map(FixedBytes::from)
        .collect();

    let expected_username_leaf = double_hash_leaf("recv:", recv_snippet);
    let username_leaf_index = leaves
        .iter()
        .position(|l| *l == expected_username_leaf)
        .ok_or_else(|| Error::MissingMerkleLeaf {
            leaf_type: "username recv (for Merkle proof)".into(),
        })?;
    let username_path: Vec<FixedBytes<32>> = merkle_proof(leaves, username_leaf_index)
        .into_iter()
        .map(FixedBytes::from)
        .collect();

    // idPath: Merkle path to the id recv leaf, computed exactly like
    // usernamePath. Snippet matches the contract: quoted → `"id":"<id>"`,
    // bare → `"id":<id>,`. The id is REQUIRED — the on-chain receiver key
    // derives from the immutable platform id, never the mutable handle.
    let (id_field, quoted) =
        platform
            .config()
            .id_field
            .ok_or_else(|| Error::MissingMerkleLeaf {
                leaf_type: "platform has no id field — id-keyed binding required".into(),
            })?;
    let id_snippet = if quoted {
        format!("\"{}\":\"{}\"", id_field, platform_user.id)
    } else {
        format!("\"{}\":{},", id_field, platform_user.id)
    }
    .into_bytes();
    let id_leaf = double_hash_leaf("recv:", &id_snippet);
    let id_leaf_index = leaves.iter().position(|l| *l == id_leaf).ok_or_else(|| {
        Error::MissingMerkleLeaf {
            leaf_type: "id recv (for Merkle proof) — id must be revealed".into(),
        }
    })?;
    let id_path: Vec<FixedBytes<32>> = merkle_proof(leaves, id_leaf_index)
        .into_iter()
        .map(FixedBytes::from)
        .collect();

    let domain_hash = keccak256(evm_proof.domain.as_bytes());

    let tls_proof = FullTlsProof {
        notarySignature: solidity_sig(evm_proof.notary_signature.clone()).into(),
        userAddress: Address::from(eth_addr),
        walletAddress: Address::from(link_wallet),
        domainHash: FixedBytes::from(domain_hash),
        clientRandom: FixedBytes::from(evm_proof.client_random),
        serverRandom: FixedBytes::from(evm_proof.server_random),
        serverEphemeralKey: evm_proof.server_ephemeral_key.clone().into(),
        transcriptRoot: FixedBytes::from(evm_proof.transcript_root),
        timestamp: U256::from(evm_proof.timestamp),
        domainPath: domain_path,
        usernamePath: username_path,
        endpointPath: endpoint_path,
        idPath: id_path,
    };

    let registration_proof = RegistrationProof {
        session_address: session_address.clone(),
        platform: platform.api_domain().to_string(),
        handle: platform_user.username.clone(),
        user_id: platform_user.id.clone(),
        tls_proof,
        domain: evm_proof.domain.clone(),
        endpoint: evm_proof.endpoint.clone(),
        registry_address: verifier_address,
        presentation: presentation.clone(),
        user: platform_user.clone(),
        platform_enum: platform,
    };

    Ok(VerifyResponse {
        user: platform_user.clone(),
        platform,
        eth_address: session_address,
        timestamp: evm_proof.timestamp,
        presentation,
        registration_proof,
        wallet_address: None,
    })
}
