//! Proof-flow tests over a fake transcript: the independent verification
//! checks and the assembled proof structure, pinned against dyaka's
//! behavior. The byte-exact digest/Merkle/EIP-191 vectors live with the
//! libid-rs crates (libid-crypto / libid-attestations carry dyaka's pinning
//! tests); here we prove the backend wires them together into a bind-ready
//! proof.
//!
//! Nothing here signs anything: the notary's is the only signature in a
//! proof, and this service holds no key.

use std::time::SystemTime;

use identity_backend::{
    error::Error,
    flow::{
        assemble_registration_proof,
        pubkey_to_session_address,
        verify_common_checks,
        verify_timestamp_freshness,
        verify_tls_handshake,
    },
    platform::{
        Platform,
        PlatformUser,
    },
};
use libid_attestations::compute_notary_digest;
use libid_crypto::{
    build_merkle_tree,
    double_hash_leaf,
    hex_to_signing_key,
    merkle_verify,
    pubkey_to_eth_address,
    pubkey_to_hex,
    sign_eth_claim,
};
use libid_transcript::{
    find_json_snippet_range,
    EvmProof,
    TlsHandshakeData,
};

// Canonical anvil keys. Public test material, not secrets.
const NOTARY_KEY: &str =
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const SESSION_KEY: &str =
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

const CHAIN_ID: u64 = 31337;
const VERIFIER: [u8; 20] = [0x42u8; 20];
const LINK_WALLET: [u8; 20] = [0x77u8; 20];

const BODY: &[u8] = br#"{"login":"alice","id":42,"name":"Alice A"}"#;
const SENT: &[u8] = b"GET /user HTTP/1.1\r\nhost: api.github.com\r\n\r\n";

struct Fixture {
    evm_proof: EvmProof,
    username_snippet: Vec<u8>,
    notary_address: [u8; 20],
}

fn fixture() -> Fixture {
    let username_range = find_json_snippet_range(BODY, "login").unwrap();
    let username_snippet = BODY[username_range].to_vec();
    assert_eq!(username_snippet, br#""login":"alice""#);
    // GitHub ids are bare numbers; the id snippet includes the trailing `,`.
    let id_snippet = br#""id":42,"#.to_vec();

    let domain = "api.github.com";
    let endpoint = "/user";
    let leaves = vec![
        double_hash_leaf("domain:", domain.as_bytes()),
        double_hash_leaf("endpoint:", endpoint.as_bytes()),
        double_hash_leaf("recv:", &username_snippet),
        double_hash_leaf("recv:", &id_snippet),
    ];
    let transcript_root = build_merkle_tree(&leaves);

    let client_random = [0xAAu8; 32];
    let server_random = [0xBBu8; 32];
    let server_ephemeral_key = vec![0x04u8; 65];
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let notary_sk = hex_to_signing_key(NOTARY_KEY).unwrap();
    let notary_address = pubkey_to_eth_address(notary_sk.verifying_key());
    let digest = compute_notary_digest(
        CHAIN_ID,
        &VERIFIER,
        domain,
        &client_random,
        &server_random,
        &server_ephemeral_key,
        &transcript_root,
        timestamp,
    );
    let notary_signature = sign_eth_claim(&notary_sk, &digest).unwrap();

    Fixture {
        evm_proof: EvmProof {
            domain: domain.into(),
            endpoint: endpoint.into(),
            client_random,
            server_random,
            server_ephemeral_key,
            transcript_root,
            leaves,
            timestamp,
            notary_signature,
            recv_segments: vec![username_snippet.clone(), id_snippet],
            explicit_nonce: Vec::new(),
            app_ciphertext: Vec::new(),
        },
        username_snippet,
        notary_address,
    }
}

#[test]
fn common_checks_pass_on_honest_proof() {
    let f = fixture();
    let endpoint =
        verify_common_checks(SENT, &f.evm_proof, CHAIN_ID, &VERIFIER, &f.notary_address)
            .unwrap();
    assert_eq!(endpoint, "/user");
}

#[test]
fn common_checks_reject_tampering() {
    let f = fixture();

    // Wrong expected notary → signature mismatch.
    let err = verify_common_checks(SENT, &f.evm_proof, CHAIN_ID, &VERIFIER, &[0u8; 20])
        .unwrap_err();
    assert!(
        matches!(err, Error::NotarySignatureMismatch { .. }),
        "{err}"
    );

    // Wrong chain id → the domain-separated digest no longer recovers to
    // the notary. This is exactly the failure a misconfigured
    // VERIFIER_CONTRACT_ADDRESS produces on-chain.
    let err = verify_common_checks(
        SENT,
        &f.evm_proof,
        CHAIN_ID + 1,
        &VERIFIER,
        &f.notary_address,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::NotarySignatureMismatch { .. }),
        "{err}"
    );

    // Wrong verifier contract → same class of failure.
    let err = verify_common_checks(
        SENT,
        &f.evm_proof,
        CHAIN_ID,
        &[0x43u8; 20],
        &f.notary_address,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::NotarySignatureMismatch { .. }),
        "{err}"
    );

    // Endpoint disagreement between prover transcript and notary proof.
    let sent = b"GET /other HTTP/1.1\r\nhost: api.github.com\r\n\r\n";
    let err =
        verify_common_checks(sent, &f.evm_proof, CHAIN_ID, &VERIFIER, &f.notary_address)
            .unwrap_err();
    assert!(matches!(err, Error::EndpointMismatch { .. }), "{err}");

    // Tampered Merkle root.
    let mut proof = f.evm_proof.clone();
    proof.transcript_root = [0u8; 32];
    let err = verify_common_checks(SENT, &proof, CHAIN_ID, &VERIFIER, &f.notary_address)
        .unwrap_err();
    assert!(matches!(err, Error::TranscriptRootMismatch), "{err}");

    // Swapped domain leaf.
    let mut proof = f.evm_proof.clone();
    proof.leaves.swap(0, 1);
    let err = verify_common_checks(SENT, &proof, CHAIN_ID, &VERIFIER, &f.notary_address)
        .unwrap_err();
    assert!(matches!(err, Error::MerkleLeafMismatch { .. }), "{err}");
}

#[test]
fn timestamp_and_handshake_checks() {
    let mut f = fixture();
    verify_timestamp_freshness(&f.evm_proof).unwrap();
    f.evm_proof.timestamp -= 3600;
    assert!(matches!(
        verify_timestamp_freshness(&f.evm_proof).unwrap_err(),
        Error::TimestampDrift { .. }
    ));

    let f = fixture();
    let good = TlsHandshakeData {
        client_random: f.evm_proof.client_random,
        server_random: f.evm_proof.server_random,
        server_ephemeral_key: f.evm_proof.server_ephemeral_key.clone(),
    };
    verify_tls_handshake(&good, &f.evm_proof).unwrap();
    let bad = TlsHandshakeData {
        client_random: [0u8; 32],
        ..good
    };
    assert!(matches!(
        verify_tls_handshake(&bad, &f.evm_proof).unwrap_err(),
        Error::TlsHandshakeMismatch { .. }
    ));
}

/// Integration-shaped: fake transcript → verification → assembled proof,
/// then check the structure the UI would submit on-chain.
#[test]
fn assembled_proof_structure_is_bind_ready() {
    let f = fixture();

    // The session key from the challenge.
    let session_sk = hex_to_signing_key(SESSION_KEY).unwrap();
    let pubkey_hex = pubkey_to_hex(session_sk.verifying_key());
    let eth_addr = pubkey_to_session_address(&pubkey_hex).unwrap();
    assert_eq!(eth_addr, pubkey_to_eth_address(session_sk.verifying_key()));

    let user = PlatformUser {
        platform: Platform::GitHub,
        id: "42".into(),
        username: "alice".into(),
        display_name: "Alice A".into(),
    };

    let resp = assemble_registration_proof(
        &f.evm_proof,
        &user,
        &f.username_snippet,
        eth_addr,
        LINK_WALLET,
        &VERIFIER,
        Platform::GitHub,
        "cHJlc2VudGF0aW9u".into(),
    )
    .unwrap();

    let proof = &resp.registration_proof;
    assert_eq!(proof.platform, "api.github.com");
    assert_eq!(proof.handle, "alice");
    assert_eq!(proof.user_id, "42");
    assert_eq!(proof.domain, "api.github.com");
    assert_eq!(proof.endpoint, "/user");
    assert_eq!(
        proof.registry_address,
        format!("0x{}", hex::encode(VERIFIER))
    );
    assert_eq!(resp.eth_address, format!("0x{}", hex::encode(eth_addr)));

    let tls = &proof.tls_proof;
    assert_eq!(tls.userAddress.into_array(), eth_addr);
    assert_eq!(tls.walletAddress.into_array(), LINK_WALLET);
    assert_eq!(tls.transcriptRoot.0, f.evm_proof.transcript_root);
    assert_eq!(tls.domainHash.0, libid_crypto::keccak256(b"api.github.com"));
    assert_eq!(
        tls.timestamp,
        alloy_primitives::U256::from(f.evm_proof.timestamp)
    );

    // Every Merkle path verifies against the transcript root.
    let root = f.evm_proof.transcript_root;
    let to_arr = |p: &[alloy_primitives::FixedBytes<32>]| -> Vec<[u8; 32]> {
        p.iter().map(|b| b.0).collect()
    };
    assert!(merkle_verify(
        &to_arr(&tls.domainPath),
        root,
        f.evm_proof.leaves[0]
    ));
    assert!(merkle_verify(
        &to_arr(&tls.endpointPath),
        root,
        f.evm_proof.leaves[1]
    ));
    assert!(merkle_verify(
        &to_arr(&tls.usernamePath),
        root,
        f.evm_proof.leaves[2]
    ));
    assert!(merkle_verify(
        &to_arr(&tls.idPath),
        root,
        f.evm_proof.leaves[3]
    ));

    // Notary signature carries the Solidity v-byte and still recovers.
    let notary_sig: &[u8] = tls.notarySignature.as_ref();
    assert!(matches!(notary_sig[64], 27 | 28));

    // The whole response serializes and round-trips.
    let json = serde_json::to_string(&resp).unwrap();
    let back: identity_backend::types::VerifyResponse =
        serde_json::from_str(&json).unwrap();
    assert_eq!(back.registration_proof.handle, "alice");
    assert_eq!(
        back.registration_proof.tls_proof.walletAddress,
        tls.walletAddress
    );

    // And it carries no countersignature, in either spelling. The backend
    // holds no key: re-adding one has to be a deliberate decision, not a
    // merge accident, and the ABI tuple must keep matching
    // `GitHubIdentityVerifier.FullTlsProof`.
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let proof_json = &value["registration_proof"];
    assert!(proof_json.get("backend_sig").is_none(), "{proof_json}");
    assert!(
        proof_json["tls_proof"].get("backendSignature").is_none(),
        "{proof_json}"
    );
}

/// A proof missing the id leaf must be refused — the receiver key derives
/// from the immutable id, and there is no handle-key fallback.
#[test]
fn missing_id_leaf_is_a_hard_error() {
    let mut f = fixture();
    f.evm_proof.leaves.truncate(3); // drop the id leaf
    f.evm_proof.transcript_root = build_merkle_tree(&f.evm_proof.leaves);

    let user = PlatformUser {
        platform: Platform::GitHub,
        id: "42".into(),
        username: "alice".into(),
        display_name: "Alice A".into(),
    };
    let err = assemble_registration_proof(
        &f.evm_proof,
        &user,
        &f.username_snippet,
        [0x01u8; 20],
        LINK_WALLET,
        &VERIFIER,
        Platform::GitHub,
        String::new(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::MissingMerkleLeaf { .. }), "{err}");
}
