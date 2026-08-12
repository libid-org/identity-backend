# identity-backend

A minimal identity backend for on-chain handle claims. It does exactly one
job: run the OAuth + MPC-TLS flow that turns "I control this GitHub account"
into a bind-ready cryptographic proof, and hand that proof back to the UI.
The UI submits the bind on-chain itself — this server holds no wallets, pays
no gas, keeps no database, and talks to no chain.

Built on the [libid-rs](https://github.com/libid-org/libid-rs) crates
(MPC-TLS session driver, transcript math, digests, signing).

## How a claim works

1. The UI generates a session keypair and calls
   `POST /auth/github/challenge` with the compressed session pubkey and the
   wallet the proof should be made out to (`link_wallet`). It gets back a
   challenge id and a GitHub authorization URL, which it opens in a popup.
2. The user authorizes on GitHub. GitHub redirects the popup to
   `GET /auth/github/callback` on this server, which exchanges the code
   server-side (PKCE + client secret — the browser never sees the token),
   serves a small page that closes the popup, and continues in the
   background.
3. In the background the server fetches `api.github.com/user` over MPC-TLS
   with the notary, so the notary co-signs what GitHub actually returned
   without ever seeing the access token in the clear. The server then
   independently re-verifies everything the notary attested — TLS handshake
   parameters, domain, endpoint, freshness, Merkle leaves and root, and the
   notary signature (which is domain-separated by chain id and verifier
   contract) — builds the Merkle paths for the domain / endpoint / username
   / user-id leaves, and countersigns the result. Two independent parties
   have now attested; forging a proof requires both to collude.
4. The UI polls `GET /auth/github/result/{challenge}` until it flips from
   `202` to `200`, takes the `registration_proof` from the payload, and
   submits the bind transaction on-chain from the user's wallet.

Proofs are bound to the `link_wallet` from step 1: the backend
countersignature commits to it, and the verifier contract refuses the proof
from any other wallet. That is also why the result endpoint needs no
authentication — the challenge id is an unguessable 32-byte secret, and the
proof it yields is unusable by anyone but `link_wallet`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness probe. Returns `OK`. |
| `POST` | `/auth/github/challenge` | Body `{"pubkey": "<33-byte compressed secp256k1 hex, no 0x>", "link_wallet": "0x..."}`. Returns `{"challenge", "auth_url", "expires_in"}`. Both fields are required; a zero `link_wallet` is rejected. |
| `GET` | `/auth/github/callback` | GitHub's OAuth redirect target. Not called by your code — but `BASE_URL` must make this URL match the OAuth App registration exactly. |
| `GET` | `/auth/github/result/{challenge}` | `202 {"status":"pending",...}` while proving; `200 {..., "registration_proof": {...}}` when the proof is ready; `500 {"status":"failed","error":...}` on failure; `404` for unknown/expired challenges. Challenges and results live for `CHALLENGE_TTL_SECS` and do not survive a restart. |
| `GET` | `/auth/gmail/callback` | Static, CSP-locked fragment relay for the Google OIDC flow: forwards `location.hash` (the id_token, which never reaches any server) to `{APP_URL}/auth/gmail/callback`. Requires `APP_URL`. |

There are no X/Twitter endpoints: the X flow runs browser ↔ notary directly
and never involves this server.

## Configuration

All settings come from environment variables (or the matching `--flag`).

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address (`0.0.0.0` in the container image). |
| `PORT` | `8722` | Bind port. |
| `BASE_URL` | `http://127.0.0.1:8722` | Public URL of this server. The GitHub OAuth App's callback URL must be exactly `{BASE_URL}/auth/github/callback`. |
| `APP_URL` | *(empty)* | Public URL of the web app; target of the Gmail fragment relay. Https required except for localhost. Empty disables the relay. |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated CORS allow-list. `*.suffix` and `prefix*` wildcards supported. |
| `NOTARY_URL` | `tcp://127.0.0.1:7047` | The notary server's TCP endpoint. |
| `NOTARY_ADDRESS` | *(required)* | The notary's Ethereum address. Every proof's notary signature must recover to it. |
| `CHAIN_ID` | *(required)* | EVM chain id of the target deployment; part of the notary digest's domain separator. |
| `VERIFIER_CONTRACT_ADDRESS` | *(required)* | **Read carefully — this is the most commonly misconfigured value.** The address of the contract that verifies the notary signature on-chain: for the naming deployment that is **`GitHubIdentityVerifier`**, *not* `IdentityNames`. The notary digest is domain-separated by `(CHAIN_ID, VERIFIER_CONTRACT_ADDRESS)`; point this at the wrong contract and every bind reverts with a notary-signature failure. (dyaka called this same value `REGISTRY_CONTRACT_ADDRESS`, which is how the confusion started.) |
| `BACKEND_SIGNING_KEY` | *(required)* | Countersigning key: a raw hex secp256k1 private key, or an AWS KMS key as `kms:<key-id>` (alias / ARN / UUID; the `kms:` prefix is optional — any value containing a non-hex character is treated as a KMS identifier). Region and credentials come from the ambient AWS config. The verifier contract must trust the corresponding address. |
| `GH_OAUTH_CLIENT_ID` | *(required)* | GitHub OAuth App client id (a plain read-only OAuth App; no GitHub App needed). |
| `GH_OAUTH_CLIENT_SECRET` | *(required)* | GitHub OAuth App client secret. |
| `CHALLENGE_TTL_SECS` | `300` | Lifetime of a challenge and of its finished result. |

### Note on Google binds

This server does not run a JWKS rotator. Until a rotator runs somewhere and
publishes Google's current signing moduli on-chain, Google/Gmail binds
revert with `UntrustedModulus`. GitHub and X are unaffected. The
`/auth/gmail/callback` relay is served regardless, so the browser side of
the Google flow works the moment a rotator exists.

## Running with Docker

```sh
docker run --rm -p 8722:8722 \
  -e BASE_URL=https://handles.example.com \
  -e APP_URL=https://app.example.com \
  -e ALLOWED_ORIGINS=https://app.example.com \
  -e NOTARY_URL=tcp://notary.example.com:7047 \
  -e NOTARY_ADDRESS=0x... \
  -e CHAIN_ID=1 \
  -e VERIFIER_CONTRACT_ADDRESS=0x...   # GitHubIdentityVerifier, see above \
  -e BACKEND_SIGNING_KEY=kms:alias/identity-backend \
  -e GH_OAUTH_CLIENT_ID=... \
  -e GH_OAUTH_CLIENT_SECRET=... \
  ghcr.io/libid-org/identity-backend:latest
```

Images are published on every GitHub release as
`ghcr.io/libid-org/identity-backend:<version>` and `:latest`. The image
listens on `0.0.0.0:8722` and carries a `/health` healthcheck.

## Building from source

```sh
cargo build --release          # rustc >= 1.94.1
cargo test
```

## License

Dual-licensed under MIT and Apache-2.0 — see `LICENSE-MIT`,
`LICENSE-APACHE` and `NOTICE`.
