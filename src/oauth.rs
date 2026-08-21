//! Platform-agnostic OAuth 2.0 integration with PKCE.
//!
//! Ported from the upstream monorepo's auth crate (`src/oauth.rs`), trimmed
//! to the server-side code-exchange path this backend uses.

use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use sha2::{
    Digest,
    Sha256,
};

use crate::{
    error::{
        Error,
        Result,
    },
    platform::PlatformConfig,
};

/// Credentials for server-side OAuth 2.0.
#[derive(Clone)]
pub struct OAuthCredentials {
    /// OAuth app client ID.
    pub client_id: String,
    /// OAuth app client secret.
    pub client_secret: String,
    /// OAuth redirect URI. Must match the OAuth app registration exactly —
    /// GitHub redirects the user's browser here.
    pub redirect_uri: String,
}

/// Build an OAuth 2.0 authorization URL with PKCE for the given platform.
/// Returns `(auth_url, code_verifier)`.
pub fn build_auth_url(
    platform: &PlatformConfig,
    credentials: &OAuthCredentials,
    state: &str,
) -> (String, String) {
    let code_verifier = generate_code_verifier();
    let code_challenge = compute_code_challenge(&code_verifier);

    // Static platform URLs are compile-time constants; parse cannot fail.
    let mut url =
        url::Url::parse(platform.authorize_url).expect("static authorize URL is valid");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", &credentials.client_id);
        q.append_pair("redirect_uri", &credentials.redirect_uri);
        if !platform.scopes.is_empty() {
            q.append_pair("scope", platform.scopes);
        }
        q.append_pair("state", state);
        q.append_pair("code_challenge", &code_challenge);
        q.append_pair("code_challenge_method", "S256");
    }

    (url.to_string(), code_verifier)
}

/// Exchange an authorization code for an access token (server-side, with
/// client_secret + PKCE).
pub async fn exchange_code_server_side(
    platform: &PlatformConfig,
    credentials: &OAuthCredentials,
    code: &str,
    code_verifier: &str,
) -> Result<String> {
    // Build body in a block so the non-Send Serializer is dropped before any
    // .await.
    let body = {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &credentials.redirect_uri)
            .append_pair("code_verifier", code_verifier);

        // Some platforms require credentials in the POST body instead of
        // Basic auth.
        if !platform.token_auth_basic {
            serializer
                .append_pair("client_id", &credentials.client_id)
                .append_pair("client_secret", &credentials.client_secret);
        }

        serializer.finish()
    };
    let client = reqwest::Client::new();

    let mut req = client
        .post(platform.token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json");

    if platform.token_auth_basic {
        req = req.basic_auth(&credentials.client_id, Some(&credentials.client_secret));
    }

    let resp = req
        .body(body)
        .send()
        .await
        .map_err(|e| Error::OAuthFailed {
            platform: platform.api_host.into(),
            detail: format!("request failed: {e}"),
        })?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.map_err(|e| Error::OAuthFailed {
        platform: platform.api_host.into(),
        detail: format!("failed to parse response: {e}"),
    })?;

    if !status.is_success() {
        return Err(Error::OAuthFailed {
            platform: platform.api_host.into(),
            detail: format!(
                "token exchange failed ({}): {}",
                status,
                serde_json::to_string_pretty(&body).unwrap_or_default()
            ),
        });
    }

    body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::OAuthFailed {
            platform: platform.api_host.into(),
            detail: "no access_token in response".into(),
        })
}

/// Generate a random PKCE code_verifier (43-128 unreserved chars).
fn generate_code_verifier() -> String {
    use rand::Rng;
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    (0..128)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Compute code_challenge = BASE64URL_NO_PAD(SHA256(code_verifier)).
fn compute_code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use crate::platform::GITHUB_CONFIG;

    use super::*;

    #[test]
    fn auth_url_carries_pkce_and_state() {
        let creds = OAuthCredentials {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "http://127.0.0.1:8722/auth/github/callback".into(),
        };
        let (auth_url, verifier) = build_auth_url(&GITHUB_CONFIG, &creds, "abc:def:gh");
        let url = url::Url::parse(&auth_url).unwrap();
        assert_eq!(url.host_str(), Some("github.com"));
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(pairs["client_id"], "cid");
        assert_eq!(pairs["state"], "abc:def:gh");
        assert_eq!(pairs["code_challenge_method"], "S256");
        assert_eq!(pairs["code_challenge"], compute_code_challenge(&verifier));
        // GitHub has empty scopes — no scope param at all.
        assert!(!pairs.contains_key("scope"));
        // The secret never appears in a user-facing URL.
        assert!(!auth_url.contains("secret"));
    }
}
