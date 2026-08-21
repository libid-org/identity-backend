//! Platform definitions for OAuth identity verification.
//!
//! Only GitHub is served by this backend today, but the config-table shape
//! is kept from the original wallet backend on purpose: a platform whose
//! proof flow is server-side-OAuth + MPC-TLS (X, Discord, ...) can be added
//! by DATA — a new enum variant plus a `PlatformConfig` entry and a parser
//! arm — with no change to the flow code. X deliberately gets NO entry: its
//! browser talks to the notary directly and never touches this server.

use serde::{
    Deserialize,
    Serialize,
};

use crate::error::{
    Error,
    Result,
};

/// Supported identity platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// GitHub (api.github.com)
    GitHub,
}

impl Platform {
    /// Returns the static configuration for this platform.
    pub fn config(self) -> &'static PlatformConfig {
        match self {
            Self::GitHub => &GITHUB_CONFIG,
        }
    }

    /// The TLS API domain for this platform (convenience for
    /// `config().api_host`). This is the on-chain platform identifier.
    pub fn api_domain(self) -> &'static str {
        self.config().api_host
    }

    /// Parse the platform's API response JSON into a [`PlatformUser`].
    pub fn extract_user(self, body: &[u8]) -> Result<PlatformUser> {
        match self {
            Self::GitHub => parse_github_user(body),
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.api_domain())
    }
}

/// Static configuration for a platform's OAuth and API endpoints.
pub struct PlatformConfig {
    /// OAuth 2.0 authorization URL (user-facing).
    pub authorize_url: &'static str,
    /// OAuth 2.0 token exchange URL (server-to-server).
    pub token_url: &'static str,
    /// TLS API host for MPC-TLS connections.
    pub api_host: &'static str,
    /// API path for fetching the authenticated user's profile.
    pub user_info_path: &'static str,
    /// OAuth scopes (space-separated).
    pub scopes: &'static str,
    /// Whether the token exchange uses HTTP Basic auth
    /// (client_id:client_secret). If false, credentials are sent as POST
    /// body parameters.
    pub token_auth_basic: bool,
    /// The JSON key name whose value is selectively disclosed
    /// (e.g. "login").
    pub username_field: &'static str,
    /// The JSON key of the immutable user-id to also reveal, and whether its
    /// value is a quoted string. `(name, quoted)`: GitHub is `("id", false)`
    /// → `"id":<n>,`. The on-chain receiver key derives from this id, never
    /// the mutable handle.
    pub id_field: Option<(&'static str, bool)>,
}

/// GitHub platform configuration. The read-only OAuth App is enough for
/// handle claims; no GitHub App is involved.
pub static GITHUB_CONFIG: PlatformConfig = PlatformConfig {
    authorize_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    api_host: "api.github.com",
    user_info_path: "/user",
    scopes: "",
    token_auth_basic: false,
    username_field: "login",
    id_field: Some(("id", false)), // GitHub ids are bare numbers: "id":<n>,
};

/// Platform-agnostic user identity extracted from an OAuth API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformUser {
    /// Which platform this identity came from.
    pub platform: Platform,
    /// Platform-specific immutable user ID.
    pub id: String,
    /// Unique username / handle on the platform.
    pub username: String,
    /// Human-readable display name.
    pub display_name: String,
}

/// Parse a GitHub `/user` response body into a [`PlatformUser`].
fn parse_github_user(body: &[u8]) -> Result<PlatformUser> {
    #[derive(Deserialize)]
    struct GitHubUser {
        id: u64,
        login: String,
        name: Option<String>,
    }
    let user: GitHubUser = serde_json::from_slice(body).map_err(|e| Error::ApiParse {
        platform: Platform::GitHub,
        detail: e.to_string(),
    })?;
    Ok(PlatformUser {
        platform: Platform::GitHub,
        id: user.id.to_string(),
        username: user.login.clone(),
        display_name: user.name.unwrap_or(user.login),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_user_parses_with_and_without_name() {
        let body = br#"{"login":"alice","id":42,"name":"Alice A"}"#;
        let user = Platform::GitHub.extract_user(body).unwrap();
        assert_eq!(user.id, "42");
        assert_eq!(user.username, "alice");
        assert_eq!(user.display_name, "Alice A");

        let body = br#"{"login":"bob","id":7,"name":null}"#;
        let user = Platform::GitHub.extract_user(body).unwrap();
        assert_eq!(user.display_name, "bob");
    }

    #[test]
    fn platform_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Platform::GitHub).unwrap(),
            "\"github\""
        );
    }
}
