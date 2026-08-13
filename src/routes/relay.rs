//! Shared target-URL construction for the provider callback relays.
//!
//! Both relays are registered with a provider as the redirect URI and bounce
//! the browser to a fixed path on `APP_URL`. The provider response never
//! influences where that bounce goes: the host comes from operator config and
//! the path is forced here, so neither relay is an open redirect.

use url::Url;

/// Build the relay's forwarding target: `APP_URL` with `path` forced and any
/// query or fragment stripped.
///
/// Rejects anything that could carry a token to a place an on-path attacker
/// can read, or that smuggles credentials into the URL.
pub(crate) fn relay_target(app_url: &str, path: &str) -> Result<Url, &'static str> {
    let mut target = Url::parse(app_url).map_err(|_| "must be an absolute URL")?;
    match target.scheme() {
        "https" => {}
        "http" if is_loopback_host(&target) => {}
        "http" => {
            return Err("http APP_URL is only allowed for loopback hosts — use https")
        }
        _ => return Err("scheme must be http or https"),
    }
    if !target.username().is_empty() || target.password().is_some() {
        return Err("credentials are not allowed");
    }
    target.set_path(path);
    target.set_query(None);
    target.set_fragment(None);
    Ok(target)
}

/// True when the URL's host is a loopback dev host — `localhost` /
/// `*.localhost` or a loopback IP (127.0.0.0/8, ::1). Permits plain http only
/// for local development, never a routable origin.
pub(crate) fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost" || d.ends_with(".localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::relay_target;

    #[test]
    fn the_provider_response_cannot_redirect_the_bounce() {
        let t = relay_target(
            "https://app.example/ignored?next=https://evil.example#x",
            "/zk/x-popup",
        )
        .unwrap();
        assert_eq!(t.as_str(), "https://app.example/zk/x-popup");
        assert!(!t.as_str().contains("evil.example"));
    }

    #[test]
    fn https_is_required_except_on_loopback() {
        assert!(relay_target("https://app.example", "/p").is_ok());
        assert!(relay_target("http://localhost:5173", "/p").is_ok());
        assert!(relay_target("http://127.0.0.1:5173", "/p").is_ok());
        assert!(relay_target("http://[::1]:5173", "/p").is_ok());
        assert!(relay_target("http://foo.localhost", "/p").is_ok());

        assert!(relay_target("http://app.example", "/p").is_err());
        assert!(relay_target("http://192.168.1.10", "/p").is_err());
        assert!(relay_target("http://localhost.evil.com", "/p").is_err());
        assert!(relay_target("javascript:alert(1)", "/p").is_err());
        assert!(relay_target("https://user:pw@app.example", "/p").is_err());
    }
}
