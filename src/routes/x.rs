//! `GET /zk/x-popup` — the X authorization-code relay.
//!
//! X's browser flow needs no server: the popup gets the code, the token
//! exchange runs over MPC-TLS from the browser, and the ZK proof is generated
//! client-side. This endpoint exists so the redirect URI registered with the X
//! app can be a stable API host rather than whichever origin the UI is served
//! from, which otherwise has to be re-registered every time that changes.
//!
//! Unlike Google's relay, this one needs no inline script. X returns `code` and
//! `state` in the QUERY, which a browser does send to the server and which
//! survives a redirect, so the bounce is a plain 303. Google's `id_token`
//! arrives in the fragment, which never reaches any server and has to be copied
//! across in JavaScript.
//!
//! The bounce lands on `{APP_URL}/zk/x-popup`, same-origin with the app, where
//! the client relay hands the code to the opener over a BroadcastChannel — that
//! channel is same-origin only, which is why this endpoint navigates rather than
//! trying to talk to the parent itself.

use std::sync::Arc;

use axum::{
    extract::{
        RawQuery,
        State,
    },
    http::{
        HeaderValue,
        StatusCode,
    },
    response::{
        IntoResponse,
        Redirect,
        Response,
    },
};
use url::Url;

use crate::{
    routes::relay::relay_target,
    state::AppState,
};

/// The client relay reads exactly these. Anything else a provider (or an
/// attacker probing the endpoint) appends is dropped rather than forwarded.
const FORWARDED: [&str; 4] = ["code", "state", "error", "error_description"];

/// `GET /zk/x-popup` handler.
pub async fn x_popup(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let app_url = state.runtime.app_url.as_deref().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "APP_URL not configured — set APP_URL env so the X callback knows where the frontend lives".to_string(),
        )
    })?;
    x_popup_response(app_url, query.as_deref()).map_err(|detail| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("invalid APP_URL: {detail}"),
        )
    })
}

/// Build the bounce with its hardening headers.
pub fn x_popup_response(
    app_url: &str,
    query: Option<&str>,
) -> Result<Response, &'static str> {
    let target = x_popup_target(app_url, query)?;
    let mut response = Redirect::to(target.as_str()).into_response();
    let headers = response.headers_mut();
    // The URL carries a single-use authorization code: keep it out of caches,
    // and out of the Referer the app's own page would otherwise send onward.
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    Ok(response)
}

/// `{APP_URL}/zk/x-popup` carrying only the allow-listed provider params.
fn x_popup_target(app_url: &str, query: Option<&str>) -> Result<Url, &'static str> {
    let mut target = relay_target(app_url, "/zk/x-popup")?;
    if let Some(raw) = query {
        let forwarded: Vec<(String, String)> =
            url::form_urlencoded::parse(raw.as_bytes())
                .filter(|(k, _)| FORWARDED.contains(&k.as_ref()))
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
        if !forwarded.is_empty() {
            target.query_pairs_mut().extend_pairs(forwarded);
        }
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use axum::http::{
        header,
        StatusCode,
    };

    use super::{
        x_popup_response,
        x_popup_target,
    };

    #[test]
    fn the_code_and_state_reach_the_app_untouched() {
        let t =
            x_popup_target("https://app.example", Some("code=abc123&state=job7~nonce"))
                .unwrap();
        assert_eq!(
            t.as_str(),
            "https://app.example/zk/x-popup?code=abc123&state=job7%7Enonce"
        );
    }

    #[test]
    fn a_denied_consent_forwards_the_error_so_the_popup_can_report_it() {
        let t = x_popup_target(
            "https://app.example",
            Some("error=access_denied&error_description=user+said+no&state=job7~n"),
        )
        .unwrap();
        let q = t.query().unwrap();
        assert!(q.contains("error=access_denied"));
        assert!(
            q.contains("error_description=user+said+no")
                || q.contains("user%20said%20no")
        );
        assert!(q.contains("state=job7"));
    }

    /// The parent resolves the platform from the jobId in `state`, so a relay
    /// that dropped unknown params but kept `state` still works — but anything
    /// NOT on the list must not ride along into the app's URL.
    #[test]
    fn unknown_params_are_dropped() {
        let t = x_popup_target(
            "https://app.example",
            Some("code=c&state=s&redirect=https://evil.example&__proto__=x"),
        )
        .unwrap();
        assert!(!t.as_str().contains("evil.example"));
        assert!(!t.as_str().contains("__proto__"));
        assert!(t.as_str().contains("code=c"));
    }

    #[test]
    fn no_query_still_bounces_to_the_app() {
        let t = x_popup_target("https://app.example", None).unwrap();
        assert_eq!(t.as_str(), "https://app.example/zk/x-popup");
    }

    #[test]
    fn the_bounce_is_a_redirect_with_no_store_and_no_referrer() {
        let r = x_popup_response("https://app.example", Some("code=c&state=s")).unwrap();
        assert!(r.status().is_redirection());
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(r.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(
            r.headers()[header::LOCATION],
            "https://app.example/zk/x-popup?code=c&state=s"
        );
    }

    #[test]
    fn an_unusable_app_url_is_refused_rather_than_bounced_anywhere() {
        assert!(x_popup_response("http://app.example", Some("code=c")).is_err());
        assert!(x_popup_response("javascript:alert(1)", None).is_err());
        assert_eq!(
            x_popup_response("https://app.example", None)
                .unwrap()
                .status(),
            StatusCode::SEE_OTHER
        );
    }
}
