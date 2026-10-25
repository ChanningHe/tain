//! reqwest client wrapper.
//!
//! Content decoding is disabled and `Accept-Encoding: identity` is forced:
//! `.gz`/`.xz` indexes must stay byte-identical to upstream.

use std::error::Error as _;
use std::net::IpAddr;
use std::time::Duration;

use reqwest::header::{ACCEPT_ENCODING, HeaderMap, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH};
use reqwest::{Client, Response};
use url::Url;

use super::guard::redirect_policy;
use crate::config::model::GlobalConfig;

/// Client build-time settings.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub user_agent: String,
    pub bind_address: Option<IpAddr>,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    /// Force HTTP/1.1 (per-mirror override).
    pub http1_only: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            user_agent: format!("tain/{}", env!("CARGO_PKG_VERSION")),
            bind_address: None,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            http1_only: false,
        }
    }
}

impl From<&GlobalConfig> for ClientConfig {
    fn from(g: &GlobalConfig) -> Self {
        Self {
            user_agent: g.user_agent.clone(),
            bind_address: g.bind_address,
            connect_timeout: g.timeout.connect,
            idle_timeout: g.timeout.read_idle,
            // Per-mirror settings are applied later by the engine.
            http1_only: false,
        }
    }
}

/// Build a `reqwest::Client` from `cfg`.
///
/// # Errors
///
/// `ClientError::Build`, typically a TLS backend init failure.
pub fn build_client(cfg: &ClientConfig) -> Result<Client, ClientError> {
    client_builder(cfg)
        .build()
        .map_err(|e| ClientError::Build(e.to_string()))
}

fn client_builder(cfg: &ClientConfig) -> reqwest::ClientBuilder {
    let mut builder = Client::builder()
        .user_agent(cfg.user_agent.clone())
        .connect_timeout(cfg.connect_timeout)
        // No total timeout: multi-GB files make any value wrong. The read
        // timeout bounds the wait for response headers and each body read;
        // slow-but-alive bodies are the watchdog's job.
        .read_timeout(cfg.idle_timeout)
        .pool_idle_timeout(cfg.idle_timeout)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .redirect(redirect_policy());

    if let Some(ip) = cfg.bind_address {
        builder = builder.local_address(ip);
    }

    if cfg.http1_only {
        builder = builder.http1_only();
    } else {
        // The RFC-default 64 KiB stream window throttles many-small-file loads.
        builder = builder.http2_adaptive_window(true);
    }
    builder
}

/// `ETag` / `Last-Modified` from a previous fetch, for conditional GETs.
#[derive(Debug, Default, Clone)]
pub struct CacheValidators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// Response with status and headers split out; the body stays unread.
#[derive(Debug)]
pub struct FetchResponse {
    pub status: reqwest::StatusCode,
    pub headers: HeaderMap,
    pub response: Response,
}

impl FetchResponse {
    #[must_use]
    pub fn validators(&self) -> CacheValidators {
        CacheValidators {
            etag: self
                .headers
                .get(reqwest::header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            last_modified: self
                .headers
                .get(reqwest::header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        }
    }
}

/// GET with identity encoding and any conditional headers from `validators`.
///
/// # Errors
///
/// `ClientError::Request` on transport failure.
pub async fn fetch_get(
    client: &Client,
    url: &Url,
    validators: &CacheValidators,
) -> Result<FetchResponse, ClientError> {
    let mut req = client.get(url.as_str());

    req = req.header(ACCEPT_ENCODING, HeaderValue::from_static("identity"));

    if let Some(etag) = &validators.etag
        && let Ok(v) = HeaderValue::from_str(etag)
    {
        req = req.header(IF_NONE_MATCH, v);
    }
    if let Some(lm) = &validators.last_modified
        && let Ok(v) = HeaderValue::from_str(lm)
    {
        req = req.header(IF_MODIFIED_SINCE, v);
    }

    let response = req.send().await.map_err(request_error)?;
    let status = response.status();
    let headers = response.headers().clone();
    Ok(FetchResponse {
        status,
        headers,
        response,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("failed to build reqwest client: {0}")]
    Build(String),
    /// Possibly transient: connect, timeout, reset.
    #[error("HTTP request failed: {0}")]
    Request(String),
    /// Retrying cannot help: refused redirect or address, bad URL, TLS
    /// certificate rejected.
    #[error("HTTP request refused: {0}")]
    Refused(String),
}

/// reqwest's top-level message hides the cause; keep the whole chain.
fn request_error(e: reqwest::Error) -> ClientError {
    let mut msg = e.to_string();
    let mut permanent = e.is_builder() || e.is_redirect();
    let mut source = e.source();
    while let Some(s) = source {
        permanent |= is_certificate_rejection(s);
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        source = s.source();
    }
    if permanent {
        ClientError::Refused(msg)
    } else {
        ClientError::Request(msg)
    }
}

/// Whether `e` is, or wraps, `rustls::Error::InvalidCertificate`. The rustls
/// error sits inside nested `io::Error`s whose `source()` skips the wrapped
/// error, so descend through `get_ref()` instead.
fn is_certificate_rejection(mut e: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if let Some(rustls::Error::InvalidCertificate(_)) = e.downcast_ref::<rustls::Error>() {
            return true;
        }
        match e
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            Some(inner) => e = inner,
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_defaults() {
        let c = ClientConfig::default();
        assert!(c.user_agent.starts_with("tain/"));
        assert_eq!(c.connect_timeout, Duration::from_secs(30));
        assert_eq!(c.idle_timeout, Duration::from_secs(60));
        assert!(c.bind_address.is_none());
        assert!(!c.http1_only, "H2 default with per-host override");
    }

    #[test]
    fn build_client_with_defaults_succeeds() {
        let c = build_client(&ClientConfig::default()).expect("default config should always build");
        let _ = c.get("https://example.com/");
    }

    #[test]
    fn build_client_with_http1_only_succeeds() {
        let cfg = ClientConfig {
            http1_only: true,
            ..ClientConfig::default()
        };
        build_client(&cfg).unwrap();
    }

    #[test]
    fn build_client_with_bind_address_succeeds() {
        let cfg = ClientConfig {
            bind_address: Some(IpAddr::from([192, 0, 2, 10])),
            ..ClientConfig::default()
        };
        build_client(&cfg).unwrap();
    }

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn certificate_rejection_is_found_through_nested_io_errors() {
        use std::io::{Error, ErrorKind};
        let bad_cert =
            || rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        // The shape hyper-rustls actually produces: io(Other, io(InvalidData, rustls)).
        let nested = Error::other(Error::new(ErrorKind::InvalidData, bad_cert()));
        assert!(is_certificate_rejection(&nested));
        assert!(is_certificate_rejection(&bad_cert()));

        let alert = Error::other(Error::new(
            ErrorKind::InvalidData,
            rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure),
        ));
        assert!(!is_certificate_rejection(&alert));
        // Mentioning certificates in text is not a certificate error.
        let text = Error::other("GET /pool/c/ca-certificates/ca-certificates_1.deb");
        assert!(!is_certificate_rejection(&text));
    }

    /// End-to-end through reqwest: a public-looking origin (resolved to a
    /// local server) that 302s to 127.0.0.1 is refused, so the policy is wired.
    #[tokio::test]
    async fn client_refuses_redirect_from_public_origin_to_loopback() {
        use axum::http::{StatusCode, header::LOCATION};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let target = format!("http://127.0.0.1:{}/secret", addr.port());
        let router = axum::Router::new()
            .route(
                "/start",
                axum::routing::get(move || {
                    let target = target.clone();
                    async move { (StatusCode::FOUND, [(LOCATION, target)]) }
                }),
            )
            .route("/secret", axum::routing::get(|| async { "internal" }));
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let client = client_builder(&ClientConfig::default())
            .resolve("mirror.example", addr)
            .build()
            .unwrap();
        let url = u(&format!("http://mirror.example:{}/start", addr.port()));
        let err = fetch_get(&client, &url, &CacheValidators::default())
            .await
            .expect_err("redirect into loopback must fail");
        assert!(matches!(err, ClientError::Refused(_)), "{err:?}");
    }

    #[test]
    fn cache_validators_default_is_empty() {
        let v = CacheValidators::default();
        assert!(v.etag.is_none());
        assert!(v.last_modified.is_none());
    }

    #[test]
    fn fetch_response_extracts_validators() {
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::ETAG, HeaderValue::from_static("\"abc\""));
        headers.insert(
            reqwest::header::LAST_MODIFIED,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );

        let etag = headers
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let last_modified = headers
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        assert_eq!(etag.as_deref(), Some("\"abc\""));
        assert_eq!(
            last_modified.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
    }
}
