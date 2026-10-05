//! reqwest client wrapper.
//!
//! Content decoding is disabled and `Accept-Encoding: identity` is forced:
//! `.gz`/`.xz` indexes must stay byte-identical to upstream.

use std::net::IpAddr;
use std::time::Duration;

use reqwest::header::{ACCEPT_ENCODING, HeaderMap, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH};
use reqwest::{Client, Response};
use url::Url;

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
            // Per-mirror `force_http1` is applied later by the engine.
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
    let mut builder = Client::builder()
        .user_agent(cfg.user_agent.clone())
        .connect_timeout(cfg.connect_timeout)
        // No total timeout: multi-GB files make any value wrong; stalls are
        // caught by the read-idle + min-throughput watchdog.
        .pool_idle_timeout(cfg.idle_timeout)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .redirect(reqwest::redirect::Policy::limited(10));

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
        .build()
        .map_err(|e| ClientError::Build(e.to_string()))
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

    let response = req
        .send()
        .await
        .map_err(|e| ClientError::Request(e.to_string()))?;
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
    #[error("HTTP request failed: {0}")]
    Request(String),
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
