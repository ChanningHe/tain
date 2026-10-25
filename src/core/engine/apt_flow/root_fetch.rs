//! Bounded fetches of suite root files (`InRelease` / `Release` /
//! `Release.gpg`): capped in size, stall-limited by the watchdog, counted
//! against the per-host budget, and retried on transient failures within
//! `retry.count`.

use std::time::Duration;

use reqwest::{Client, StatusCode};
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::core::fetch::budget::Budget;
use crate::core::fetch::client::{CacheValidators, ClientError, FetchResponse, fetch_get};
use crate::core::fetch::retry::{BACKOFF_BASE, BACKOFF_MAX, full_jitter};
use crate::core::fetch::watchdog::{
    DEFAULT_RETRY_AFTER, RateTracker, WatchdogConfig, WatchdogError, next_chunk_watchdog,
    parse_retry_after,
};

use super::AptFlowError;
use super::pool_download::FetchTuning;

/// Debian's largest InRelease is ~250 KiB; anything near this is hostile.
pub(super) const MAX_RELEASE_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_SIGNATURE_BYTES: usize = 1024 * 1024;

pub(super) enum SmallFetch {
    NotModified,
    /// Any other non-2xx status; the body is discarded unread.
    Status(StatusCode),
    Body {
        bytes: Vec<u8>,
        validators: CacheValidators,
    },
}

/// "Not there" for optional root files. S3-style hosts answer 403 for a
/// missing object; 408/429 are transient and must not read as absence.
pub(super) fn is_absent_status(status: StatusCode) -> bool {
    status.is_client_error() && !is_transient_status(status)
}

fn is_transient_status(status: StatusCode) -> bool {
    status.is_server_error()
        || matches!(
            status,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
        )
}

/// Worth another attempt: transport trouble, stalls, 5xx/408/429. A
/// `ClientError::Refused` (certificate, redirect policy, bad URL) is
/// permanent, as on the pool path.
fn is_transient(e: &AptFlowError) -> bool {
    match e {
        AptFlowError::Client(ClientError::Request(_))
        | AptFlowError::WatchdogTripped { .. }
        | AptFlowError::BodyRead { .. } => true,
        AptFlowError::UpstreamStatus { status, .. } => is_transient_status(*status),
        _ => false,
    }
}

/// Full-jitter backoff before retry number `attempt + 1` (`attempt` counts
/// from 0 here, from 1 in [`full_jitter`]).
fn backoff(attempt: u32) -> Duration {
    full_jitter(BACKOFF_BASE, attempt.saturating_add(1), BACKOFF_MAX)
}

pub(super) fn unexpected_status(url: &url::Url, fetched: SmallFetch) -> AptFlowError {
    let status = match fetched {
        SmallFetch::Status(status) => status,
        SmallFetch::NotModified | SmallFetch::Body { .. } => StatusCode::NOT_MODIFIED,
    };
    AptFlowError::UpstreamStatus {
        url: url.clone(),
        status,
    }
}

#[derive(Clone, Copy)]
pub(super) struct RootFetcher<'a> {
    pub(super) client: &'a Client,
    pub(super) budget: &'a Budget,
    pub(super) tuning: &'a FetchTuning,
}

impl RootFetcher<'_> {
    /// GET a small metadata file into memory, bounded in size (`cap`) and
    /// time, retrying transient failures up to `retry.count` times with
    /// exponential backoff (or the server's `Retry-After`). A budget permit
    /// is held per attempt only, never across the backoff sleep.
    pub(super) async fn small(
        &self,
        url: &url::Url,
        validators: &CacheValidators,
        cap: usize,
    ) -> Result<SmallFetch, AptFlowError> {
        let mut attempt: u32 = 0;
        loop {
            let (result, retry_after) = {
                let _permit = self.budget.acquire(url).await;
                self.once(url, validators, cap).await
            };
            let transient = match &result {
                Ok(SmallFetch::Status(status)) => is_transient_status(*status),
                Ok(_) => false,
                Err(e) => is_transient(e),
            };
            if !transient || attempt >= self.tuning.retry_count {
                return result;
            }
            let delay = retry_after.unwrap_or_else(|| backoff(attempt));
            warn!(%url, attempt = attempt + 1, ?delay, "transient root-file fetch failure — retrying");
            tokio::time::sleep(delay).await;
            attempt += 1;
        }
    }

    /// One attempt, plus the server's `Retry-After` on a 429/503 (which
    /// also throttles the host in the shared pacer).
    async fn once(
        &self,
        url: &url::Url,
        validators: &CacheValidators,
        cap: usize,
    ) -> (Result<SmallFetch, AptFlowError>, Option<Duration>) {
        let watchdog = &self.tuning.watchdog;
        let host = url.host_str().unwrap_or("");
        let resp = match tokio::time::timeout(
            watchdog.idle_timeout,
            fetch_get(self.client, url, validators),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return (Err(e.into()), None),
            Err(_) => {
                let e = AptFlowError::WatchdogTripped {
                    url: url.clone(),
                    msg: format!("no response headers within {:?}", watchdog.idle_timeout),
                };
                return (Err(e), None);
            }
        };
        if resp.status == StatusCode::NOT_MODIFIED {
            self.budget.note_success(host);
            return (Ok(SmallFetch::NotModified), None);
        }
        if !resp.status.is_success() {
            let retry_after = resp
                .headers
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after);
            if matches!(
                resp.status,
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
            ) {
                self.budget
                    .throttle_host(host, retry_after.unwrap_or(DEFAULT_RETRY_AFTER));
            }
            return (Ok(SmallFetch::Status(resp.status)), retry_after);
        }
        let result = read_capped(resp, url, watchdog, cap).await;
        if result.is_ok() {
            self.budget.note_success(host);
        }
        (result, None)
    }

    /// Unconditional GET that must succeed.
    pub(super) async fn required(
        &self,
        url: &url::Url,
    ) -> Result<(Vec<u8>, CacheValidators), AptFlowError> {
        let validators = CacheValidators::default();
        match self.small(url, &validators, MAX_RELEASE_BYTES).await? {
            SmallFetch::Body { bytes, validators } => Ok((bytes, validators)),
            other => Err(unexpected_status(url, other)),
        }
    }

    /// Unconditional GET of a root file that may legitimately be missing.
    pub(super) async fn optional(
        &self,
        url: &url::Url,
        cap: usize,
    ) -> Result<Option<Vec<u8>>, AptFlowError> {
        match self.small(url, &CacheValidators::default(), cap).await? {
            SmallFetch::Body { bytes, .. } => Ok(Some(bytes)),
            SmallFetch::Status(status) if is_absent_status(status) => {
                debug!(%url, %status, "optional root file absent");
                Ok(None)
            }
            other => Err(unexpected_status(url, other)),
        }
    }

    /// [`Self::optional`] for a sibling we merely republish: still failing
    /// after the retries, or refused outright (e.g. a CDN redirecting it to
    /// plain http), drops it instead of failing the suite. Oversized bodies
    /// stay fatal — that is hostile, not flaky.
    pub(super) async fn sibling(
        &self,
        url: &url::Url,
        cap: usize,
    ) -> Result<Option<Vec<u8>>, AptFlowError> {
        match self.optional(url, cap).await {
            Err(e)
                if is_transient(&e)
                    || matches!(e, AptFlowError::Client(ClientError::Refused(_))) =>
            {
                warn!(%url, err = %e, "optional root file unavailable — not publishing it");
                Ok(None)
            }
            other => other,
        }
    }
}

async fn read_capped(
    resp: FetchResponse,
    url: &url::Url,
    watchdog: &WatchdogConfig,
    cap: usize,
) -> Result<SmallFetch, AptFlowError> {
    let too_large = || AptFlowError::MetadataTooLarge {
        url: url.clone(),
        limit: cap,
    };
    if resp
        .response
        .content_length()
        .is_some_and(|n| n > cap as u64)
    {
        return Err(too_large());
    }
    let validators = resp.validators();
    let mut stream = resp.response.bytes_stream();
    let mut tracker = RateTracker::new(Instant::now(), watchdog);
    let mut bytes = Vec::new();
    while let Some(chunk) = next_chunk_watchdog(&mut stream, watchdog, &mut tracker)
        .await
        .map_err(|e| watchdog_error(url, e))?
    {
        if bytes.len() + chunk.len() > cap {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(SmallFetch::Body { bytes, validators })
}

fn watchdog_error(url: &url::Url, e: WatchdogError) -> AptFlowError {
    match e {
        WatchdogError::Stream(msg) => AptFlowError::BodyRead {
            url: url.clone(),
            msg,
        },
        other => AptFlowError::WatchdogTripped {
            url: url.clone(),
            msg: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_status_covers_4xx_but_not_transient_ones() {
        assert!(is_absent_status(StatusCode::NOT_FOUND));
        assert!(is_absent_status(StatusCode::FORBIDDEN));
        assert!(is_absent_status(StatusCode::GONE));
        assert!(!is_absent_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(!is_absent_status(StatusCode::REQUEST_TIMEOUT));
        assert!(!is_absent_status(StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn backoff_is_jittered_within_doubling_cap() {
        for _ in 0..50 {
            assert!(backoff(0) <= BACKOFF_BASE);
            assert!(backoff(3) <= BACKOFF_BASE * 8);
            assert!(backoff(10) <= BACKOFF_MAX);
            assert!(backoff(u32::MAX) <= BACKOFF_MAX);
        }
    }

    #[test]
    fn transient_classification() {
        let url = url::Url::parse("http://x/").unwrap();
        let status = |s| AptFlowError::UpstreamStatus {
            url: url.clone(),
            status: s,
        };
        assert!(is_transient(&status(StatusCode::BAD_GATEWAY)));
        assert!(is_transient(&status(StatusCode::TOO_MANY_REQUESTS)));
        assert!(!is_transient(&status(StatusCode::FORBIDDEN)));
        assert!(!is_transient(&AptFlowError::MetadataTooLarge {
            url: url.clone(),
            limit: 1
        }));
        assert!(is_transient(&AptFlowError::WatchdogTripped {
            url,
            msg: String::new()
        }));
        assert!(is_transient(&AptFlowError::Client(ClientError::Request(
            "connection reset".into()
        ))));
        assert!(!is_transient(&AptFlowError::Client(ClientError::Refused(
            "invalid peer certificate".into()
        ))));
    }
}
