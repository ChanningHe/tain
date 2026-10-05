//! Pool-file download primitives.

use std::path::Path;
use std::time::Instant;

use reqwest::{Client, StatusCode};
use sha2::{Digest as _, Sha256};
use tracing::warn;

use crate::config::model::GlobalConfig;
use crate::core::fetch::budget::Budget;
use crate::core::fetch::client::{CacheValidators, fetch_get};
use crate::core::fetch::segmented::{SegmentedConfig, download_segmented, probe_range_support};
use crate::core::fetch::sink::HashingSink;
use crate::core::fetch::watchdog::{
    RateTracker, WatchdogConfig, WatchdogError, next_chunk_watchdog, parse_retry_after,
};
use crate::core::types::{DigestAlgo, DigestSet};

use super::AptFlowError;
use super::hex::{hex_of, hex_of_digest_algo};

/// Download settings from `[global]`.
#[derive(Debug, Clone, Copy)]
pub struct FetchTuning {
    pub retry_count: u32,
    pub segmented: SegmentedConfig,
    pub watchdog: WatchdogConfig,
}

impl From<&GlobalConfig> for FetchTuning {
    fn from(g: &GlobalConfig) -> Self {
        Self {
            retry_count: g.retry.count,
            segmented: SegmentedConfig::from(g),
            watchdog: WatchdogConfig::from(g),
        }
    }
}

/// Segmented download for large files on range-capable hosts, else
/// [`download_verified`].
pub(super) async fn download_pool_file(
    budget: &Budget,
    client: &Client,
    url: &url::Url,
    dest: &Path,
    expected: DigestSet,
    size: Option<u64>,
    tuning: &FetchTuning,
) -> Result<(), AptFlowError> {
    let seg_cfg = &tuning.segmented;
    if let Some(sz) = size
        && sz >= seg_cfg.min_size
    {
        let supports_range = probe_range_support(client, url).await.unwrap_or(false);
        if supports_range {
            match download_segmented(client, budget, url, dest, sz, &expected, seg_cfg).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(%url, %e, "segmented download failed — falling back to single-connection");
                }
            }
        }
    }
    download_verified(
        budget,
        client,
        url,
        dest,
        expected,
        size,
        tuning.retry_count,
        tuning.watchdog,
    )
    .await
}

/// Single-connection GET with hash + size verification, retrying 429/503
/// per `Retry-After` within `retry_count`.
///
/// Public so integration tests can drive the pacer and watchdog directly.
#[allow(clippy::too_many_arguments)]
pub async fn download_verified(
    budget: &Budget,
    client: &Client,
    url: &url::Url,
    dest: &Path,
    expected: DigestSet,
    size: Option<u64>,
    retry_count: u32,
    watchdog_cfg: WatchdogConfig,
) -> Result<(), AptFlowError> {
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    // 429/503 share the bounded retry budget so a hostile 429 stream can't
    // stall forever. `retry_count` counts retries, not attempts.
    let max_attempts: usize = (retry_count as usize).saturating_add(1).max(1);
    for attempt in 1..=max_attempts {
        let _permit = budget.acquire(url).await;
        let resp = fetch_get(client, url, &CacheValidators::default()).await?;
        // Only 429/503 are retried here; other failures are hard errors.
        if matches!(
            resp.status,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
        ) {
            let retry_after = resp
                .response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after)
                .unwrap_or(std::time::Duration::from_secs(30));
            budget.throttle_host(&host, retry_after);
            tracing::warn!(
                %url,
                status = %resp.status,
                ?retry_after,
                attempt,
                "upstream throttled (429/503) — backing off + shrinking per-host budget"
            );
            if attempt == max_attempts {
                return Err(AptFlowError::UpstreamStatus {
                    url: url.clone(),
                    status: resp.status,
                });
            }
            continue;
        }
        if !resp.status.is_success() {
            return Err(AptFlowError::UpstreamStatus {
                url: url.clone(),
                status: resp.status,
            });
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AptFlowError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let mut sink = HashingSink::new(dest.to_path_buf(), expected.clone(), size).await?;
        let mut tracker = RateTracker::new(Instant::now());
        let mut stream = resp.response.bytes_stream();
        loop {
            match next_chunk_watchdog(&mut stream, &watchdog_cfg, &mut tracker).await {
                Ok(Some(chunk)) => sink.write(&chunk).await?,
                Ok(None) => break,
                Err(WatchdogError::Stream(msg)) => {
                    return Err(AptFlowError::BodyRead {
                        url: url.clone(),
                        msg,
                    });
                }
                Err(e @ WatchdogError::Idle { .. }) | Err(e @ WatchdogError::Slow { .. }) => {
                    return Err(AptFlowError::WatchdogTripped {
                        url: url.clone(),
                        msg: e.to_string(),
                    });
                }
            }
        }
        sink.finish().await?;
        budget.note_success(&host);
        return Ok(());
    }
    Err(AptFlowError::UpstreamStatus {
        url: url.clone(),
        status: StatusCode::SERVICE_UNAVAILABLE,
    })
}

pub(super) async fn is_already_present(
    local: &Path,
    expected_size: Option<u64>,
    expected: &DigestSet,
) -> Result<bool, AptFlowError> {
    let meta = match tokio::fs::metadata(local).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(AptFlowError::Io {
                path: local.to_path_buf(),
                source: e,
            });
        }
    };
    if let Some(want) = expected_size
        && meta.len() != want
    {
        return Ok(false);
    }
    // Streamed so multi-GB files (d-i ISOs) aren't read into memory.
    let Some(want) = hex_of_digest_algo(expected, DigestAlgo::Sha256) else {
        return Ok(false);
    };
    let local_path = local.to_path_buf();
    let actual = tokio::task::spawn_blocking(move || -> std::io::Result<String> {
        use std::io::Read;
        let mut file = std::fs::File::open(&local_path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex_of(hasher.finalize()))
    })
    .await
    .map_err(|e| AptFlowError::Io {
        path: local.to_path_buf(),
        source: std::io::Error::other(e.to_string()),
    })?
    .map_err(|e| AptFlowError::Io {
        path: local.to_path_buf(),
        source: e,
    })?;
    Ok(actual == want)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::GlobalConfig;
    use std::time::Duration;

    #[test]
    fn fetch_tuning_carries_global_download_settings() {
        let mut g = GlobalConfig::default();
        g.retry.count = 7;
        g.segments_per_file = 3;
        g.segment_min_size = 128 * 1024 * 1024;
        g.timeout.read_idle = Duration::from_secs(15);

        let t = FetchTuning::from(&g);
        assert_eq!(t.retry_count, 7);
        assert_eq!(t.segmented.segments, 3);
        assert_eq!(t.segmented.min_size, 128 * 1024 * 1024);
        assert_eq!(t.segmented.watchdog.idle_timeout, Duration::from_secs(15));
        assert_eq!(t.watchdog.idle_timeout, Duration::from_secs(15));
    }
}
