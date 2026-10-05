//! Range-segmented large-file download.
//!
//! Files of at least `min_size` from servers advertising `Accept-Ranges` are
//! split into equal ranges fetched concurrently under the shared per-host
//! budget. Every segment must answer 206 with a matching `Content-Range`; the
//! reassembled file is hash-verified before being renamed into place.

use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use reqwest::header::{ACCEPT_ENCODING, ACCEPT_RANGES, CONTENT_RANGE, RANGE};
use reqwest::{Client, StatusCode};
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use url::Url;

use super::budget::Budget;
use super::watchdog::{RateTracker, WatchdogConfig, WatchdogError, next_chunk_watchdog};
use crate::config::model::GlobalConfig;
use crate::core::types::{DigestAlgo, DigestSet};

#[derive(Debug, Clone, Copy)]
pub struct SegmentedConfig {
    /// Smaller files use a single connection.
    pub min_size: u64,
    /// Preferred segment count (capped at 8).
    pub segments: usize,
    /// Minimum segment size; smaller splits are pure overhead.
    pub segment_min_size: u64,
    pub watchdog: WatchdogConfig,
}

impl Default for SegmentedConfig {
    fn default() -> Self {
        Self {
            min_size: 256 * 1024 * 1024,
            segments: 4,
            segment_min_size: 32 * 1024 * 1024,
            watchdog: WatchdogConfig::default(),
        }
    }
}

impl From<&GlobalConfig> for SegmentedConfig {
    /// `global.segment_min_size` maps to `min_size` (the threshold), not
    /// `segment_min_size`.
    fn from(g: &GlobalConfig) -> Self {
        Self {
            min_size: g.segment_min_size,
            segments: g.segments_per_file,
            watchdog: WatchdogConfig::from(g),
            ..Self::default()
        }
    }
}

impl SegmentedConfig {
    /// Segment count for `size`, bounded by `segments` and `segment_min_size`.
    #[must_use]
    pub fn segments_for(&self, size: u64) -> usize {
        let capped = self.segments.clamp(1, 8);
        let by_min = if self.segment_min_size == 0 {
            capped
        } else {
            let by_min = size.checked_div(self.segment_min_size).unwrap_or(1).max(1) as usize;
            by_min.min(capped)
        };
        by_min.max(1)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SegmentError {
    #[error("I/O on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("upstream refused Range (returned status {0})")]
    NoRangeSupport(StatusCode),
    #[error("segment {segment}: expected 206, got {status}")]
    UnexpectedStatus { segment: usize, status: StatusCode },
    #[error("segment {segment}: watchdog tripped: {msg}")]
    Watchdog { segment: usize, msg: String },
    #[error(
        "segment {segment}: upstream sent {got} bytes, expected {expected} for range {start}..={end}"
    )]
    SegmentSize {
        segment: usize,
        start: u64,
        end: u64,
        expected: u64,
        got: u64,
    },
    #[error("digest mismatch after reassembly: {algo:?} expected `{expected}`, got `{actual}`")]
    DigestMismatch {
        algo: DigestAlgo,
        expected: String,
        actual: String,
    },
    #[error("no strong digest available to verify segmented download")]
    NoStrongDigest,
    #[error("segment {segment}: Content-Range missing on 206 response")]
    ContentRangeMissing { segment: usize },
    #[error(
        "segment {segment}: Content-Range mismatch — requested {}-{}, upstream sent {}-{}",
        requested.0, requested.1, got.0, got.1
    )]
    ContentRangeMismatch {
        segment: usize,
        requested: (u64, u64),
        got: (u64, u64),
    },
    #[error("worker task join failed: {0}")]
    Join(String),
}

/// Parse `bytes start-end/total` into `(start, end)`.
fn parse_content_range(v: Option<&reqwest::header::HeaderValue>) -> Option<(u64, u64)> {
    let s = v?.to_str().ok()?;
    let rest = s.strip_prefix("bytes ")?;
    let range_part = rest.split('/').next()?;
    let mut iter = range_part.splitn(2, '-');
    let start = iter.next()?.parse::<u64>().ok()?;
    let end = iter.next()?.parse::<u64>().ok()?;
    Some((start, end))
}

/// Whether a HEAD advertises `Accept-Ranges: bytes`; a non-2xx is `false`.
///
/// # Errors
///
/// Transport-level reqwest errors.
pub async fn probe_range_support(client: &Client, url: &Url) -> Result<bool, reqwest::Error> {
    let resp = client.head(url.clone()).send().await?;
    if !resp.status().is_success() {
        return Ok(false);
    }
    let accepts = resp
        .headers()
        .get(ACCEPT_RANGES)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.to_ascii_lowercase().contains("bytes"));
    Ok(accepts)
}

/// Download `url` in segments and atomically replace `dest` with the
/// verified file. The caller has already checked Range support. Failure
/// leaves the `.tmp~` sidecar behind.
///
/// # Errors
///
/// [`SegmentError`]; `NoStrongDigest` unless `expected` has SHA-256/512.
pub async fn download_segmented(
    client: &Client,
    budget: &Budget,
    url: &Url,
    dest: &Path,
    size: u64,
    expected: &DigestSet,
    cfg: &SegmentedConfig,
) -> Result<(), SegmentError> {
    if expected
        .get(DigestAlgo::Sha256)
        .or(expected.get(DigestAlgo::Sha512))
        .is_none()
    {
        return Err(SegmentError::NoStrongDigest);
    }
    let tmp_path = tmp_path(dest);
    if let Some(parent) = tmp_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SegmentError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let file = {
        let tmp = tmp_path.clone();
        tokio::task::spawn_blocking(move || {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            f.set_len(0)?;
            Ok::<_, io::Error>(f)
        })
        .await
        .map_err(|e| SegmentError::Join(e.to_string()))?
        .map_err(|e| SegmentError::Io {
            path: tmp_path.clone(),
            source: e,
        })?
    };
    let file = Arc::new(file);

    let segments = cfg.segments_for(size);
    let base_seg = size / segments as u64;
    let mut handles: Vec<JoinHandle<Result<(), SegmentError>>> = Vec::new();
    for i in 0..segments {
        let start = i as u64 * base_seg;
        let end = if i + 1 == segments {
            size - 1
        } else {
            (i as u64 + 1) * base_seg - 1
        };
        let range_len = end - start + 1;
        let range_header = format!("bytes={start}-{end}");
        let file_c = Arc::clone(&file);
        let client_c = client.clone();
        let url_c = url.clone();
        let budget_c = budget.clone();
        let watchdog_cfg = cfg.watchdog;
        handles.push(tokio::spawn(async move {
            fetch_segment(
                i,
                client_c,
                budget_c,
                url_c,
                range_header,
                start,
                range_len,
                file_c,
                watchdog_cfg,
            )
            .await
        }));
    }

    for h in handles {
        h.await.map_err(|e| SegmentError::Join(e.to_string()))??;
    }

    let algo = if expected.get(DigestAlgo::Sha512).is_some() {
        DigestAlgo::Sha512
    } else {
        DigestAlgo::Sha256
    };
    let expected_hex = expected
        .get(algo)
        .map(|d| hex_of(&d.bytes))
        .expect("guarded above");
    let tmp_c = tmp_path.clone();
    let actual_hex = tokio::task::spawn_blocking(move || hash_file(&tmp_c, algo))
        .await
        .map_err(|e| SegmentError::Join(e.to_string()))?
        .map_err(|e| SegmentError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
    if !actual_hex.eq_ignore_ascii_case(&expected_hex) {
        return Err(SegmentError::DigestMismatch {
            algo,
            expected: expected_hex,
            actual: actual_hex,
        });
    }
    let final_path = dest.to_path_buf();
    let tmp_final = tmp_path.clone();
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        let f = std::fs::File::open(&tmp_final)?;
        f.sync_data()?;
        std::fs::rename(&tmp_final, &final_path)?;
        Ok(())
    })
    .await
    .map_err(|e| SegmentError::Join(e.to_string()))?
    .map_err(|e| SegmentError::Io {
        path: dest.to_path_buf(),
        source: e,
    })?;
    // One pacer credit per file, not per segment (see fetch_segment).
    budget.note_success(url.host_str().unwrap_or(""));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn fetch_segment(
    segment: usize,
    client: Client,
    budget: Budget,
    url: Url,
    range_header: String,
    start: u64,
    range_len: u64,
    file: Arc<std::fs::File>,
    watchdog_cfg: WatchdogConfig,
) -> Result<(), SegmentError> {
    let _permit = budget.acquire(&url).await;
    let resp = client
        .get(url.clone())
        .header(RANGE, &range_header)
        .header(ACCEPT_ENCODING, "identity")
        .send()
        .await?;
    let status = resp.status();
    if status != StatusCode::PARTIAL_CONTENT {
        // 200 means the server ignored Range.
        return Err(SegmentError::UnexpectedStatus { segment, status });
    }
    // A wrong range would be written at the wrong offset and only caught by
    // the final hash, after the whole download is wasted.
    let expected_end = start + range_len - 1;
    match parse_content_range(resp.headers().get(CONTENT_RANGE)) {
        Some((got_start, got_end)) if got_start == start && got_end == expected_end => {}
        Some((got_start, got_end)) => {
            return Err(SegmentError::ContentRangeMismatch {
                segment,
                requested: (start, expected_end),
                got: (got_start, got_end),
            });
        }
        None => {
            return Err(SegmentError::ContentRangeMissing { segment });
        }
    }
    let mut stream = resp.bytes_stream();
    let mut tracker = RateTracker::new(Instant::now());
    let mut written = 0u64;
    let mut offset = start;
    loop {
        match next_chunk_watchdog(&mut stream, &watchdog_cfg, &mut tracker).await {
            Ok(Some(chunk)) => {
                let bytes: Bytes = chunk;
                let off = offset;
                let file_c = Arc::clone(&file);
                let chunk_len = bytes.len() as u64;
                tokio::task::spawn_blocking(move || file_c.write_all_at(&bytes, off))
                    .await
                    .map_err(|e| SegmentError::Join(e.to_string()))?
                    .map_err(|e| SegmentError::Io {
                        path: PathBuf::from("(segment tmp)"),
                        source: e,
                    })?;
                offset += chunk_len;
                written += chunk_len;
            }
            Ok(None) => break,
            Err(WatchdogError::Stream(msg)) => {
                warn!(segment, %msg, "segment upstream stream error");
                return Err(SegmentError::Watchdog { segment, msg });
            }
            Err(e @ WatchdogError::Idle { .. }) | Err(e @ WatchdogError::Slow { .. }) => {
                return Err(SegmentError::Watchdog {
                    segment,
                    msg: e.to_string(),
                });
            }
        }
    }
    // No pacer credit here: per-segment credits would regrow the host cap
    // N times faster than single-connection downloads.
    let _ = budget;
    if written != range_len {
        return Err(SegmentError::SegmentSize {
            segment,
            start,
            end: start + range_len - 1,
            expected: range_len,
            got: written,
        });
    }
    debug!(segment, %range_header, written, "segment complete");
    // Keeps the `Duration` import used in non-test builds.
    let _ = Duration::from_secs(0);
    Ok(())
}

fn tmp_path(dest: &Path) -> PathBuf {
    let mut buf = dest.as_os_str().to_owned();
    buf.push(".tmp~");
    PathBuf::from(buf)
}

fn hash_file(path: &Path, algo: DigestAlgo) -> io::Result<String> {
    use io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buf = [0u8; 64 * 1024];
    match algo {
        DigestAlgo::Sha256 => {
            let mut h = Sha256::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(hex_of(h.finalize()))
        }
        DigestAlgo::Sha512 => {
            let mut h = Sha512::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(hex_of(h.finalize()))
        }
        DigestAlgo::Sha1 | DigestAlgo::Md5 => {
            // Unreachable: rejected by `download_segmented`.
            let _ = Sha1::new();
            Err(io::Error::other("segmented download refuses weak digests"))
        }
    }
}

fn hex_of(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let s = bytes.as_ref();
    let mut out = String::with_capacity(s.len() * 2);
    for &b in s {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_global_takes_segment_settings_and_idle_timeout() {
        let mut g = GlobalConfig::default();
        let default = SegmentedConfig::from(&g);
        let builtin = SegmentedConfig::default();
        assert_eq!(default.min_size, builtin.min_size);
        assert_eq!(default.segments, builtin.segments);
        assert_eq!(default.segment_min_size, builtin.segment_min_size);
        assert_eq!(default.watchdog.idle_timeout, builtin.watchdog.idle_timeout);

        g.segments_per_file = 2;
        g.segment_min_size = 64 * 1024 * 1024;
        g.timeout.read_idle = Duration::from_secs(9);
        let cfg = SegmentedConfig::from(&g);
        assert_eq!(cfg.segments, 2);
        assert_eq!(cfg.min_size, 64 * 1024 * 1024);
        assert_eq!(cfg.watchdog.idle_timeout, Duration::from_secs(9));
    }

    #[test]
    fn segments_for_respects_min_size() {
        let cfg = SegmentedConfig {
            min_size: 256 * 1024 * 1024,
            segments: 8,
            segment_min_size: 32 * 1024 * 1024,
            watchdog: WatchdogConfig::default(),
        };
        assert_eq!(cfg.segments_for(64 * 1024 * 1024), 2);
        assert_eq!(cfg.segments_for(512 * 1024 * 1024), 8);
        assert_eq!(cfg.segments_for(40 * 1024 * 1024), 1);
    }

    #[test]
    fn segments_for_never_zero() {
        let cfg = SegmentedConfig::default();
        assert_eq!(cfg.segments_for(0), 1);
        assert_eq!(cfg.segments_for(1), 1);
    }

    #[test]
    fn segments_for_caps_at_eight() {
        let cfg = SegmentedConfig {
            segments: 32,
            ..SegmentedConfig::default()
        };
        assert_eq!(cfg.segments_for(u64::MAX), 8);
    }

    #[test]
    fn tmp_path_appends_suffix() {
        let p = tmp_path(Path::new("/a/b/c.deb"));
        assert_eq!(p, PathBuf::from("/a/b/c.deb.tmp~"));
    }

    #[test]
    fn parse_content_range_bytes_form() {
        use reqwest::header::HeaderValue;
        let h = HeaderValue::from_static("bytes 100-199/1000");
        assert_eq!(parse_content_range(Some(&h)), Some((100, 199)));
    }

    #[test]
    fn parse_content_range_star_length_ok() {
        use reqwest::header::HeaderValue;
        let h = HeaderValue::from_static("bytes 0-511/*");
        assert_eq!(parse_content_range(Some(&h)), Some((0, 511)));
    }

    #[test]
    fn parse_content_range_missing_and_malformed() {
        use reqwest::header::HeaderValue;
        assert_eq!(parse_content_range(None), None);
        let h = HeaderValue::from_static("junk");
        assert_eq!(parse_content_range(Some(&h)), None);
        let h = HeaderValue::from_static("bytes NaN-99/500");
        assert_eq!(parse_content_range(Some(&h)), None);
    }
}
