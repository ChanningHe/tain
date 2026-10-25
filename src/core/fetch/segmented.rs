//! Range-segmented large-file download.
//!
//! Files of at least `min_size` from servers advertising `Accept-Ranges` are
//! split into equal ranges fetched concurrently under the shared per-host
//! budget. Every segment must answer 206 with a matching `Content-Range` and
//! exactly its range's bytes; the reassembled file is hash-verified before
//! being renamed into place.

use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use reqwest::header::{ACCEPT_ENCODING, ACCEPT_RANGES, CONTENT_RANGE, RANGE, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use sha2::{Sha256, Sha512};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{debug, warn};
use url::Url;

use super::budget::Budget;
use super::sink::tmp_path_for;
use super::watchdog::{
    DEFAULT_RETRY_AFTER, RateTracker, WatchdogConfig, WatchdogError, next_chunk_watchdog,
    parse_retry_after,
};
use crate::config::model::{GlobalConfig, MAX_SEGMENTS_PER_FILE};
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
    /// Segment count for `size`: bounded by `segments` (config load enforces
    /// 1..=[`MAX_SEGMENTS_PER_FILE`]; clamped again for direct callers),
    /// `segment_min_size`, and `size` itself so no range is empty.
    #[must_use]
    pub fn segments_for(&self, size: u64) -> usize {
        let capped = self.segments.clamp(1, MAX_SEGMENTS_PER_FILE);
        let by_min = size.checked_div(self.segment_min_size).unwrap_or(u64::MAX);
        let n = by_min.min(size).min(capped as u64).max(1);
        usize::try_from(n).expect("n <= MAX_SEGMENTS_PER_FILE")
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
    #[error("segmented download of an empty file")]
    Empty,
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
    #[error("segment {segment}: Content-Range total {got}, expected file size {expected}")]
    ContentRangeTotal {
        segment: usize,
        expected: u64,
        got: u64,
    },
    #[error("worker task join failed: {0}")]
    Join(String),
}

/// `bytes start-end/total` → `(start, end, total)`; `total` is `None` for `*`.
fn parse_content_range(
    v: Option<&reqwest::header::HeaderValue>,
) -> Option<(u64, u64, Option<u64>)> {
    let rest = v?.to_str().ok()?.strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let total = match total {
        "*" => None,
        t => Some(t.parse().ok()?),
    };
    Some((start.parse().ok()?, end.parse().ok()?, total))
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

/// Unlinks the tmp file on drop unless disarmed: a `pwrite` still in flight
/// from an aborted segment then lands in an orphaned inode, never in the
/// file a later download creates at the same path.
struct TmpGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Download `url` in segments and atomically replace `dest` with the
/// verified file. The caller has already checked Range support. On failure
/// or cancellation every segment task is stopped and the `.tmp~` removed.
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
    let algo = if expected.get(DigestAlgo::Sha512).is_some() {
        DigestAlgo::Sha512
    } else if expected.get(DigestAlgo::Sha256).is_some() {
        DigestAlgo::Sha256
    } else {
        return Err(SegmentError::NoStrongDigest);
    };
    if size == 0 {
        return Err(SegmentError::Empty);
    }
    let tmp_path = tmp_path_for(dest);
    let file = {
        let tmp = tmp_path.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(parent) = tmp.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
        })
        .await
        .map_err(|e| SegmentError::Join(e.to_string()))?
        .map_err(|e| SegmentError::Io {
            path: tmp_path.clone(),
            source: e,
        })?
    };
    let mut guard = TmpGuard {
        path: tmp_path.clone(),
        armed: true,
    };
    fetch_all_segments(client, budget, url, size, Arc::new(file), cfg).await?;

    let expected_hex = expected
        .get(algo)
        .map(|d| hex_of(&d.bytes))
        .expect("algo chosen from expected");
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
        std::fs::File::open(&tmp_final)?.sync_data()?;
        std::fs::rename(&tmp_final, &final_path)
    })
    .await
    .map_err(|e| SegmentError::Join(e.to_string()))?
    .map_err(|e| SegmentError::Io {
        path: dest.to_path_buf(),
        source: e,
    })?;
    guard.armed = false;
    // One pacer credit per file, not per segment: per-segment credits would
    // regrow the host cap N times faster than single-connection downloads.
    budget.note_success(url.host_str().unwrap_or(""));
    Ok(())
}

/// Run every segment; on the first failure abort the rest and wait until
/// they have all stopped (and released their permits) before returning.
/// Dropping the returned future aborts them too (`JoinSet` drop).
async fn fetch_all_segments(
    client: &Client,
    budget: &Budget,
    url: &Url,
    size: u64,
    file: Arc<std::fs::File>,
    cfg: &SegmentedConfig,
) -> Result<(), SegmentError> {
    let segments = cfg.segments_for(size);
    let base_seg = size / segments as u64;
    let mut set = JoinSet::new();
    for index in 0..segments {
        let start = index as u64 * base_seg;
        let end = if index + 1 == segments {
            size - 1
        } else {
            start + base_seg - 1
        };
        let seg = Segment {
            index,
            start,
            end,
            file_size: size,
        };
        set.spawn(fetch_segment(
            seg,
            client.clone(),
            budget.clone(),
            url.clone(),
            Arc::clone(&file),
            cfg.watchdog,
        ));
    }
    while let Some(joined) = set.join_next().await {
        let res = joined
            .map_err(|e| SegmentError::Join(e.to_string()))
            .and_then(|r| r);
        if let Err(e) = res {
            set.abort_all();
            while set.join_next().await.is_some() {}
            return Err(e);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Segment {
    index: usize,
    start: u64,
    /// Inclusive.
    end: u64,
    file_size: u64,
}

impl Segment {
    fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    fn size_error(&self, got: u64) -> SegmentError {
        SegmentError::SegmentSize {
            segment: self.index,
            start: self.start,
            end: self.end,
            expected: self.len(),
            got,
        }
    }
}

async fn fetch_segment(
    seg: Segment,
    client: Client,
    budget: Budget,
    url: Url,
    file: Arc<std::fs::File>,
    watchdog_cfg: WatchdogConfig,
) -> Result<(), SegmentError> {
    let segment = seg.index;
    let _permit = budget.acquire(&url).await;
    let resp = client
        .get(url.clone())
        .header(RANGE, format!("bytes={}-{}", seg.start, seg.end))
        .header(ACCEPT_ENCODING, "identity")
        .send()
        .await?;
    let status = resp.status();
    if matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    ) {
        let retry_after = resp
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_retry_after)
            .unwrap_or(DEFAULT_RETRY_AFTER);
        budget.throttle_host(url.host_str().unwrap_or(""), retry_after);
    }
    if status != StatusCode::PARTIAL_CONTENT {
        // 200 means the server ignored Range.
        return Err(SegmentError::UnexpectedStatus { segment, status });
    }
    // A wrong range would be written at the wrong offset and only caught by
    // the final hash, after the whole download is wasted.
    match parse_content_range(resp.headers().get(CONTENT_RANGE)) {
        None => return Err(SegmentError::ContentRangeMissing { segment }),
        Some((s, e, _)) if (s, e) != (seg.start, seg.end) => {
            return Err(SegmentError::ContentRangeMismatch {
                segment,
                requested: (seg.start, seg.end),
                got: (s, e),
            });
        }
        Some((_, _, Some(total))) if total != seg.file_size => {
            return Err(SegmentError::ContentRangeTotal {
                segment,
                expected: seg.file_size,
                got: total,
            });
        }
        Some(_) => {}
    }
    if let Some(cl) = resp.content_length()
        && cl != seg.len()
    {
        return Err(seg.size_error(cl));
    }
    let mut stream = resp.bytes_stream();
    let mut tracker = RateTracker::new(Instant::now(), &watchdog_cfg);
    let mut written = 0u64;
    loop {
        let chunk: Bytes = match next_chunk_watchdog(&mut stream, &watchdog_cfg, &mut tracker).await
        {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(e) => {
                if let WatchdogError::Stream(msg) = &e {
                    warn!(segment, %msg, "segment upstream stream error");
                }
                return Err(SegmentError::Watchdog {
                    segment,
                    msg: e.to_string(),
                });
            }
        };
        let chunk_len = chunk.len() as u64;
        // Never write past the range: it belongs to a sibling segment.
        if written + chunk_len > seg.len() {
            return Err(seg.size_error(written + chunk_len));
        }
        let off = seg.start + written;
        let file_c = Arc::clone(&file);
        tokio::task::spawn_blocking(move || file_c.write_all_at(&chunk, off))
            .await
            .map_err(|e| SegmentError::Join(e.to_string()))?
            .map_err(|e| SegmentError::Io {
                path: PathBuf::from("(segment tmp)"),
                source: e,
            })?;
        written += chunk_len;
    }
    if written != seg.len() {
        return Err(seg.size_error(written));
    }
    debug!(
        segment,
        start = seg.start,
        end = seg.end,
        "segment complete"
    );
    Ok(())
}

fn hash_file(path: &Path, algo: DigestAlgo) -> io::Result<String> {
    use io::Read;
    fn digest<D: sha2::Digest>(mut file: std::fs::File) -> io::Result<String> {
        let mut h = D::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                return Ok(hex_of(h.finalize()));
            }
            h.update(&buf[..n]);
        }
    }
    let file = std::fs::File::open(path)?;
    match algo {
        DigestAlgo::Sha256 => digest::<Sha256>(file),
        DigestAlgo::Sha512 => digest::<Sha512>(file),
        // Unreachable: rejected by `download_segmented`.
        DigestAlgo::Sha1 | DigestAlgo::Md5 => {
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
    use std::time::Duration;

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
    fn segments_for_never_exceeds_size() {
        let cfg = SegmentedConfig {
            segment_min_size: 0,
            ..SegmentedConfig::default()
        };
        assert_eq!(cfg.segments_for(3), 3);
        assert_eq!(cfg.segments_for(0), 1);
        assert_eq!(cfg.segments_for(1 << 40), 4);
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
    fn parse_content_range_bytes_form() {
        use reqwest::header::HeaderValue;
        let h = HeaderValue::from_static("bytes 100-199/1000");
        assert_eq!(parse_content_range(Some(&h)), Some((100, 199, Some(1000))));
    }

    #[test]
    fn parse_content_range_star_length_ok() {
        use reqwest::header::HeaderValue;
        let h = HeaderValue::from_static("bytes 0-511/*");
        assert_eq!(parse_content_range(Some(&h)), Some((0, 511, None)));
    }

    #[test]
    fn parse_content_range_missing_and_malformed() {
        use reqwest::header::HeaderValue;
        assert_eq!(parse_content_range(None), None);
        for bad in ["junk", "bytes NaN-99/500", "bytes 0-99", "bytes 0-99/x"] {
            let h = HeaderValue::from_static(bad);
            assert_eq!(parse_content_range(Some(&h)), None, "{bad}");
        }
    }

    #[test]
    fn tmp_guard_unlinks_unless_disarmed() {
        let dir = std::env::temp_dir().join(format!("tain-seg-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let armed = dir.join("a.tmp~");
        let disarmed = dir.join("b.tmp~");
        std::fs::write(&armed, b"x").unwrap();
        std::fs::write(&disarmed, b"x").unwrap();
        drop(TmpGuard {
            path: armed.clone(),
            armed: true,
        });
        drop(TmpGuard {
            path: disarmed.clone(),
            armed: false,
        });
        assert!(!armed.exists());
        assert!(disarmed.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
