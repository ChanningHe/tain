//! Read-idle and minimum-rate watchdogs for response body streams.
//!
//! There is deliberately no whole-request timeout: no value is defensible
//! for multi-GB files.
//!
//! Silence is the idle watchdog's alone: no byte for `idle_timeout` trips
//! `Idle`. With floor `F`, `w = min_rate_window`, `I = idle_timeout` and
//! horizon `H = w + I`, each arriving chunk after `startup_grace` is judged
//! against the last `H` as it stood just before that chunk (the chunk itself
//! is excluded):
//!
//! 1. discounting the longest pause (one still in progress included), the
//!    remaining active time, if ≥ `w`, averaged at least `F`;
//! 2. once a full `H` has elapsed, the plain average was at least `F·w/H`.
//!
//! A window's byte count only falls between arrivals, so rule 2 at each
//! arrival bounds every window. History is kept in samples up to
//! `s = max(250 ms, H/256)` apart, so a window may count up to `s` of extra
//! bytes: no stream is sustained below about `F·w/(H + s)` (≈3.3 KiB/s at the
//! defaults), however its bytes are bunched. A transfer at ≥ `F` apart from
//! at most one pause shorter than `I` per `H` never trips either rule.

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;
use futures::Stream;
use futures::StreamExt;
use tokio::time::Instant;

use crate::config::model::GlobalConfig;

#[derive(Debug, Clone, Copy)]
pub struct WatchdogConfig {
    /// Abort if no bytes arrive for this long.
    pub idle_timeout: Duration,
    /// Rate floor; see the module docs for exactly how it is applied.
    pub min_rate_bytes_per_sec: u64,
    pub min_rate_window: Duration,
    /// No rate enforcement this early: TCP slow-start and TLS move few bytes.
    pub startup_grace: Duration,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            min_rate_bytes_per_sec: 10 * 1024,
            min_rate_window: Duration::from_secs(30),
            startup_grace: Duration::from_secs(10),
        }
    }
}

impl From<&GlobalConfig> for WatchdogConfig {
    /// Only the read-idle limit is configurable.
    fn from(g: &GlobalConfig) -> Self {
        Self {
            idle_timeout: g.timeout.read_idle,
            ..Self::default()
        }
    }
}

impl WatchdogConfig {
    /// `min_rate_window + idle_timeout`: the span every rate check covers.
    #[must_use]
    pub fn horizon(&self) -> Duration {
        self.min_rate_window.saturating_add(self.idle_timeout)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WatchdogError {
    #[error("no bytes for {waited:?} (idle_timeout {limit:?})")]
    Idle { waited: Duration, limit: Duration },
    #[error(
        "slow transfer: {rate_bytes_per_sec} B/s over {window:?} (floor {floor_bytes_per_sec} B/s)"
    )]
    Slow {
        rate_bytes_per_sec: u64,
        floor_bytes_per_sec: u64,
        window: Duration,
    },
    #[error("upstream stream error: {0}")]
    Stream(String),
}

/// Floor on the merge distance between samples (see [`RateTracker::push`]).
const MIN_SAMPLE_SPACING: Duration = Duration::from_millis(250);
/// Spacing is `horizon / SAMPLES_PER_HORIZON`, so [`MAX_SAMPLES`] cover
/// several horizons and pruning never cuts into a live window.
const SAMPLES_PER_HORIZON: u32 = 256;
const MAX_SAMPLES: usize = 1024;

#[derive(Debug, Clone, Copy)]
struct Sample {
    at: Instant,
    /// Cumulative bytes at `at`.
    bytes: u64,
    /// Longest arrival gap that ended in this sample.
    max_gap: Duration,
}

/// What the last horizon looked like at some instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowStats {
    /// Covered time: the horizon, or less early on.
    pub span: Duration,
    pub bytes: u64,
    /// Longest pause inside the span, counting one still in progress.
    pub longest_gap: Duration,
}

/// Byte-rate history of one response body.
#[derive(Debug, Clone)]
pub struct RateTracker {
    /// Oldest first; the first is the `(started_at, 0)` origin until pruned.
    samples: VecDeque<Sample>,
    total_bytes: u64,
    started_at: Instant,
    last_progress: Instant,
    horizon: Duration,
    spacing: Duration,
}

impl RateTracker {
    #[must_use]
    pub fn new(started_at: Instant, cfg: &WatchdogConfig) -> Self {
        let horizon = cfg.horizon();
        Self {
            samples: VecDeque::from([Sample {
                at: started_at,
                bytes: 0,
                max_gap: Duration::ZERO,
            }]),
            total_bytes: 0,
            started_at,
            last_progress: started_at,
            horizon,
            spacing: (horizon / SAMPLES_PER_HORIZON).max(MIN_SAMPLE_SPACING),
        }
    }

    /// Record `bytes` arriving at `now`; empty chunks are not progress.
    /// Arrivals within `spacing` of the sample before the newest are merged
    /// into the newest, bounding memory at line rate.
    pub fn push(&mut self, bytes: usize, now: Instant) {
        if bytes == 0 {
            return;
        }
        let gap = now.saturating_duration_since(self.last_progress);
        self.total_bytes = self.total_bytes.saturating_add(bytes as u64);
        self.last_progress = now;
        let n = self.samples.len();
        if n >= 2 && now.saturating_duration_since(self.samples[n - 2].at) < self.spacing {
            let last = self.samples.back_mut().expect("n >= 2");
            last.at = now;
            last.bytes = self.total_bytes;
            last.max_gap = last.max_gap.max(gap);
            return;
        }
        self.samples.push_back(Sample {
            at: now,
            bytes: self.total_bytes,
            max_gap: gap,
        });
        if self.samples.len() > MAX_SAMPLES {
            self.samples.pop_front();
        }
    }

    /// The last horizon (or everything since start) as of `now`.
    #[must_use]
    pub fn window_stats(&self, now: Instant) -> WindowStats {
        let cutoff = now
            .checked_sub(self.horizon)
            .map_or(self.started_at, |c| c.max(self.started_at));
        // Base = newest sample at or before the cutoff; if history was pruned
        // past it, the oldest sample left.
        let base_idx = self
            .samples
            .iter()
            .rposition(|s| s.at <= cutoff)
            .unwrap_or(0);
        let base = self.samples[base_idx];
        let longest_gap = self
            .samples
            .iter()
            .skip(base_idx + 1)
            .map(|s| s.max_gap)
            .chain([now.saturating_duration_since(self.last_progress)])
            .max()
            .unwrap_or_default();
        WindowStats {
            span: now.saturating_duration_since(cutoff.max(base.at)),
            bytes: self.total_bytes.saturating_sub(base.bytes),
            longest_gap,
        }
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    #[must_use]
    pub fn last_progress(&self) -> Instant {
        self.last_progress
    }
}

/// Poll `stream` for the next chunk (`None` at end), enforcing the watchdogs.
///
/// # Errors
///
/// `Idle` once `idle_timeout` has passed since the last byte, `Slow` (after
/// `startup_grace`), or `Stream` for upstream errors.
pub async fn next_chunk_watchdog<S, E>(
    stream: &mut S,
    cfg: &WatchdogConfig,
    tracker: &mut RateTracker,
) -> Result<Option<Bytes>, WatchdogError>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    // Anchored on the last byte, not on this call: empty chunks (e.g. H2
    // DATA frames) must not keep a silent stream alive.
    let deadline = tracker.last_progress() + cfg.idle_timeout;
    let item = tokio::time::timeout_at(deadline, stream.next())
        .await
        .map_err(|_| WatchdogError::Idle {
            waited: tracker.last_progress().elapsed(),
            limit: cfg.idle_timeout,
        })?;
    match item {
        None => Ok(None),
        Some(Err(e)) => Err(WatchdogError::Stream(e.to_string())),
        Some(Ok(bytes)) => {
            if !bytes.is_empty() {
                let now = Instant::now();
                // Judged before the chunk lands: that is the window's low point.
                check_min_rate(cfg, tracker, now)?;
                tracker.push(bytes.len(), now);
            }
            Ok(Some(bytes))
        }
    }
}

fn per_sec(bytes: u64, over: Duration) -> u64 {
    (bytes as f64 / over.as_secs_f64()) as u64
}

fn check_min_rate(
    cfg: &WatchdogConfig,
    tracker: &RateTracker,
    now: Instant,
) -> Result<(), WatchdogError> {
    if now.saturating_duration_since(tracker.started_at()) < cfg.startup_grace {
        return Ok(());
    }
    let floor = cfg.min_rate_bytes_per_sec;
    let s = tracker.window_stats(now);
    let active = s.span.saturating_sub(s.longest_gap);
    if !active.is_zero() && active >= cfg.min_rate_window {
        let rate = per_sec(s.bytes, active);
        if rate < floor {
            return Err(WatchdogError::Slow {
                rate_bytes_per_sec: rate,
                floor_bytes_per_sec: floor,
                window: active,
            });
        }
    }
    let horizon = cfg.horizon();
    if !s.span.is_zero() && s.span >= horizon {
        let scaled = u64::try_from(
            u128::from(floor) * cfg.min_rate_window.as_nanos() / horizon.as_nanos().max(1),
        )
        .unwrap_or(u64::MAX);
        let rate = per_sec(s.bytes, s.span);
        if rate < scaled {
            return Err(WatchdogError::Slow {
                rate_bytes_per_sec: rate,
                floor_bytes_per_sec: scaled,
                window: s.span,
            });
        }
    }
    Ok(())
}

/// Pacer cool-down for a 429/503 without a usable `Retry-After`.
pub const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Parse `Retry-After` (seconds or HTTP-date), capped at 5 minutes.
#[must_use]
pub fn parse_retry_after(header: &str) -> Option<Duration> {
    let raw = header.trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs.min(300)));
    }
    let target: std::time::SystemTime = httpdate_parse(raw)?;
    let now = std::time::SystemTime::now();
    let dur = target.duration_since(now).ok()?;
    Some(dur.min(Duration::from_secs(300)))
}

fn httpdate_parse(s: &str) -> Option<std::time::SystemTime> {
    use time::format_description::well_known::Rfc2822;
    let odt = time::OffsetDateTime::parse(s, &Rfc2822).ok()?;
    Some(odt.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    #[test]
    fn from_global_takes_idle_timeout() {
        let mut g = GlobalConfig::default();
        let default = WatchdogConfig::from(&g);
        let builtin = WatchdogConfig::default();
        assert_eq!(default.idle_timeout, builtin.idle_timeout);
        assert_eq!(
            default.min_rate_bytes_per_sec,
            builtin.min_rate_bytes_per_sec
        );
        assert_eq!(default.min_rate_window, builtin.min_rate_window);
        assert_eq!(default.startup_grace, builtin.startup_grace);

        g.timeout.read_idle = Duration::from_secs(7);
        assert_eq!(
            WatchdogConfig::from(&g).idle_timeout,
            Duration::from_secs(7)
        );
    }

    /// Horizon 60 s.
    fn h60() -> WatchdogConfig {
        WatchdogConfig {
            idle_timeout: Duration::from_secs(30),
            min_rate_window: Duration::from_secs(30),
            ..WatchdogConfig::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn window_stats_cover_span_bytes_and_gaps() {
        let t0 = Instant::now();
        let mut t = RateTracker::new(t0, &h60());
        for s in 1..=10 {
            t.push(1000, t0 + Duration::from_secs(s));
        }
        t.push(1000, t0 + Duration::from_secs(50));
        let s = t.window_stats(t0 + Duration::from_secs(52));
        assert_eq!(
            s,
            WindowStats {
                span: Duration::from_secs(52),
                bytes: 11_000,
                longest_gap: Duration::from_secs(40),
            }
        );
        // Later: the window slides and a pause in progress counts as a gap.
        let s = t.window_stats(t0 + Duration::from_secs(105));
        assert_eq!(s.span, Duration::from_secs(60));
        assert_eq!(s.bytes, 1000, "only the arrival at 50 s is inside");
        assert_eq!(s.longest_gap, Duration::from_secs(55));
    }

    #[tokio::test(start_paused = true)]
    async fn tracker_history_is_bounded_but_covers_the_horizon() {
        let t0 = Instant::now();
        let cfg = WatchdogConfig {
            idle_timeout: Duration::from_secs(600),
            ..WatchdogConfig::default()
        };
        let mut t = RateTracker::new(t0, &cfg);
        for i in 0..200_000u64 {
            t.push(100, t0 + Duration::from_millis(i * 10));
        }
        assert!(t.samples.len() <= MAX_SAMPLES);
        assert_eq!(t.total_bytes(), 20_000_000);
        let now = t0 + Duration::from_secs(2000);
        assert_eq!(t.window_stats(now).span, cfg.horizon());
    }

    #[test]
    fn parse_retry_after_integer_seconds() {
        assert_eq!(parse_retry_after("120"), Some(Duration::from_secs(120)));
        assert_eq!(parse_retry_after("0"), Some(Duration::from_secs(0)));
        assert_eq!(parse_retry_after("999999"), Some(Duration::from_secs(300)));
    }

    #[test]
    fn parse_retry_after_garbage_returns_none() {
        assert_eq!(parse_retry_after("not-a-date"), None);
    }

    #[tokio::test]
    async fn watchdog_relays_progress() {
        let chunks = vec![
            Ok::<Bytes, std::io::Error>(Bytes::from(vec![0u8; 128])),
            Ok(Bytes::from(vec![0u8; 128])),
        ];
        let mut s = stream::iter(chunks);
        let mut t = RateTracker::new(Instant::now(), &WatchdogConfig::default());
        let cfg = WatchdogConfig {
            idle_timeout: Duration::from_secs(5),
            min_rate_bytes_per_sec: 0,
            min_rate_window: Duration::from_secs(30),
            startup_grace: Duration::from_secs(10),
        };
        let first = next_chunk_watchdog(&mut s, &cfg, &mut t).await.unwrap();
        assert_eq!(first.unwrap().len(), 128);
        let second = next_chunk_watchdog(&mut s, &cfg, &mut t).await.unwrap();
        assert_eq!(second.unwrap().len(), 128);
        let end = next_chunk_watchdog(&mut s, &cfg, &mut t).await.unwrap();
        assert!(end.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_idle_fires_when_stream_stalls() {
        let s = futures::stream::pending::<Result<Bytes, std::io::Error>>();
        let mut s = Box::pin(s);
        let mut t = RateTracker::new(Instant::now(), &WatchdogConfig::default());
        let cfg = WatchdogConfig {
            idle_timeout: Duration::from_millis(80),
            ..WatchdogConfig::default()
        };
        let err = next_chunk_watchdog(&mut s, &cfg, &mut t)
            .await
            .expect_err("idle fires");
        assert!(matches!(err, WatchdogError::Idle { .. }));
    }

    /// `(delay before chunk, chunk length)` pairs, in paused time.
    fn timed_stream(
        plan: Vec<(Duration, usize)>,
    ) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Unpin {
        Box::pin(stream::unfold(plan.into_iter(), |mut it| async move {
            let (delay, len) = it.next()?;
            tokio::time::sleep(delay).await;
            Some((Ok(Bytes::from(vec![0u8; len])), it))
        }))
    }

    async fn drain(
        mut s: impl Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
        cfg: &WatchdogConfig,
    ) -> Result<u64, WatchdogError> {
        let mut t = RateTracker::new(Instant::now(), cfg);
        while next_chunk_watchdog(&mut s, cfg, &mut t).await?.is_some() {}
        Ok(t.total_bytes())
    }

    /// 1 MiB/s in 64 KiB chunks.
    fn fast(secs: u64) -> Vec<(Duration, usize)> {
        (0..secs * 16)
            .map(|_| (Duration::from_micros(62_500), 64 * 1024))
            .collect()
    }

    fn idle_120() -> WatchdogConfig {
        WatchdogConfig {
            idle_timeout: Duration::from_secs(120),
            ..WatchdogConfig::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pause_shorter_than_idle_timeout_does_not_trip_slow() {
        let mut plan = fast(40);
        plan.push((Duration::from_secs(60), 64 * 1024));
        plan.extend(fast(40));
        let total = drain(timed_stream(plan), &idle_120())
            .await
            .expect("a 60 s pause under idle_timeout=120s must be tolerated");
        assert_eq!(total, 80 * 1024 * 1024 + 64 * 1024);
    }

    #[tokio::test(start_paused = true)]
    async fn pause_at_startup_shorter_than_idle_timeout_is_tolerated() {
        let mut plan = vec![(Duration::from_millis(100), 64 * 1024)];
        plan.push((Duration::from_secs(90), 64 * 1024));
        plan.extend(fast(40));
        drain(timed_stream(plan), &idle_120())
            .await
            .expect("slow first byte burst then a pause is not a slow transfer");
    }

    #[tokio::test(start_paused = true)]
    async fn pause_longer_than_idle_timeout_trips_idle_not_slow() {
        let mut plan = fast(10);
        plan.push((Duration::from_secs(130), 1));
        let err = drain(timed_stream(plan), &idle_120()).await.unwrap_err();
        assert!(matches!(err, WatchdogError::Idle { .. }), "{err:?}");
    }

    /// `bursts` × (`gap` of silence, then `size` bytes in 16 KiB chunks).
    fn bursty(bursts: usize, gap: Duration, size: usize) -> Vec<(Duration, usize)> {
        let mut plan = Vec::new();
        for _ in 0..bursts {
            plan.push((gap, 16 * 1024));
            plan.extend((1..size / (16 * 1024)).map(|_| (Duration::ZERO, 16 * 1024)));
        }
        plan
    }

    /// Bursts that dodge the idle limit must still respect `F·w/(w+I)`.
    async fn assert_bursty_trips(idle_secs: u64, gap_secs: u64, burst: usize) {
        let cfg = WatchdogConfig {
            idle_timeout: Duration::from_secs(idle_secs),
            ..WatchdogConfig::default()
        };
        let plan = bursty(1000, Duration::from_secs(gap_secs), burst);
        let start = Instant::now();
        let err = drain(timed_stream(plan), &cfg).await.unwrap_err();
        assert!(matches!(err, WatchdogError::Slow { .. }), "{err:?}");
        // Caught within about two horizons, not thousands of seconds.
        assert!(
            start.elapsed() <= cfg.horizon() * 2 + Duration::from_secs(gap_secs),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn bursty_stream_below_effective_floor_trips_slow_idle_60() {
        // ≈2.7 KB/s average, under 10 KiB·30/90 ≈ 3.3 KiB/s.
        assert_bursty_trips(60, 59, 160 * 1024).await;
    }

    #[tokio::test(start_paused = true)]
    async fn bursty_stream_below_effective_floor_trips_slow_idle_600() {
        // ≈270 B/s average, under 10 KiB·30/630 ≈ 487 B/s.
        assert_bursty_trips(600, 599, 160 * 1024).await;
    }

    #[tokio::test(start_paused = true)]
    async fn bursty_stream_above_effective_floor_survives() {
        // Idle 60 s (horizon 90 s): 12 KiB/s while active, then a 55 s pause,
        // every 100 s. The average (~5.4 KiB/s) is below F but the stream
        // is legitimate: above F when active, one sub-idle pause per horizon.
        let cfg = WatchdogConfig {
            idle_timeout: Duration::from_secs(60),
            ..WatchdogConfig::default()
        };
        let mut plan = Vec::new();
        for _ in 0..20 {
            plan.push((Duration::from_secs(55), 12 * 1024));
            plan.extend((0..44).map(|_| (Duration::from_secs(1), 12 * 1024)));
        }
        drain(timed_stream(plan), &cfg)
            .await
            .expect("one sub-idle pause per window at a rate above F is legitimate");
    }

    #[tokio::test(start_paused = true)]
    async fn trickle_just_inside_idle_timeout_trips_slow() {
        let plan = vec![(Duration::from_secs(110), 1); 10];
        let err = drain(timed_stream(plan), &idle_120()).await.unwrap_err();
        assert!(matches!(err, WatchdogError::Slow { .. }), "{err:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_slow_rate_trips_slow() {
        // 1 KiB/s steady, a tenth of the floor.
        let plan = vec![(Duration::from_secs(1), 1024); 120];
        let err = drain(timed_stream(plan), &WatchdogConfig::default())
            .await
            .unwrap_err();
        assert!(matches!(err, WatchdogError::Slow { .. }), "{err:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn empty_chunks_do_not_reset_idle_deadline() {
        let plan = vec![(Duration::from_secs(1), 0); 1000];
        let cfg = WatchdogConfig {
            idle_timeout: Duration::from_secs(5),
            ..WatchdogConfig::default()
        };
        let start = Instant::now();
        let err = drain(timed_stream(plan), &cfg).await.unwrap_err();
        assert!(matches!(err, WatchdogError::Idle { .. }), "{err:?}");
        assert!(start.elapsed() <= Duration::from_secs(6));
    }

    #[tokio::test]
    async fn watchdog_upstream_error_surfaces() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![Err(std::io::Error::other("boom"))];
        let mut s = stream::iter(chunks);
        let mut t = RateTracker::new(Instant::now(), &WatchdogConfig::default());
        let err = next_chunk_watchdog(&mut s, &WatchdogConfig::default(), &mut t)
            .await
            .expect_err("upstream error");
        assert!(matches!(err, WatchdogError::Stream(_)));
    }
}
