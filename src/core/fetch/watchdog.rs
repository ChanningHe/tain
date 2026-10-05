//! Read-idle and minimum-rate watchdogs for response body streams.
//!
//! There is deliberately no whole-request timeout: no value is defensible
//! for multi-GB files.

use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::Stream;
use futures::StreamExt;

use crate::config::model::GlobalConfig;

#[derive(Debug, Clone, Copy)]
pub struct WatchdogConfig {
    /// Abort if no bytes arrive for this long.
    pub idle_timeout: Duration,
    /// Abort if the rate over `min_rate_window` falls below this.
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

/// Sliding-window byte-rate tracker.
#[derive(Debug, Clone)]
pub struct RateTracker {
    /// `(instant, cumulative_bytes)`, oldest first.
    samples: Vec<(Instant, u64)>,
    total_bytes: u64,
    started_at: Instant,
}

impl RateTracker {
    #[must_use]
    pub fn new(started_at: Instant) -> Self {
        Self {
            samples: vec![(started_at, 0)],
            total_bytes: 0,
            started_at,
        }
    }

    pub fn push(&mut self, bytes: usize, now: Instant) {
        self.total_bytes = self.total_bytes.saturating_add(bytes as u64);
        self.samples.push((now, self.total_bytes));
        if self.samples.len() > 256 {
            let excess = self.samples.len() - 256;
            self.samples.drain(0..excess);
        }
    }

    /// Bytes/sec since the oldest sample inside `window`.
    #[must_use]
    pub fn rate_over(&self, window: Duration, now: Instant) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let cutoff = now.checked_sub(window).unwrap_or(now);
        let oldest = self
            .samples
            .iter()
            .find(|(t, _)| *t >= cutoff)
            .copied()
            .unwrap_or_else(|| *self.samples.last().unwrap());
        let (t0, b0) = oldest;
        let elapsed = now.saturating_duration_since(t0);
        let bytes = self.total_bytes.saturating_sub(b0);
        let secs = elapsed.as_secs_f64().max(0.001);
        (bytes as f64 / secs) as u64
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub fn started_at(&self) -> Instant {
        self.started_at
    }
}

/// Poll `stream` for the next chunk (`None` at end), enforcing the watchdogs.
///
/// # Errors
///
/// `Idle`, `Slow` (after `startup_grace`), or `Stream` for upstream errors.
pub async fn next_chunk_watchdog<S, E>(
    stream: &mut S,
    cfg: &WatchdogConfig,
    tracker: &mut RateTracker,
) -> Result<Option<Bytes>, WatchdogError>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    // A byte trickled just inside idle_timeout never trips Idle, so a
    // periodic tick runs the min-rate check even while the stream is silent.
    let tick_period = tick_period_for(cfg);
    let mut interval = tokio::time::interval(tick_period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick completes immediately.
    interval.tick().await;
    loop {
        tokio::select! {
            biased;
            item = tokio::time::timeout(cfg.idle_timeout, stream.next()) => {
                match item {
                    Err(_) => return Err(WatchdogError::Idle {
                        waited: cfg.idle_timeout,
                        limit: cfg.idle_timeout,
                    }),
                    Ok(None) => return Ok(None),
                    Ok(Some(Err(e))) => return Err(WatchdogError::Stream(e.to_string())),
                    Ok(Some(Ok(bytes))) => {
                        let now = Instant::now();
                        tracker.push(bytes.len(), now);
                        check_min_rate(cfg, tracker, now)?;
                        return Ok(Some(bytes));
                    }
                }
            }
            _ = interval.tick() => {
                let now = Instant::now();
                check_min_rate(cfg, tracker, now)?;
            }
        }
    }
}

fn tick_period_for(cfg: &WatchdogConfig) -> Duration {
    let window_third = cfg.min_rate_window / 3;
    window_third.clamp(Duration::from_millis(500), Duration::from_secs(30))
}

fn check_min_rate(
    cfg: &WatchdogConfig,
    tracker: &RateTracker,
    now: Instant,
) -> Result<(), WatchdogError> {
    if now.saturating_duration_since(tracker.started_at()) < cfg.startup_grace {
        return Ok(());
    }
    let rate = tracker.rate_over(cfg.min_rate_window, now);
    if rate < cfg.min_rate_bytes_per_sec {
        return Err(WatchdogError::Slow {
            rate_bytes_per_sec: rate,
            floor_bytes_per_sec: cfg.min_rate_bytes_per_sec,
            window: cfg.min_rate_window,
        });
    }
    Ok(())
}

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

    #[test]
    fn rate_tracker_averages_over_window() {
        let now = Instant::now();
        let mut t = RateTracker::new(now);
        t.push(1000, now + Duration::from_secs(1));
        t.push(1000, now + Duration::from_secs(2));
        let r = t.rate_over(Duration::from_secs(10), now + Duration::from_secs(2));
        assert!((800..=1200).contains(&r), "rate={r}");
    }

    #[test]
    fn rate_tracker_prunes_old_samples() {
        let start = Instant::now();
        let mut t = RateTracker::new(start);
        for i in 0..300 {
            t.push(100, start + Duration::from_millis(i * 10));
        }
        assert!(t.samples.len() <= 256);
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
        let mut t = RateTracker::new(Instant::now());
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

    #[tokio::test]
    async fn watchdog_idle_fires_when_stream_stalls() {
        let s = futures::stream::pending::<Result<Bytes, std::io::Error>>();
        let mut s = Box::pin(s);
        let mut t = RateTracker::new(Instant::now());
        let cfg = WatchdogConfig {
            idle_timeout: Duration::from_millis(80),
            ..WatchdogConfig::default()
        };
        let err = next_chunk_watchdog(&mut s, &cfg, &mut t)
            .await
            .expect_err("idle fires");
        assert!(matches!(err, WatchdogError::Idle { .. }));
    }

    #[tokio::test]
    async fn watchdog_slow_fires_after_startup_grace() {
        let now = Instant::now();
        let mut t = RateTracker::new(now - Duration::from_secs(30));
        t.push(1, now);
        let cfg = WatchdogConfig {
            idle_timeout: Duration::from_secs(60),
            min_rate_bytes_per_sec: 1_000_000,
            min_rate_window: Duration::from_secs(20),
            startup_grace: Duration::from_secs(0),
        };
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![Ok(Bytes::from(vec![0u8; 1]))];
        let mut s = stream::iter(chunks);
        let err = next_chunk_watchdog(&mut s, &cfg, &mut t)
            .await
            .expect_err("slow fires");
        assert!(matches!(err, WatchdogError::Slow { .. }));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn watchdog_trickle_below_min_rate_trips_via_tick() {
        // 1 byte per 200ms: never idle, far below the rate floor.
        use futures::stream::unfold;
        let s = unfold(0usize, |i| async move {
            if i >= 100 {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            Some((
                Ok::<Bytes, std::io::Error>(Bytes::from(vec![0u8; 1])),
                i + 1,
            ))
        });
        let mut s = Box::pin(s);
        let mut tracker = RateTracker::new(Instant::now());
        let cfg = WatchdogConfig {
            idle_timeout: Duration::from_secs(5),
            min_rate_bytes_per_sec: 10 * 1024,
            min_rate_window: Duration::from_secs(1),
            startup_grace: Duration::from_millis(0),
        };
        let mut err = None;
        for _ in 0..100 {
            match next_chunk_watchdog(&mut s, &cfg, &mut tracker).await {
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        let err = err.expect("watchdog must fire against sustained low rate");
        assert!(
            matches!(err, WatchdogError::Slow { .. }),
            "expected Slow via tick, got {err:?}"
        );
    }

    #[tokio::test]
    async fn watchdog_upstream_error_surfaces() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![Err(std::io::Error::other("boom"))];
        let mut s = stream::iter(chunks);
        let mut t = RateTracker::new(Instant::now());
        let err = next_chunk_watchdog(&mut s, &WatchdogConfig::default(), &mut t)
            .await
            .expect_err("upstream error");
        assert!(matches!(err, WatchdogError::Stream(_)));
    }
}
