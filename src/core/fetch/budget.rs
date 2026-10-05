//! Global + per-host concurrency budgets.
//!
//! Each request holds a global permit (`global.parallel`) and a per-host
//! request permit (`host_connections`, not TCP connections) until its
//! `BudgetGuard` drops.
//!
//! Pacer: a 429/503 sets a per-host cool-down deadline and halves the host
//! cap; successes regrow it one permit at a time.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;

use crate::config::model::GlobalConfig;

/// Pacer circuit breaker: reset a host after this many throttles with no
/// success, spanning at least the window, so one broken mirror cannot starve
/// others sharing the host.
const POISON_THROTTLE_STREAK: usize = 8;
const POISON_STREAK_WINDOW: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy)]
pub struct BudgetConfig {
    pub global_parallel: usize,
    pub host_connections: usize,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            global_parallel: 32,
            host_connections: 8,
        }
    }
}

impl From<&GlobalConfig> for BudgetConfig {
    fn from(g: &GlobalConfig) -> Self {
        Self {
            global_parallel: g.parallel,
            host_connections: g.host_connections,
        }
    }
}

/// Global + per-host semaphores. Clones share state.
#[derive(Debug, Clone)]
pub struct Budget {
    global: Arc<Semaphore>,
    per_host_capacity: usize,
    per_host: Arc<Mutex<HashMap<String, HostState>>>,
}

#[derive(Debug)]
struct HostState {
    /// Resized via `forget_permits` / `add_permits`.
    sem: Arc<Semaphore>,
    current_cap: usize,
    throttle_until: Option<Instant>,
    consecutive_successes: usize,
    throttles_since_last_success: usize,
    first_streak_throttle_at: Option<Instant>,
}

impl Budget {
    #[must_use]
    pub fn new(cfg: BudgetConfig) -> Self {
        assert!(cfg.global_parallel > 0, "global_parallel must be > 0");
        assert!(cfg.host_connections > 0, "host_connections must be > 0");
        Self {
            global: Arc::new(Semaphore::new(cfg.global_parallel)),
            per_host_capacity: cfg.host_connections,
            per_host: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Wait out any host throttle, then acquire a global permit followed by a
    /// per-host one (the reverse order lets hosts hoard permits while the
    /// global budget starves). `None` if the URL has no host.
    pub async fn acquire(&self, url: &Url) -> Option<BudgetGuard> {
        let host = url.host_str()?.to_ascii_lowercase();
        let (host_sem, throttle_wait) = {
            let mut map = self.per_host.lock().expect("per-host map mutex poisoned");
            let entry = map.entry(host.clone()).or_insert_with(|| HostState {
                sem: Arc::new(Semaphore::new(self.per_host_capacity)),
                current_cap: self.per_host_capacity,
                throttle_until: None,
                consecutive_successes: 0,
                throttles_since_last_success: 0,
                first_streak_throttle_at: None,
            });
            let wait = entry.throttle_until.and_then(|dl| {
                let now = Instant::now();
                if dl > now {
                    Some(dl.saturating_duration_since(now))
                } else {
                    entry.throttle_until = None;
                    None
                }
            });
            (Arc::clone(&entry.sem), wait)
        };
        if let Some(dur) = throttle_wait {
            tokio::time::sleep(dur).await;
        }

        let global_permit = Arc::clone(&self.global)
            .acquire_owned()
            .await
            .expect("global semaphore is never closed by Budget");
        let host_permit = host_sem
            .acquire_owned()
            .await
            .expect("per-host semaphore is never closed by Budget");

        Some(BudgetGuard {
            _global: global_permit,
            _host: host_permit,
            host,
        })
    }

    /// Record a 429/503: block the host until `retry_after` and halve its cap
    /// (min 1). Trips the circuit breaker (full reset) after a long
    /// success-free streak.
    pub fn throttle_host(&self, host: &str, retry_after: Duration) {
        let host = host.to_ascii_lowercase();
        let now = Instant::now();
        let deadline = now + retry_after;
        let mut map = self.per_host.lock().expect("per-host map mutex poisoned");
        let entry = map.entry(host.clone()).or_insert_with(|| HostState {
            sem: Arc::new(Semaphore::new(self.per_host_capacity)),
            current_cap: self.per_host_capacity,
            throttle_until: None,
            consecutive_successes: 0,
            throttles_since_last_success: 0,
            first_streak_throttle_at: None,
        });
        entry.throttles_since_last_success += 1;
        if entry.first_streak_throttle_at.is_none() {
            entry.first_streak_throttle_at = Some(now);
        }
        let streak_age = entry
            .first_streak_throttle_at
            .map(|t| now.saturating_duration_since(t))
            .unwrap_or_default();
        if entry.throttles_since_last_success >= POISON_THROTTLE_STREAK
            && streak_age >= POISON_STREAK_WINDOW
        {
            tracing::error!(
                host = %host,
                throttles = entry.throttles_since_last_success,
                streak_age_secs = streak_age.as_secs(),
                "pacer circuit breaker: repeated throttles without success — resetting host \
                 pacer state so other mirrors sharing this host can proceed. Fix the failing \
                 mirror or its upstream before the next tick."
            );
            let missing = self.per_host_capacity.saturating_sub(entry.current_cap);
            if missing > 0 {
                entry.sem.add_permits(missing);
            }
            entry.current_cap = self.per_host_capacity;
            entry.throttle_until = None;
            entry.consecutive_successes = 0;
            entry.throttles_since_last_success = 0;
            entry.first_streak_throttle_at = None;
            return;
        }
        // A later, shorter Retry-After must not shorten the deadline.
        entry.throttle_until = Some(
            entry
                .throttle_until
                .map_or(deadline, |cur| cur.max(deadline)),
        );
        entry.consecutive_successes = 0;
        let new_cap = (entry.current_cap / 2).max(1);
        if new_cap < entry.current_cap {
            let shrink_by = entry.current_cap - new_cap;
            entry.sem.forget_permits(shrink_by);
            entry.current_cap = new_cap;
        }
    }

    /// Record a success; every 10 in a row regrows the host cap by one.
    pub fn note_success(&self, host: &str) {
        let host = host.to_ascii_lowercase();
        const SUCCESSES_PER_GROWTH: usize = 10;
        let mut map = self.per_host.lock().expect("per-host map mutex poisoned");
        let Some(entry) = map.get_mut(&host) else {
            return;
        };
        entry.throttles_since_last_success = 0;
        entry.first_streak_throttle_at = None;
        if entry.current_cap >= self.per_host_capacity {
            return;
        }
        entry.consecutive_successes += 1;
        if entry.consecutive_successes >= SUCCESSES_PER_GROWTH {
            entry.consecutive_successes = 0;
            entry.sem.add_permits(1);
            entry.current_cap += 1;
        }
    }

    /// Current per-host cap; `None` for an unseen host.
    #[must_use]
    pub fn host_cap(&self, host: &str) -> Option<usize> {
        let map = self.per_host.lock().ok()?;
        map.get(&host.to_ascii_lowercase()).map(|s| s.current_cap)
    }

    /// Global permits currently available.
    #[must_use]
    pub fn global_available(&self) -> usize {
        self.global.available_permits()
    }

    /// Available permits for `host`; `None` for an unseen host.
    #[must_use]
    pub fn host_available(&self, host: &str) -> Option<usize> {
        let map = self.per_host.lock().ok()?;
        map.get(&host.to_ascii_lowercase())
            .map(|s| s.sem.available_permits())
    }

    /// Backdate the streak start to test the circuit breaker.
    #[cfg(test)]
    pub(crate) fn __test_backdate_streak(&self, host: &str, dur: Duration) {
        let mut map = self.per_host.lock().expect("mutex poisoned");
        if let Some(entry) = map.get_mut(&host.to_ascii_lowercase())
            && let Some(t) = entry.first_streak_throttle_at
        {
            entry.first_streak_throttle_at = t.checked_sub(dur);
        }
    }
}

/// Holds both permits until dropped.
pub struct BudgetGuard {
    _global: OwnedSemaphorePermit,
    _host: OwnedSemaphorePermit,
    host: String,
}

impl std::fmt::Debug for BudgetGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BudgetGuard")
            .field("host", &self.host)
            .finish()
    }
}

impl BudgetGuard {
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn default_config_matches_documented_defaults() {
        let c = BudgetConfig::default();
        assert_eq!(c.global_parallel, 32);
        assert_eq!(c.host_connections, 8);
    }

    #[tokio::test]
    async fn acquire_uses_one_permit_from_each_scope() {
        let b = Budget::new(BudgetConfig {
            global_parallel: 4,
            host_connections: 2,
        });
        let g = b.acquire(&url("http://example.com/x")).await.unwrap();
        assert_eq!(b.global_available(), 3);
        assert_eq!(b.host_available("example.com"), Some(1));
        drop(g);
        tokio::task::yield_now().await;
        assert_eq!(b.global_available(), 4);
        assert_eq!(b.host_available("example.com"), Some(2));
    }

    #[tokio::test]
    async fn host_is_case_insensitive() {
        let b = Budget::new(BudgetConfig::default());
        let g1 = b.acquire(&url("http://Example.COM/a")).await.unwrap();
        let g2 = b.acquire(&url("http://example.com/b")).await.unwrap();
        assert_eq!(g1.host(), g2.host());
        drop((g1, g2));
    }

    #[tokio::test]
    async fn per_host_semaphores_are_independent() {
        let b = Budget::new(BudgetConfig {
            global_parallel: 10,
            host_connections: 1,
        });
        let g_a = b.acquire(&url("http://a.example/")).await.unwrap();
        let g_b = b.acquire(&url("http://b.example/")).await.unwrap();
        assert_eq!(b.host_available("a.example"), Some(0));
        assert_eq!(b.host_available("b.example"), Some(0));
        drop((g_a, g_b));
    }

    #[tokio::test]
    async fn host_permit_saturation_blocks_further_acquires() {
        let b = Budget::new(BudgetConfig {
            global_parallel: 100,
            host_connections: 1,
        });
        let g = b.acquire(&url("http://one-host/")).await.unwrap();
        let acquired_second = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            b.acquire(&url("http://one-host/other")),
        )
        .await;
        assert!(
            acquired_second.is_err(),
            "second acquire on saturated host should not resolve"
        );
        drop(g);
        tokio::task::yield_now().await;
        let g2 = b.acquire(&url("http://one-host/other")).await;
        assert!(g2.is_some());
    }

    #[tokio::test]
    async fn no_host_url_returns_none() {
        let b = Budget::new(BudgetConfig::default());
        let file_url = Url::parse("file:///data/local").unwrap();
        assert!(b.acquire(&file_url).await.is_none());
    }

    #[tokio::test]
    async fn budget_is_shareable_across_tasks() {
        let b = Budget::new(BudgetConfig {
            global_parallel: 5,
            host_connections: 2,
        });
        let b2 = b.clone();
        let handle = tokio::spawn(async move {
            let _g = b2.acquire(&url("http://shared/")).await.unwrap();
            tokio::task::yield_now().await;
        });
        {
            let _g = b.acquire(&url("http://shared/")).await.unwrap();
            handle.await.unwrap();
        }
        tokio::task::yield_now().await;
        assert_eq!(b.host_available("shared"), Some(2));
    }

    #[test]
    fn debug_guard_hides_permits() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let b = Budget::new(BudgetConfig::default());
        rt.block_on(async {
            let g = b.acquire(&url("http://example.com/")).await.unwrap();
            let s = format!("{g:?}");
            assert!(s.contains("BudgetGuard"));
            assert!(s.contains("example.com"));
        });
    }

    #[test]
    #[should_panic(expected = "global_parallel must be > 0")]
    fn zero_global_panics() {
        let _ = Budget::new(BudgetConfig {
            global_parallel: 0,
            host_connections: 1,
        });
    }

    #[test]
    #[should_panic(expected = "host_connections must be > 0")]
    fn zero_host_panics() {
        let _ = Budget::new(BudgetConfig {
            global_parallel: 1,
            host_connections: 0,
        });
    }

    #[tokio::test]
    async fn throttle_host_shrinks_cap_and_blocks_acquire() {
        let b = Budget::new(BudgetConfig {
            global_parallel: 4,
            host_connections: 4,
        });
        drop(b.acquire(&url("http://origin/")).await.unwrap());
        b.throttle_host("origin", Duration::from_millis(200));
        let cap_after = b.host_cap("origin").unwrap();
        assert!(cap_after < 4, "cap halved: {cap_after}");
        let u = url("http://origin/");
        let start = std::time::Instant::now();
        let _g = b.acquire(&u).await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(150),
            "acquire returned too fast: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn throttle_shrinks_cap_and_note_success_regrows() {
        let b = Budget::new(BudgetConfig {
            global_parallel: 10,
            host_connections: 8,
        });
        drop(b.acquire(&url("http://origin/")).await.unwrap());
        b.throttle_host("origin", Duration::from_millis(0));
        assert_eq!(b.host_cap("origin"), Some(4));
        for _ in 0..10 {
            b.note_success("origin");
        }
        assert_eq!(b.host_cap("origin"), Some(5));
    }

    #[test]
    fn note_success_before_throttle_is_noop() {
        let b = Budget::new(BudgetConfig {
            global_parallel: 4,
            host_connections: 4,
        });
        b.note_success("never-touched");
        assert_eq!(b.host_cap("never-touched"), None);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn poison_streak_resets_host_state() {
        let b = Budget::new(BudgetConfig {
            global_parallel: 4,
            host_connections: 4,
        });
        drop(b.acquire(&url("http://cdn/")).await.unwrap());
        for _ in 0..POISON_THROTTLE_STREAK {
            b.throttle_host("cdn", Duration::from_millis(50));
        }
        assert_eq!(b.host_cap("cdn"), Some(1));
        b.__test_backdate_streak("cdn", POISON_STREAK_WINDOW + Duration::from_secs(1));
        b.throttle_host("cdn", Duration::from_millis(50));
        assert_eq!(b.host_cap("cdn"), Some(4));
        let start = std::time::Instant::now();
        let _g = b.acquire(&url("http://cdn/")).await.unwrap();
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "post-breaker acquire should not wait a Retry-After: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn note_success_clears_poison_streak_counter() {
        let b = Budget::new(BudgetConfig {
            global_parallel: 4,
            host_connections: 4,
        });
        drop(b.acquire(&url("http://cdn/")).await.unwrap());
        for _ in 0..(POISON_THROTTLE_STREAK - 1) {
            b.throttle_host("cdn", Duration::from_millis(1));
        }
        b.note_success("cdn");
        b.throttle_host("cdn", Duration::from_millis(1));
        // Breaker did not fire (it would restore cap to 4).
        assert_eq!(b.host_cap("cdn"), Some(1));
    }

    #[tokio::test]
    async fn later_retry_after_extends_deadline() {
        let b = Budget::new(BudgetConfig {
            global_parallel: 4,
            host_connections: 4,
        });
        drop(b.acquire(&url("http://origin/")).await.unwrap());
        b.throttle_host("origin", Duration::from_millis(100));
        b.throttle_host("origin", Duration::from_millis(300));
        let u2 = url("http://origin/");
        let start = std::time::Instant::now();
        let _g = b.acquire(&u2).await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(250),
            "should have waited for the longer deadline: {elapsed:?}"
        );
    }
}
