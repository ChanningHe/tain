//! Full-jitter exponential backoff (AWS "Exponential Backoff And Jitter").

use std::time::Duration;

/// First backoff ceiling of a retried request; doubles per attempt.
pub const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// No single backoff sleep exceeds this.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Uniform in `[0, min(max, base * 2^(attempt-1))]`; `attempt` counts from 1.
#[must_use]
pub fn full_jitter(base: Duration, attempt: u32, max: Duration) -> Duration {
    let shift = attempt.max(1).saturating_sub(1).min(30);
    let bound = base
        .as_nanos()
        .saturating_mul(1u128 << shift)
        .min(max.as_nanos());
    let bound = u64::try_from(bound).unwrap_or(u64::MAX);
    if bound == 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(fastrand::u64(..=bound))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_doubling_bound() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(60);
        for attempt in 1..=5u32 {
            let upper = base * (1 << (attempt - 1));
            for _ in 0..50 {
                assert!(full_jitter(base, attempt, max) <= upper);
            }
        }
    }

    #[test]
    fn respects_cap_and_huge_attempts() {
        let base = Duration::from_secs(10);
        let max = Duration::from_secs(15);
        for attempt in [1, 2, 10, 64, u32::MAX] {
            assert!(full_jitter(base, attempt, max) <= max);
        }
    }

    #[test]
    fn zero_base_is_zero() {
        assert_eq!(
            full_jitter(Duration::ZERO, 3, Duration::from_secs(1)),
            Duration::ZERO
        );
    }

    #[test]
    fn actually_jitters() {
        let base = Duration::from_secs(1);
        let picks: std::collections::HashSet<_> = (0..20)
            .map(|_| full_jitter(base, 4, Duration::from_secs(60)))
            .collect();
        assert!(picks.len() > 1, "20 identical picks: not random");
    }
}
