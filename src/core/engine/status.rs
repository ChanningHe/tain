//! `status` subcommand: per-mirror generation, sync age and health.
//!
//! The serialized JSON shape is consumed by cron/Prometheus scripts; keep it
//! stable.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::core::store::state;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MirrorStatus {
    pub mirror_name: String,
    pub mirror_root: PathBuf,
    pub generation: u64,
    pub latest_suite: Option<String>,
    /// Age of the upstream Release `Date`; `None` if unknown or in the future.
    pub age_seconds: Option<u64>,
    pub healthy: Option<bool>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusReport {
    pub mirrors: Vec<MirrorStatus>,
}

impl StatusReport {
    /// Mirrors without a `--healthy-within` verdict count as healthy.
    #[must_use]
    pub fn all_healthy(&self) -> bool {
        self.mirrors.iter().all(|m| m.healthy.unwrap_or(true))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    #[error(transparent)]
    State(#[from] state::StateError),
    #[error("cannot parse `--healthy-within {value}`: {msg}")]
    BadHealthyWithin { value: String, msg: String },
}

/// Collect status for one mirror.
///
/// # Errors
///
/// State-load errors.
pub fn snapshot(
    mirror_name: &str,
    mirror_root: &Path,
    now: std::time::SystemTime,
    healthy_within: Option<Duration>,
) -> Result<MirrorStatus, StatusError> {
    let st = state::load(mirror_root)?;
    let Some(st) = st else {
        return Ok(MirrorStatus {
            mirror_name: mirror_name.to_owned(),
            mirror_root: mirror_root.to_path_buf(),
            generation: 0,
            latest_suite: None,
            age_seconds: None,
            healthy: healthy_within.map(|_| false),
            reason: Some("mirror was never successfully synced".into()),
        });
    };

    // Highest generation; name breaks ties deterministically.
    let (latest_suite, age_verdict) = st
        .suites
        .iter()
        .max_by(|(name_a, a), (name_b, b)| {
            a.generation
                .cmp(&b.generation)
                .then_with(|| name_a.as_str().cmp(name_b.as_str()))
        })
        .map(|(name, s)| (Some(name.clone()), age_from_suite(s, now)))
        .unwrap_or((None, AgeVerdict::NoStateRecorded));

    let age_seconds = match age_verdict {
        AgeVerdict::Fresh(s) => Some(s),
        _ => None,
    };
    let healthy = match (healthy_within, &age_verdict) {
        (Some(window), AgeVerdict::Fresh(age_secs)) => Some(*age_secs <= window.as_secs()),
        (Some(_), _) => Some(false),
        (None, _) => None,
    };
    let reason = if healthy == Some(false) {
        Some(match &age_verdict {
            AgeVerdict::Fresh(s) => format!(
                "last successful sync was {} ago, outside healthy_within",
                format_duration(*s)
            ),
            AgeVerdict::FutureDate { by_secs, raw } => format!(
                "upstream Release Date `{raw}` is {} in the future — check upstream / local clock",
                format_duration(*by_secs)
            ),
            AgeVerdict::UnparseableDate { raw, err } => {
                format!("upstream Release Date `{raw}` did not parse: {err}")
            }
            AgeVerdict::NoDateAdvertised => {
                "latest suite has no upstream Date field — cannot judge freshness".to_owned()
            }
            AgeVerdict::NoStateRecorded => "mirror was never successfully synced".to_owned(),
        })
    } else {
        None
    };
    Ok(MirrorStatus {
        mirror_name: mirror_name.to_owned(),
        mirror_root: mirror_root.to_path_buf(),
        generation: st.generation,
        latest_suite,
        age_seconds,
        healthy,
        reason,
    })
}

/// `NoStateRecorded` means no suites at all; `age_from_suite` never returns it.
enum AgeVerdict {
    Fresh(u64),
    FutureDate { by_secs: u64, raw: String },
    UnparseableDate { raw: String, err: String },
    NoDateAdvertised,
    NoStateRecorded,
}

fn age_from_suite(
    s: &crate::core::store::state::SuiteState,
    now: std::time::SystemTime,
) -> AgeVerdict {
    let Some(raw) = s.date_raw.as_deref() else {
        return AgeVerdict::NoDateAdvertised;
    };
    let dt = match crate::backends::apt::datetime::parse_release_datetime(raw) {
        Ok(dt) => dt,
        Err(e) => {
            return AgeVerdict::UnparseableDate {
                raw: raw.to_owned(),
                err: e.to_string(),
            };
        }
    };
    let dt_std: std::time::SystemTime = dt.into();
    match now.duration_since(dt_std) {
        Ok(d) => AgeVerdict::Fresh(d.as_secs()),
        Err(err) => AgeVerdict::FutureDate {
            by_secs: err.duration().as_secs(),
            raw: raw.to_owned(),
        },
    }
}

/// Human-readable one-line summary.
#[must_use]
pub fn format_line(m: &MirrorStatus) -> String {
    let age = m
        .age_seconds
        .map(format_duration)
        .unwrap_or_else(|| "never".into());
    let health = match m.healthy {
        Some(true) => "HEALTHY".to_owned(),
        Some(false) => "UNHEALTHY".to_owned(),
        None => "-".to_owned(),
    };
    format!(
        "{name:30}  gen={gen:<5}  suite={suite:<20}  age={age}  {health}",
        name = m.mirror_name,
        gen = m.generation,
        suite = m.latest_suite.as_deref().unwrap_or("-"),
        age = age,
        health = health,
    )
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Parse a `--healthy-within` duration like `48h`, `72h30m`, `1d`.
///
/// # Errors
///
/// Returns [`StatusError::BadHealthyWithin`] on bad input.
pub fn parse_healthy_within(value: &str) -> Result<Duration, StatusError> {
    humantime::parse_duration(value).map_err(|e| StatusError::BadHealthyWithin {
        value: value.to_owned(),
        msg: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::store::state::{MirrorState, SuiteState};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_root(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("tain-status-{name}-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_state(root: &Path, generation: u64, suite: &str, date_raw: Option<&str>) {
        let mut s = MirrorState::new("http://example.com/".to_owned());
        s.generation = generation;
        s.suites.insert(
            suite.to_owned(),
            SuiteState {
                token_sha256: "aa".repeat(32),
                date_raw: date_raw.map(str::to_owned),
                etag: None,
                last_modified: None,
                generation,
            },
        );
        state::save(root, &s).unwrap();
    }

    #[test]
    fn snapshot_without_state_reports_never() {
        let root = temp_root("no-state");
        let s = snapshot("m", &root, std::time::SystemTime::now(), None).unwrap();
        assert_eq!(s.generation, 0);
        assert_eq!(s.age_seconds, None);
        assert_eq!(s.healthy, None);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn snapshot_with_recent_date_is_healthy() {
        let root = temp_root("healthy");
        write_state(&root, 5, "bookworm", Some("Sat, 03 Feb 2024 09:15:38 UTC"));
        use time::macros::datetime;
        let now: std::time::SystemTime = datetime!(2024-02-04 09:15:38 UTC).into();
        let window = Duration::from_secs(3600 * 48);
        let s = snapshot("m", &root, now, Some(window)).unwrap();
        assert_eq!(s.generation, 5);
        assert_eq!(s.latest_suite.as_deref(), Some("bookworm"));
        assert_eq!(s.age_seconds, Some(24 * 3600));
        assert_eq!(s.healthy, Some(true));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn snapshot_beyond_window_is_unhealthy() {
        let root = temp_root("stale");
        write_state(&root, 5, "bookworm", Some("Sat, 03 Feb 2024 09:15:38 UTC"));
        use time::macros::datetime;
        let now: std::time::SystemTime = datetime!(2024-02-10 09:15:38 UTC).into();
        let window = Duration::from_secs(3600 * 48);
        let s = snapshot("m", &root, now, Some(window)).unwrap();
        assert_eq!(s.healthy, Some(false));
        assert!(s.reason.is_some());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn healthy_without_window_is_none() {
        let root = temp_root("no-window");
        write_state(&root, 5, "bookworm", Some("Sat, 03 Feb 2024 09:15:38 UTC"));
        let s = snapshot("m", &root, std::time::SystemTime::now(), None).unwrap();
        assert_eq!(s.healthy, None);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn snapshot_with_future_date_reports_specific_reason() {
        let root = temp_root("future");
        write_state(&root, 5, "bookworm", Some("Sat, 03 Feb 2024 09:15:38 UTC"));
        use time::macros::datetime;
        let now: std::time::SystemTime = datetime!(2024-02-01 00:00:00 UTC).into();
        let s = snapshot("m", &root, now, Some(Duration::from_secs(3600 * 48))).unwrap();
        assert_eq!(s.age_seconds, None);
        assert_eq!(s.healthy, Some(false));
        let reason = s.reason.expect("future-date reason present");
        assert!(
            reason.contains("in the future"),
            "reason should call out future date, got: {reason}"
        );
        assert!(
            !reason.contains("never"),
            "reason must not misreport as 'never', got: {reason}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn snapshot_without_date_field_reports_specific_reason() {
        let root = temp_root("no-date");
        write_state(&root, 5, "bookworm", None);
        let s = snapshot(
            "m",
            &root,
            std::time::SystemTime::now(),
            Some(Duration::from_secs(3600 * 48)),
        )
        .unwrap();
        assert_eq!(s.age_seconds, None);
        assert_eq!(s.healthy, Some(false));
        let reason = s.reason.expect("no-date reason present");
        assert!(
            reason.contains("no upstream Date"),
            "reason should call out missing Date field, got: {reason}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn duration_parser_accepts_common_forms() {
        assert!(parse_healthy_within("48h").is_ok());
        assert!(parse_healthy_within("30m").is_ok());
        assert!(parse_healthy_within("1d").is_ok());
        assert!(parse_healthy_within("nope").is_err());
    }
}
