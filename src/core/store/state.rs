//! `state.json`: per-mirror generation counter, upstream URL, and the last
//! successful InRelease snapshot per suite (hash, `Date`, cache validators).
//! Written atomically (tmp, fsync, rename); a missing file means first run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{STATE_DIR, ensure_state_dir};

pub const STATE_FILE: &str = "state.json";

/// Bump on incompatible changes so old binaries reject new files.
pub const CURRENT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MirrorState {
    pub schema: u32,
    pub generation: u64,
    /// Upstream URL; a different URL refuses to reuse this state.
    pub mirror_url: String,
    pub suites: BTreeMap<String, SuiteState>,
}

// Hand-written so `schema` is `CURRENT_SCHEMA`, not 0.
impl Default for MirrorState {
    fn default() -> Self {
        Self {
            schema: CURRENT_SCHEMA,
            generation: 0,
            mirror_url: String::new(),
            suites: BTreeMap::new(),
        }
    }
}

impl MirrorState {
    #[must_use]
    pub fn new(mirror_url: String) -> Self {
        Self {
            schema: CURRENT_SCHEMA,
            generation: 0,
            mirror_url,
            suites: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SuiteState {
    /// SHA-256 of the last synced `InRelease`.
    pub token_sha256: String,
    /// Raw `Date` field, for the Date-monotonicity check.
    pub date_raw: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub generation: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("I/O on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("state file `{path}` is not valid JSON: {msg}")]
    Parse { path: PathBuf, msg: String },
    #[error("state file `{path}` has unknown schema `{got}` (expected `{expected}`)")]
    SchemaMismatch {
        path: PathBuf,
        got: u32,
        expected: u32,
    },
    #[error(
        "state file at `{path}` records mirror URL `{stored}` but this run targets `{expected}` — refusing to reuse state"
    )]
    UrlMismatch {
        path: PathBuf,
        stored: String,
        expected: String,
    },
}

/// Read the mirror state; `None` if the file is missing.
///
/// # Errors
///
/// I/O, invalid JSON, or schema mismatch.
pub fn load(mirror_root: &Path) -> Result<Option<MirrorState>, StateError> {
    let path = state_path(mirror_root);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(StateError::Io { path, source: e });
        }
    };
    let value: MirrorState = serde_json::from_slice(&bytes).map_err(|e| StateError::Parse {
        path: path.clone(),
        msg: e.to_string(),
    })?;
    if value.schema != CURRENT_SCHEMA {
        return Err(StateError::SchemaMismatch {
            path,
            got: value.schema,
            expected: CURRENT_SCHEMA,
        });
    }
    Ok(Some(value))
}

/// [`load`], also requiring the stored URL to match.
///
/// # Errors
///
/// [`StateError::UrlMismatch`] if upstream changed: Date monotonicity
/// across different upstreams is meaningless.
pub fn load_for_url(
    mirror_root: &Path,
    expected_url: &str,
) -> Result<Option<MirrorState>, StateError> {
    let Some(state) = load(mirror_root)? else {
        return Ok(None);
    };
    if state.mirror_url != expected_url {
        return Err(StateError::UrlMismatch {
            path: state_path(mirror_root),
            stored: state.mirror_url,
            expected: expected_url.to_owned(),
        });
    }
    Ok(Some(state))
}

/// Persist `state` atomically.
///
/// # Errors
///
/// I/O or serialization failure.
pub fn save(mirror_root: &Path, state: &MirrorState) -> Result<(), StateError> {
    ensure_state_dir(mirror_root).map_err(|e| StateError::Io {
        path: mirror_root.join(STATE_DIR),
        source: e,
    })?;
    let path = state_path(mirror_root);
    let tmp = tmp_state_path(mirror_root);
    let json = serde_json::to_vec_pretty(state).map_err(|e| StateError::Parse {
        path: path.clone(),
        msg: e.to_string(),
    })?;
    std::fs::write(&tmp, &json).map_err(|e| StateError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    {
        let f = std::fs::File::open(&tmp).map_err(|e| StateError::Io {
            path: tmp.clone(),
            source: e,
        })?;
        f.sync_data().map_err(|e| StateError::Io {
            path: tmp.clone(),
            source: e,
        })?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| StateError::Io {
        path: tmp,
        source: e,
    })?;
    Ok(())
}

#[must_use]
pub fn state_path(mirror_root: &Path) -> PathBuf {
    mirror_root.join(STATE_DIR).join(STATE_FILE)
}

#[must_use]
pub fn tmp_state_path(mirror_root: &Path) -> PathBuf {
    mirror_root
        .join(STATE_DIR)
        .join(format!("{STATE_FILE}.tmp~"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_root(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("tain-state-{name}-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn missing_state_file_is_none() {
        let root = temp_root("missing");
        assert!(load(&root).unwrap().is_none());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn save_then_load_roundtrips() {
        let root = temp_root("roundtrip");
        let mut state = MirrorState::new("https://deb.debian.org/debian".into());
        state.generation = 42;
        state.suites.insert(
            "bookworm".into(),
            SuiteState {
                token_sha256: "abc123".into(),
                date_raw: Some("Sat, 03 Feb 2024 09:15:38 UTC".into()),
                etag: Some("\"deadbeef\"".into()),
                last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".into()),
                generation: 42,
            },
        );
        save(&root, &state).unwrap();
        let loaded = load(&root).unwrap().unwrap();
        assert_eq!(loaded, state);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn corrupt_state_reports_parse_error() {
        let root = temp_root("bad-json");
        ensure_state_dir(&root).unwrap();
        std::fs::write(state_path(&root), b"not json").unwrap();
        let err = load(&root).unwrap_err();
        assert!(matches!(err, StateError::Parse { .. }), "{err:?}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn future_schema_rejected() {
        let root = temp_root("future");
        ensure_state_dir(&root).unwrap();
        let raw = serde_json::json!({
            "schema": CURRENT_SCHEMA + 99,
            "generation": 0,
            "mirror_url": "http://x",
            "suites": {},
        });
        std::fs::write(state_path(&root), raw.to_string()).unwrap();
        let err = load(&root).unwrap_err();
        assert!(matches!(err, StateError::SchemaMismatch { .. }), "{err:?}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn url_mismatch_rejected_by_load_for_url() {
        let root = temp_root("urlswap");
        let state = MirrorState::new("http://old.example/".into());
        save(&root, &state).unwrap();
        let err = load_for_url(&root, "http://new.example/").unwrap_err();
        assert!(matches!(err, StateError::UrlMismatch { .. }), "{err:?}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn matching_url_passes_load_for_url() {
        let root = temp_root("urlmatch");
        let state = MirrorState::new("http://x/".into());
        save(&root, &state).unwrap();
        let ok = load_for_url(&root, "http://x/").unwrap();
        assert!(ok.is_some());
        std::fs::remove_dir_all(&root).ok();
    }
}
