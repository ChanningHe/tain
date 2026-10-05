//! Generation manifest (`.tain/manifest/<generation>.json`): the
//! authoritative list of files a successful sync published. GC keeps the
//! union of recent generations.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::types::DigestAlgo;

use super::{STATE_DIR, ensure_state_dir};

pub const MANIFEST_DIR: &str = "manifest";
pub const CURRENT_SCHEMA: u32 = 1;

/// One published file. At least one of `sha256_hex` / `sha512_hex` must be
/// set; an entry with neither cannot be verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub rel_path: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha512_hex: Option<String>,
}

impl ManifestEntry {
    #[must_use]
    pub fn strongest_algo(&self) -> Option<DigestAlgo> {
        if self.sha512_hex.is_some() {
            Some(DigestAlgo::Sha512)
        } else if self.sha256_hex.is_some() {
            Some(DigestAlgo::Sha256)
        } else {
            None
        }
    }

    #[must_use]
    pub fn strongest_hex(&self) -> Option<(DigestAlgo, &str)> {
        if let Some(s) = &self.sha512_hex {
            Some((DigestAlgo::Sha512, s.as_str()))
        } else {
            self.sha256_hex.as_deref().map(|s| (DigestAlgo::Sha256, s))
        }
    }
}

/// Everything published in one generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationManifest {
    pub schema: u32,
    pub generation: u64,
    /// Keyed by `rel_path`; ordered for stable JSON.
    pub files: BTreeMap<String, ManifestEntry>,
}

impl GenerationManifest {
    #[must_use]
    pub fn new(generation: u64) -> Self {
        Self {
            schema: CURRENT_SCHEMA,
            generation,
            files: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, entry: ManifestEntry) {
        self.files.insert(entry.rel_path.clone(), entry);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("I/O on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("manifest at `{path}` is not valid JSON: {msg}")]
    Parse { path: PathBuf, msg: String },
    #[error("manifest at `{path}` has schema `{got}` (expected `{expected}`)")]
    SchemaMismatch {
        path: PathBuf,
        got: u32,
        expected: u32,
    },
}

#[must_use]
pub fn manifest_dir(mirror_root: &Path) -> PathBuf {
    mirror_root.join(STATE_DIR).join(MANIFEST_DIR)
}

#[must_use]
pub fn manifest_path(mirror_root: &Path, generation: u64) -> PathBuf {
    manifest_dir(mirror_root).join(format!("{generation}.json"))
}

/// Atomically write a generation manifest (tmp, fsync, rename).
///
/// # Errors
///
/// I/O or serialization failure.
pub fn save(mirror_root: &Path, manifest: &GenerationManifest) -> Result<(), ManifestError> {
    ensure_state_dir(mirror_root).map_err(|e| ManifestError::Io {
        path: mirror_root.join(STATE_DIR),
        source: e,
    })?;
    let dir = manifest_dir(mirror_root);
    std::fs::create_dir_all(&dir).map_err(|e| ManifestError::Io {
        path: dir.clone(),
        source: e,
    })?;
    let final_path = manifest_path(mirror_root, manifest.generation);
    let tmp = dir.join(format!("{}.json.tmp~", manifest.generation));
    let json = serde_json::to_vec_pretty(manifest).map_err(|e| ManifestError::Parse {
        path: final_path.clone(),
        msg: e.to_string(),
    })?;
    std::fs::write(&tmp, &json).map_err(|e| ManifestError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    {
        let f = std::fs::File::open(&tmp).map_err(|e| ManifestError::Io {
            path: tmp.clone(),
            source: e,
        })?;
        f.sync_data().map_err(|e| ManifestError::Io {
            path: tmp.clone(),
            source: e,
        })?;
    }
    std::fs::rename(&tmp, &final_path).map_err(|e| ManifestError::Io {
        path: tmp,
        source: e,
    })?;
    Ok(())
}

/// # Errors
///
/// I/O, parse, or schema mismatch.
pub fn load(mirror_root: &Path, generation: u64) -> Result<GenerationManifest, ManifestError> {
    let path = manifest_path(mirror_root, generation);
    let bytes = std::fs::read(&path).map_err(|e| ManifestError::Io {
        path: path.clone(),
        source: e,
    })?;
    let m: GenerationManifest =
        serde_json::from_slice(&bytes).map_err(|e| ManifestError::Parse {
            path: path.clone(),
            msg: e.to_string(),
        })?;
    if m.schema != CURRENT_SCHEMA {
        return Err(ManifestError::SchemaMismatch {
            path,
            got: m.schema,
            expected: CURRENT_SCHEMA,
        });
    }
    Ok(m)
}

/// Generation numbers with a manifest on disk, ascending.
///
/// # Errors
///
/// Directory read failure (a missing directory is empty, not an error).
pub fn list_generations(mirror_root: &Path) -> Result<Vec<u64>, ManifestError> {
    let dir = manifest_dir(mirror_root);
    let read = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(ManifestError::Io {
                path: dir,
                source: e,
            });
        }
    };
    let mut out = Vec::new();
    for entry in read {
        let entry = entry.map_err(|e| ManifestError::Io {
            path: dir.clone(),
            source: e,
        })?;
        let name = entry.file_name();
        let s = name.to_string_lossy();
        if let Some(num) = s.strip_suffix(".json").and_then(|n| n.parse::<u64>().ok()) {
            out.push(num);
        }
    }
    out.sort_unstable();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_root(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("tain-manifest-{name}-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn sample_entry(rel: &str) -> ManifestEntry {
        ManifestEntry {
            rel_path: rel.into(),
            size: 100,
            sha256_hex: Some("00".repeat(32)),
            sha512_hex: None,
        }
    }

    #[test]
    fn save_then_load_roundtrips() {
        let root = temp_root("rt");
        let mut m = GenerationManifest::new(7);
        m.insert(sample_entry("dists/bookworm/InRelease"));
        m.insert(sample_entry("pool/main/n/nginx/nginx.deb"));
        save(&root, &m).unwrap();
        let loaded = load(&root, 7).unwrap();
        assert_eq!(loaded, m);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn strongest_algo_reflects_sha512_presence() {
        let mut e = sample_entry("f");
        assert_eq!(e.strongest_algo(), Some(DigestAlgo::Sha256));
        e.sha512_hex = Some("00".repeat(64));
        assert_eq!(e.strongest_algo(), Some(DigestAlgo::Sha512));
    }

    #[test]
    fn strongest_algo_none_when_no_hash_recorded() {
        let mut e = sample_entry("f");
        e.sha256_hex = None;
        e.sha512_hex = None;
        assert_eq!(e.strongest_algo(), None);
        assert_eq!(e.strongest_hex(), None);
    }

    #[test]
    fn strongest_hex_prefers_sha512() {
        let mut e = sample_entry("f");
        e.sha512_hex = Some("11".repeat(64));
        let (algo, hex) = e.strongest_hex().unwrap();
        assert_eq!(algo, DigestAlgo::Sha512);
        assert_eq!(hex, "11".repeat(64));
    }

    #[test]
    fn list_generations_returns_sorted_ascending() {
        let root = temp_root("list");
        for g in &[3u64, 1, 2, 5] {
            let m = GenerationManifest::new(*g);
            save(&root, &m).unwrap();
        }
        let list = list_generations(&root).unwrap();
        assert_eq!(list, vec![1, 2, 3, 5]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn list_generations_missing_dir_is_empty() {
        let root = temp_root("nolist");
        assert!(list_generations(&root).unwrap().is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn future_schema_rejected() {
        let root = temp_root("future");
        ensure_state_dir(&root).unwrap();
        std::fs::create_dir_all(manifest_dir(&root)).unwrap();
        let raw = serde_json::json!({
            "schema": CURRENT_SCHEMA + 99,
            "generation": 1u64,
            "files": {},
        });
        std::fs::write(manifest_path(&root, 1), raw.to_string()).unwrap();
        let err = load(&root, 1).unwrap_err();
        assert!(
            matches!(err, ManifestError::SchemaMismatch { .. }),
            "{err:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn corrupt_json_rejected() {
        let root = temp_root("bad");
        ensure_state_dir(&root).unwrap();
        std::fs::create_dir_all(manifest_dir(&root)).unwrap();
        std::fs::write(manifest_path(&root, 1), b"not json").unwrap();
        let err = load(&root, 1).unwrap_err();
        assert!(matches!(err, ManifestError::Parse { .. }));
        std::fs::remove_dir_all(&root).ok();
    }
}
