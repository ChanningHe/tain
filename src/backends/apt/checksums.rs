//! Release checksum blocks, folded per path across algorithms, plus the weak-hash policy.

use std::collections::BTreeMap;

use crate::core::types::{Digest, DigestAlgo, DigestError, DigestSet, DuplicateDigest};

/// One `<hex> <size> <path>` fact, folded across algorithm blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumEntry {
    pub path: String,
    pub size: u64,
    pub digests: DigestSet,
}

/// Every file this Release names, with the union of digests advertised.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReleaseChecksums {
    entries: Vec<ChecksumEntry>,
    index: BTreeMap<String, usize>,
}

impl ReleaseChecksums {
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&ChecksumEntry> {
        self.index.get(path).map(|&i| &self.entries[i])
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ChecksumEntry> {
        self.entries.iter()
    }

    /// Insert or merge (algo, hex, size, path) into the set.
    ///
    /// # Errors
    ///
    /// Bubbles up hex-decode / length / size-conflict problems.
    pub fn upsert(
        &mut self,
        algo: DigestAlgo,
        hex: &str,
        size: u64,
        path: &str,
    ) -> Result<(), ChecksumError> {
        let bytes = decode_hex(hex).ok_or_else(|| ChecksumError::BadHex {
            path: path.to_owned(),
            algo,
            hex: hex.to_owned(),
        })?;
        let digest = Digest::new(algo, bytes).map_err(|e| match e {
            DigestError::LengthMismatch { expected, got, .. } => ChecksumError::HexLengthMismatch {
                path: path.to_owned(),
                algo,
                expected,
                got,
            },
        })?;

        if let Some(&idx) = self.index.get(path) {
            let entry = &mut self.entries[idx];
            if entry.size != size {
                return Err(ChecksumError::SizeConflict {
                    path: path.to_owned(),
                    previous: entry.size,
                    current: size,
                });
            }
            entry
                .digests
                .push(digest)
                .map_err(|dup| ChecksumError::ConflictingDigest {
                    path: path.to_owned(),
                    algo: dup.algo,
                    existing: dup.existing,
                    incoming: dup.incoming,
                })?;
        } else {
            let mut digests = DigestSet::new();
            digests
                .push(digest)
                .map_err(|dup| ChecksumError::ConflictingDigest {
                    path: path.to_owned(),
                    algo: dup.algo,
                    existing: dup.existing,
                    incoming: dup.incoming,
                })?;
            let idx = self.entries.len();
            self.entries.push(ChecksumEntry {
                path: path.to_owned(),
                size,
                digests,
            });
            self.index.insert(path.to_owned(), idx);
        }
        Ok(())
    }

    /// Apply `verify.allow_weak_hash`: when denied, drop entries whose strongest digest is
    /// MD5/SHA-1. Weak-only paths are reported either way.
    #[must_use]
    pub fn apply_weak_hash_policy(mut self, allow_weak_hash: bool) -> (Self, WeakHashReport) {
        let mut weak_only = Vec::new();
        let mut i = self.entries.len();
        while i > 0 {
            i -= 1;
            let is_weak = self
                .entries
                .get(i)
                .and_then(|e| e.digests.strongest())
                .is_some_and(|d| d.algo.is_weak());
            if is_weak {
                weak_only.push(self.entries[i].path.clone());
                if !allow_weak_hash {
                    self.entries.swap_remove(i);
                }
            }
        }
        if !allow_weak_hash && !weak_only.is_empty() {
            self.index.clear();
            for (idx, entry) in self.entries.iter().enumerate() {
                self.index.insert(entry.path.clone(), idx);
            }
        }
        weak_only.sort();
        let kept = self.entries.len();
        let report = WeakHashReport {
            weak_only_count: weak_only.len(),
            weak_only_paths: weak_only,
            kept_count: kept,
            policy_dropped: !allow_weak_hash,
        };
        (self, report)
    }
}

/// Outcome of `apply_weak_hash_policy`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WeakHashReport {
    pub weak_only_paths: Vec<String>,
    pub weak_only_count: usize,
    pub kept_count: usize,
    pub policy_dropped: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ChecksumError {
    #[error("hex digest for `{path}` ({algo:?}) is not valid: `{hex}`")]
    BadHex {
        path: String,
        algo: DigestAlgo,
        hex: String,
    },
    #[error("hex digest for `{path}` ({algo:?}) length mismatch: expected {expected}, got {got}")]
    HexLengthMismatch {
        path: String,
        algo: DigestAlgo,
        expected: usize,
        got: usize,
    },
    #[error("checksum size mismatch for `{path}`: was {previous}, now {current}")]
    SizeConflict {
        path: String,
        previous: u64,
        current: u64,
    },
    #[error("conflicting {algo:?} digest for `{path}`: existing {existing} vs incoming {incoming}")]
    ConflictingDigest {
        path: String,
        algo: DigestAlgo,
        existing: String,
        incoming: String,
    },
}

impl From<DuplicateDigest> for ChecksumError {
    /// For a bare `DigestSet::push` with no path in scope.
    fn from(dup: DuplicateDigest) -> Self {
        Self::ConflictingDigest {
            path: String::new(),
            algo: dup.algo,
            existing: dup.existing,
            incoming: dup.incoming,
        }
    }
}

#[must_use]
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: usize) -> String {
        "0".repeat(n)
    }

    #[test]
    fn upsert_creates_entry() {
        let mut c = ReleaseChecksums::default();
        c.upsert(DigestAlgo::Sha256, &h(64), 100, "a").unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("a").unwrap().size, 100);
    }

    #[test]
    fn upsert_merges_across_algorithms() {
        let mut c = ReleaseChecksums::default();
        c.upsert(DigestAlgo::Sha256, &h(64), 100, "a").unwrap();
        c.upsert(DigestAlgo::Sha512, &"1".repeat(128), 100, "a")
            .unwrap();
        assert_eq!(c.len(), 1);
        let e = c.get("a").unwrap();
        assert_eq!(e.digests.len(), 2);
        assert_eq!(e.digests.strongest().unwrap().algo, DigestAlgo::Sha512);
    }

    #[test]
    fn size_conflict_rejected() {
        let mut c = ReleaseChecksums::default();
        c.upsert(DigestAlgo::Sha256, &h(64), 100, "a").unwrap();
        let err = c
            .upsert(DigestAlgo::Sha512, &"1".repeat(128), 200, "a")
            .unwrap_err();
        assert!(matches!(err, ChecksumError::SizeConflict { .. }));
    }

    #[test]
    fn conflicting_sha256_across_lines_for_same_path_rejected() {
        // Malicious Release: two different SHA-256 digests for the same path and size.
        let mut c = ReleaseChecksums::default();
        c.upsert(
            DigestAlgo::Sha256,
            &h(64),
            100,
            "main/binary-amd64/Packages",
        )
        .unwrap();
        let err = c
            .upsert(
                DigestAlgo::Sha256,
                &"f".repeat(64),
                100,
                "main/binary-amd64/Packages",
            )
            .unwrap_err();
        match err {
            ChecksumError::ConflictingDigest {
                path,
                algo,
                existing,
                incoming,
            } => {
                assert_eq!(path, "main/binary-amd64/Packages");
                assert_eq!(algo, DigestAlgo::Sha256);
                assert_eq!(existing, h(64));
                assert_eq!(incoming, "f".repeat(64));
            }
            other => panic!("expected ConflictingDigest, got {other:?}"),
        }
    }

    #[test]
    fn bad_hex_rejected() {
        let mut c = ReleaseChecksums::default();
        let err = c
            .upsert(DigestAlgo::Sha256, &format!("{}zz", h(62)), 100, "a")
            .unwrap_err();
        assert!(matches!(err, ChecksumError::BadHex { .. }));
    }

    #[test]
    fn hex_length_mismatch_rejected() {
        let mut c = ReleaseChecksums::default();
        let err = c.upsert(DigestAlgo::Sha256, &h(60), 100, "a").unwrap_err();
        assert!(
            matches!(
                err,
                ChecksumError::BadHex { .. } | ChecksumError::HexLengthMismatch { .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn weak_only_dropped_when_denied() {
        let mut c = ReleaseChecksums::default();
        c.upsert(DigestAlgo::Md5, &h(32), 100, "weak").unwrap();
        c.upsert(DigestAlgo::Sha256, &h(64), 100, "strong").unwrap();
        let (filtered, report) = c.apply_weak_hash_policy(false);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.get("weak").is_none());
        assert!(filtered.get("strong").is_some());
        assert_eq!(report.weak_only_paths, vec!["weak".to_owned()]);
        assert!(report.policy_dropped);
    }

    #[test]
    fn weak_only_kept_when_allowed() {
        let mut c = ReleaseChecksums::default();
        c.upsert(DigestAlgo::Md5, &h(32), 100, "weak").unwrap();
        let (filtered, report) = c.apply_weak_hash_policy(true);
        assert_eq!(filtered.len(), 1);
        assert_eq!(report.weak_only_count, 1);
        assert!(!report.policy_dropped);
    }

    #[test]
    fn strong_untouched_by_policy() {
        let mut c = ReleaseChecksums::default();
        c.upsert(DigestAlgo::Sha512, &"1".repeat(128), 100, "a")
            .unwrap();
        let (filtered, report) = c.apply_weak_hash_policy(false);
        assert_eq!(filtered.len(), 1);
        assert_eq!(report.weak_only_count, 0);
    }

    #[test]
    fn decode_hex_handles_case_and_odd_length() {
        assert_eq!(decode_hex("aB"), Some(vec![0xAB]));
        assert_eq!(decode_hex(""), Some(vec![]));
        assert_eq!(decode_hex("f"), None); // odd length
        assert_eq!(decode_hex("xy"), None); // non-hex
    }
}
