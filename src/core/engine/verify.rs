//! `verify` subcommand: re-hash every file in the latest manifest.
//!
//! Unreferenced files on disk are GC's concern, not this scrub's.

use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256, Sha512};

use crate::core::store::manifest::{self, ManifestEntry};
use crate::core::types::DigestAlgo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryVerdict {
    Ok,
    Missing,
    /// Any I/O error other than not-found.
    IoError {
        msg: String,
    },
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    DigestMismatch {
        algo: DigestAlgo,
        expected: String,
        actual: String,
    },
    /// No SHA-256/SHA-512 recorded: an old or corrupt manifest.
    NoDigest,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub scanned: usize,
    pub ok: usize,
    pub problems: Vec<(String, EntryVerdict)>,
}

impl VerifyReport {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error(transparent)]
    Manifest(#[from] manifest::ManifestError),
    #[error("no manifest generation found under `{mirror_root}` — nothing to verify")]
    NoManifest { mirror_root: PathBuf },
}

/// Run scrub against the latest generation manifest under `mirror_root`.
///
/// # Errors
///
/// Manifest loading failures.
pub fn scrub_latest(mirror_root: &Path) -> Result<VerifyReport, VerifyError> {
    let gens = manifest::list_generations(mirror_root)?;
    let Some(latest) = gens.last().copied() else {
        return Err(VerifyError::NoManifest {
            mirror_root: mirror_root.to_path_buf(),
        });
    };
    let m = manifest::load(mirror_root, latest)?;
    let total = m.len();
    let mut report = VerifyReport {
        scanned: total,
        ..VerifyReport::default()
    };
    // TB-scale scrubs take hours: log progress every ~2% (min 500 files).
    let step = std::cmp::max(500, total / 50);
    tracing::info!(generation = latest, files = total, "verify starting");
    for (i, (rel_path, entry)) in m.files.iter().enumerate() {
        let abs = mirror_root.join(rel_path);
        let verdict = verify_entry(&abs, entry);
        if verdict == EntryVerdict::Ok {
            report.ok += 1;
        } else {
            report.problems.push((rel_path.clone(), verdict));
        }
        let n = i + 1;
        if step > 0 && n % step == 0 && n < total {
            tracing::info!(
                verified = n,
                total = total,
                problems = report.problems.len(),
                "verify progress"
            );
        }
    }
    tracing::info!(
        verified = total,
        problems = report.problems.len(),
        "verify done"
    );
    Ok(report)
}

fn verify_entry(path: &Path, entry: &ManifestEntry) -> EntryVerdict {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return EntryVerdict::Missing,
        Err(e) => return EntryVerdict::IoError { msg: e.to_string() },
    };
    if meta.len() != entry.size {
        return EntryVerdict::SizeMismatch {
            expected: entry.size,
            actual: meta.len(),
        };
    }
    let Some((algo, expected_hex)) = entry.strongest_hex() else {
        return EntryVerdict::NoDigest;
    };
    let actual_hex = match hash_file(path, algo) {
        Ok(h) => h,
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            return EntryVerdict::NoDigest;
        }
        Err(e) => return EntryVerdict::IoError { msg: e.to_string() },
    };
    if actual_hex.eq_ignore_ascii_case(expected_hex) {
        EntryVerdict::Ok
    } else {
        EntryVerdict::DigestMismatch {
            algo,
            expected: expected_hex.to_owned(),
            actual: actual_hex,
        }
    }
}

fn hash_file(path: &Path, algo: DigestAlgo) -> std::io::Result<String> {
    use std::io::Read;
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
            Ok(hex_encode(h.finalize()))
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
            Ok(hex_encode(h.finalize()))
        }
        DigestAlgo::Sha1 | DigestAlgo::Md5 => {
            // Manifests record only SHA-256/SHA-512.
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "verify does not hash weak algorithms",
            ))
        }
    }
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
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
    use crate::core::store::manifest::GenerationManifest;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_root(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("tain-verify-{name}-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes))
    }

    #[test]
    fn all_ok_when_bytes_match() {
        let root = temp_root("ok");
        let mut m = GenerationManifest::new(1);
        std::fs::create_dir_all(root.join("pool")).unwrap();
        std::fs::write(root.join("pool/x.deb"), b"contents").unwrap();
        m.insert(ManifestEntry {
            rel_path: "pool/x.deb".to_owned(),
            size: 8,
            sha256_hex: Some(sha256_hex(b"contents")),
            sha512_hex: None,
        });
        manifest::save(&root, &m).unwrap();
        let r = scrub_latest(&root).unwrap();
        assert_eq!(r.ok, 1);
        assert!(r.is_clean());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn size_mismatch_reported() {
        let root = temp_root("size");
        let mut m = GenerationManifest::new(1);
        std::fs::create_dir_all(root.join("pool")).unwrap();
        std::fs::write(root.join("pool/x.deb"), b"contents").unwrap();
        m.insert(ManifestEntry {
            rel_path: "pool/x.deb".to_owned(),
            size: 100, // wrong
            sha256_hex: Some(sha256_hex(b"contents")),
            sha512_hex: None,
        });
        manifest::save(&root, &m).unwrap();
        let r = scrub_latest(&root).unwrap();
        assert_eq!(r.problems.len(), 1);
        assert!(matches!(
            &r.problems[0].1,
            EntryVerdict::SizeMismatch { .. }
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn digest_mismatch_reported() {
        let root = temp_root("hash");
        let mut m = GenerationManifest::new(1);
        std::fs::create_dir_all(root.join("pool")).unwrap();
        std::fs::write(root.join("pool/x.deb"), b"contents").unwrap();
        m.insert(ManifestEntry {
            rel_path: "pool/x.deb".to_owned(),
            size: 8,
            sha256_hex: Some(sha256_hex(b"WRONG")),
            sha512_hex: None,
        });
        manifest::save(&root, &m).unwrap();
        let r = scrub_latest(&root).unwrap();
        assert_eq!(r.problems.len(), 1);
        assert!(matches!(
            &r.problems[0].1,
            EntryVerdict::DigestMismatch { .. }
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn missing_reported() {
        let root = temp_root("miss");
        let mut m = GenerationManifest::new(1);
        m.insert(ManifestEntry {
            rel_path: "pool/gone.deb".to_owned(),
            size: 8,
            sha256_hex: Some(sha256_hex(b"contents")),
            sha512_hex: None,
        });
        manifest::save(&root, &m).unwrap();
        let r = scrub_latest(&root).unwrap();
        assert_eq!(r.problems.len(), 1);
        assert!(matches!(r.problems[0].1, EntryVerdict::Missing));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn no_manifest_errors() {
        let root = temp_root("empty");
        let err = scrub_latest(&root).unwrap_err();
        assert!(matches!(err, VerifyError::NoManifest { .. }));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn sha512_used_when_only_sha512() {
        let root = temp_root("s512");
        let mut m = GenerationManifest::new(1);
        std::fs::create_dir_all(root.join("pool")).unwrap();
        std::fs::write(root.join("pool/x.deb"), b"contents").unwrap();
        let sha512 = hex_encode(Sha512::digest(b"contents"));
        m.insert(ManifestEntry {
            rel_path: "pool/x.deb".to_owned(),
            size: 8,
            sha256_hex: None,
            sha512_hex: Some(sha512),
        });
        manifest::save(&root, &m).unwrap();
        let r = scrub_latest(&root).unwrap();
        assert_eq!(r.ok, 1);
        std::fs::remove_dir_all(&root).ok();
    }
}
