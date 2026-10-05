//! `by-hash/` generation and inheritance.
//!
//! Hardlinks each staged index into `by-hash/<algo>/<hex>`, and carries the
//! previously published by-hash objects over so clients holding the prior
//! InRelease still resolve across the swap. Hardlink failures (overlay, 9p,
//! some FUSE) are surfaced rather than silently falling back to copies.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// By-hash slots for one staged index file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByHashInput<'a> {
    pub staged_path: PathBuf,
    pub sha256_hex: Option<&'a str>,
    pub sha512_hex: Option<&'a str>,
    /// Set only when MD5 is the sole digest (weak-hash policy).
    pub md5_hex: Option<&'a str>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GenerationReport {
    pub links_written: usize,
    pub links_skipped_existing: usize,
}

/// Write by-hash hardlinks for every input's advertised digests.
///
/// # Errors
///
/// I/O creating the dir or link; an existing link is not an error.
pub fn write_generation<'a, I>(inputs: I) -> Result<GenerationReport, ByHashError>
where
    I: IntoIterator<Item = ByHashInput<'a>>,
{
    let mut report = GenerationReport::default();
    for input in inputs {
        let parent = match input.staged_path.parent() {
            Some(p) => p,
            None => continue,
        };
        for (algo_dir, hex) in [
            ("SHA256", input.sha256_hex),
            ("SHA512", input.sha512_hex),
            ("MD5Sum", input.md5_hex),
        ] {
            let Some(hex) = hex else { continue };
            let by_hash_dir = parent.join("by-hash").join(algo_dir);
            std::fs::create_dir_all(&by_hash_dir).map_err(|e| ByHashError::Io {
                path: by_hash_dir.clone(),
                source: e,
            })?;
            let target = by_hash_dir.join(hex);
            if target.exists() {
                report.links_skipped_existing += 1;
                continue;
            }
            match std::fs::hard_link(&input.staged_path, &target) {
                Ok(()) => report.links_written += 1,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    report.links_skipped_existing += 1;
                }
                Err(e) => {
                    return Err(ByHashError::Io {
                        path: target,
                        source: e,
                    });
                }
            }
        }
    }
    Ok(report)
}

/// Hardlink every by-hash object under `prev_dist` into the same relative
/// slot in `staging`, skipping slots that already exist.
///
/// # Errors
///
/// I/O reading `prev_dist` (a missing one is a no-op) or writing links.
pub fn inherit_from_previous(
    prev_dist: &Path,
    staging: &Path,
) -> Result<InheritanceReport, ByHashError> {
    let mut report = InheritanceReport::default();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    if !prev_dist.exists() {
        return Ok(report);
    }
    walk_and_link(prev_dist, staging, prev_dist, &mut report, &mut visited)?;
    Ok(report)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InheritanceReport {
    pub links_written: usize,
    pub links_skipped_existing: usize,
}

fn walk_and_link(
    root: &Path,
    staging: &Path,
    current: &Path,
    report: &mut InheritanceReport,
    visited: &mut HashSet<PathBuf>,
) -> Result<(), ByHashError> {
    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(ByHashError::Io {
                path: current.to_path_buf(),
                source: e,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|e| ByHashError::Io {
            path: current.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| ByHashError::Io {
            path: path.clone(),
            source: e,
        })?;
        if ft.is_dir() {
            if !visited.insert(path.clone()) {
                continue;
            }
            walk_and_link(root, staging, &path, report, visited)?;
            continue;
        }
        if !is_inside_by_hash(&path) {
            continue;
        }
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        let target = staging.join(rel);
        if target.exists() {
            report.links_skipped_existing += 1;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ByHashError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        match std::fs::hard_link(&path, &target) {
            Ok(()) => report.links_written += 1,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                report.links_skipped_existing += 1;
            }
            Err(e) => {
                return Err(ByHashError::Io {
                    path: target,
                    source: e,
                });
            }
        }
    }
    Ok(())
}

fn is_inside_by_hash(path: &Path) -> bool {
    let mut hit_by_hash = false;
    for comp in path.components() {
        if let std::path::Component::Normal(s) = comp {
            if s == "by-hash" {
                hit_by_hash = true;
                continue;
            }
            if hit_by_hash && matches!(s.to_str(), Some("SHA256" | "SHA512" | "MD5Sum")) {
                return true;
            }
        }
    }
    false
}

#[derive(Debug, thiserror::Error)]
pub enum ByHashError {
    #[error("I/O on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_root(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("tain-byhash-{name}-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn touch(path: &Path, content: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn writes_sha256_and_sha512_links() {
        let root = temp_root("write");
        let staged = root.join("main/binary-amd64/Packages");
        touch(&staged, b"packages body");
        let sha256 = "a".repeat(64);
        let sha512 = "b".repeat(128);
        let report = write_generation([ByHashInput {
            staged_path: staged.clone(),
            sha256_hex: Some(&sha256),
            sha512_hex: Some(&sha512),
            md5_hex: None,
        }])
        .unwrap();
        assert_eq!(report.links_written, 2);
        let sha256_link = root.join(format!("main/binary-amd64/by-hash/SHA256/{sha256}"));
        let sha512_link = root.join(format!("main/binary-amd64/by-hash/SHA512/{sha512}"));
        assert!(sha256_link.exists());
        assert!(sha512_link.exists());
        assert_eq!(std::fs::read(&sha256_link).unwrap(), b"packages body");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn write_generation_idempotent() {
        let root = temp_root("idempotent");
        let staged = root.join("main/binary-amd64/Packages");
        touch(&staged, b"body");
        let sha256 = "a".repeat(64);
        let input = || ByHashInput {
            staged_path: staged.clone(),
            sha256_hex: Some("a".repeat(64).leak() as &'static str),
            sha512_hex: None,
            md5_hex: None,
        };
        let _ = write_generation([input()]).unwrap();
        let r = write_generation([ByHashInput {
            staged_path: staged.clone(),
            sha256_hex: Some(&sha256),
            sha512_hex: None,
            md5_hex: None,
        }])
        .unwrap();
        assert_eq!(r.links_skipped_existing, 1);
        assert_eq!(r.links_written, 0);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn inherit_from_previous_copies_existing_by_hash() {
        let root = temp_root("inherit");
        let prev = root.join("prev");
        let staging = root.join("staging");
        let prev_obj = prev.join("main/binary-amd64/by-hash/SHA256/oldhash");
        touch(&prev_obj, b"old bytes");
        let staged_index = staging.join("main/binary-amd64/Packages");
        touch(&staged_index, b"new");
        let report = inherit_from_previous(&prev, &staging).unwrap();
        assert_eq!(report.links_written, 1);
        assert!(
            staging
                .join("main/binary-amd64/by-hash/SHA256/oldhash")
                .exists()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn inherit_from_previous_skips_when_new_side_already_has_hash() {
        let root = temp_root("inherit-skip");
        let prev = root.join("prev");
        let staging = root.join("staging");
        let obj_name = "sharedhash";
        touch(
            &prev.join(format!("main/binary-amd64/by-hash/SHA256/{obj_name}")),
            b"old",
        );
        touch(
            &staging.join(format!("main/binary-amd64/by-hash/SHA256/{obj_name}")),
            b"new",
        );
        let report = inherit_from_previous(&prev, &staging).unwrap();
        assert_eq!(report.links_skipped_existing, 1);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn inherit_from_previous_noop_when_prev_missing() {
        let root = temp_root("inherit-missing");
        let prev = root.join("prev-does-not-exist");
        let staging = root.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let report = inherit_from_previous(&prev, &staging).unwrap();
        assert_eq!(report.links_written, 0);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn inherit_ignores_non_by_hash_files() {
        let root = temp_root("inherit-nonbh");
        let prev = root.join("prev");
        let staging = root.join("staging");
        touch(&prev.join("main/binary-amd64/Packages"), b"regular");
        touch(
            &prev.join("main/binary-amd64/by-hash/SHA256/hh"),
            b"should be copied",
        );
        let report = inherit_from_previous(&prev, &staging).unwrap();
        assert_eq!(report.links_written, 1);
        assert!(
            !staging.join("main/binary-amd64/Packages").exists(),
            "regular files stay in prev — only by-hash inherits"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn is_inside_by_hash_matches_all_algos() {
        assert!(is_inside_by_hash(Path::new(
            "main/binary-amd64/by-hash/SHA256/hh"
        )));
        assert!(is_inside_by_hash(Path::new(
            "main/binary-amd64/by-hash/SHA512/hh"
        )));
        assert!(is_inside_by_hash(Path::new(
            "main/binary-amd64/by-hash/MD5Sum/hh"
        )));
        assert!(!is_inside_by_hash(Path::new("main/binary-amd64/Packages")));
        assert!(!is_inside_by_hash(Path::new(
            "main/binary-amd64/by-hash/UNKNOWN/hh"
        )));
    }
}
