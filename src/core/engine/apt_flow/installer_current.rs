//! d-i `current` symlink rebuild.
//!
//! After publish, point each `<comp>/installer-<arch>/current` at the newest
//! version dir. Failures only warn: a stale `current` is not a correctness
//! issue.

use std::path::Path;

use tracing::warn;

/// Rebuild every d-i `current` symlink under `final_dist_dir`.
///
/// Versions (`yyyymmdd[+deb<N>u<K>]`) are lex-sorted, which is correct
/// except for double-digit `u<K>` (u10 < u9); Debian hasn't gone past u9.
pub(super) fn rebuild(final_dist_dir: &Path, suite: &str) {
    let entries = match std::fs::read_dir(final_dist_dir) {
        Ok(r) => r,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    dist_dir = %final_dist_dir.display(),
                    err = %e,
                    "d-i current rebuild: cannot read dist dir",
                );
            }
            return;
        }
    };
    for comp_entry in entries.flatten() {
        let comp_path = comp_entry.path();
        let Ok(ft) = comp_entry.file_type() else {
            continue;
        };
        if !ft.is_dir() {
            continue;
        }
        let arch_entries = match std::fs::read_dir(&comp_path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for arch_entry in arch_entries.flatten() {
            let arch_path = arch_entry.path();
            let Some(arch_name) = arch_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !arch_name.starts_with("installer-") {
                continue;
            }
            if !arch_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            match refresh_in(&arch_path) {
                Ok(Some(v)) => tracing::debug!(
                    suite,
                    installer_dir = %arch_path.display(),
                    version = %v,
                    "d-i current symlink refreshed",
                ),
                Ok(None) => {}
                Err(e) => warn!(
                    suite,
                    installer_dir = %arch_path.display(),
                    err = %e,
                    "d-i current symlink refresh failed — installer clients may serve stale version"
                ),
            }
        }
    }
}

/// Point `<installer_dir>/current` at the newest version subdir and return
/// it; `None` when there is none.
pub(super) fn refresh_in(installer_dir: &Path) -> std::io::Result<Option<String>> {
    let latest = match pick_latest(installer_dir)? {
        Some(v) => v,
        None => return Ok(None),
    };

    let link_path = installer_dir.join("current");
    // Never clobber a real directory.
    match std::fs::symlink_metadata(&link_path) {
        Ok(meta) if meta.file_type().is_dir() && !meta.file_type().is_symlink() => {
            warn!(
                path = %link_path.display(),
                "d-i current is a real directory — refusing to replace with symlink"
            );
            return Ok(Some(latest));
        }
        Ok(_) => {
            let _ = std::fs::remove_file(&link_path);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&latest, &link_path)?;
    }
    #[cfg(not(unix))]
    {
        let _ = &latest;
    }
    Ok(Some(latest))
}

fn pick_latest(installer_dir: &Path) -> std::io::Result<Option<String>> {
    let mut versions: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(installer_dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if !ft.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name == "current" {
            continue;
        }
        if !name.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        versions.push(name);
    }
    if versions.is_empty() {
        return Ok(None);
    }
    versions.sort();
    Ok(versions.pop())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_root(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("tain-di-cur-{name}-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn deb_nu_suffix_sorts_after_bare_date() {
        let mut v = [
            "20250803".to_owned(),
            "20250803+deb13u5".to_owned(),
            "20250803+deb13u0".to_owned(),
        ];
        v.sort();
        assert_eq!(v.last().unwrap(), "20250803+deb13u5");
    }

    #[test]
    fn newer_date_beats_older_date_with_suffix() {
        let mut v = ["20250803+deb13u9".to_owned(), "20250901".to_owned()];
        v.sort();
        assert_eq!(v.last().unwrap(), "20250901");
    }

    /// Pins the accepted u9/u10 mis-ordering.
    #[test]
    fn known_lex_sort_failure_at_double_digit_u() {
        let mut v = [
            "20250803+deb13u9".to_owned(),
            "20250803+deb13u10".to_owned(),
        ];
        v.sort();
        assert_eq!(
            v.last().unwrap(),
            "20250803+deb13u9",
            "double-digit u breaks lex; upgrade to natural-sort if needed"
        );
    }

    #[test]
    fn refresh_creates_current_pointing_at_max() {
        let root = temp_root("basic");
        std::fs::create_dir_all(root.join("20250803")).unwrap();
        std::fs::create_dir_all(root.join("20250901")).unwrap();
        std::fs::create_dir_all(root.join("20250901+deb13u1")).unwrap();

        let chosen = refresh_in(&root).unwrap().unwrap();
        assert_eq!(chosen, "20250901+deb13u1");

        let current = root.join("current");
        let target = std::fs::read_link(&current).unwrap();
        assert_eq!(target, PathBuf::from("20250901+deb13u1"));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refresh_replaces_stale_current_symlink() {
        let root = temp_root("stale");
        std::fs::create_dir_all(root.join("20250803")).unwrap();
        std::fs::create_dir_all(root.join("20250901")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("20250803", root.join("current")).unwrap();

        let chosen = refresh_in(&root).unwrap().unwrap();
        assert_eq!(chosen, "20250901");
        #[cfg(unix)]
        {
            let target = std::fs::read_link(root.join("current")).unwrap();
            assert_eq!(target, PathBuf::from("20250901"));
        }

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refresh_no_versions_yields_none() {
        let root = temp_root("empty");
        let out = refresh_in(&root).unwrap();
        assert!(out.is_none());
        assert!(!root.join("current").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refresh_skips_non_version_siblings() {
        let root = temp_root("junk");
        std::fs::create_dir_all(root.join("README-directory")).unwrap();
        std::fs::create_dir_all(root.join("20250803")).unwrap();
        let chosen = refresh_in(&root).unwrap().unwrap();
        assert_eq!(chosen, "20250803");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refresh_refuses_to_clobber_real_dir_named_current() {
        let root = temp_root("real-dir");
        std::fs::create_dir_all(root.join("20250803")).unwrap();
        std::fs::create_dir_all(root.join("current")).unwrap();
        std::fs::write(root.join("current/pinned-file"), b"user data").unwrap();

        let chosen = refresh_in(&root).unwrap();
        assert_eq!(chosen.as_deref(), Some("20250803"));
        assert!(root.join("current/pinned-file").exists());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebuild_walks_multi_component_multi_arch() {
        let dist = temp_root("multi");
        for (comp, arch, ver) in [
            ("main", "amd64", "20250803"),
            ("main", "amd64", "20250901"),
            ("main", "arm64", "20250901"),
            ("contrib", "amd64", "20250803"),
        ] {
            std::fs::create_dir_all(dist.join(comp).join(format!("installer-{arch}")).join(ver))
                .unwrap();
        }
        std::fs::create_dir_all(dist.join("main/binary-amd64")).unwrap();

        rebuild(&dist, "trixie");

        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::read_link(dist.join("main/installer-amd64/current")).unwrap(),
                PathBuf::from("20250901")
            );
            assert_eq!(
                std::fs::read_link(dist.join("main/installer-arm64/current")).unwrap(),
                PathBuf::from("20250901")
            );
            assert_eq!(
                std::fs::read_link(dist.join("contrib/installer-amd64/current")).unwrap(),
                PathBuf::from("20250803")
            );
        }
        assert!(!dist.join("main/binary-amd64/current").exists());

        std::fs::remove_dir_all(&dist).ok();
    }

    #[test]
    fn rebuild_on_missing_dist_dir_is_silent_noop() {
        let ghost = std::env::temp_dir().join("tain-di-ghost-XXXXXX-does-not-exist");
        rebuild(&ghost, "trixie");
        assert!(!ghost.exists());
    }
}
