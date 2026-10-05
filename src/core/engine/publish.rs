//! Atomic suite publish.
//!
//! Linux swaps old and new suite dirs in one `renameat2(RENAME_EXCHANGE)`;
//! elsewhere (macOS dev) a two-step rename leaves a brief window. Flat repos
//! (`<dir>/./`) swap `<mirror_root>/<dir>/` the same way; pure `./` is
//! rejected at config parse because it can't be swapped atomically.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("I/O on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("renameat2(RENAME_EXCHANGE) failed for `{a}` ↔ `{b}`: {source}")]
    Exchange {
        a: PathBuf,
        b: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Atomically replace `final_dir` with `staging`.
///
/// The replaced dir is moved to `retain_prev_to` (normally
/// `.tain/prev/<suite>/<gen>/`, later retired by GC) or deleted if `None`.
///
/// # Errors
///
/// Any I/O along the way.
pub fn publish_suite(
    staging: &Path,
    final_dir: &Path,
    retain_prev_to: Option<&Path>,
) -> Result<(), PublishError> {
    if let Some(parent) = final_dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| PublishError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    if final_dir.exists() {
        exchange_or_fallback(staging, final_dir, retain_prev_to)?;
    } else {
        std::fs::rename(staging, final_dir).map_err(|e| PublishError::Io {
            path: staging.to_path_buf(),
            source: e,
        })?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn exchange_or_fallback(
    a: &Path,
    b: &Path,
    retain_prev_to: Option<&Path>,
) -> Result<(), PublishError> {
    use std::os::unix::ffi::OsStrExt;

    let ca = std::ffi::CString::new(a.as_os_str().as_bytes()).map_err(|e| PublishError::Io {
        path: a.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
    })?;
    let cb = std::ffi::CString::new(b.as_os_str().as_bytes()).map_err(|e| PublishError::Io {
        path: b.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
    })?;

    // Raw syscall: `libc::renameat2` is gnu-only and the static release
    // build targets musl.
    //
    // SAFETY: valid NUL-terminated paths and AT_FDCWD sentinel; kernel
    // ignores extra vararg slots on this syscall.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            ca.as_ptr(),
            libc::AT_FDCWD,
            cb.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if rc == 0 {
        // `a` now holds the previously published dir.
        retire_previous(a, retain_prev_to);
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EINVAL) || err.raw_os_error() == Some(libc::ENOSYS) {
        // Filesystem lacks RENAME_EXCHANGE.
        return two_step_rename(a, b, retain_prev_to);
    }
    Err(PublishError::Exchange {
        a: a.to_path_buf(),
        b: b.to_path_buf(),
        source: err,
    })
}

#[cfg(not(target_os = "linux"))]
fn exchange_or_fallback(
    a: &Path,
    b: &Path,
    retain_prev_to: Option<&Path>,
) -> Result<(), PublishError> {
    two_step_rename(a, b, retain_prev_to)
}

fn two_step_rename(a: &Path, b: &Path, retain_prev_to: Option<&Path>) -> Result<(), PublishError> {
    // Not atomic: `b` is briefly missing between the two renames.
    let sidecar = b.with_extension("prev.tain~");
    if sidecar.exists() {
        std::fs::remove_dir_all(&sidecar).map_err(|e| PublishError::Io {
            path: sidecar.clone(),
            source: e,
        })?;
    }
    std::fs::rename(b, &sidecar).map_err(|e| PublishError::Io {
        path: b.to_path_buf(),
        source: e,
    })?;
    std::fs::rename(a, b).map_err(|e| PublishError::Io {
        path: a.to_path_buf(),
        source: e,
    })?;
    retire_previous(&sidecar, retain_prev_to);
    Ok(())
}

/// Move `stale` to `retain_to`, else delete it. Errors are only logged:
/// the swap already succeeded, so a leftover tree is not fatal.
fn retire_previous(stale: &Path, retain_to: Option<&Path>) {
    if let Some(dst) = retain_to {
        if let Some(parent) = dst.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!(
                parent = %parent.display(),
                err = %e,
                "failed to create .tain/prev parent — falling back to remove_dir_all"
            );
            let _ = std::fs::remove_dir_all(stale);
            return;
        }
        // A stale slot (e.g. after a crash) must not merge two generations.
        if dst.exists() {
            let _ = std::fs::remove_dir_all(dst);
        }
        match std::fs::rename(stale, dst) {
            Ok(()) => {
                tracing::debug!(
                    prev = %dst.display(),
                    "previous published dir retained for keep_generations"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    stale = %stale.display(),
                    dst = %dst.display(),
                    err = %e,
                    "failed to retain previous published dir — falling back to remove_dir_all"
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(stale);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_root(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("tain-pub-{name}-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn first_publish_renames_into_place() {
        let root = temp_root("first");
        let staging = root.join("staging");
        let final_dir = root.join("dists/bookworm");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("InRelease"), b"hello").unwrap();

        publish_suite(&staging, &final_dir, None).unwrap();

        assert!(!staging.exists());
        assert_eq!(
            std::fs::read(final_dir.join("InRelease")).unwrap(),
            b"hello"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flat_subdir_publish_reuses_atomic_swap() {
        let root = temp_root("flatsub");
        let mirror_root = root.join("mirror");
        std::fs::create_dir_all(mirror_root.join(".tain/manifest")).unwrap();
        std::fs::write(mirror_root.join(".tain/manifest/1.json"), b"state").unwrap();

        let final_dir = mirror_root.join("repo");
        std::fs::create_dir_all(&final_dir).unwrap();
        std::fs::write(final_dir.join("InRelease"), b"old inrel").unwrap();

        let staging = mirror_root.join(".tain/staging/repo");
        std::fs::create_dir_all(staging.join("pool")).unwrap();
        std::fs::write(staging.join("InRelease"), b"new inrel").unwrap();
        std::fs::write(staging.join("pool/x.deb"), b"deb bytes").unwrap();

        publish_suite(&staging, &final_dir, None).unwrap();

        assert_eq!(
            std::fs::read(final_dir.join("InRelease")).unwrap(),
            b"new inrel"
        );
        assert_eq!(
            std::fs::read(final_dir.join("pool/x.deb")).unwrap(),
            b"deb bytes"
        );
        assert_eq!(
            std::fs::read(mirror_root.join(".tain/manifest/1.json")).unwrap(),
            b"state",
            "the .tain/ state must survive a flat-subdir publish",
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn second_publish_swaps_contents() {
        let root = temp_root("swap");
        let final_dir = root.join("dists/bookworm");
        std::fs::create_dir_all(&final_dir).unwrap();
        std::fs::write(final_dir.join("InRelease"), b"old").unwrap();

        let staging = root.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("InRelease"), b"new").unwrap();

        publish_suite(&staging, &final_dir, None).unwrap();

        assert_eq!(std::fs::read(final_dir.join("InRelease")).unwrap(), b"new");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn publish_retains_previous_dir_when_asked() {
        let root = temp_root("retain");
        let final_dir = root.join("dists/bookworm");
        std::fs::create_dir_all(&final_dir).unwrap();
        std::fs::write(final_dir.join("InRelease"), b"old").unwrap();
        std::fs::write(final_dir.join("Release"), b"old release").unwrap();

        let staging = root.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("InRelease"), b"new").unwrap();

        let prev_slot = root.join(".tain/prev/bookworm/1");
        publish_suite(&staging, &final_dir, Some(&prev_slot)).unwrap();

        assert_eq!(std::fs::read(final_dir.join("InRelease")).unwrap(), b"new");
        assert!(prev_slot.exists(), "prev slot must have the old dir");
        assert_eq!(
            std::fs::read(prev_slot.join("InRelease")).unwrap(),
            b"old",
            "prev slot must contain the old bytes"
        );
        assert_eq!(
            std::fs::read(prev_slot.join("Release")).unwrap(),
            b"old release",
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
