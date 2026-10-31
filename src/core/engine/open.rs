//! Opening a mirror: create and lock its root, check the filesystem
//! layout, load its state, and sweep what a crashed run left behind.

use std::path::{Path, PathBuf};

use tracing::warn;

use crate::config::model::{GlobalConfig, MirrorConfig};
use crate::core::store::state::MirrorState;
use crate::core::store::{lock, manifest, state};

use super::{EngineError, apt_flow};

/// A created and locked mirror root with its loaded state.
pub(super) struct OpenMirror {
    pub(super) root: PathBuf,
    pub(super) state: MirrorState,
    /// Legacy content without `state.json`: GC is forced to dry-run.
    pub(super) is_migration_boot: bool,
    _lock: lock::MirrorLock,
}

/// Create and lock the mirror root, then load its state.
pub(super) fn open_mirror(
    global: &GlobalConfig,
    mirror: &MirrorConfig,
    target_root: &Path,
) -> Result<OpenMirror, EngineError> {
    let root = target_root.join(&mirror.path);
    std::fs::create_dir_all(&root).map_err(|e| EngineError::Io {
        path: root.clone(),
        source: e,
    })?;
    let lock = lock::acquire(&root, global.lock_timeout).map_err(|e| match e {
        lock::LockError::Contended { .. } => EngineError::LockContended(e),
        other => EngineError::Lock(other),
    })?;
    check_same_filesystem(&root)?;
    let (state, is_migration_boot) = load_state(&root, mirror)?;
    Ok(OpenMirror {
        root,
        state,
        is_migration_boot,
        _lock: lock,
    })
}

/// Staged suites and pending pool replacements are moved out of `.tain/`
/// by rename, so `dists/` and `pool/` must live on its filesystem. Checked
/// up front: otherwise every publish or content change fails with EXDEV.
#[cfg(unix)]
fn check_same_filesystem(mirror_root: &Path) -> Result<(), EngineError> {
    use std::os::unix::fs::MetadataExt;
    let dev = |path: &Path| std::fs::metadata(path).map(|m| m.dev());
    let tain = mirror_root.join(crate::core::store::STATE_DIR);
    let tain_dev = dev(&tain).map_err(|e| EngineError::Io {
        path: tain.clone(),
        source: e,
    })?;
    // The root itself catches a separately mounted `.tain` before the
    // first run has created `dists/` or `pool/`.
    let paths = [
        mirror_root.to_path_buf(),
        mirror_root.join("dists"),
        mirror_root.join("pool"),
    ];
    for path in paths {
        match dev(&path) {
            Ok(d) if d != tain_dev => {
                return Err(EngineError::SplitFilesystem { tain, other: path });
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(EngineError::Io { path, source: e }),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_same_filesystem(_mirror_root: &Path) -> Result<(), EngineError> {
    Ok(())
}

/// The mirror's state and whether this is a migration boot.
fn load_state(
    mirror_root: &Path,
    mirror: &MirrorConfig,
) -> Result<(MirrorState, bool), EngineError> {
    match state::load_for_url(mirror_root, mirror.url.as_str()) {
        Ok(Some(s)) => Ok((s, false)),
        Ok(None) => {
            // Migration guard: existing content without state.json means a
            // legacy mirror; force GC dry-run so its pool isn't wiped.
            let looks_migrated = mirror_root_has_non_tain_content(mirror_root).unwrap_or(false);
            if looks_migrated {
                warn!(
                    mirror = %mirror.name,
                    mirror_root = %mirror_root.display(),
                    "no state.json but mirror_root already has content — assuming migration \
                     from a legacy layout; forcing GC to dry-run for this round. \
                     Verify the recovered manifest with `tain verify --mirror {name}` before \
                     enabling live GC.",
                    name = mirror.name,
                );
            }
            Ok((MirrorState::new(mirror.url.to_string()), looks_migrated))
        }
        Err(state::StateError::UrlMismatch { .. }) => {
            warn!(
                mirror = %mirror.name,
                "state file records a different URL — discarding state (the published Release \
                 Date still applies as the monotonicity floor)"
            );
            Ok((MirrorState::new(mirror.url.to_string()), false))
        }
        Err(e) => Err(EngineError::State(e)),
    }
}

/// Best-effort removal of what a crashed run left behind: `.tmp~` sidecars
/// of downloads under `pool/` and `dists/`, the state and manifest temp
/// files directly in `.tain/` and `.tain/manifest/` (never inside
/// `.tain/prev/`), and pool replacements no round committed.
pub(super) fn sweep_tmp_sidecars(mirror_root: &Path) {
    for sub in ["pool", "dists"] {
        sweep_dir(&mirror_root.join(sub), true);
    }
    let state_dir = mirror_root.join(crate::core::store::STATE_DIR);
    sweep_dir(&state_dir, false);
    sweep_dir(&manifest::manifest_dir(mirror_root), false);
    let pending = mirror_root.join(apt_flow::PENDING_DIR);
    if let Err(e) = std::fs::remove_dir_all(&pending)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(path = %pending.display(), %e, "failed to sweep pending pool replacements");
    }
}

/// True when `mirror_root` holds anything besides `.tain` (migration guard).
fn mirror_root_has_non_tain_content(mirror_root: &Path) -> std::io::Result<bool> {
    let entries = match std::fs::read_dir(mirror_root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name != ".tain" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sweep_dir(dir: &Path, recursive: bool) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            if recursive {
                sweep_dir(&path, true);
            }
        } else if ft.is_file()
            && path
                .as_os_str()
                .to_str()
                .is_some_and(|s| s.ends_with(".tmp~"))
            && let Err(e) = std::fs::remove_file(&path)
        {
            warn!(path = %path.display(), %e, "failed to sweep stale .tmp~");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir(base: &Path, tag: &str) -> PathBuf {
        let dir = base.join(format!("tain-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn same_filesystem_layout_passes_the_check() {
        let root = fresh_dir(&std::env::temp_dir(), "samefs");
        for sub in [".tain", "dists", "pool"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        assert!(check_same_filesystem(&root).is_ok());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pool_on_another_filesystem_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let elsewhere = Path::new("/dev/shm");
        let root = fresh_dir(&std::env::temp_dir(), "splitfs");
        let dev = |p: &Path| std::fs::metadata(p).map(|m| m.dev()).ok();
        if dev(elsewhere).is_none() || dev(elsewhere) == dev(&root) {
            std::fs::remove_dir_all(&root).unwrap();
            return; // no second filesystem to test against
        }
        let pool = fresh_dir(elsewhere, "splitfs-pool");
        std::fs::create_dir_all(root.join(".tain")).unwrap();
        std::os::unix::fs::symlink(&pool, root.join("pool")).unwrap();
        let err = check_same_filesystem(&root).unwrap_err();
        assert!(
            matches!(&err, EngineError::SplitFilesystem { other, .. } if other.ends_with("pool")),
            "{err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&pool).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn separately_mounted_state_dir_is_refused_before_the_first_run() {
        use std::os::unix::fs::MetadataExt;
        let elsewhere = Path::new("/dev/shm");
        let root = fresh_dir(&std::env::temp_dir(), "splitfs-root");
        let dev = |p: &Path| std::fs::metadata(p).map(|m| m.dev()).ok();
        if dev(elsewhere).is_none() || dev(elsewhere) == dev(&root) {
            std::fs::remove_dir_all(&root).unwrap();
            return; // no second filesystem to test against
        }
        let tain = fresh_dir(elsewhere, "splitfs-tain");
        std::os::unix::fs::symlink(&tain, root.join(".tain")).unwrap();
        let err = check_same_filesystem(&root).unwrap_err();
        assert!(
            matches!(&err, EngineError::SplitFilesystem { other, .. } if *other == root),
            "{err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&tain).unwrap();
    }

    #[test]
    fn sweep_removes_state_and_manifest_sidecars_too() {
        let root = std::env::temp_dir().join(format!("tain-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let stale = [
            "pool/main/a.deb.tmp~",
            "dists/x/InRelease.tmp~",
            ".tain/state.json.tmp~",
            ".tain/manifest/7.json.tmp~",
            ".tain/pending/pool/main/a.deb",
        ];
        let kept = [
            "pool/main/a.deb",
            ".tain/state.json",
            ".tain/manifest/7.json",
            ".tain/prev/x/1/Release.tmp~",
        ];
        for rel in stale.iter().chain(&kept) {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"x").unwrap();
        }
        sweep_tmp_sidecars(&root);
        for rel in stale {
            assert!(!root.join(rel).exists(), "{rel} not swept");
        }
        for rel in kept {
            assert!(root.join(rel).exists(), "{rel} swept");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }
}
