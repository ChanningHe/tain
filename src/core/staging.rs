//! Context handles the core passes to backends. `StagingOps` and
//! `GenerationSnapshot` are placeholders.

use std::path::{Path, PathBuf};

use crate::config::MirrorConfig;

/// Immutable context passed to every `ManifestBackend` method.
#[derive(Debug)]
pub struct SyncCtx<'a> {
    pub mirror: &'a MirrorConfig,
    pub target_root: PathBuf,
}

impl<'a> SyncCtx<'a> {
    #[must_use]
    pub fn new(mirror: &'a MirrorConfig, target_root: PathBuf) -> Self {
        Self {
            mirror,
            target_root,
        }
    }

    #[must_use]
    pub fn mirror_dir(&self) -> PathBuf {
        self.target_root.join(&self.mirror.path)
    }
}

/// Context passed to `TransportBackend::sync`.
#[derive(Debug)]
pub struct TransportCtx<'a> {
    pub mirror: &'a MirrorConfig,
    pub target_root: PathBuf,
}

impl<'a> TransportCtx<'a> {
    #[must_use]
    pub fn new(mirror: &'a MirrorConfig, target_root: PathBuf) -> Self {
        Self {
            mirror,
            target_root,
        }
    }
}

/// The staging area at `.tain/staging/<suite>/`; mutated only via [`StagingOps`].
#[derive(Debug)]
pub struct StagedTree {
    root: PathBuf,
}

impl StagedTree {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Layout primitives (hardlink/rename/symlink) a backend may apply to staging
/// in `prepare_publish`. Placeholder with no methods yet.
#[derive(Debug, Default)]
pub struct StagingOps {}

/// Read-only view of the previous generation (e.g. for by-hash inheritance).
#[derive(Debug)]
pub struct GenerationSnapshot {
    pub id: u64,
}

/// Transport backend transfer counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransferReport {
    pub files_transferred: u64,
    pub bytes_transferred: u64,
    pub files_deleted: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{
        AptOptions, BackendKind, BackendOptions, GcConfig, MirrorConfig, VerifyConfig,
    };
    use std::path::PathBuf;
    use url::Url;

    fn fixture_mirror() -> MirrorConfig {
        MirrorConfig {
            name: "proxmox".to_owned(),
            backend: BackendKind::Apt,
            url: Url::parse("http://download.proxmox.com/debian/pve").unwrap(),
            path: PathBuf::from("proxmox"),
            verify: VerifyConfig::default(),
            gc: GcConfig::default(),
            force_http1: false,
            backend_options: BackendOptions::Apt(AptOptions::test_new(
                vec!["bookworm".to_owned()],
                vec!["pve-no-subscription".to_owned()],
                vec!["amd64".to_owned()],
            )),
        }
    }

    #[test]
    fn sync_ctx_mirror_dir_joins_target_and_path() {
        let mirror = fixture_mirror();
        let ctx = SyncCtx::new(&mirror, PathBuf::from("/srv/mirrors"));
        assert_eq!(ctx.mirror_dir(), PathBuf::from("/srv/mirrors/proxmox"));
    }

    #[test]
    fn transport_ctx_holds_target() {
        let mirror = fixture_mirror();
        let ctx = TransportCtx::new(&mirror, PathBuf::from("/data"));
        assert_eq!(ctx.target_root, PathBuf::from("/data"));
    }

    #[test]
    fn staged_tree_reports_root() {
        let t = StagedTree::new(PathBuf::from("/tmp/staging"));
        assert_eq!(t.root(), Path::new("/tmp/staging"));
    }
}
