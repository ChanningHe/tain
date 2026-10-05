//! APT backend. The sync pipeline lives in `core::engine::apt_flow`; the
//! `ManifestBackend` methods are stubs. Parsers here are pure (no I/O) and only
//! produce `FileSpec`/`PublishSpec`; `core` does all placement.

pub mod checksums;
pub mod clearsign;
pub mod compression;
pub mod datetime;
pub mod deb822;
pub mod index_selector;
pub mod installer_sums;
pub mod layout;
pub mod packages;
pub mod pgp;
pub mod release;
pub mod sources;

use async_trait::async_trait;

use crate::config::model::{BackendOptions, MirrorConfig, PgpMode};
use crate::core::backend::{Backend, BackendError, ManifestBackend, PlanOutput, SyncStrategy};
use crate::core::staging::SyncCtx;
use crate::core::types::{Probe, Token};

/// Stateless APT backend handle; config is read from `SyncCtx` on each call.
#[derive(Debug, Default)]
pub struct AptBackend;

impl AptBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Backend for AptBackend {
    fn name(&self) -> &'static str {
        "apt"
    }

    fn validate_config(&self, mirror: &MirrorConfig) -> Result<(), BackendError> {
        let BackendOptions::Apt(apt) = &mirror.backend_options;

        // Backstop for configs built without the loader, which rejects all flat suites.
        // Pure `./` targets the mirror root and cannot be swapped atomically.
        for suite in &apt.suites {
            if suite == "./" || suite == "." {
                return Err(BackendError::Config(format!(
                    "mirror `{}`: flat-repo suite `{}` targets the mirror root and can't be \
                     published atomically — use `<dir>/./` instead",
                    mirror.name, suite,
                )));
            }
        }

        let has_flat_suite = apt.suites.iter().any(|s| is_layout_flat_form(s));
        let has_non_flat_suite = apt.suites.iter().any(|s| !is_layout_flat_form(s));
        if has_flat_suite && has_non_flat_suite {
            return Err(BackendError::Config(format!(
                "mirror `{}`: cannot mix flat-repo suites (`./`) with dists-style suites in the same mirror",
                mirror.name,
            )));
        }
        if has_flat_suite && !apt.components.is_empty() {
            return Err(BackendError::Config(format!(
                "mirror `{}`: flat repo (suites = [`./`, ...]) must have empty components",
                mirror.name,
            )));
        }
        if !has_flat_suite && apt.components.is_empty() {
            return Err(BackendError::Config(format!(
                "mirror `{}`: dists-style mirror must declare at least one component",
                mirror.name,
            )));
        }
        if mirror.verify.pgp == PgpMode::Required && mirror.verify.keyring.is_none() {
            return Err(BackendError::Config(format!(
                "mirror `{}`: verify.pgp = required needs verify.keyring",
                mirror.name,
            )));
        }
        // Fail at config load rather than mid-sync.
        #[cfg(not(feature = "pgp"))]
        if mirror.verify.pgp == PgpMode::Required {
            return Err(BackendError::Config(format!(
                "mirror `{}`: verify.pgp = required is unavailable — this tain build was compiled without the `pgp` feature",
                mirror.name,
            )));
        }

        // Reject unsafe suite paths at config load rather than mid-sync.
        for suite in &apt.suites {
            if is_layout_flat_form(suite) {
                continue;
            }
            let layout = crate::backends::apt::layout::SuiteLayout::new(&mirror.url, suite);
            if let Err(e) = layout.suite_rel("InRelease") {
                return Err(BackendError::Config(format!(
                    "mirror `{}`: suite `{}` produces an unsafe path: {}",
                    mirror.name, suite, e,
                )));
            }
        }

        Ok(())
    }

    fn strategy(&self) -> SyncStrategy<'_> {
        SyncStrategy::Manifest(self)
    }
}

/// Flat forms `SuiteLayout::is_flat` handles: `./` or a suite ending in `/./`.
fn is_layout_flat_form(s: &str) -> bool {
    s == "./" || s.ends_with("/./")
}

#[async_trait]
impl ManifestBackend for AptBackend {
    async fn probe(&self, _ctx: &SyncCtx<'_>) -> Result<Probe, BackendError> {
        Err(BackendError::NotImplementedYet("AptBackend::probe"))
    }

    async fn plan<'a>(
        &'a self,
        _ctx: &'a SyncCtx<'_>,
        _token: Token,
    ) -> Result<PlanOutput<'a>, BackendError> {
        Err(BackendError::NotImplementedYet("AptBackend::plan"))
    }
    // by-hash and the Release recheck live in `core::engine`, so the trait defaults suffice.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{
        AptOptions, BackendKind, BackendOptions, GcConfig, MirrorConfig, PgpMode, VerifyConfig,
    };
    use std::path::PathBuf;
    use url::Url;

    fn mirror(name: &str, apt: AptOptions, verify: VerifyConfig) -> MirrorConfig {
        MirrorConfig {
            name: name.to_owned(),
            backend: BackendKind::Apt,
            url: Url::parse("http://example.com/repo").unwrap(),
            path: PathBuf::from(name),
            verify,
            gc: GcConfig::default(),
            force_http1: false,
            backend_options: BackendOptions::Apt(apt),
        }
    }

    #[test]
    fn name_is_apt() {
        assert_eq!(AptBackend::new().name(), "apt");
    }

    #[test]
    fn strategy_is_manifest() {
        let b = AptBackend::new();
        assert!(matches!(b.strategy(), SyncStrategy::Manifest(_)));
    }

    #[test]
    fn validate_accepts_normal_pool_mirror() {
        let apt = AptOptions::test_new(
            vec!["bookworm".to_owned()],
            vec!["main".to_owned()],
            vec!["amd64".to_owned()],
        );
        let m = mirror("debian", apt, VerifyConfig::default());
        AptBackend::new().validate_config(&m).unwrap();
    }

    #[test]
    fn validate_rejects_flat_repo_dot_slash() {
        let apt = AptOptions::test_new(vec!["./".to_owned()], vec![], vec!["amd64".to_owned()]);
        let m = mirror("flat", apt, VerifyConfig::default());
        let err = AptBackend::new().validate_config(&m).unwrap_err();
        assert!(
            matches!(&err, BackendError::Config(msg) if msg.contains("mirror root")),
            "{err:?}",
        );
    }

    #[test]
    fn validate_rejects_flat_repo_bare_dot() {
        let apt = AptOptions::test_new(vec![".".to_owned()], vec![], vec!["amd64".to_owned()]);
        let m = mirror("flat", apt, VerifyConfig::default());
        let err = AptBackend::new().validate_config(&m).unwrap_err();
        assert!(matches!(err, BackendError::Config(_)), "{err:?}");
    }

    #[test]
    fn validate_accepts_flat_repo_subdir() {
        let apt = AptOptions::test_new(vec!["foo/./".to_owned()], vec![], vec!["amd64".to_owned()]);
        let m = mirror("flat", apt, VerifyConfig::default());
        AptBackend::new().validate_config(&m).unwrap();
    }

    #[test]
    fn validate_rejects_flat_repo_with_components() {
        let apt = AptOptions::test_new(
            vec!["foo/./".to_owned()],
            vec!["main".to_owned()],
            vec!["amd64".to_owned()],
        );
        let m = mirror("flat", apt, VerifyConfig::default());
        let err = AptBackend::new().validate_config(&m).unwrap_err();
        assert!(matches!(err, BackendError::Config(_)), "{err:?}");
    }

    #[test]
    fn validate_rejects_mixed_flat_and_dists() {
        let apt = AptOptions::test_new(
            vec!["foo/./".to_owned(), "bookworm".to_owned()],
            vec!["main".to_owned()],
            vec!["amd64".to_owned()],
        );
        let m = mirror("mixed", apt, VerifyConfig::default());
        let err = AptBackend::new().validate_config(&m).unwrap_err();
        assert!(matches!(err, BackendError::Config(_)), "{err:?}");
    }

    #[test]
    fn validate_rejects_dists_repo_without_components() {
        let apt = AptOptions::test_new(
            vec!["bookworm".to_owned()],
            vec![],
            vec!["amd64".to_owned()],
        );
        let m = mirror("no-comp", apt, VerifyConfig::default());
        let err = AptBackend::new().validate_config(&m).unwrap_err();
        assert!(matches!(err, BackendError::Config(_)), "{err:?}");
    }

    #[test]
    fn validate_rejects_pgp_required_without_keyring() {
        let apt = AptOptions::test_new(
            vec!["bookworm".to_owned()],
            vec!["main".to_owned()],
            vec!["amd64".to_owned()],
        );
        let v = VerifyConfig {
            pgp: PgpMode::Required,
            keyring: None,
            ..VerifyConfig::default()
        };
        let m = mirror("d", apt, v);
        let err = AptBackend::new().validate_config(&m).unwrap_err();
        assert!(
            matches!(&err, BackendError::Config(msg) if msg.contains("keyring")),
            "{err:?}"
        );
    }

    #[cfg(feature = "pgp")]
    #[test]
    fn validate_accepts_pgp_required_with_keyring() {
        let apt = AptOptions::test_new(
            vec!["bookworm".to_owned()],
            vec!["main".to_owned()],
            vec!["amd64".to_owned()],
        );
        let v = VerifyConfig {
            pgp: PgpMode::Required,
            keyring: Some(PathBuf::from("/etc/keys.gpg")),
            ..VerifyConfig::default()
        };
        let m = mirror("d", apt, v);
        AptBackend::new().validate_config(&m).unwrap();
    }

    #[cfg(not(feature = "pgp"))]
    #[test]
    fn validate_rejects_pgp_required_without_pgp_feature() {
        let apt = AptOptions::test_new(
            vec!["bookworm".to_owned()],
            vec!["main".to_owned()],
            vec!["amd64".to_owned()],
        );
        let v = VerifyConfig {
            pgp: PgpMode::Required,
            keyring: Some(PathBuf::from("/etc/keys.gpg")),
            ..VerifyConfig::default()
        };
        let m = mirror("d", apt, v);
        let err = AptBackend::new().validate_config(&m).unwrap_err();
        assert!(
            matches!(&err, BackendError::Config(msg) if msg.contains("`pgp` feature")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn probe_stubs_notimplemented() {
        let apt = AptBackend::new();
        let mirror = mirror(
            "d",
            AptOptions::test_new(
                vec!["bookworm".to_owned()],
                vec!["main".to_owned()],
                vec!["amd64".to_owned()],
            ),
            VerifyConfig::default(),
        );
        let ctx = SyncCtx::new(&mirror, PathBuf::from("/tmp"));
        let err = apt.probe(&ctx).await.unwrap_err();
        assert!(matches!(err, BackendError::NotImplementedYet(_)));
    }

    #[tokio::test]
    async fn default_prepare_publish_is_noop() {
        use crate::core::staging::{StagedTree, StagingOps};
        let apt = AptBackend::new();
        let mut staged = StagedTree::new(PathBuf::from("/tmp/staging"));
        let ops = StagingOps::default();
        apt.prepare_publish(&mut staged, None, &ops).await.unwrap();
    }

    #[tokio::test]
    async fn default_pre_publish_check_returns_ok() {
        use crate::core::staging::StagedTree;
        use crate::core::types::CheckOutcome;
        let apt = AptBackend::new();
        let mirror = mirror(
            "d",
            AptOptions::test_new(
                vec!["bookworm".to_owned()],
                vec!["main".to_owned()],
                vec!["amd64".to_owned()],
            ),
            VerifyConfig::default(),
        );
        let ctx = SyncCtx::new(&mirror, PathBuf::from("/tmp"));
        let staged = StagedTree::new(PathBuf::from("/tmp/staging"));
        assert_eq!(
            apt.pre_publish_check(&ctx, &staged).await.unwrap(),
            CheckOutcome::Ok
        );
    }

    #[test]
    fn is_layout_flat_form_recognizes_flat_forms() {
        assert!(is_layout_flat_form("./"));
        assert!(is_layout_flat_form("foo/./"));
        assert!(!is_layout_flat_form("bookworm"));
        assert!(!is_layout_flat_form("stable/updates"));
    }
}
