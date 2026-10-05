//! The core/backend trait boundary.
//!
//! * `ManifestBackend` — backend yields `FileSpec`s and a `PublishSpec`; core
//!   downloads, verifies and publishes (APT).
//! * `TransportBackend` — backend moves the bytes itself (e.g. rsync); core
//!   still owns lock, staging, trace and status. No implementation yet.

use async_trait::async_trait;
use futures::stream::BoxStream;

use crate::config::MirrorConfig;

use super::staging::{
    GenerationSnapshot, StagedTree, StagingOps, SyncCtx, TransferReport, TransportCtx,
};
use super::types::{CheckOutcome, FileSpec, Probe, PublishSpec, Token};

/// Which strategy a backend uses; borrowed from the backend.
pub enum SyncStrategy<'a> {
    Manifest(&'a dyn ManifestBackend),
    Transport(&'a dyn TransportBackend),
}

/// The trait every backend implements; registered statically in `backends::dispatch`.
pub trait Backend: Send + Sync {
    /// Stable identifier, e.g. `"apt"`.
    fn name(&self) -> &'static str;

    /// Check format-specific config rules (e.g. flat APT repos need empty
    /// `components`); generic shape is validated by `crate::config`.
    ///
    /// # Errors
    ///
    /// `BackendError::Config` when a field is nonsensical for this backend.
    fn validate_config(&self, mirror: &MirrorConfig) -> Result<(), BackendError>;

    fn strategy(&self) -> SyncStrategy<'_>;
}

/// Manifest-driven sync strategy. Implementations must be stateless across
/// concurrent sync passes.
#[async_trait]
pub trait ManifestBackend: Send + Sync {
    /// Cheap upstream-changed probe; the returned `Token` is persisted so the
    /// next probe can answer `Unchanged`.
    ///
    /// # Errors
    ///
    /// `BackendError::Metadata` when the freshness signal is unreachable.
    async fn probe(&self, ctx: &SyncCtx<'_>) -> Result<Probe, BackendError>;

    /// Verify the upstream trust chain, then stream this generation's file
    /// set. The stream may be huge; keep backend memory O(1).
    ///
    /// # Errors
    ///
    /// `Verify` (bad signature), `Parse` (malformed index), `Metadata`
    /// (index unreachable).
    async fn plan<'a>(
        &'a self,
        ctx: &'a SyncCtx<'_>,
        token: Token,
    ) -> Result<PlanOutput<'a>, BackendError>;

    /// Optional pre-publish staging touch-up (APT by-hash, suite symlinks).
    ///
    /// # Errors
    ///
    /// `BackendError::Io` from staging ops.
    async fn prepare_publish(
        &self,
        _staged: &mut StagedTree,
        _prev: Option<&GenerationSnapshot>,
        _ops: &StagingOps,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    /// Optional last check before publish. `Stale` sends the engine back to
    /// `probe` (bounded by `retry.index_rounds`).
    ///
    /// # Errors
    ///
    /// Any suite-fatal metadata or verify error.
    async fn pre_publish_check(
        &self,
        _ctx: &SyncCtx<'_>,
        _staged: &StagedTree,
    ) -> Result<CheckOutcome, BackendError> {
        Ok(CheckOutcome::Ok)
    }
}

/// Output of `ManifestBackend::plan`: streamed file list plus publish spec.
pub struct PlanOutput<'a> {
    pub files: BoxStream<'a, Result<FileSpec, BackendError>>,
    pub publish: PublishSpec,
}

impl<'a> std::fmt::Debug for PlanOutput<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlanOutput")
            .field("publish", &self.publish)
            .field("files", &"<BoxStream>")
            .finish()
    }
}

/// Transport-driven sync strategy (no implementation yet).
#[async_trait]
pub trait TransportBackend: Send + Sync {
    /// # Errors
    ///
    /// Whatever the underlying transport surfaces.
    async fn sync(&self, ctx: &TransportCtx<'_>) -> Result<TransferReport, BackendError>;
}

/// Backend error; the engine maps it to suite-fatal vs. retryable.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// Rejected by `validate_config`.
    #[error("backend configuration invalid: {0}")]
    Config(String),
    /// Failed to fetch a metadata file.
    #[error("upstream metadata unreachable: {0}")]
    Metadata(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("{0} is not implemented yet")]
    NotImplementedYet(&'static str),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

// Fails the build if any trait stops being dyn-compatible.
const _: fn() = || {
    fn _assert_backend(_: &dyn Backend) {}
    fn _assert_manifest(_: &dyn ManifestBackend) {}
    fn _assert_transport(_: &dyn TransportBackend) {}
};

#[cfg(test)]
mod tests {
    use super::*;

    struct StubMan;

    #[async_trait]
    impl ManifestBackend for StubMan {
        async fn probe(&self, _ctx: &SyncCtx<'_>) -> Result<Probe, BackendError> {
            Ok(Probe::Unchanged)
        }
        async fn plan<'a>(
            &'a self,
            _ctx: &'a SyncCtx<'_>,
            _token: Token,
        ) -> Result<PlanOutput<'a>, BackendError> {
            Err(BackendError::NotImplementedYet("StubMan.plan"))
        }
    }

    struct StubBack;
    impl Backend for StubBack {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn validate_config(&self, _m: &crate::config::MirrorConfig) -> Result<(), BackendError> {
            Ok(())
        }
        fn strategy(&self) -> SyncStrategy<'_> {
            static M: StubMan = StubMan;
            SyncStrategy::Manifest(&M)
        }
    }

    #[test]
    fn backend_trait_is_object_safe() {
        let b: Box<dyn Backend> = Box::new(StubBack);
        assert_eq!(b.name(), "stub");
        match b.strategy() {
            SyncStrategy::Manifest(_) => {}
            SyncStrategy::Transport(_) => panic!("expected Manifest"),
        }
    }

    #[test]
    fn plan_output_debug_hides_stream() {
        use futures::stream;
        use std::time::Duration;
        let po = PlanOutput {
            files: Box::pin(stream::empty()),
            publish: PublishSpec {
                layer_order: vec![],
                atomic_root: vec![],
                grace: Duration::ZERO,
            },
        };
        let s = format!("{po:?}");
        assert!(s.contains("<BoxStream>"), "debug = {s}");
    }
}
