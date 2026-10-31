//! The suite loop of one mirror sync.

use std::collections::BTreeSet;
use std::path::Path;

use tracing::{info, warn};

use super::apt_flow::{
    AptFlowError, ApttSyncOutcome, FetchTuning, SuiteDryRun, SuiteVerdict, sync_apt_suite,
};
use super::{EngineError, MirrorRun, by_hash, next_generation, walk_for_fatal_io};
use crate::backends::apt::pgp::VerifyOutcome as PgpVerifyOutcome;
use crate::config::model::BackendOptions;
use crate::core::store::manifest::{self, GenerationManifest, ManifestEntry};
use crate::core::store::state::{MirrorState, SuiteState};

/// What the suite loop of one mirror sync produced.
pub(super) struct SuiteResults {
    pub(super) succeeded: Vec<String>,
    pub(super) failed: Vec<String>,
    pub(super) unchanged: Vec<String>,
    /// PGP outcome for suites that were `Updated`.
    pub(super) pgp_by_suite: Vec<(String, PgpVerifyOutcome)>,
    /// `--dry-run` plans, failed plans included.
    pub(super) dry_run: Vec<SuiteDryRun>,
    /// The next generation, holding the entries of every updated suite.
    pub(super) manifest: GenerationManifest,
}

impl SuiteResults {
    fn new(generation: u64) -> Self {
        Self {
            succeeded: Vec::new(),
            failed: Vec::new(),
            unchanged: Vec::new(),
            pgp_by_suite: Vec::new(),
            dry_run: Vec::new(),
            manifest: GenerationManifest::new(generation),
        }
    }

    /// Some suite was updated or confirmed unchanged.
    pub(super) fn any_progress(&self) -> bool {
        !self.succeeded.is_empty() || !self.unchanged.is_empty()
    }

    fn record(
        &mut self,
        run: &MirrorRun<'_>,
        state: &mut MirrorState,
        suite: &str,
        outcome: Result<ApttSyncOutcome, AptFlowError>,
        suite_manifest: GenerationManifest,
    ) -> Result<(), EngineError> {
        let mirror = &run.mirror.name;
        match outcome {
            Ok(ApttSyncOutcome::Unchanged) => {
                self.unchanged.push(suite.to_owned());
                info!(mirror = %mirror, %suite, "suite unchanged (304 or same InRelease hash)");
            }
            Ok(ApttSyncOutcome::Updated {
                token_sha256,
                date_raw,
                etag,
                last_modified,
                pgp,
            }) => {
                self.succeeded.push(suite.to_owned());
                let entries = suite_manifest.files.into_values().collect();
                record_suite(&mut self.manifest, run.root, suite, entries);
                self.pgp_by_suite.push((suite.to_owned(), pgp));
                state.suites.insert(
                    suite.to_owned(),
                    SuiteState {
                        token_sha256,
                        date_raw,
                        etag,
                        last_modified,
                        generation: self.manifest.generation,
                    },
                );
                info!(mirror = %mirror, %suite, "suite published");
            }
            Ok(ApttSyncOutcome::DryRun(sd)) => {
                info!(
                    mirror = %mirror,
                    %suite,
                    verdict = %sd.verdict,
                    pool_would_download = sd.pool_would_download.len(),
                    pool_already_present = sd.pool_already_present,
                    bytes_estimate = sd.bytes_estimate,
                    "dry-run suite plan"
                );
                self.dry_run.push(sd);
            }
            Err(e) => return self.record_failure(run, suite, e),
        }
        Ok(())
    }

    fn record_failure(
        &mut self,
        run: &MirrorRun<'_>,
        suite: &str,
        e: AptFlowError,
    ) -> Result<(), EngineError> {
        let mirror = &run.mirror.name;
        // Full disk / unwritable target is environmental: fail the whole
        // mirror (exit 4), not just this suite.
        if walk_for_fatal_io(&e) {
            warn!(mirror = %mirror, %suite, err = %e, "suite failed with fatal I/O — bailing mirror");
            return Err(EngineError::Apt(e));
        }
        warn!(mirror = %mirror, %suite, err = %e, "suite failed — skipping publish");
        if run.overrides.dry_run {
            self.dry_run.push(SuiteDryRun {
                suite: suite.to_owned(),
                verdict: SuiteVerdict::Failed(e.to_string()),
                indexes_would_download: vec![],
                pool_would_download: vec![],
                pool_already_present: 0,
                bytes_estimate: 0,
                gc_candidates: None,
            });
        } else {
            self.failed.push(suite.to_owned());
        }
        Ok(())
    }
}

/// Sync every configured suite in order. `published` is the manifest of
/// the generation standing before this sync.
///
/// # Errors
///
/// Fatal local I/O in any suite; other suite failures are recorded.
pub(super) async fn sync_suites(
    run: &MirrorRun<'_>,
    state: &mut MirrorState,
    published: Option<&GenerationManifest>,
) -> Result<SuiteResults, EngineError> {
    let BackendOptions::Apt(apt_opts) = &run.mirror.backend_options;
    let tuning = FetchTuning::from(run.global);
    let attributed = manifest::attributed_suites(run.root, state.generation);
    let mut results = SuiteResults::new(next_generation(run.root, state.generation));
    for suite in &apt_opts.suites {
        info!(mirror = %run.mirror.name, %suite, "sync suite");
        let prior = state.suites.get(suite).cloned().unwrap_or_default();
        let prior = resync_if_unattributed(prior, suite, &attributed);
        // Per suite, so a failed or refolded suite can't drop shared entries.
        let mut suite_manifest = GenerationManifest::new(results.manifest.generation);
        let outcome = sync_apt_suite(
            run.client,
            run.budget,
            run.mirror,
            apt_opts,
            run.root,
            suite,
            &prior,
            &mut suite_manifest,
            &tuning,
            run.global.retry.index_rounds,
            run.overrides.dry_run,
            published,
        )
        .await;
        results.record(run, state, suite, outcome, suite_manifest)?;
    }
    Ok(results)
}

/// A published suite the current manifest doesn't attribute (older
/// manifest, lost entry) syncs as if new so its files get recorded
/// exactly. `date_raw` stays for Date monotonicity.
fn resync_if_unattributed(
    prior: SuiteState,
    suite: &str,
    attributed: &BTreeSet<String>,
) -> SuiteState {
    if prior.token_sha256.is_empty() || attributed.contains(suite) {
        return prior;
    }
    info!(%suite, "suite not attributed in the manifest — re-syncing to record its files");
    SuiteState {
        token_sha256: String::new(),
        etag: None,
        last_modified: None,
        ..prior
    }
}

/// Attribute freshly synced `entries` and their by-hash objects to `suite`.
fn record_suite(
    m: &mut GenerationManifest,
    mirror_root: &Path,
    suite: &str,
    entries: Vec<ManifestEntry>,
) {
    let objects = by_hash::published_objects(mirror_root, &entries);
    m.attribute(suite, entries.into_iter().chain(objects));
}
