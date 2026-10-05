//! Sync main loop.
//!
//! Each configured suite of a mirror runs this shape, followed by GC:
//!
//! ```text
//! lock() → plan_suite() → fetch_indexes() → parse_packages()
//!        → fetch_pool() → publish_suite() → write state/manifest → unlock()
//! ```

pub mod apt_flow;
pub mod by_hash;
pub mod gc;
pub mod publish;
pub mod status;
pub mod verify;

use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use crate::config::model::{BackendKind, BackendOptions, MirrorConfig};
use crate::core::fetch::budget::{Budget, BudgetConfig};
use crate::core::fetch::client::{ClientConfig, ClientError, build_client};
use crate::core::store::state::{MirrorState, SuiteState};
use crate::core::store::{lock, manifest, state};

use apt_flow::{
    AptFlowError, ApttSyncOutcome, DryRunReport, FetchTuning, SuiteDryRun, sync_apt_suite,
};

use crate::backends::apt::pgp::VerifyOutcome as PgpVerifyOutcome;

/// CLI-scoped overrides (`--dry-run` / `--gc-dry-run`) that force safe modes
/// regardless of per-mirror config.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncOverrides {
    /// Plan only: no pool downloads, staging, publish or state/manifest
    /// writes. `dists/` and `pool/` stay byte-for-byte unchanged.
    pub dry_run: bool,
    /// Force GC into dry-run mode regardless of per-mirror `gc.dry_run`.
    pub gc_dry_run: bool,
}

/// Outcome of syncing one mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorOutcome {
    pub mirror_name: String,
    pub suites_succeeded: Vec<String>,
    pub suites_failed: Vec<String>,
    pub suites_unchanged: Vec<String>,
    pub new_generation: u64,
    /// `None` when GC was skipped.
    pub gc: Option<gc::GcResult>,
    pub sync_duration: std::time::Duration,
    /// `pool/` file count of the manifest standing after this sync (the new
    /// generation, else the last on disk; 0 if none).
    pub pool_files: u64,
    pub pool_bytes: u64,
    /// Max upstream Release `Date` across suites, as a "last success" proxy.
    pub last_success_unix: Option<i64>,
    /// PGP outcome for suites that were `Updated` this round.
    pub pgp_by_suite: Vec<(String, PgpVerifyOutcome)>,
    /// Planner report; `Some` only for `--dry-run`.
    pub dry_run: Option<DryRunReport>,
}

impl MirrorOutcome {
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.suites_failed.is_empty()
    }
}

/// Synchronize one mirror.
///
/// # Errors
///
/// Anything the sub-steps surface — lock contention, config-level
/// rejection, network / parse / verify failures.
pub async fn sync_mirror(
    global: &crate::config::model::GlobalConfig,
    mirror: &MirrorConfig,
    target_root: &Path,
) -> Result<MirrorOutcome, EngineError> {
    sync_mirror_with(global, mirror, target_root, SyncOverrides::default()).await
}

/// [`sync_mirror`] with CLI-scoped overrides.
///
/// # Errors
///
/// Same as [`sync_mirror`].
pub async fn sync_mirror_with(
    global: &crate::config::model::GlobalConfig,
    mirror: &MirrorConfig,
    target_root: &Path,
    overrides: SyncOverrides,
) -> Result<MirrorOutcome, EngineError> {
    let budget = Budget::new(BudgetConfig::from(global));
    sync_mirror_with_budget(global, mirror, target_root, overrides, &budget).await
}

/// [`sync_mirror_with`] with a shared `Budget`, so mirrors on the same
/// upstream host share per-host limits and 429/503 pacing.
///
/// # Errors
///
/// Same as [`sync_mirror`].
pub async fn sync_mirror_with_budget(
    global: &crate::config::model::GlobalConfig,
    mirror: &MirrorConfig,
    target_root: &Path,
    overrides: SyncOverrides,
    budget: &Budget,
) -> Result<MirrorOutcome, EngineError> {
    match mirror.backend {
        BackendKind::Apt => {}
    }

    let mirror_root = target_root.join(&mirror.path);
    std::fs::create_dir_all(&mirror_root).map_err(|e| EngineError::Io {
        path: mirror_root.clone(),
        source: e,
    })?;

    let _guard = lock::acquire(&mirror_root, global.lock_timeout).map_err(|e| match e {
        lock::LockError::Contended { .. } => EngineError::LockContended(e),
        other => EngineError::Lock(other),
    })?;

    let (mut state, is_migration_boot) =
        match state::load_for_url(&mirror_root, mirror.url.as_str()) {
            Ok(Some(s)) => (s, false),
            Ok(None) => {
                // Migration guard: existing content without state.json means a
                // legacy mirror; force GC dry-run so its pool isn't wiped.
                let looks_migrated =
                    mirror_root_has_non_tain_content(&mirror_root).unwrap_or(false);
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
                (MirrorState::new(mirror.url.to_string()), looks_migrated)
            }
            Err(state::StateError::UrlMismatch { .. }) => {
                warn!(
                    mirror = %mirror.name,
                    "state file records a different URL — starting fresh (Date monotonicity guard)"
                );
                (MirrorState::new(mirror.url.to_string()), false)
            }
            Err(e) => return Err(EngineError::State(e)),
        };

    let mut client_cfg = ClientConfig::from(global);
    // Some CDNs bungle H2 for large-file transfers.
    if mirror.force_http1 {
        client_cfg.http1_only = true;
    }
    let client = build_client(&client_cfg).map_err(EngineError::Client)?;
    let tuning = FetchTuning::from(global);

    sweep_tmp_sidecars(&mirror_root);

    let BackendOptions::Apt(apt_opts) = &mirror.backend_options;

    let mut succeeded = Vec::new();
    let mut failed = Vec::new();
    let mut unchanged = Vec::new();
    let mut new_manifest = manifest::GenerationManifest::new(state.generation + 1);
    let mut pgp_by_suite: Vec<(String, PgpVerifyOutcome)> = Vec::new();
    let mut dry_run_suites: Vec<SuiteDryRun> = Vec::new();
    let sync_started_at = std::time::Instant::now();

    for suite in &apt_opts.suites {
        info!(mirror = %mirror.name, %suite, "sync suite");
        let prior = state.suites.get(suite).cloned().unwrap_or_default();
        let outcome = sync_apt_suite(
            &client,
            budget,
            mirror,
            apt_opts,
            &mirror_root,
            suite,
            &prior,
            &mut new_manifest,
            &tuning,
            global.retry.index_rounds,
            overrides.dry_run,
        )
        .await;

        match outcome {
            Ok(ApttSyncOutcome::Unchanged) => {
                unchanged.push(suite.clone());
                info!(mirror = %mirror.name, %suite, "suite unchanged (304 or same InRelease hash)");
            }
            Ok(ApttSyncOutcome::Updated {
                token_sha256,
                date_raw,
                etag,
                last_modified,
                pgp,
            }) => {
                succeeded.push(suite.clone());
                pgp_by_suite.push((suite.clone(), pgp));
                state.suites.insert(
                    suite.clone(),
                    SuiteState {
                        token_sha256,
                        date_raw,
                        etag,
                        last_modified,
                        generation: new_manifest.generation,
                    },
                );
                info!(mirror = %mirror.name, %suite, "suite published");
            }
            Ok(ApttSyncOutcome::DryRun(sd)) => {
                info!(
                    mirror = %mirror.name,
                    %suite,
                    verdict = %sd.verdict,
                    pool_would_download = sd.pool_would_download.len(),
                    pool_already_present = sd.pool_already_present,
                    bytes_estimate = sd.bytes_estimate,
                    "dry-run suite plan"
                );
                dry_run_suites.push(sd);
            }
            Err(e) => {
                // Full disk / unwritable target is environmental: fail the
                // whole mirror (exit 4), not just this suite.
                if walk_for_fatal_io(&e) {
                    warn!(mirror = %mirror.name, %suite, err = %e, "suite failed with fatal I/O — bailing mirror");
                    return Err(EngineError::Apt(e));
                }
                warn!(mirror = %mirror.name, %suite, err = %e, "suite failed — skipping publish");
                if overrides.dry_run {
                    dry_run_suites.push(SuiteDryRun {
                        suite: suite.clone(),
                        verdict: apt_flow::SuiteVerdict::Failed(e.to_string()),
                        indexes_would_download: vec![],
                        pool_would_download: vec![],
                        pool_already_present: 0,
                        bytes_estimate: 0,
                        gc_candidates: None,
                    });
                } else {
                    failed.push(suite.clone());
                }
            }
        }
    }

    // Failure neutrality: persist only when some suite was updated; dry-run
    // never writes state or manifest.
    let any_progress = !succeeded.is_empty() || !unchanged.is_empty();
    if !overrides.dry_run && any_progress && !succeeded.is_empty() {
        state.generation = new_manifest.generation;
        manifest::save(&mirror_root, &new_manifest).map_err(EngineError::Manifest)?;
        state::save(&mirror_root, &state).map_err(EngineError::State)?;
        debug!(
            mirror = %mirror.name,
            generation = new_manifest.generation,
            files = new_manifest.len(),
            "state + manifest written"
        );
    }

    // GC also runs on unchanged-only rounds, else idle mirrors accumulate
    // old generations forever. A failed suite means an incomplete manifest,
    // so live GC is skipped.
    let _ = global;
    let mut gc_result = None;
    let should_run_gc = if overrides.dry_run {
        // Preview only: nothing is deleted, so the failure gate doesn't apply.
        !dry_run_suites.is_empty()
    } else {
        failed.is_empty() && any_progress
    };
    if should_run_gc {
        let opts = gc::GcOptions {
            enabled: mirror.gc.enabled,
            grace_period: mirror.gc.grace_period,
            max_delete_ratio: mirror.gc.max_delete_ratio.as_f64(),
            max_delete_byte_ratio: mirror.gc.max_delete_ratio.as_f64(),
            keep_generations: mirror.gc.keep_generations,
            // On migration boot the fresh manifest is unverified against the
            // legacy layout; a live delete could remove still-wanted files.
            dry_run: mirror.gc.dry_run
                || overrides.gc_dry_run
                || is_migration_boot
                || overrides.dry_run,
        };
        match gc::run_gc(&mirror_root, &opts, std::time::SystemTime::now()) {
            Ok(r) => {
                info!(
                    mirror = %mirror.name,
                    scanned = r.scanned,
                    referenced = r.referenced,
                    candidates = r.candidates.len(),
                    deleted = r.deleted.len(),
                    skipped_grace = r.skipped_grace,
                    circuit_broken = r.circuit_broken,
                    disabled = r.disabled,
                    dry_run = r.dry_run,
                    "gc pass complete"
                );
                if r.circuit_broken {
                    warn!(
                        mirror = %mirror.name,
                        candidates = ?r.candidates,
                        reason = ?r.circuit_reason,
                        "gc circuit broken — full candidate list logged"
                    );
                }
                gc_result = Some(r);
            }
            Err(e) => {
                warn!(mirror = %mirror.name, %e, "gc pass failed (non-fatal)");
            }
        }
    } else if !failed.is_empty() {
        info!(mirror = %mirror.name, "gc skipped — at least one suite failed this round");
    }

    // Fall back to the last manifest on disk so gauges don't drop to zero
    // on a quiet round.
    let (pool_files, pool_bytes) = if !succeeded.is_empty() {
        pool_totals(&new_manifest)
    } else {
        match manifest::list_generations(&mirror_root) {
            Ok(gens) => gens
                .last()
                .and_then(|g| manifest::load(&mirror_root, *g).ok())
                .as_ref()
                .map_or((0, 0), pool_totals),
            Err(_) => (0, 0),
        }
    };

    // Same signal as `tain status`; failed suites keep their prior date_raw.
    let last_success_unix = state
        .suites
        .values()
        .filter_map(|s| s.date_raw.as_deref())
        .filter_map(|raw| {
            crate::backends::apt::datetime::parse_release_datetime(raw)
                .ok()
                .map(|dt| dt.unix_timestamp())
        })
        .max();

    let dry_run_report = if overrides.dry_run {
        let gc_preview = gc_result.as_ref().map(|g| apt_flow::GcPreview {
            candidates: g.candidates.len(),
            candidate_bytes: g.candidate_bytes,
            circuit_broken: g.circuit_broken,
        });
        let suites = dry_run_suites
            .into_iter()
            .map(|mut sd| {
                if let Some(preview) = gc_preview.clone() {
                    sd.gc_candidates = Some(preview);
                }
                sd
            })
            .collect();
        Some(DryRunReport {
            mirror: mirror.name.clone(),
            suites,
        })
    } else {
        None
    };

    Ok(MirrorOutcome {
        mirror_name: mirror.name.clone(),
        suites_succeeded: succeeded,
        suites_failed: failed,
        suites_unchanged: unchanged,
        new_generation: state.generation,
        gc: gc_result,
        sync_duration: sync_started_at.elapsed(),
        pool_files,
        pool_bytes,
        last_success_unix,
        pgp_by_suite,
        dry_run: dry_run_report,
    })
}

/// `(files, bytes)` of manifest entries under `pool/`.
fn pool_totals(m: &manifest::GenerationManifest) -> (u64, u64) {
    let mut files = 0u64;
    let mut bytes = 0u64;
    for entry in m.files.values() {
        if entry.rel_path.starts_with("pool/") {
            files += 1;
            bytes = bytes.saturating_add(entry.size);
        }
    }
    (files, bytes)
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    LockContended(lock::LockError),
    #[error(transparent)]
    Lock(lock::LockError),
    #[error(transparent)]
    Client(ClientError),
    #[error(transparent)]
    State(state::StateError),
    #[error(transparent)]
    Manifest(manifest::ManifestError),
    #[error(transparent)]
    Apt(#[from] AptFlowError),
    #[error("I/O on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// True for fatal local I/O (disk full, quota, unwritable target), which
/// maps to exit 4 rather than a partial-failure exit 1.
#[must_use]
pub fn is_fatal_io(err: &EngineError) -> bool {
    walk_for_fatal_io(err)
}

fn walk_for_fatal_io(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = source {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && is_fatal_io_kind(io)
        {
            return true;
        }
        source = e.source();
    }
    false
}

/// Best-effort removal of `.tmp~` download sidecars left by a crashed run.
fn sweep_tmp_sidecars(mirror_root: &Path) {
    for sub in ["pool", "dists"] {
        let root = mirror_root.join(sub);
        sweep_dir(&root);
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

fn sweep_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            sweep_dir(&path);
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

fn is_fatal_io_kind(io: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(
        io.kind(),
        ErrorKind::StorageFull
            | ErrorKind::QuotaExceeded
            | ErrorKind::ReadOnlyFilesystem
            | ErrorKind::PermissionDenied
    ) {
        return true;
    }
    // Raw errno fallback where ErrorKind stays generic: EACCES 13, ENOSPC 28,
    // EROFS 30, EDQUOT 69 (BSD) / 122 (Linux).
    if let Some(raw) = io.raw_os_error() {
        return matches!(raw, 13 | 28 | 30 | 69 | 122);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap_io(kind: std::io::ErrorKind) -> EngineError {
        EngineError::Io {
            path: PathBuf::from("/tmp/x"),
            source: std::io::Error::new(kind, "synthetic"),
        }
    }

    fn wrap_raw(errno: i32) -> EngineError {
        EngineError::Io {
            path: PathBuf::from("/tmp/x"),
            source: std::io::Error::from_raw_os_error(errno),
        }
    }

    #[test]
    fn classifies_storage_full_as_fatal() {
        assert!(is_fatal_io(&wrap_io(std::io::ErrorKind::StorageFull)));
    }

    #[test]
    fn classifies_permission_denied_as_fatal() {
        assert!(is_fatal_io(&wrap_io(std::io::ErrorKind::PermissionDenied)));
    }

    #[test]
    fn classifies_read_only_fs_as_fatal() {
        assert!(is_fatal_io(&wrap_io(
            std::io::ErrorKind::ReadOnlyFilesystem
        )));
    }

    #[test]
    fn classifies_enospc_by_errno() {
        assert!(is_fatal_io(&wrap_raw(28))); // ENOSPC
    }

    #[test]
    fn classifies_eacces_by_errno() {
        assert!(is_fatal_io(&wrap_raw(13))); // EACCES
    }

    #[test]
    fn does_not_classify_generic_not_found() {
        assert!(!is_fatal_io(&wrap_io(std::io::ErrorKind::NotFound)));
    }

    #[test]
    fn does_not_classify_generic_broken_pipe() {
        assert!(!is_fatal_io(&wrap_io(std::io::ErrorKind::BrokenPipe)));
    }
}
