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
    /// `pool/` file count of the manifest standing after this sync (0 if
    /// none).
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

    /// Every suite that failed, including dry-run plan failures (which, by
    /// design, do not count against [`Self::is_success`]).
    #[must_use]
    pub fn failed_suites(&self) -> Vec<&str> {
        let planned = self.dry_run.iter().flat_map(|r| {
            r.suites
                .iter()
                .filter(|s| matches!(s.verdict, apt_flow::SuiteVerdict::Failed(_)))
                .map(|s| s.suite.as_str())
        });
        self.suites_failed
            .iter()
            .map(String::as_str)
            .chain(planned)
            .collect()
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
                    "state file records a different URL — discarding state (the published Release \
                     Date still applies as the monotonicity floor)"
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
    let attributed = manifest::attributed_suites(&mirror_root, state.generation);
    let mut new_manifest =
        manifest::GenerationManifest::new(next_generation(&mirror_root, state.generation));
    let mut pgp_by_suite: Vec<(String, PgpVerifyOutcome)> = Vec::new();
    let mut dry_run_suites: Vec<SuiteDryRun> = Vec::new();
    let sync_started_at = std::time::Instant::now();

    for suite in &apt_opts.suites {
        info!(mirror = %mirror.name, %suite, "sync suite");
        let prior = state.suites.get(suite).cloned().unwrap_or_default();
        let prior = resync_if_unattributed(prior, suite, &attributed);
        // Per suite, so a failed or refolded suite can't drop shared entries.
        let mut suite_manifest = manifest::GenerationManifest::new(new_manifest.generation);
        let outcome = sync_apt_suite(
            &client,
            budget,
            mirror,
            apt_opts,
            &mirror_root,
            suite,
            &prior,
            &mut suite_manifest,
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
                let entries = suite_manifest.files.into_values().collect();
                record_suite(&mut new_manifest, &mirror_root, suite, entries);
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

    // Loaded only now so it isn't held through the pool phase.
    let latest = load_manifest(&mirror_root, state.generation);
    let untracked = if overrides.dry_run {
        Vec::new()
    } else {
        let published = unchanged
            .iter()
            .chain(&failed)
            .filter(|s| state.suites.contains_key(*s));
        carry_forward(&mut new_manifest, latest.as_ref(), published)
    };
    if !untracked.is_empty() {
        warn!(mirror = %mirror.name, suites = ?untracked, "published files of these suites are not in the manifest");
    }

    // Failure neutrality: persist only when some suite was updated, or when a
    // quiet round drops entries (e.g. a suite removed from config).
    let any_progress = !succeeded.is_empty() || !unchanged.is_empty();
    let manifest_changed = latest
        .as_ref()
        .is_none_or(|l| l.files != new_manifest.files);
    let persist = !overrides.dry_run
        && (!succeeded.is_empty()
            || (!unchanged.is_empty() && untracked.is_empty() && manifest_changed));
    if persist {
        state.generation = new_manifest.generation;
        manifest::save(&mirror_root, &new_manifest).map_err(EngineError::Manifest)?;
        state::save(&mirror_root, &state).map_err(EngineError::State)?;
        debug!(
            mirror = %mirror.name,
            generation = new_manifest.generation,
            files = new_manifest.len(),
            "state + manifest written"
        );
        // GC references only the newest `keep_generations`; older ones are dead weight.
        if let Err(e) = manifest::prune(&mirror_root, mirror.gc.keep_generations as usize) {
            warn!(mirror = %mirror.name, %e, "pruning old manifests failed (non-fatal)");
        }
    }

    // GC also runs on unchanged-only rounds, else idle mirrors accumulate
    // old generations forever. A failed or untracked suite means an
    // incomplete manifest, so live GC is skipped.
    let _ = global;
    let mut gc_result = None;
    let should_run_gc = if overrides.dry_run {
        // Preview only: nothing is deleted, so the failure gate doesn't apply.
        !dry_run_suites.is_empty()
    } else {
        failed.is_empty() && untracked.is_empty() && any_progress
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
    } else if !failed.is_empty() || !untracked.is_empty() {
        info!(mirror = %mirror.name, "gc skipped — manifest incomplete this round");
    }

    let (pool_files, pool_bytes) = if persist {
        pool_totals(&new_manifest)
    } else {
        standing_pool_totals(&mirror_root, latest.as_ref())
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
        // Index bytes fetched for planning (also by a suite that failed
        // mid-plan) must not linger; nothing else lives there in a dry run
        // worth keeping.
        let staging = mirror_root.join(".tain/staging");
        if let Err(e) = std::fs::remove_dir_all(&staging)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %staging.display(), %e, "failed to remove dry-run staging");
        }
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

/// The manifest `state.json` points at, if any.
fn load_manifest(mirror_root: &Path, generation: u64) -> Option<manifest::GenerationManifest> {
    if generation == 0 {
        return None;
    }
    manifest::load(mirror_root, generation)
        .inspect_err(|e| warn!(%e, "cannot load current manifest"))
        .ok()
}

/// Past every manifest on disk, not just state's: a reset state (URL change,
/// lost state.json) must not overwrite or sort below stale manifests.
fn next_generation(mirror_root: &Path, state_generation: u64) -> u64 {
    let on_disk = manifest::list_generations(mirror_root)
        .ok()
        .and_then(|g| g.last().copied())
        .unwrap_or(0);
    state_generation.max(on_disk) + 1
}

/// A published suite the current manifest doesn't attribute (older
/// manifest, lost entry) syncs as if new so its files get recorded
/// exactly. `date_raw` stays for Date monotonicity.
fn resync_if_unattributed(
    prior: SuiteState,
    suite: &str,
    attributed: &std::collections::BTreeSet<String>,
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
    m: &mut manifest::GenerationManifest,
    mirror_root: &Path,
    suite: &str,
    entries: Vec<manifest::ManifestEntry>,
) {
    let objects = by_hash::published_objects(mirror_root, &entries);
    m.attribute(suite, entries.into_iter().chain(objects));
}

/// Carry each suite's attributed entries from `latest` unchanged (its
/// by-hash objects are already among them). Returns suites with nothing to
/// carry.
fn carry_forward<'a>(
    m: &mut manifest::GenerationManifest,
    latest: Option<&manifest::GenerationManifest>,
    suites: impl IntoIterator<Item = &'a String>,
) -> Vec<String> {
    let mut untracked = Vec::new();
    for suite in suites {
        match latest.and_then(|l| l.suite_entries(suite)) {
            Some(entries) => m.attribute(suite, entries),
            None => untracked.push(suite.clone()),
        }
    }
    untracked
}

/// Pool totals of `latest`, else of the newest manifest on disk.
fn standing_pool_totals(
    mirror_root: &Path,
    latest: Option<&manifest::GenerationManifest>,
) -> (u64, u64) {
    if let Some(m) = latest {
        return pool_totals(m);
    }
    manifest::list_generations(mirror_root)
        .ok()
        .and_then(|g| g.last().copied())
        .and_then(|g| manifest::load(mirror_root, g).ok())
        .map_or((0, 0), |m| pool_totals(&m))
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

/// Best-effort removal of `.tmp~` sidecars left by a crashed run: downloads
/// under `pool/` and `dists/`, plus the state and manifest temp files
/// directly in `.tain/` and `.tain/manifest/` (never inside `.tain/prev/`).
fn sweep_tmp_sidecars(mirror_root: &Path) {
    for sub in ["pool", "dists"] {
        sweep_dir(&mirror_root.join(sub), true);
    }
    let state_dir = mirror_root.join(crate::core::store::STATE_DIR);
    sweep_dir(&state_dir, false);
    sweep_dir(&manifest::manifest_dir(mirror_root), false);
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

    #[test]
    fn sweep_removes_state_and_manifest_sidecars_too() {
        let root = std::env::temp_dir().join(format!("tain-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let stale = [
            "pool/main/a.deb.tmp~",
            "dists/x/InRelease.tmp~",
            ".tain/state.json.tmp~",
            ".tain/manifest/7.json.tmp~",
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
