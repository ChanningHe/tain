//! APT single-suite sync flow.
//!
//! InRelease → verify + parse Release → stage served index variants (404
//! tolerated) → derive pool set → fetch pool → by-hash → recheck → publish.
//! The recheck loop refolds up to `retry.index_rounds` times if upstream
//! changes mid-sync.

mod derive_pool;
pub mod dry_run;
mod hex;
mod installer_current;
mod pool_download;
mod stage;

pub use dry_run::{DryRunReport, GcPreview, PoolPlan, SuiteDryRun, SuiteVerdict};
pub use pool_download::{FetchTuning, download_verified};

use std::path::{Path, PathBuf};

use reqwest::Client;
use reqwest::StatusCode;
use sha2::{Digest as _, Sha256};
use tracing::{debug, info, warn};

use crate::backends::apt::checksums::ReleaseChecksums;
use crate::backends::apt::clearsign::{ClearSignError, extract_signed_body};
use crate::backends::apt::datetime::parse_release_datetime;
use crate::backends::apt::deb822::ParseError as Deb822Error;
use crate::backends::apt::index_selector::select_indexes;
use crate::backends::apt::installer_sums::InstallerSumsError;
use crate::backends::apt::layout::{LayoutError, SuiteLayout};
use crate::backends::apt::packages::PackageParseError;
use crate::backends::apt::pgp::{self, PgpError};
use crate::backends::apt::release::{ReleaseHeader, ReleaseParseError, parse_release};
use crate::backends::apt::sources::SourceParseError;

use super::by_hash;
use crate::config::model::{AptOptions, MirrorConfig, PgpMode};
use crate::core::fetch::budget::Budget;
use crate::core::fetch::client::{CacheValidators, ClientError, fetch_get};
use crate::core::fetch::sink::SinkError;
use crate::core::store::manifest::{GenerationManifest, ManifestEntry};
use crate::core::store::state::SuiteState;
use crate::core::types::{Digest, DigestAlgo, FileSpec};

use derive_pool::{parse_installer_sums_into, parse_packages_into, parse_sources_into};
use hex::{hex_of, hex_of_digest_algo, hex_of_digest_bytes};
use pool_download::{download_pool_file, is_already_present};
use stage::{StageMode, StagedIndex, pick_parseable_variant, stage_indexes_with_mode};
use std::collections::HashSet;

use super::publish;

/// Which signed body drove this round: selects clearsign vs detached
/// verification and the recheck URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerbatimKind {
    InRelease,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApttSyncOutcome {
    /// Signed body unchanged (304 or byte-identical).
    Unchanged,
    Updated {
        token_sha256: String,
        date_raw: Option<String>,
        etag: Option<String>,
        last_modified: Option<String>,
        pgp: pgp::VerifyOutcome,
    },
    /// `--dry-run` plan; nothing published or saved, staging wiped.
    DryRun(SuiteDryRun),
}

/// Sync one APT suite end-to-end.
///
/// # Errors
///
/// Any step's error — network, parse, verify, I/O, publish.
#[allow(clippy::too_many_arguments)]
pub async fn sync_apt_suite(
    client: &Client,
    budget: &Budget,
    mirror: &MirrorConfig,
    apt: &AptOptions,
    mirror_root: &Path,
    suite: &str,
    prior: &SuiteState,
    manifest: &mut GenerationManifest,
    tuning: &FetchTuning,
    retry_index_rounds: u32,
    dry_run: bool,
) -> Result<ApttSyncOutcome, AptFlowError> {
    let layout = SuiteLayout::new(&mirror.url, suite);

    // If disk diverges from state.json (crash, manual edit), the Unchanged
    // fast paths would mask a broken mirror: drop prior state to force a
    // fresh sync (no validators, no hash shortcut).
    let effective_prior_owned;
    let prior: &SuiteState = if disk_matches_state(mirror_root, &layout, suite, prior).await {
        prior
    } else {
        warn!(
            suite,
            "disk InRelease does not match state.token_sha256 — forcing fresh sync"
        );
        effective_prior_owned = SuiteState::default();
        &effective_prior_owned
    };

    // ---- 1. probe InRelease, fall back to Release + Release.gpg ----
    // Some upstreams never clearsign and ship only detached signatures.
    let inrelease_url = layout.inrelease_url()?;
    let release_url = layout.release_url()?;
    let validators = CacheValidators {
        etag: prior.etag.clone(),
        last_modified: prior.last_modified.clone(),
    };
    let (token_bytes, new_validators, verbatim_kind) = {
        let resp = fetch_get(client, &inrelease_url, &validators).await?;
        if resp.status == StatusCode::NOT_MODIFIED {
            debug!(suite, "InRelease 304");
            if dry_run {
                return Ok(ApttSyncOutcome::DryRun(dry_run_unchanged(suite)));
            }
            return Ok(ApttSyncOutcome::Unchanged);
        }
        if resp.status.is_success() {
            let new_validators = resp.validators();
            let bytes = resp
                .response
                .bytes()
                .await
                .map_err(|e| AptFlowError::BodyRead {
                    url: inrelease_url.clone(),
                    msg: e.to_string(),
                })?;
            (bytes.to_vec(), new_validators, VerbatimKind::InRelease)
        } else {
            debug!(
                suite,
                status = %resp.status,
                "InRelease non-success — trying plain Release + Release.gpg"
            );
            drop(resp);
            let release_resp = fetch_get(client, &release_url, &validators).await?;
            if release_resp.status == StatusCode::NOT_MODIFIED {
                debug!(suite, "Release 304");
                if dry_run {
                    return Ok(ApttSyncOutcome::DryRun(dry_run_unchanged(suite)));
                }
                return Ok(ApttSyncOutcome::Unchanged);
            }
            if !release_resp.status.is_success() {
                return Err(AptFlowError::UpstreamStatus {
                    url: release_url,
                    status: release_resp.status,
                });
            }
            let new_validators = release_resp.validators();
            let bytes =
                release_resp
                    .response
                    .bytes()
                    .await
                    .map_err(|e| AptFlowError::BodyRead {
                        url: release_url.clone(),
                        msg: e.to_string(),
                    })?;
            (bytes.to_vec(), new_validators, VerbatimKind::Release)
        }
    };

    let inrelease_hash = hex_of(Sha256::digest(&token_bytes));
    if inrelease_hash == prior.token_sha256 {
        debug!(
            suite,
            ?verbatim_kind,
            "signed body byte-identical to prior state"
        );
        if dry_run {
            return Ok(ApttSyncOutcome::DryRun(dry_run_unchanged(suite)));
        }
        return Ok(ApttSyncOutcome::Unchanged);
    }

    // Recheck loop: each round runs steps 2-9.7 and publishes only if the
    // re-fetched signed body is byte-identical to this round's token;
    // otherwise it refolds with the new body. Manifest keys added by this
    // suite are tracked so a refold rolls back only its own entries.
    let mut token_bytes = token_bytes;
    let mut new_validators = new_validators;
    let mut round: u32 = 0;
    let mut round_manifest_keys: HashSet<String> = HashSet::new();
    let staging = staging_dir(mirror_root, suite);
    let (final_pgp_outcome, final_token_sha256, final_date_raw) = 'rounds: loop {
        // ---- 2. extract signed body + PGP verify ----
        let (parse_body, is_clearsigned, pgp_outcome) = match verbatim_kind {
            VerbatimKind::InRelease => {
                let s = std::str::from_utf8(&token_bytes).map_err(|e| AptFlowError::Utf8 {
                    what: "InRelease",
                    msg: e.to_string(),
                })?;
                let extracted = extract_signed_body(s)?;
                let is_clearsigned = matches!(
                    extracted.kind,
                    crate::backends::apt::clearsign::ReleaseKind::Clearsigned
                );
                let outcome = pgp::verify_inrelease(
                    mirror.verify.pgp,
                    &token_bytes,
                    is_clearsigned,
                    mirror.verify.keyring.as_deref(),
                )
                .map_err(AptFlowError::Pgp)?;
                (extracted.body.into_owned(), is_clearsigned, outcome)
            }
            VerbatimKind::Release => {
                let release_gpg_url = layout.release_gpg_url()?;
                let release_gpg_bytes = fetch_optional(client, &release_gpg_url).await?;
                let outcome = pgp::verify_release_gpg(
                    mirror.verify.pgp,
                    &token_bytes,
                    release_gpg_bytes.as_deref(),
                    mirror.verify.keyring.as_deref(),
                )
                .map_err(AptFlowError::Pgp)?;
                let body = std::str::from_utf8(&token_bytes)
                    .map_err(|e| AptFlowError::Utf8 {
                        what: "Release",
                        msg: e.to_string(),
                    })?
                    .to_owned();
                (body, false, outcome)
            }
        };
        let _ = is_clearsigned;
        let (header, checksums_raw) = parse_release(&parse_body)?;

        // ---- 3. Date monotonicity + Valid-Until ----
        check_temporal(&header, prior, suite)?;

        // ---- 4. weak-hash policy ----
        let (checksums, weak_report) =
            checksums_raw.apply_weak_hash_policy(mirror.verify.allow_weak_hash);
        if weak_report.policy_dropped && weak_report.weak_only_count > 0 {
            warn!(
                suite,
                dropped = weak_report.weak_only_count,
                "Release entries dropped as weak-only per policy",
            );
        }
        if checksums.is_empty() {
            return Err(AptFlowError::EmptyReleaseAfterPolicy);
        }

        // ---- 5. select indexes ----
        let selection = select_indexes(&header, &checksums, apt);
        if selection.is_empty() {
            return Err(AptFlowError::NoIndexSelected {
                suite: suite.to_owned(),
            });
        }

        // ---- 6. stage signed files ----
        // Fresh staging each round; pool files on disk are reused.
        reset_dir(&staging).map_err(|e| AptFlowError::Io {
            path: staging.clone(),
            source: e,
        })?;
        // Byte fidelity: the driving signed body lands verbatim under its
        // own name; sibling forms are staged too when upstream serves them.
        match verbatim_kind {
            VerbatimKind::InRelease => {
                write_bytes(&staging.join("InRelease"), &token_bytes)?;
                for (name, rel_url) in [
                    ("Release", layout.release_url()?),
                    ("Release.gpg", layout.release_gpg_url()?),
                ] {
                    if let Some(bytes) = fetch_optional(client, &rel_url).await? {
                        write_bytes(&staging.join(name), &bytes)?;
                    }
                }
            }
            VerbatimKind::Release => {
                write_bytes(&staging.join("Release"), &token_bytes)?;
                let release_gpg_url = layout.release_gpg_url()?;
                if let Some(bytes) = fetch_optional(client, &release_gpg_url).await? {
                    write_bytes(&staging.join("Release.gpg"), &bytes)?;
                }
                if let Some(bytes) = fetch_optional(client, &inrelease_url).await? {
                    write_bytes(&staging.join("InRelease"), &bytes)?;
                }
            }
        }

        // ---- 7. stage index variants ----
        // Dry-run still downloads parseable indexes to derive the pool set.
        let stage_mode = if dry_run {
            StageMode::PlannerOnly
        } else {
            StageMode::Full
        };
        let staged = stage_indexes_with_mode(
            client,
            budget,
            &layout,
            &staging,
            &selection,
            header.acquire_by_hash,
            tuning,
            stage_mode,
        )
        .await?;

        // ---- 8. derive pool set ----
        let allow_weak = mirror.verify.allow_weak_hash;
        let mut pool_specs: Vec<FileSpec> = Vec::new();
        for group in selection.packages_groups() {
            let Some(parseable) = pick_parseable_variant(&staged, group) else {
                return Err(AptFlowError::AllVariantsMissing {
                    component: group.component.clone().unwrap_or_default(),
                    arch: group.arch.clone().unwrap_or_default(),
                });
            };
            parse_packages_into(
                &parseable.staged_path,
                parseable.compression,
                &layout,
                allow_weak,
                &mut pool_specs,
            )?;
        }
        for group in selection.sources_groups() {
            let Some(parseable) = pick_parseable_variant(&staged, group) else {
                return Err(AptFlowError::AllVariantsMissing {
                    component: group.component.clone().unwrap_or_default(),
                    arch: "source".to_owned(),
                });
            };
            parse_sources_into(
                &parseable.staged_path,
                parseable.compression,
                &layout,
                allow_weak,
                &mut pool_specs,
            )?;
        }
        // d-i SHA256SUMS lists image files that must be fetched, verified and
        // published in the same swap (debmirror LP#1550852 dropped them).
        for group in selection.installer_sums_groups() {
            let Some(parseable) = pick_parseable_variant(&staged, group) else {
                return Err(AptFlowError::AllVariantsMissing {
                    component: group.component.clone().unwrap_or_default(),
                    arch: group.arch.clone().unwrap_or_default(),
                });
            };
            // `<comp>/installer-<arch>/<ver>/images/SHA256SUMS` → its directory.
            let sums_base = group
                .base_path
                .rsplit_once('/')
                .map(|(dir, _)| dir)
                .unwrap_or("");
            parse_installer_sums_into(&parseable.staged_path, sums_base, &layout, &mut pool_specs)?;
        }
        info!(
            suite,
            pool_files = pool_specs.len(),
            index_files = staged.len(),
            "pool wanted set derived"
        );

        // ---- 8b. dry-run exit: everything past here mutates disk ----
        if dry_run {
            let (pool_would, already, bytes) =
                dry_run::classify_pool(mirror_root, &pool_specs).await?;
            let indexes = dry_run::collect_verbatim_indexes(selection.groups.iter());
            let _ = std::fs::remove_dir_all(&staging);
            let verdict = if prior.token_sha256.is_empty() {
                SuiteVerdict::Fresh
            } else {
                SuiteVerdict::Incremental
            };
            return Ok(ApttSyncOutcome::DryRun(SuiteDryRun {
                suite: suite.to_owned(),
                verdict,
                indexes_would_download: indexes,
                pool_would_download: pool_would,
                pool_already_present: already,
                bytes_estimate: bytes,
                gc_candidates: None,
            }));
        }

        // ---- 9. download pool ----
        // `pool/**` files go straight to their final path (pool-first, for
        // published-index closure). Files under the suite dir (Proxmox,
        // Tailscale, ...) go into staging: at the final path the swap would
        // move them into prev/ and clients would 404.
        let suite_prefix = suite_dir_prefix(&layout, suite);
        for spec in &pool_specs {
            let rel = spec.rel_path.as_str();
            let inside_suite = suite_prefix.as_deref().is_some_and(|p| rel.starts_with(p));
            let target = if inside_suite {
                let suffix = &rel[suite_prefix.as_deref().unwrap().len()..];
                staging.join(suffix)
            } else {
                mirror_root.join(rel)
            };
            let final_local = mirror_root.join(rel);
            if !inside_suite && is_already_present(&final_local, spec.size, &spec.digests).await? {
                manifest.insert(ManifestEntry {
                    rel_path: rel.to_owned(),
                    size: spec.size.unwrap_or(0),
                    sha256_hex: hex_of_digest_algo(&spec.digests, DigestAlgo::Sha256),
                    sha512_hex: hex_of_digest_algo(&spec.digests, DigestAlgo::Sha512),
                });
                round_manifest_keys.insert(rel.to_owned());
                continue;
            }
            download_pool_file(
                budget,
                client,
                &spec.url,
                &target,
                spec.digests.clone(),
                spec.size,
                tuning,
            )
            .await
            .map_err(|source| AptFlowError::PoolFetch {
                url: spec.url.clone(),
                source: Box::new(source),
            })?;
            manifest.insert(ManifestEntry {
                rel_path: rel.to_owned(),
                size: spec.size.unwrap_or(0),
                sha256_hex: hex_of_digest_algo(&spec.digests, DigestAlgo::Sha256),
                sha512_hex: hex_of_digest_algo(&spec.digests, DigestAlgo::Sha512),
            });
            round_manifest_keys.insert(rel.to_owned());
        }

        // ---- 9.5 by-hash ----
        struct StagedHex {
            path: PathBuf,
            sha256: Option<String>,
            sha512: Option<String>,
            md5: Option<String>,
        }
        let hexes: Vec<StagedHex> = staged
            .iter()
            .map(|s| {
                let get_hex = |algo| s.entry.digests.get(algo).map(|d| hex_of(&d.bytes));
                StagedHex {
                    path: s.staged_path.clone(),
                    sha256: get_hex(DigestAlgo::Sha256),
                    sha512: get_hex(DigestAlgo::Sha512),
                    md5: get_hex(DigestAlgo::Md5),
                }
            })
            .collect();
        let by_hash_inputs = hexes.iter().map(|h| by_hash::ByHashInput {
            staged_path: h.path.clone(),
            sha256_hex: h.sha256.as_deref(),
            sha512_hex: h.sha512.as_deref(),
            // MD5 only when it's the sole advertised digest.
            md5_hex: if h.sha256.is_none() && h.sha512.is_none() {
                h.md5.as_deref()
            } else {
                None
            },
        });
        by_hash::write_generation(by_hash_inputs).map_err(AptFlowError::ByHash)?;

        // ---- 9.6 inherit by-hash from the published dist ----
        let final_dist_dir = final_dist_path(mirror_root, &layout, suite);
        by_hash::inherit_from_previous(&final_dist_dir, &staging).map_err(AptFlowError::ByHash)?;

        // ---- 9.7 signed-body recheck ----
        // A mismatch means upstream published mid-sync; refold or fail.
        let recheck_url = match verbatim_kind {
            VerbatimKind::InRelease => inrelease_url.clone(),
            VerbatimKind::Release => release_url.clone(),
        };
        // Counted against the per-host budget; permit held only for the GET.
        let (recheck_bytes, recheck_validators) = {
            let _recheck_permit = budget.acquire(&recheck_url).await;
            let recheck = fetch_get(client, &recheck_url, &CacheValidators::default()).await?;
            if !recheck.status.is_success() {
                return Err(AptFlowError::UpstreamStatus {
                    url: recheck_url.clone(),
                    status: recheck.status,
                });
            }
            let vals = recheck.validators();
            let bytes = recheck
                .response
                .bytes()
                .await
                .map_err(|e| AptFlowError::BodyRead {
                    url: recheck_url.clone(),
                    msg: e.to_string(),
                })?;
            (bytes, vals)
        };
        if recheck_bytes.as_ref() == token_bytes.as_slice() {
            info!(suite, round, "recheck stable");
            // ---- 10. publish (atomic swap; old dir → prev/ for GC) ----
            let prev_slot = mirror_root
                .join(".tain/prev")
                .join(suite)
                .join(manifest.generation.to_string());
            publish::publish_suite(&staging, &final_dist_dir, Some(&prev_slot))
                .map_err(AptFlowError::Publish)?;

            if apt.create_suite_symlinks && !layout.is_flat() {
                maybe_create_suite_symlink(mirror_root, &header, suite)?;
            }

            if apt.indexes.debian_installer && !layout.is_flat() {
                installer_current::rebuild(&final_dist_dir, suite);
            }

            record_published_indexes(mirror_root, &final_dist_dir, &staged, &layout, manifest);

            let token_sha256 = hex_of(Sha256::digest(&token_bytes));
            break 'rounds (pgp_outcome, token_sha256, header.date_raw);
        }
        // Refold: roll back this suite's manifest entries, then retry.
        if round >= retry_index_rounds {
            warn!(
                suite,
                ?verbatim_kind,
                rounds = round,
                "signed body still refreshing after retry.index_rounds refolds — aborting suite"
            );
            for key in round_manifest_keys.drain() {
                manifest.files.remove(&key);
            }
            return Err(AptFlowError::UpstreamRefreshedMidSyncExhausted { rounds: round });
        }
        warn!(
            suite,
            ?verbatim_kind,
            round,
            "upstream signed body refreshed mid-sync — refolding indexes"
        );
        for key in round_manifest_keys.drain() {
            manifest.files.remove(&key);
        }
        token_bytes = recheck_bytes.to_vec();
        new_validators = recheck_validators;
        round += 1;
        continue 'rounds;
    };

    Ok(ApttSyncOutcome::Updated {
        token_sha256: final_token_sha256,
        date_raw: final_date_raw,
        etag: new_validators.etag,
        last_modified: new_validators.last_modified,
        pgp: final_pgp_outcome,
    })
}

fn check_temporal(
    header: &ReleaseHeader,
    prior: &SuiteState,
    suite: &str,
) -> Result<(), AptFlowError> {
    let Some(new_date_raw) = header.date_raw.as_deref() else {
        return Ok(());
    };
    let new_dt = parse_release_datetime(new_date_raw).map_err(|e| AptFlowError::BadDate {
        which: "Date",
        raw: new_date_raw.to_owned(),
        msg: e.to_string(),
    })?;

    if let Some(prior_raw) = prior.date_raw.as_deref()
        && let Ok(prior_dt) = parse_release_datetime(prior_raw)
        && new_dt < prior_dt
    {
        return Err(AptFlowError::DateRegressed {
            suite: suite.to_owned(),
            prior: prior_raw.to_owned(),
            incoming: new_date_raw.to_owned(),
        });
    }

    if let Some(valid_until_raw) = header.valid_until_raw.as_deref()
        && let Ok(valid_until) = parse_release_datetime(valid_until_raw)
    {
        let now = time::OffsetDateTime::now_utc();
        if valid_until < now {
            warn!(
                suite,
                valid_until = valid_until_raw,
                "Release Valid-Until is in the past — upstream may be stale"
            );
        }
    }

    Ok(())
}

/// Link `dists/<alias>` to the synced suite when Release's Suite and
/// Codename differ (e.g. `stable` → `trixie`).
///
/// No-op for slash-suites (`stable/updates` is a separate suite, not an
/// alias) and when a non-symlink already occupies the alias path.
fn maybe_create_suite_symlink(
    mirror_root: &Path,
    header: &ReleaseHeader,
    synced_suite: &str,
) -> Result<(), AptFlowError> {
    let Some(codename) = header.codename.as_deref() else {
        return Ok(());
    };
    let Some(suite_name) = header.suite.as_deref() else {
        return Ok(());
    };
    if codename == suite_name {
        return Ok(());
    }
    let (other, target) = if synced_suite == codename {
        (suite_name, codename)
    } else if synced_suite == suite_name {
        (codename, suite_name)
    } else {
        return Ok(());
    };
    if other.contains('/') || other.is_empty() || other == "." || other == ".." {
        return Ok(());
    }
    let link_path = mirror_root.join("dists").join(other);
    match std::fs::symlink_metadata(&link_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let _ = std::fs::remove_file(&link_path);
        }
        Ok(_) => {
            // Never clobber a real dir/file.
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(AptFlowError::Io {
                path: link_path,
                source: e,
            });
        }
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &link_path).map_err(|e| AptFlowError::Io {
        path: link_path,
        source: e,
    })?;
    #[cfg(not(unix))]
    let _ = target;
    Ok(())
}

fn staging_dir(mirror_root: &Path, suite: &str) -> PathBuf {
    // A literal `./` component would trip `Path::strip_prefix` in publish.
    let normalized = if let Some(dir) = suite.strip_suffix("/./") {
        dir.to_owned()
    } else {
        suite.to_owned()
    };
    mirror_root.join(".tain/staging").join(normalized)
}

/// Mirror-root-relative prefix of the atomic-swap tree. Pure `./` flat repos
/// are rejected at config parse, so there's always a real subdirectory.
fn suite_dir_prefix(layout: &SuiteLayout<'_>, suite: &str) -> Option<String> {
    if layout.is_flat() {
        Some(format!("{}/", suite.trim_end_matches("/./")))
    } else {
        Some(format!("dists/{suite}/"))
    }
}

fn final_dist_path(mirror_root: &Path, layout: &SuiteLayout<'_>, suite: &str) -> PathBuf {
    if layout.is_flat() {
        mirror_root.join(suite.trim_end_matches("/./"))
    } else {
        mirror_root.join("dists").join(suite)
    }
}

/// True when the published `InRelease` hashes to `prior.token_sha256` (or
/// there is no prior state).
///
/// A symlinked InRelease fails the check: a crafted target could otherwise
/// satisfy it while the published tree is arbitrary.
async fn disk_matches_state(
    mirror_root: &Path,
    layout: &SuiteLayout<'_>,
    suite: &str,
    prior: &SuiteState,
) -> bool {
    if prior.token_sha256.is_empty() {
        return true;
    }
    let inrelease_path = final_dist_path(mirror_root, layout, suite).join("InRelease");
    match tokio::fs::symlink_metadata(&inrelease_path).await {
        Ok(meta) if meta.file_type().is_symlink() => {
            warn!(
                path = %inrelease_path.display(),
                "spot-check refuses to follow a symlink at InRelease — forcing fresh sync"
            );
            return false;
        }
        Ok(_) => {}
        Err(_) => return false,
    }
    match tokio::fs::read(&inrelease_path).await {
        Ok(bytes) => {
            let hash = hex_of(Sha256::digest(&bytes));
            hash == prior.token_sha256
        }
        Err(_) => false,
    }
}

fn reset_dir(p: &Path) -> std::io::Result<()> {
    if p.exists() {
        std::fs::remove_dir_all(p)?;
    }
    std::fs::create_dir_all(p)
}

fn write_bytes(p: &Path, bytes: &[u8]) -> Result<(), AptFlowError> {
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| AptFlowError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    std::fs::write(p, bytes).map_err(|e| AptFlowError::Io {
        path: p.to_path_buf(),
        source: e,
    })
}

async fn fetch_optional(
    client: &Client,
    url: &url::Url,
) -> Result<Option<bytes::Bytes>, AptFlowError> {
    let resp = fetch_get(client, url, &CacheValidators::default()).await?;
    if resp.status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status.is_success() {
        return Err(AptFlowError::UpstreamStatus {
            url: url.clone(),
            status: resp.status,
        });
    }
    let bytes = resp
        .response
        .bytes()
        .await
        .map_err(|e| AptFlowError::BodyRead {
            url: url.clone(),
            msg: e.to_string(),
        })?;
    Ok(Some(bytes))
}

fn record_published_indexes(
    mirror_root: &Path,
    dist_dir: &Path,
    staged: &[StagedIndex<'_>],
    layout: &SuiteLayout<'_>,
    manifest: &mut GenerationManifest,
) {
    for name in ["InRelease", "Release", "Release.gpg"] {
        let path = dist_dir.join(name);
        if let Ok(bytes) = std::fs::read(&path) {
            let rel = if let Ok(rel_path) = path.strip_prefix(mirror_root) {
                rel_path.to_string_lossy().into_owned()
            } else {
                continue;
            };
            let sha256 = hex_of(Sha256::digest(&bytes));
            manifest.insert(ManifestEntry {
                rel_path: rel,
                size: bytes.len() as u64,
                sha256_hex: Some(sha256),
                sha512_hex: None,
            });
        }
    }
    for staged_entry in staged {
        let Ok(rel_path) = layout.suite_rel(&staged_entry.entry.path) else {
            continue;
        };
        let sha256 = hex_of_digest_bytes(staged_entry.entry, DigestAlgo::Sha256);
        let sha512 = hex_of_digest_bytes(staged_entry.entry, DigestAlgo::Sha512);
        manifest.insert(ManifestEntry {
            rel_path: rel_path.as_str().to_owned(),
            size: staged_entry.entry.size,
            sha256_hex: sha256,
            sha512_hex: sha512,
        });
    }
}

/// Dry-run counterpart of `ApttSyncOutcome::Unchanged`.
fn dry_run_unchanged(suite: &str) -> SuiteDryRun {
    SuiteDryRun {
        suite: suite.to_owned(),
        verdict: SuiteVerdict::Unchanged,
        indexes_would_download: vec![],
        pool_would_download: vec![],
        pool_already_present: 0,
        bytes_estimate: 0,
        gc_candidates: None,
    }
}

// Keeps imports used under `--no-default-features`.
#[allow(dead_code)]
fn _touch(_: PgpMode, _: Digest, _: ReleaseChecksums) {}

#[derive(Debug, thiserror::Error)]
pub enum AptFlowError {
    #[error(transparent)]
    Layout(#[from] LayoutError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("HTTP `{status}` for {url}")]
    UpstreamStatus {
        url: url::Url,
        status: reqwest::StatusCode,
    },
    #[error("reading body of {url}: {msg}")]
    BodyRead { url: url::Url, msg: String },
    #[error("{what} bytes are not valid UTF-8: {msg}")]
    Utf8 { what: &'static str, msg: String },
    #[error(transparent)]
    Clearsign(#[from] ClearSignError),
    #[error(transparent)]
    Release(#[from] ReleaseParseError),
    #[error(transparent)]
    Deb822(#[from] Deb822Error),
    #[error(transparent)]
    Package(#[from] PackageParseError),
    #[error(transparent)]
    Source(#[from] SourceParseError),
    #[error(transparent)]
    InstallerSums(#[from] InstallerSumsError),
    #[error(transparent)]
    ByHash(#[from] super::by_hash::ByHashError),
    #[error(transparent)]
    Pgp(#[from] PgpError),
    #[error(
        "upstream published a new InRelease mid-sync — this round's pool set may be incomplete for the new state"
    )]
    UpstreamRefreshedMidSync,
    #[error(
        "upstream signed body kept refreshing after {rounds} refold rounds (retry.index_rounds cap) — suite not published"
    )]
    UpstreamRefreshedMidSyncExhausted { rounds: u32 },
    #[error("watchdog tripped for {url}: {msg}")]
    WatchdogTripped { url: url::Url, msg: String },
    #[error(transparent)]
    Sink(#[from] SinkError),
    #[error("failed to fetch index `{url}`: {source}")]
    IndexFetch {
        url: url::Url,
        #[source]
        source: Box<AptFlowError>,
    },
    #[error("failed to fetch pool file `{url}`: {source}")]
    PoolFetch {
        url: url::Url,
        #[source]
        source: Box<AptFlowError>,
    },
    #[error("bad {which} field `{raw}`: {msg}")]
    BadDate {
        which: &'static str,
        raw: String,
        msg: String,
    },
    #[error("suite `{suite}`: incoming Date `{incoming}` predates last-published `{prior}`")]
    DateRegressed {
        suite: String,
        prior: String,
        incoming: String,
    },
    #[error("Release has no checksum entries after weak-hash policy filtering")]
    EmptyReleaseAfterPolicy,
    #[error(
        "suite `{suite}`: no Packages index selected for the configured components × architectures"
    )]
    NoIndexSelected { suite: String },
    #[error(
        "no Packages variant served for group `{component}/binary-{arch}` — every advertised variant returned 404"
    )]
    AllVariantsMissing { component: String, arch: String },
    #[error(
        "upstream index would produce more than {limit} pool entries — refusing to allocate (memory cap; possible compression bomb / poisoned upstream)"
    )]
    TooManyPoolEntries { limit: usize },
    #[error("I/O on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Publish(#[from] publish::PublishError),
}

impl From<Box<AptFlowError>> for AptFlowError {
    fn from(b: Box<AptFlowError>) -> Self {
        *b
    }
}
