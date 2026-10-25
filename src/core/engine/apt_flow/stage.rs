//! Index staging.
//!
//! Stages every served variant of each selected index group. 404s (and the
//! 403s S3-style hosts send for missing objects) are tolerated (indexes are
//! often listed but not served), but each parse group must land at least
//! one variant.

use std::path::{Path, PathBuf};

use reqwest::Client;
use tracing::debug;

use crate::backends::apt::checksums::ChecksumEntry;
use crate::backends::apt::index_selector::{Compression, IndexGroup, IndexRole, IndexSelection};
use crate::backends::apt::layout::SuiteLayout;
use crate::core::fetch::budget::Budget;
use crate::core::types::DigestAlgo;

use super::AptFlowError;
use super::hex::hex_of;
use super::pool_download::{FetchTuning, download_verified};
use super::root_fetch::is_absent_status;

#[derive(Debug, Clone)]
pub(super) struct StagedIndex<'a> {
    pub(super) entry: &'a ChecksumEntry,
    pub(super) staged_path: PathBuf,
    pub(super) compression: Compression,
}

pub(super) enum StageOutcome {
    Staged(PathBuf),
    ListedButNotServed,
}

/// `PlannerOnly` (dry-run) downloads only the groups parsed to derive the
/// pool set; `Full` downloads everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StageMode {
    Full,
    PlannerOnly,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn stage_indexes_with_mode<'a>(
    client: &Client,
    budget: &Budget,
    layout: &SuiteLayout<'_>,
    staging: &Path,
    selection: &IndexSelection<'a>,
    acquire_by_hash: bool,
    tuning: &FetchTuning,
    mode: StageMode,
) -> Result<Vec<StagedIndex<'a>>, AptFlowError> {
    let mut staged = Vec::new();

    for group in &selection.groups {
        if matches!(mode, StageMode::PlannerOnly)
            && !matches!(
                group.role,
                IndexRole::PackagesParse | IndexRole::SourcesParse | IndexRole::InstallerSumsParse
            )
        {
            continue;
        }
        let mut any_present = false;
        for variant in &group.variants {
            let outcome = stage_one_variant(
                client,
                budget,
                layout,
                staging,
                variant.entry,
                variant.compression,
                acquire_by_hash,
                tuning,
            )
            .await?;
            if let StageOutcome::Staged(path) = outcome {
                any_present = true;
                staged.push(StagedIndex {
                    entry: variant.entry,
                    staged_path: path,
                    compression: variant.compression,
                });
            }
        }
        // Without a parse group the pool set is incomplete; Verbatim groups
        // may be entirely absent upstream.
        if !any_present
            && matches!(
                group.role,
                IndexRole::PackagesParse | IndexRole::SourcesParse | IndexRole::InstallerSumsParse
            )
        {
            return Err(AptFlowError::AllVariantsMissing {
                component: group.component.clone().unwrap_or_default(),
                arch: group.arch.clone().unwrap_or_default(),
            });
        }
    }

    Ok(staged)
}

#[allow(clippy::too_many_arguments)]
async fn stage_one_variant(
    client: &Client,
    budget: &Budget,
    layout: &SuiteLayout<'_>,
    staging: &Path,
    entry: &ChecksumEntry,
    _compression: Compression,
    acquire_by_hash: bool,
    tuning: &FetchTuning,
) -> Result<StageOutcome, AptFlowError> {
    let canonical_url = layout.suite_url(&entry.path)?;
    let dest = staging.join(&entry.path);
    let expected = entry.digests.clone();

    // by-hash objects are immutable, so they survive a mid-sync upstream
    // refresh where the canonical name may not.
    if acquire_by_hash && let Some(sha256) = entry.digests.get(DigestAlgo::Sha256) {
        let hex = hex_of(&sha256.bytes);
        let by_hash_url = layout.by_hash_url(&entry.path, "SHA256", &hex)?;
        match download_verified(
            budget,
            client,
            &by_hash_url,
            &dest,
            expected.clone(),
            Some(entry.size),
            tuning.retry_count,
            tuning.watchdog,
        )
        .await
        {
            Ok(()) => {
                debug!(url = %by_hash_url, "index staged via by-hash URL");
                return Ok(StageOutcome::Staged(dest));
            }
            Err(AptFlowError::UpstreamStatus { status, .. }) if is_absent_status(status) => {
                debug!(
                    url = %by_hash_url,
                    "by-hash URL absent — falling back to canonical name"
                );
            }
            Err(e) => {
                return Err(AptFlowError::IndexFetch {
                    url: by_hash_url,
                    source: Box::new(e),
                });
            }
        }
    }

    match download_verified(
        budget,
        client,
        &canonical_url,
        &dest,
        expected,
        Some(entry.size),
        tuning.retry_count,
        tuning.watchdog,
    )
    .await
    {
        Ok(()) => Ok(StageOutcome::Staged(dest)),
        Err(AptFlowError::UpstreamStatus { status, .. }) if is_absent_status(status) => {
            // Common for uncompressed variants; the caller enforces
            // at-least-one per group.
            debug!(
                url = %canonical_url,
                "index variant listed in Release but not served — accepting"
            );
            Ok(StageOutcome::ListedButNotServed)
        }
        Err(e) => Err(AptFlowError::IndexFetch {
            url: canonical_url,
            source: Box::new(e),
        }),
    }
}

/// First staged variant in group order (xz → gz → bz2 → uncompressed).
pub(super) fn pick_parseable_variant<'a, 's>(
    staged: &'s [StagedIndex<'a>],
    group: &IndexGroup<'a>,
) -> Option<&'s StagedIndex<'a>> {
    for variant in &group.variants {
        if let Some(hit) = staged.iter().find(|s| s.entry.path == variant.entry.path) {
            return Some(hit);
        }
    }
    None
}
