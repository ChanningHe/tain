//! One suite's refold loop: verify → temporal checks → stage → derive pool
//! → fetch pool → by-hash → recheck → publish.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use reqwest::Client;
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::backends::apt::checksums::ReleaseChecksums;
use crate::backends::apt::clearsign::{ReleaseKind, extract_signed_body};
use crate::backends::apt::datetime::parse_release_datetime;
use crate::backends::apt::index_selector::{IndexGroup, IndexSelection, select_indexes};
use crate::backends::apt::layout::SuiteLayout;
use crate::backends::apt::pgp::{self, VerifyOutcome};
use crate::backends::apt::release::{ReleaseHeader, parse_release};
use crate::config::model::{AptOptions, MirrorConfig, PgpMode};
use crate::core::fetch::budget::Budget;
use crate::core::fetch::client::CacheValidators;
use crate::core::store::manifest::{GenerationManifest, ManifestEntry};
use crate::core::store::state::SuiteState;
use crate::core::types::{DigestAlgo, FileSpec};

use super::derive_pool::{parse_installer_sums_into, parse_packages_into, parse_sources_into};
use super::hex::{hex_of, hex_of_digest_algo};
use super::pool_download::{download_pool_file, is_already_present};
use super::pool_fence::{PoolFence, symlinked_dists};
use super::root_fetch::{MAX_RELEASE_BYTES, MAX_SIGNATURE_BYTES, RootFetcher};
use super::root_files::{PublishedRoot, VerbatimKind, change_token, vet_siblings};
use super::stage::{StageMode, StagedIndex, pick_parseable_variant, stage_indexes_with_mode};
use super::{
    AptFlowError, ApttSyncOutcome, FetchTuning, SuiteDryRun, SuiteVerdict, by_hash, dry_run,
    installer_current, maybe_create_suite_symlink, publish, record_published_indexes, reset_dir,
    suite_dir_prefix, write_bytes,
};

/// Manifest keys this suite added that were not already present: the only
/// ones a refold or failure may roll back (a shared pool entry must
/// survive). The engine hands each suite its own manifest, so there this
/// resets an abandoned refold round; the scoping keeps `sync_apt_suite`
/// failure-neutral for callers passing a shared manifest.
#[derive(Default)]
pub(super) struct OwnedKeys(HashSet<String>);

impl OwnedKeys {
    fn insert(&mut self, manifest: &mut GenerationManifest, entry: ManifestEntry) {
        if !manifest.files.contains_key(&entry.rel_path) {
            self.0.insert(entry.rel_path.clone());
        }
        manifest.insert(entry);
    }

    pub(super) fn rollback(&mut self, manifest: &mut GenerationManifest) {
        for key in self.0.drain() {
            manifest.files.remove(&key);
        }
    }
}

/// The verified signed body of one round.
struct SignedBody {
    body: String,
    pgp: VerifyOutcome,
    /// Release mode: the detached signature exactly as verified.
    release_gpg: Option<Vec<u8>>,
}

enum RoundEnd {
    Published {
        pgp: VerifyOutcome,
        date_raw: Option<String>,
    },
    /// Upstream published mid-sync: refold with these bytes.
    Refreshed {
        bytes: Vec<u8>,
        validators: CacheValidators,
    },
    DryRun(SuiteDryRun),
}

/// Per-suite inputs fixed across refold rounds.
pub(super) struct SuiteRun<'a> {
    pub(super) client: &'a Client,
    pub(super) budget: &'a Budget,
    pub(super) mirror: &'a MirrorConfig,
    pub(super) apt: &'a AptOptions,
    pub(super) mirror_root: &'a Path,
    pub(super) suite: &'a str,
    pub(super) layout: SuiteLayout<'a>,
    pub(super) tuning: &'a FetchTuning,
    pub(super) dry_run: bool,
    pub(super) kind: VerbatimKind,
    pub(super) prior: SuiteState,
    /// Latest `Date` already published on disk.
    pub(super) date_floor: Option<String>,
    pub(super) published: PublishedRoot,
    pub(super) staging: PathBuf,
    pub(super) dist_dir: PathBuf,
}

impl SuiteRun<'_> {
    /// Each round runs steps 2-10 and publishes only if the re-fetched
    /// signed body carries this round's change token; otherwise it refolds.
    pub(super) async fn rounds(
        &self,
        mut token_bytes: Vec<u8>,
        mut validators: CacheValidators,
        max_refolds: u32,
        manifest: &mut GenerationManifest,
        owned: &mut OwnedKeys,
    ) -> Result<ApttSyncOutcome, AptFlowError> {
        let suite = self.suite;
        let mut round: u32 = 0;
        loop {
            let (bytes, new_validators) =
                match self.round(&token_bytes, round, manifest, owned).await? {
                    RoundEnd::DryRun(plan) => return Ok(ApttSyncOutcome::DryRun(plan)),
                    RoundEnd::Published { pgp, date_raw } => {
                        return Ok(ApttSyncOutcome::Updated {
                            token_sha256: change_token(&token_bytes),
                            date_raw,
                            etag: validators.etag,
                            last_modified: validators.last_modified,
                            pgp,
                        });
                    }
                    RoundEnd::Refreshed { bytes, validators } => (bytes, validators),
                };
            owned.rollback(manifest);
            if round >= max_refolds {
                warn!(
                    suite,
                    kind = ?self.kind,
                    rounds = round,
                    "signed body still refreshing after retry.index_rounds refolds — aborting suite"
                );
                return Err(AptFlowError::UpstreamRefreshedMidSyncExhausted { rounds: round });
            }
            warn!(
                suite,
                kind = ?self.kind,
                round,
                "upstream signed body refreshed mid-sync — refolding indexes"
            );
            token_bytes = bytes;
            validators = new_validators;
            round += 1;
        }
    }

    async fn round(
        &self,
        token_bytes: &[u8],
        round: u32,
        manifest: &mut GenerationManifest,
        owned: &mut OwnedKeys,
    ) -> Result<RoundEnd, AptFlowError> {
        // ---- 2-4. verify, temporal checks, weak-hash policy ----
        let signed = self.verify(token_bytes).await?;
        let (header, checksums) = self.checked_release(&signed)?;

        // ---- 5. select indexes ----
        let selection = select_indexes(&header, &checksums, self.apt);
        if selection.is_empty() {
            return Err(AptFlowError::NoIndexSelected {
                suite: self.suite.to_owned(),
            });
        }

        // ---- 6. stage root files (fresh staging; pool files are reused) ----
        self.stage_root_files(token_bytes, &signed).await?;

        // ---- 7. stage index variants ----
        let staged = self.stage_indexes(&header, &selection).await?;

        // ---- 8. derive pool set ----
        let pool_specs = self.derive_pool(&selection, &staged)?;
        self.fence_pool(&checksums, &pool_specs)?;

        // ---- 8b. dry-run exit: everything past here mutates disk ----
        if self.dry_run {
            return Ok(RoundEnd::DryRun(
                self.dry_run_plan(&selection, &pool_specs).await?,
            ));
        }

        // ---- 9. download pool; 9.5 / 9.6 by-hash ----
        self.fetch_pool(&pool_specs, manifest, owned).await?;
        self.write_by_hash(&staged)?;

        // ---- 9.7 signed-body recheck ----
        if let Some(refreshed) = self.recheck(token_bytes).await? {
            return Ok(refreshed);
        }
        info!(suite = self.suite, round, "recheck stable");

        // ---- 10. publish (atomic swap; old dir → prev/ for GC) ----
        self.publish(&header, &staged, manifest)?;
        Ok(RoundEnd::Published {
            pgp: signed.pgp,
            date_raw: header.date_raw,
        })
    }

    fn fetcher(&self) -> RootFetcher<'_> {
        RootFetcher {
            client: self.client,
            budget: self.budget,
            tuning: self.tuning,
        }
    }

    async fn verify(&self, token_bytes: &[u8]) -> Result<SignedBody, AptFlowError> {
        let signed = self.verify_kind(token_bytes).await?;
        // `if-present` must not trade a published signature for none.
        if signed.pgp == VerifyOutcome::AbsentInIfPresent
            && self.published.is_signed(&self.mirror.verify)
        {
            return Err(AptFlowError::PgpDowngrade {
                suite: self.suite.to_owned(),
            });
        }
        Ok(signed)
    }

    async fn verify_kind(&self, token_bytes: &[u8]) -> Result<SignedBody, AptFlowError> {
        let verify = &self.mirror.verify;
        match self.kind {
            VerbatimKind::InRelease => {
                let text = utf8(token_bytes, "InRelease")?;
                let extracted = extract_signed_body(text)?;
                let is_clearsigned = extracted.kind == ReleaseKind::Clearsigned;
                // One rule for every path (probe, refold): under PGP an
                // unsigned InRelease never drives a round — apt rejects it.
                if verify.pgp != PgpMode::Off && !is_clearsigned {
                    return Err(AptFlowError::UnsignedInRelease {
                        suite: self.suite.to_owned(),
                    });
                }
                let pgp = pgp::verify_inrelease(
                    verify.pgp,
                    token_bytes,
                    is_clearsigned,
                    verify.keyring.as_deref(),
                )?;
                Ok(SignedBody {
                    body: extracted.body.into_owned(),
                    pgp,
                    release_gpg: None,
                })
            }
            VerbatimKind::Release => {
                let gpg_url = self.layout.release_gpg_url()?;
                let release_gpg = self
                    .fetcher()
                    .optional(&gpg_url, MAX_SIGNATURE_BYTES)
                    .await?;
                let pgp = pgp::verify_release_gpg(
                    verify.pgp,
                    token_bytes,
                    release_gpg.as_deref(),
                    verify.keyring.as_deref(),
                )?;
                Ok(SignedBody {
                    body: utf8(token_bytes, "Release")?.to_owned(),
                    pgp,
                    release_gpg,
                })
            }
        }
    }

    /// Steps 2b-4: parse, Date floor / Valid-Until, weak-hash policy.
    fn checked_release(
        &self,
        signed: &SignedBody,
    ) -> Result<(ReleaseHeader, ReleaseChecksums), AptFlowError> {
        let (header, checksums_raw) = parse_release(&signed.body)?;
        check_temporal(
            &header,
            self.prior.date_raw.as_deref(),
            self.date_floor.as_deref(),
            self.suite,
        )?;
        let (checksums, weak_report) =
            checksums_raw.apply_weak_hash_policy(self.mirror.verify.allow_weak_hash);
        if weak_report.policy_dropped && weak_report.weak_only_count > 0 {
            warn!(
                suite = self.suite,
                dropped = weak_report.weak_only_count,
                "Release entries dropped as weak-only per policy",
            );
        }
        if checksums.is_empty() {
            return Err(AptFlowError::EmptyReleaseAfterPolicy);
        }
        Ok((header, checksums))
    }

    /// Byte fidelity: the driving body lands verbatim under its own name;
    /// sibling forms only when they match what was verified.
    async fn stage_root_files(
        &self,
        token_bytes: &[u8],
        signed: &SignedBody,
    ) -> Result<(), AptFlowError> {
        reset_dir(&self.staging).map_err(|e| AptFlowError::Io {
            path: self.staging.clone(),
            source: e,
        })?;
        write_bytes(&self.staging.join(self.kind.file_name()), token_bytes)?;
        let siblings = match self.kind {
            // InRelease was absent upstream: only the verified signature.
            VerbatimKind::Release => signed
                .release_gpg
                .clone()
                .map(|sig| ("Release.gpg", sig))
                .into_iter()
                .collect(),
            VerbatimKind::InRelease => self.vetted_siblings(&signed.body).await?,
        };
        for (name, bytes) in siblings {
            write_bytes(&self.staging.join(name), &bytes)?;
        }
        Ok(())
    }

    async fn vetted_siblings(
        &self,
        inrelease_body: &str,
    ) -> Result<Vec<(&'static str, Vec<u8>)>, AptFlowError> {
        let fetch = self.fetcher();
        let release_url = self.layout.release_url()?;
        let release = fetch.sibling(&release_url, MAX_RELEASE_BYTES).await?;
        let release_gpg = match release {
            Some(_) => {
                let gpg_url = self.layout.release_gpg_url()?;
                fetch.sibling(&gpg_url, MAX_SIGNATURE_BYTES).await?
            }
            None => None,
        };
        Ok(vet_siblings(
            inrelease_body,
            release,
            release_gpg,
            &self.mirror.verify,
            self.suite,
        ))
    }

    async fn stage_indexes<'c>(
        &self,
        header: &ReleaseHeader,
        selection: &IndexSelection<'c>,
    ) -> Result<Vec<StagedIndex<'c>>, AptFlowError> {
        // Dry-run still downloads parseable indexes to derive the pool set.
        let stage_mode = if self.dry_run {
            StageMode::PlannerOnly
        } else {
            StageMode::Full
        };
        stage_indexes_with_mode(
            self.client,
            self.budget,
            &self.layout,
            &self.staging,
            selection,
            header.acquire_by_hash,
            self.tuning,
            stage_mode,
        )
        .await
    }

    /// Refuse pool specs that would overwrite root files, indexes, by-hash
    /// objects or another configured suite's tree.
    fn fence_pool(
        &self,
        checksums: &ReleaseChecksums,
        pool_specs: &[FileSpec],
    ) -> Result<(), AptFlowError> {
        let own = suite_dir_prefix(&self.layout, self.suite).unwrap_or_default();
        let others: Vec<String> = self
            .apt
            .suites
            .iter()
            .filter(|s| s.as_str() != self.suite)
            .filter_map(|s| suite_dir_prefix(&SuiteLayout::new(&self.mirror.url, s), s))
            .collect();
        PoolFence {
            own: &own,
            others: &others,
            checksums,
            symlinked: &symlinked_dists(self.mirror_root),
        }
        .check(pool_specs)
    }

    fn derive_pool(
        &self,
        selection: &IndexSelection<'_>,
        staged: &[StagedIndex<'_>],
    ) -> Result<Vec<FileSpec>, AptFlowError> {
        let allow_weak = self.mirror.verify.allow_weak_hash;
        let mut pool_specs: Vec<FileSpec> = Vec::new();
        for group in selection.packages_groups() {
            let parseable = parseable(staged, group, None)?;
            parse_packages_into(
                &parseable.staged_path,
                &parseable.entry.path,
                parseable.compression,
                &self.layout,
                allow_weak,
                &mut pool_specs,
            )?;
        }
        for group in selection.sources_groups() {
            let parseable = parseable(staged, group, Some("source"))?;
            parse_sources_into(
                &parseable.staged_path,
                &parseable.entry.path,
                parseable.compression,
                &self.layout,
                allow_weak,
                &mut pool_specs,
            )?;
        }
        // d-i SHA256SUMS lists image files that must be fetched, verified and
        // published in the same swap (debmirror LP#1550852 dropped them).
        for group in selection.installer_sums_groups() {
            let parseable = parseable(staged, group, None)?;
            // `<comp>/installer-<arch>/<ver>/images/SHA256SUMS` → its directory.
            let sums_base = group
                .base_path
                .rsplit_once('/')
                .map(|(dir, _)| dir)
                .unwrap_or("");
            parse_installer_sums_into(
                &parseable.staged_path,
                sums_base,
                &self.layout,
                &mut pool_specs,
            )?;
        }
        info!(
            suite = self.suite,
            pool_files = pool_specs.len(),
            index_files = staged.len(),
            "pool wanted set derived"
        );
        Ok(pool_specs)
    }

    async fn dry_run_plan(
        &self,
        selection: &IndexSelection<'_>,
        pool_specs: &[FileSpec],
    ) -> Result<SuiteDryRun, AptFlowError> {
        let (pool_would, already, bytes) =
            dry_run::classify_pool(self.mirror_root, pool_specs).await?;
        let indexes = dry_run::collect_verbatim_indexes(selection.groups.iter());
        let _ = std::fs::remove_dir_all(&self.staging);
        let verdict = if self.prior.token_sha256.is_empty() {
            SuiteVerdict::Fresh
        } else {
            SuiteVerdict::Incremental
        };
        Ok(SuiteDryRun {
            suite: self.suite.to_owned(),
            verdict,
            indexes_would_download: indexes,
            pool_would_download: pool_would,
            pool_already_present: already,
            bytes_estimate: bytes,
            gc_candidates: None,
        })
    }

    /// `pool/**` files go straight to their final path (pool-first, for
    /// published-index closure). Files under the suite dir (Proxmox,
    /// Tailscale, ...) go into staging: at the final path the swap would
    /// move them into prev/ and clients would 404.
    async fn fetch_pool(
        &self,
        pool_specs: &[FileSpec],
        manifest: &mut GenerationManifest,
        owned: &mut OwnedKeys,
    ) -> Result<(), AptFlowError> {
        let suite_prefix = suite_dir_prefix(&self.layout, self.suite);
        for spec in pool_specs {
            let rel = spec.rel_path.as_str();
            let inside_suite = suite_prefix.as_deref().is_some_and(|p| rel.starts_with(p));
            let target = if inside_suite {
                let suffix = &rel[suite_prefix.as_deref().unwrap().len()..];
                self.staging.join(suffix)
            } else {
                self.mirror_root.join(rel)
            };
            let final_local = self.mirror_root.join(rel);
            if !inside_suite && is_already_present(&final_local, spec.size, &spec.digests).await? {
                owned.insert(manifest, pool_entry(spec));
                continue;
            }
            download_pool_file(
                self.budget,
                self.client,
                &spec.url,
                &target,
                spec.digests.clone(),
                spec.size,
                self.tuning,
            )
            .await
            .map_err(|source| AptFlowError::PoolFetch {
                url: spec.url.clone(),
                source: Box::new(source),
            })?;
            owned.insert(manifest, pool_entry(spec));
        }
        Ok(())
    }

    fn write_by_hash(&self, staged: &[StagedIndex<'_>]) -> Result<(), AptFlowError> {
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
        // Inherit by-hash objects from the published dist.
        by_hash::inherit_from_previous(&self.dist_dir, &self.staging)
            .map_err(AptFlowError::ByHash)?;
        Ok(())
    }

    /// A different change token means upstream published mid-sync.
    async fn recheck(&self, token_bytes: &[u8]) -> Result<Option<RoundEnd>, AptFlowError> {
        let url = match self.kind {
            VerbatimKind::InRelease => self.layout.inrelease_url()?,
            VerbatimKind::Release => self.layout.release_url()?,
        };
        // The fetcher holds a budget permit per attempt, not across backoff.
        let (bytes, validators) = self.fetcher().required(&url).await?;
        if change_token(&bytes) == change_token(token_bytes) {
            return Ok(None);
        }
        Ok(Some(RoundEnd::Refreshed { bytes, validators }))
    }

    fn publish(
        &self,
        header: &ReleaseHeader,
        staged: &[StagedIndex<'_>],
        manifest: &mut GenerationManifest,
    ) -> Result<(), AptFlowError> {
        let prev_slot = self
            .mirror_root
            .join(".tain/prev")
            .join(self.suite)
            .join(manifest.generation.to_string());
        publish::publish_suite(&self.staging, &self.dist_dir, Some(&prev_slot))
            .map_err(AptFlowError::Publish)?;

        // The swap is done: nothing below may fail the suite, or state.json
        // would lag the published tree.
        if self.apt.create_suite_symlinks
            && !self.layout.is_flat()
            && let Err(e) = maybe_create_suite_symlink(self.mirror_root, header, self.suite)
        {
            warn!(suite = self.suite, err = %e, "suite alias symlink not updated");
        }
        if self.apt.indexes.debian_installer && !self.layout.is_flat() {
            installer_current::rebuild(&self.dist_dir, self.suite);
        }
        record_published_indexes(
            self.mirror_root,
            &self.dist_dir,
            staged,
            &self.layout,
            manifest,
        );
        Ok(())
    }
}

fn pool_entry(spec: &FileSpec) -> ManifestEntry {
    ManifestEntry {
        rel_path: spec.rel_path.as_str().to_owned(),
        size: spec.size.unwrap_or(0),
        sha256_hex: hex_of_digest_algo(&spec.digests, DigestAlgo::Sha256),
        sha512_hex: hex_of_digest_algo(&spec.digests, DigestAlgo::Sha512),
    }
}

fn utf8<'b>(bytes: &'b [u8], what: &'static str) -> Result<&'b str, AptFlowError> {
    std::str::from_utf8(bytes).map_err(|e| AptFlowError::Utf8 {
        what,
        msg: e.to_string(),
    })
}

/// First staged variant of a parse group; `arch` overrides the label used
/// when none was served (Sources groups carry no arch).
fn parseable<'s, 'c>(
    staged: &'s [StagedIndex<'c>],
    group: &IndexGroup<'c>,
    arch: Option<&str>,
) -> Result<&'s StagedIndex<'c>, AptFlowError> {
    pick_parseable_variant(staged, group).ok_or_else(|| AptFlowError::AllVariantsMissing {
        component: group.component.clone().unwrap_or_default(),
        arch: arch.map_or_else(|| group.arch.clone().unwrap_or_default(), str::to_owned),
    })
}

fn parse_date(which: &'static str, raw: &str) -> Result<OffsetDateTime, AptFlowError> {
    parse_release_datetime(raw).map_err(|e| AptFlowError::BadDate {
        which,
        raw: raw.to_owned(),
        msg: e.to_string(),
    })
}

/// The later of state's last published Date and the trusted published Date
/// on disk. An unreadable state Date fails closed.
fn date_floor(
    state_date: Option<&str>,
    disk_date: Option<&str>,
) -> Result<Option<(OffsetDateTime, String)>, AptFlowError> {
    let mut floors = Vec::with_capacity(2);
    if let Some(raw) = state_date {
        floors.push((parse_date("state.json date_raw", raw)?, raw.to_owned()));
    }
    // Already validated when read from disk.
    if let Some(raw) = disk_date
        && let Ok(dt) = parse_release_datetime(raw)
    {
        floors.push((dt, raw.to_owned()));
    }
    Ok(floors.into_iter().max_by_key(|(dt, _)| *dt))
}

/// Date monotonicity: the incoming `Date` must not predate the floor, and
/// once a floor exists a Release without a Date is refused rather than
/// erasing it.
fn check_temporal(
    header: &ReleaseHeader,
    state_date: Option<&str>,
    disk_date: Option<&str>,
    suite: &str,
) -> Result<(), AptFlowError> {
    let floor = date_floor(state_date, disk_date)?;
    let incoming = header
        .date_raw
        .as_deref()
        .map(|raw| parse_date("Date", raw).map(|dt| (dt, raw)))
        .transpose()?;
    match (incoming, floor) {
        (None, Some((_, prior))) => {
            return Err(AptFlowError::DateMissing {
                suite: suite.to_owned(),
                prior,
            });
        }
        (Some((new_dt, new_raw)), Some((floor_dt, prior))) if new_dt < floor_dt => {
            return Err(AptFlowError::DateRegressed {
                suite: suite.to_owned(),
                prior,
                incoming: new_raw.to_owned(),
            });
        }
        _ => {}
    }
    warn_if_expired(header, suite);
    Ok(())
}

fn warn_if_expired(header: &ReleaseHeader, suite: &str) {
    if let Some(valid_until_raw) = header.valid_until_raw.as_deref()
        && let Ok(valid_until) = parse_release_datetime(valid_until_raw)
        && valid_until < OffsetDateTime::now_utc()
    {
        warn!(
            suite,
            valid_until = valid_until_raw,
            "Release Valid-Until is in the past — upstream may be stale"
        );
    }
}
