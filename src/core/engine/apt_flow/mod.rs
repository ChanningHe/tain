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
mod pool_fence;
mod root_fetch;
mod root_files;
mod round;
mod stage;

pub use dry_run::{DryRunReport, GcPreview, PoolPlan, SuiteDryRun, SuiteVerdict};
pub use pool_download::{FetchTuning, download_verified};

use std::path::{Path, PathBuf};

use reqwest::Client;
use sha2::{Digest as _, Sha256};
use tracing::{debug, warn};

use crate::backends::apt::clearsign::ClearSignError;
use crate::backends::apt::deb822::ParseError as Deb822Error;
use crate::backends::apt::installer_sums::InstallerSumsError;
use crate::backends::apt::layout::{LayoutError, SuiteLayout};
use crate::backends::apt::packages::PackageParseError;
use crate::backends::apt::pgp::{self, PgpError};
use crate::backends::apt::release::{ReleaseHeader, ReleaseParseError};
use crate::backends::apt::sources::SourceParseError;

use super::by_hash;
use crate::config::model::{AptOptions, MirrorConfig, PgpMode};
use crate::core::fetch::budget::Budget;
use crate::core::fetch::client::{CacheValidators, ClientError};
use crate::core::fetch::sink::SinkError;
use crate::core::store::manifest::{GenerationManifest, ManifestEntry};
use crate::core::store::state::SuiteState;
use crate::core::types::DigestAlgo;

use hex::{hex_of, hex_of_digest_bytes};
use root_fetch::{MAX_RELEASE_BYTES, RootFetcher, SmallFetch, is_absent_status, unexpected_status};
use root_files::{PublishedRoot, VerbatimKind, is_clearsigned, token_matches};
use round::{OwnedKeys, SuiteRun};
use stage::StagedIndex;

use super::publish;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApttSyncOutcome {
    /// Signed body unchanged (304 or same change token).
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
    let dist_dir = final_dist_path(mirror_root, &layout, suite);
    let published = PublishedRoot::read(&dist_dir);

    // ---- 1. probe InRelease, fall back to Release + Release.gpg ----
    let fetch = RootFetcher {
        client,
        budget,
        tuning,
    };
    let pgp_on = mirror.verify.pgp != PgpMode::Off;
    let Some(probe) = probe(fetch, &layout, prior, &published, pgp_on, suite).await? else {
        return Ok(if dry_run {
            ApttSyncOutcome::DryRun(dry_run_unchanged(suite))
        } else {
            ApttSyncOutcome::Unchanged
        });
    };

    let run = SuiteRun {
        client,
        budget,
        mirror,
        apt,
        mirror_root,
        suite,
        layout,
        tuning,
        dry_run,
        kind: probe.kind,
        prior: probe.prior,
        date_floor: published.date_floor(probe.kind, &mirror.verify),
        published,
        staging: staging_dir(mirror_root, suite),
        dist_dir,
    };
    let mut owned = OwnedKeys::default();
    let result = run
        .rounds(
            probe.bytes,
            probe.validators,
            retry_index_rounds,
            manifest,
            &mut owned,
        )
        .await;
    // Failure neutrality for the manifest too: a failed suite leaves no
    // entries of its own behind.
    if result.is_err() {
        owned.rollback(manifest);
    }
    if probe.unsigned_inrelease && matches!(result, Ok(ApttSyncOutcome::Updated { .. })) {
        warn!(
            suite,
            "upstream InRelease is not clearsigned — published Release + Release.gpg only"
        );
    }
    result
}

struct Probe {
    kind: VerbatimKind,
    bytes: Vec<u8>,
    validators: CacheValidators,
    /// Effective prior: a drifted published tree keeps only `date_raw`.
    prior: SuiteState,
    unsigned_inrelease: bool,
}

/// Fetch the driving signed body; `None` means Unchanged.
async fn probe(
    fetch: RootFetcher<'_>,
    layout: &SuiteLayout<'_>,
    prior: &SuiteState,
    published: &PublishedRoot,
    pgp_on: bool,
    suite: &str,
) -> Result<Option<Probe>, AptFlowError> {
    // The stored validators belong to the file that drove the last round;
    // sent to the other URL they can earn a bogus 304.
    let conditional = Conditional {
        owner: published.driver(pgp_on),
        validators: CacheValidators {
            etag: prior.etag.clone(),
            last_modified: prior.last_modified.clone(),
        },
    };
    let FirstFetch {
        kind,
        url,
        fetched: first,
        unsigned_inrelease,
    } = first_fetch(fetch, layout, &conditional, pgp_on, suite).await?;

    // Spot-check the published copy of this token source, so the Unchanged
    // fast paths can't mask a published tree broken by a crash or a manual
    // edit. Under PGP an unsigned published InRelease is broken.
    let disk_ok = prior.token_sha256.is_empty()
        || (published.matches(kind, &prior.token_sha256)
            && !(pgp_on && published.has_unsigned_inrelease()));
    if !disk_ok {
        warn!(
            suite,
            file = kind.file_name(),
            "published root files do not match state.token_sha256 — forcing fresh sync"
        );
    }
    let (kind, bytes, validators, unsigned_inrelease) = match first {
        SmallFetch::NotModified if disk_ok => {
            debug!(suite, ?kind, "304 Not Modified");
            return Ok(None);
        }
        SmallFetch::NotModified => {
            let unconditional = Conditional::default();
            let again = first_fetch(fetch, layout, &unconditional, pgp_on, suite).await?;
            match again.fetched {
                SmallFetch::Body { bytes, validators } => {
                    (again.kind, bytes, validators, again.unsigned_inrelease)
                }
                other => return Err(unexpected_status(&again.url, other)),
            }
        }
        SmallFetch::Status(status) => return Err(AptFlowError::UpstreamStatus { url, status }),
        SmallFetch::Body { bytes, validators } => (kind, bytes, validators, unsigned_inrelease),
    };
    if disk_ok && token_matches(&bytes, &prior.token_sha256) {
        debug!(suite, ?kind, "signed body unchanged");
        return Ok(None);
    }
    Ok(Some(Probe {
        kind,
        bytes,
        validators,
        prior: effective_prior(prior, disk_ok),
        unsigned_inrelease,
    }))
}

struct FirstFetch {
    kind: VerbatimKind,
    url: url::Url,
    fetched: SmallFetch,
    /// PGP is on and upstream's InRelease is not clearsigned, so Release +
    /// Release.gpg drive instead.
    unsigned_inrelease: bool,
}

/// GET InRelease, else Release. Some upstreams never clearsign and ship
/// only detached signatures, so an absent (4xx) InRelease falls back to
/// Release; transient failures (5xx/408/429) don't. Under PGP an InRelease
/// that isn't clearsigned is unusable, as in apt: Release + Release.gpg
/// drive the round instead and the unsigned InRelease is never published.
async fn first_fetch(
    fetch: RootFetcher<'_>,
    layout: &SuiteLayout<'_>,
    conditional: &Conditional,
    pgp_on: bool,
    suite: &str,
) -> Result<FirstFetch, AptFlowError> {
    let url = layout.inrelease_url()?;
    let validators = conditional.for_kind(VerbatimKind::InRelease);
    let first = fetch.small(&url, &validators, MAX_RELEASE_BYTES).await?;
    let unsigned_inrelease = match &first {
        SmallFetch::Status(status) if is_absent_status(*status) => {
            debug!(suite, %status, "InRelease absent — trying plain Release + Release.gpg");
            false
        }
        // Warned about only when a round publishes (see `sync_apt_suite`):
        // the probe repeats every run, Unchanged ones included.
        SmallFetch::Body { bytes, .. } if pgp_on && !is_clearsigned(bytes) => {
            debug!(
                suite,
                "upstream InRelease is not clearsigned — using Release + Release.gpg"
            );
            true
        }
        _ => {
            return Ok(FirstFetch {
                kind: VerbatimKind::InRelease,
                url,
                fetched: first,
                unsigned_inrelease: false,
            });
        }
    };
    let url = layout.release_url()?;
    let validators = conditional.for_kind(VerbatimKind::Release);
    let fetched = fetch.small(&url, &validators, MAX_RELEASE_BYTES).await?;
    Ok(FirstFetch {
        kind: VerbatimKind::Release,
        url,
        fetched,
        unsigned_inrelease,
    })
}

/// Stored cache validators and the file they were issued for.
#[derive(Default)]
struct Conditional {
    owner: Option<VerbatimKind>,
    validators: CacheValidators,
}

impl Conditional {
    fn for_kind(&self, kind: VerbatimKind) -> CacheValidators {
        if self.owner == Some(kind) {
            self.validators.clone()
        } else {
            CacheValidators::default()
        }
    }
}

/// A drifted tree voids the fast-path hints, never the Date floor.
fn effective_prior(prior: &SuiteState, disk_ok: bool) -> SuiteState {
    if disk_ok {
        return prior.clone();
    }
    SuiteState {
        date_raw: prior.date_raw.clone(),
        ..SuiteState::default()
    }
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
    #[error("{url}: body exceeds the {limit}-byte cap for suite metadata")]
    MetadataTooLarge { url: url::Url, limit: usize },
    #[error(
        "suite `{suite}`: the published tree is signed but upstream now serves no signature — refusing the verify.pgp = if-present downgrade (possible signature stripping)"
    )]
    PgpDowngrade { suite: String },
    #[error(
        "suite `{suite}`: upstream InRelease is not clearsigned although verify.pgp is on — refusing it (apt rejects an unsigned InRelease)"
    )]
    UnsignedInRelease { suite: String },
    #[error(
        "{index}: {count} entr{plural} carry only MD5/SHA-1 digests (e.g. {examples}) — they would stay listed in the published index but be missing from pool; set verify.allow_weak_hash = true to mirror them",
        plural = if *count == 1 { "y" } else { "ies" }
    )]
    WeakDigestOnlyEntries {
        index: String,
        count: usize,
        examples: String,
    },
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
    /// An index names a pool file where verified metadata lives.
    #[error("index entry {path:?} would overwrite {reason} — refusing to sync this suite")]
    PoolPathConflict { path: String, reason: &'static str },
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
    #[error(
        "suite `{suite}`: incoming Release has no Date but `{prior}` is already published — refusing to drop the Date floor"
    )]
    DateMissing { suite: String, prior: String },
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
