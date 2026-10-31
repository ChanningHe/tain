//! The pool phase of a round: plan where each wanted file comes from,
//! download what is missing, record it in the manifest, and move
//! verified same-path replacements into place right before the swap.

use std::path::{Path, PathBuf};

use tracing::warn;

use crate::core::store::manifest::{GenerationManifest, ManifestEntry};
use crate::core::types::{DigestAlgo, FileSpec};

use super::hex::hex_of_digest_algo;
use super::pool_download::{download_pool_file, is_already_present};
use super::round::{OwnedKeys, SuiteRun};
use super::{AptFlowError, suite_dir_prefix};

/// Mirror-root-relative area holding verified replacements for pool files
/// whose upstream content changed at the same path, laid out like the
/// mirror. Suites run one at a time, so one area serves them all; it must
/// share a filesystem with `pool/` for the final rename.
pub(crate) const PENDING_DIR: &str = ".tain/pending";

/// Where one wanted pool file comes from this round.
pub(super) enum PoolAction {
    /// Already at its final path with the expected content.
    Reuse { size: u64 },
    /// Fetch to `target`: the final path, staging, or the pending area.
    Download { target: PathBuf },
}

pub(super) struct PoolJob<'s> {
    pub(super) spec: &'s FileSpec,
    pub(super) action: PoolAction,
}

/// A pool file in place (final path, staging or pending) and its size.
pub(super) struct Fetched<'s> {
    pub(super) spec: &'s FileSpec,
    pub(super) size: u64,
}

impl SuiteRun<'_> {
    /// Plan, download and record the wanted pool set. A leftover pending
    /// area from an abandoned round or run is dropped first, so only this
    /// round's verified replacements can be committed.
    pub(super) async fn fetch_pool(
        &self,
        pool_specs: &[FileSpec],
        manifest: &mut GenerationManifest,
        owned: &mut OwnedKeys,
    ) -> Result<(), AptFlowError> {
        let pending = self.pending_dir();
        if let Err(e) = std::fs::remove_dir_all(&pending)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(AptFlowError::Io {
                path: pending,
                source: e,
            });
        }
        let jobs = self.plan_pool(pool_specs).await?;
        let fetched = self.run_downloads(jobs).await?;
        self.record(&fetched, manifest, owned);
        Ok(())
    }

    /// Decide where each wanted file comes from.
    ///
    /// - Under the suite dir (Proxmox, Tailscale, ...): into staging, since
    ///   at the final path the swap would move it into prev/ and clients
    ///   would 404.
    /// - New `pool/**` path: straight to the final path (pool-first: no
    ///   published index references it yet).
    /// - Existing path with other content: into the pending area, moved
    ///   into place by [`Self::commit_pending`] right before the swap. Until
    ///   then the published index and the bytes at that path still agree,
    ///   whatever happens to the rest of the round.
    async fn plan_pool<'s>(
        &self,
        pool_specs: &'s [FileSpec],
    ) -> Result<Vec<PoolJob<'s>>, AptFlowError> {
        let suite_prefix = suite_dir_prefix(&self.layout, self.suite);
        let mut jobs = Vec::with_capacity(pool_specs.len());
        for spec in pool_specs {
            let rel = spec.rel_path.as_str();
            let action =
                if let Some(suffix) = suite_prefix.as_deref().and_then(|p| rel.strip_prefix(p)) {
                    PoolAction::Download {
                        target: self.staging.join(suffix),
                    }
                } else {
                    self.plan_pool_path(spec).await?
                };
            jobs.push(PoolJob { spec, action });
        }
        Ok(jobs)
    }

    async fn plan_pool_path(&self, spec: &FileSpec) -> Result<PoolAction, AptFlowError> {
        let rel = spec.rel_path.as_str();
        let final_local = self.mirror_root.join(rel);
        match tokio::fs::symlink_metadata(&final_local).await {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PoolAction::Download {
                    target: final_local,
                });
            }
            Err(e) => {
                return Err(AptFlowError::Io {
                    path: final_local,
                    source: e,
                });
            }
            Ok(_) => {}
        }
        if is_already_present(&final_local, spec.size, &spec.digests).await? {
            let size = match spec.size {
                Some(size) => size,
                None => file_len(&final_local).await?,
            };
            return Ok(PoolAction::Reuse { size });
        }
        // Known limitation: without a SHA256 the presence check cannot tell
        // a changed file from an unchanged one, so every such file would be
        // re-fetched through pending (twice the disk). These entries are
        // still overwritten in place, and a later failure in the round can
        // leave the published index disagreeing with them until the next
        // success. Route them through pending once the presence check
        // compares the strongest available digest.
        if spec.digests.get(DigestAlgo::Sha256).is_none() {
            return Ok(PoolAction::Download {
                target: final_local,
            });
        }
        Ok(PoolAction::Download {
            target: self.pending_dir().join(rel),
        })
    }

    /// Fetch every `Download` job; fail-fast on the first error.
    async fn run_downloads<'s>(
        &self,
        jobs: Vec<PoolJob<'s>>,
    ) -> Result<Vec<Fetched<'s>>, AptFlowError> {
        let mut fetched = Vec::with_capacity(jobs.len());
        for PoolJob { spec, action } in jobs {
            let size = match action {
                PoolAction::Reuse { size } => size,
                PoolAction::Download { target } => {
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
                    file_len(&target).await?
                }
            };
            fetched.push(Fetched { spec, size });
        }
        Ok(fetched)
    }

    /// Record the round's pool files with the size actually on disk: the
    /// index may omit it (d-i `SHA256SUMS`), and `tain verify` checks it.
    fn record(
        &self,
        fetched: &[Fetched<'_>],
        manifest: &mut GenerationManifest,
        owned: &mut OwnedKeys,
    ) {
        for f in fetched {
            owned.insert(manifest, pool_entry(f.spec, f.size));
        }
    }

    fn pending_dir(&self) -> PathBuf {
        self.mirror_root.join(PENDING_DIR)
    }

    /// Move this round's verified replacements to their pool paths. Called
    /// after the recheck and right before the swap: between the two, clients
    /// may see new bytes under the old index. A crash there self-heals, as
    /// the next round finds the new content already in place; if a rename
    /// or the swap itself fails, the moved files keep their new bytes until
    /// the suite next publishes.
    pub(super) fn commit_pending(&self) -> Result<(), AptFlowError> {
        let pending = self.pending_dir();
        for path in walk_files(&pending)? {
            let Ok(rel) = path.strip_prefix(&pending) else {
                continue;
            };
            let dest = self.mirror_root.join(rel);
            std::fs::rename(&path, &dest).map_err(|e| AptFlowError::Io {
                path: dest,
                source: e,
            })?;
        }
        Ok(())
    }

    /// Best-effort drop of fetched replacements a refold or failure
    /// abandoned; the next round or run clears whatever remains.
    pub(super) fn discard_pending(&self) {
        let pending = self.pending_dir();
        if let Err(e) = std::fs::remove_dir_all(&pending)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %pending.display(), %e, "failed to discard pending pool replacements");
        }
    }
}

fn pool_entry(spec: &FileSpec, size: u64) -> ManifestEntry {
    ManifestEntry {
        rel_path: spec.rel_path.as_str().to_owned(),
        size,
        sha256_hex: hex_of_digest_algo(&spec.digests, DigestAlgo::Sha256),
        sha512_hex: hex_of_digest_algo(&spec.digests, DigestAlgo::Sha512),
    }
}

async fn file_len(path: &Path) -> Result<u64, AptFlowError> {
    tokio::fs::metadata(path)
        .await
        .map(|m| m.len())
        .map_err(|e| AptFlowError::Io {
            path: path.to_path_buf(),
            source: e,
        })
}

/// Regular files under `dir`, recursively; a missing `dir` has none.
fn walk_files(dir: &Path) -> Result<Vec<PathBuf>, AptFlowError> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| AptFlowError::Io { path, source }
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(dir)(e)),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io(dir))?;
        let path = entry.path();
        if entry.file_type().map_err(io(&path))?.is_dir() {
            files.extend(walk_files(&path)?);
        } else {
            files.push(path);
        }
    }
    Ok(files)
}
