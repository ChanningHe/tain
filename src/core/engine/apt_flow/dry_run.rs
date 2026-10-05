//! Dry-run planner output and text renderer.
//!
//! Parseable indexes (Packages/Sources/SHA256SUMS) are downloaded to staging
//! so the pool set is real; Verbatim indexes are only listed. Nothing is
//! published or saved, and staging is wiped afterwards.

use std::fmt::Write as _;

use super::pool_download::is_already_present;
use crate::core::types::{DigestAlgo, FileSpec};

use super::AptFlowError;
use super::hex::hex_of_digest_algo;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DryRunReport {
    pub mirror: String,
    pub suites: Vec<SuiteDryRun>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteDryRun {
    pub suite: String,
    pub verdict: SuiteVerdict,
    /// Verbatim index `base_path`s, one per group (not per compression
    /// variant); sorted, deduped.
    pub indexes_would_download: Vec<String>,
    pub pool_would_download: Vec<PoolPlan>,
    pub pool_already_present: usize,
    /// Sum of known sizes; entries without a size count as 0.
    pub bytes_estimate: u64,
    pub gc_candidates: Option<GcPreview>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteVerdict {
    /// No prior state.
    Fresh,
    /// 304 or byte-identical signed body.
    Unchanged,
    Incremental,
    UpstreamRefreshed,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolPlan {
    pub rel_path: String,
    pub size: Option<u64>,
    pub sha256_hex: Option<String>,
}

/// GC preview numbers carried into the same report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcPreview {
    pub candidates: usize,
    pub candidate_bytes: u64,
    pub circuit_broken: bool,
}

impl DryRunReport {
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "dry-run report: mirror `{}`", self.mirror);
        if self.suites.is_empty() {
            let _ = writeln!(out, "  (no suites)");
            return out;
        }
        for suite in &self.suites {
            suite.write_into(&mut out);
        }
        out
    }
}

impl SuiteDryRun {
    fn write_into(&self, out: &mut String) {
        let _ = writeln!(out, "  suite `{}`: {}", self.suite, self.verdict);
        if matches!(
            self.verdict,
            SuiteVerdict::Unchanged | SuiteVerdict::Failed(_) | SuiteVerdict::UpstreamRefreshed
        ) && self.pool_would_download.is_empty()
            && self.indexes_would_download.is_empty()
        {
            return;
        }
        let _ = writeln!(
            out,
            "    indexes to download: {}",
            self.indexes_would_download.len()
        );
        let _ = writeln!(
            out,
            "    pool files: {} to download, {} already present",
            self.pool_would_download.len(),
            self.pool_already_present,
        );
        let _ = writeln!(
            out,
            "    estimated bytes: {}",
            format_bytes(self.bytes_estimate)
        );
        const TOP: usize = 10;
        for plan in self.pool_would_download.iter().take(TOP) {
            let _ = writeln!(out, "      + {}", plan.rel_path);
        }
        if self.pool_would_download.len() > TOP {
            let _ = writeln!(
                out,
                "      ... ({} more)",
                self.pool_would_download.len() - TOP
            );
        }
        if let Some(gc) = &self.gc_candidates {
            let _ = writeln!(
                out,
                "    gc: {} candidates ({}){}",
                gc.candidates,
                format_bytes(gc.candidate_bytes),
                if gc.circuit_broken {
                    " [circuit broken]"
                } else {
                    ""
                },
            );
        }
    }
}

impl std::fmt::Display for SuiteVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fresh => f.write_str("fresh"),
            Self::Unchanged => f.write_str("unchanged"),
            Self::Incremental => f.write_str("incremental"),
            Self::UpstreamRefreshed => f.write_str("upstream refreshed mid-sync"),
            Self::Failed(msg) => write!(f, "failed: {msg}"),
        }
    }
}

/// Split the wanted pool set into `(would_download, already_present,
/// bytes_estimate)`; `would_download` is sorted by `rel_path`.
///
/// # Errors
///
/// I/O error probing a pool file.
pub(super) async fn classify_pool(
    mirror_root: &std::path::Path,
    pool_specs: &[FileSpec],
) -> Result<(Vec<PoolPlan>, usize, u64), AptFlowError> {
    let mut plans: Vec<PoolPlan> = Vec::new();
    let mut already = 0usize;
    let mut bytes = 0u64;
    for spec in pool_specs {
        let local = mirror_root.join(spec.rel_path.as_str());
        if is_already_present(&local, spec.size, &spec.digests).await? {
            already += 1;
            continue;
        }
        let sha256 = hex_of_digest_algo(&spec.digests, DigestAlgo::Sha256);
        bytes = bytes.saturating_add(spec.size.unwrap_or(0));
        plans.push(PoolPlan {
            rel_path: spec.rel_path.as_str().to_owned(),
            size: spec.size,
            sha256_hex: sha256,
        });
    }
    plans.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    plans.dedup_by(|a, b| a.rel_path == b.rel_path);
    Ok((plans, already, bytes))
}

/// Sorted, deduped `base_path`s of Verbatim / LegacyRelease groups.
pub(super) fn collect_verbatim_indexes<'a>(
    groups: impl IntoIterator<Item = &'a crate::backends::apt::index_selector::IndexGroup<'a>>,
) -> Vec<String> {
    use crate::backends::apt::index_selector::IndexRole;
    let mut paths: Vec<String> = groups
        .into_iter()
        .filter(|g| matches!(g.role, IndexRole::Verbatim | IndexRole::LegacyRelease))
        .map(|g| g.base_path.clone())
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

fn format_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;
    if n >= TIB {
        format!("{:.2} TiB", n as f64 / TIB as f64)
    } else if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_display_forms_frozen() {
        assert_eq!(SuiteVerdict::Fresh.to_string(), "fresh");
        assert_eq!(SuiteVerdict::Unchanged.to_string(), "unchanged");
        assert_eq!(SuiteVerdict::Incremental.to_string(), "incremental");
        assert_eq!(
            SuiteVerdict::UpstreamRefreshed.to_string(),
            "upstream refreshed mid-sync"
        );
        assert_eq!(
            SuiteVerdict::Failed("parse blew up".into()).to_string(),
            "failed: parse blew up"
        );
    }

    #[test]
    fn format_bytes_thresholds() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.00 GiB");
    }

    #[test]
    fn pool_plan_sorted_by_rel_path() {
        let mut plans = [
            PoolPlan {
                rel_path: "pool/main/b/beta/beta.deb".to_owned(),
                size: None,
                sha256_hex: None,
            },
            PoolPlan {
                rel_path: "pool/main/a/alpha/alpha.deb".to_owned(),
                size: None,
                sha256_hex: None,
            },
        ];
        plans.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        assert_eq!(plans[0].rel_path, "pool/main/a/alpha/alpha.deb");
        assert_eq!(plans[1].rel_path, "pool/main/b/beta/beta.deb");
    }

    #[test]
    fn empty_report_text_frozen() {
        let r = DryRunReport {
            mirror: "debian".into(),
            suites: vec![],
        };
        assert_eq!(r.text(), "dry-run report: mirror `debian`\n  (no suites)\n");
    }

    #[test]
    fn unchanged_suite_text_is_compact() {
        let r = DryRunReport {
            mirror: "debian".into(),
            suites: vec![SuiteDryRun {
                suite: "bookworm".into(),
                verdict: SuiteVerdict::Unchanged,
                indexes_would_download: vec![],
                pool_would_download: vec![],
                pool_already_present: 0,
                bytes_estimate: 0,
                gc_candidates: None,
            }],
        };
        assert_eq!(
            r.text(),
            "dry-run report: mirror `debian`\n  suite `bookworm`: unchanged\n"
        );
    }

    #[test]
    fn fresh_suite_text_lists_counts_and_top_paths() {
        let plans = (0..12)
            .map(|i| PoolPlan {
                rel_path: format!("pool/main/a/alpha/alpha_{i:02}.deb"),
                size: Some(1024),
                sha256_hex: None,
            })
            .collect::<Vec<_>>();
        let r = DryRunReport {
            mirror: "debian".into(),
            suites: vec![SuiteDryRun {
                suite: "bookworm".into(),
                verdict: SuiteVerdict::Fresh,
                indexes_would_download: vec![
                    "main/Contents-amd64.gz".into(),
                    "main/i18n/Translation-en.gz".into(),
                ],
                pool_would_download: plans,
                pool_already_present: 3,
                bytes_estimate: 12 * 1024,
                gc_candidates: None,
            }],
        };
        let text = r.text();
        assert!(text.contains("suite `bookworm`: fresh"));
        assert!(text.contains("indexes to download: 2"));
        assert!(text.contains("pool files: 12 to download, 3 already present"));
        assert!(text.contains("estimated bytes: 12.00 KiB"));
        assert!(text.contains("+ pool/main/a/alpha/alpha_00.deb"));
        assert!(text.contains("+ pool/main/a/alpha/alpha_09.deb"));
        assert!(text.contains("... (2 more)"));
        assert!(!text.contains("+ pool/main/a/alpha/alpha_10.deb"));
    }

    #[test]
    fn failed_verdict_text_includes_reason() {
        let r = DryRunReport {
            mirror: "debian".into(),
            suites: vec![SuiteDryRun {
                suite: "bookworm".into(),
                verdict: SuiteVerdict::Failed("HTTP 404 for .../InRelease".into()),
                indexes_would_download: vec![],
                pool_would_download: vec![],
                pool_already_present: 0,
                bytes_estimate: 0,
                gc_candidates: None,
            }],
        };
        assert!(r.text().contains("failed: HTTP 404 for .../InRelease"));
    }

    #[test]
    fn gc_preview_line_included_when_set() {
        let r = DryRunReport {
            mirror: "debian".into(),
            suites: vec![SuiteDryRun {
                suite: "bookworm".into(),
                verdict: SuiteVerdict::Fresh,
                indexes_would_download: vec![],
                pool_would_download: vec![PoolPlan {
                    rel_path: "pool/main/x/x/x.deb".into(),
                    size: Some(10),
                    sha256_hex: None,
                }],
                pool_already_present: 0,
                bytes_estimate: 10,
                gc_candidates: Some(GcPreview {
                    candidates: 4,
                    candidate_bytes: 2048,
                    circuit_broken: false,
                }),
            }],
        };
        let text = r.text();
        assert!(text.contains("gc: 4 candidates (2.00 KiB)"));
        assert!(!text.contains("circuit broken"));
    }
}
