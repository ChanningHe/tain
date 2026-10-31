//! Derive the pool wanted set from staged Packages / Sources / SHA256SUMS.
//!
//! Weak-only entries fail the index unless `verify.allow_weak_hash` is set:
//! byte fidelity forbids dropping them from the published index, and
//! skipping their pool files would leave clients with 404s.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::BufReader;
use std::path::Path;

use crate::backends::apt::compression;
use crate::backends::apt::deb822::Deb822Reader;
use crate::backends::apt::index_selector::Compression;
use crate::backends::apt::installer_sums::parse_installer_sums;
use crate::backends::apt::layout::SuiteLayout;
use crate::backends::apt::packages::{PackageParseError, paragraph_to_filespec};
use crate::backends::apt::sources::{SourceParseError, paragraph_to_sourcespecs};
use crate::core::types::{DigestSet, FileSpec};

use super::AptFlowError;

/// OOM guard against a hostile index. Debian's largest suite has ~65k
/// entries, so 5M is ample headroom.
const MAX_FILESPEC_COUNT: usize = 5_000_000;

/// Package names quoted in the weak-digest error.
const WEAK_EXAMPLES: usize = 5;

/// Weak-digest-only entries of one index, reported together.
#[derive(Default)]
struct WeakOnly {
    count: usize,
    examples: Vec<String>,
}

impl WeakOnly {
    fn note(&mut self, name: String) {
        self.count += 1;
        if self.examples.len() < WEAK_EXAMPLES {
            self.examples.push(name);
        }
    }

    fn into_result(self, index: &str) -> Result<(), AptFlowError> {
        if self.count == 0 {
            return Ok(());
        }
        let more = if self.count > self.examples.len() {
            ", ..."
        } else {
            ""
        };
        Err(AptFlowError::WeakDigestOnlyEntries {
            index: index.to_owned(),
            count: self.count,
            examples: format!("{}{more}", self.examples.join(", ")),
        })
    }
}

/// `index` names the Release-relative index in errors.
pub(super) fn parse_sources_into(
    path: &Path,
    index: &str,
    compression: Compression,
    layout: &SuiteLayout<'_>,
    allow_weak: bool,
    out: &mut Vec<FileSpec>,
) -> Result<(), AptFlowError> {
    let reader = compression::open_with(path, compression).map_err(|e| AptFlowError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut deb = Deb822Reader::new(BufReader::new(reader));
    let mut weak = WeakOnly::default();
    while let Some(p) = deb.read_paragraph().map_err(AptFlowError::from)? {
        match paragraph_to_sourcespecs(&p, layout, allow_weak) {
            Ok(specs) => {
                if out.len().saturating_add(specs.len()) > MAX_FILESPEC_COUNT {
                    return Err(AptFlowError::TooManyPoolEntries {
                        limit: MAX_FILESPEC_COUNT,
                    });
                }
                out.extend(specs);
            }
            Err(SourceParseError::WeakDigestOnly { package, filename }) => {
                weak.note(format!("{package} ({filename})"));
            }
            Err(e) => return Err(AptFlowError::Source(e)),
        }
    }
    weak.into_result(index)
}

/// Parse a staged d-i `SHA256SUMS`; listed files are relative to
/// `base_path`, the suite-relative directory holding it.
pub(super) fn parse_installer_sums_into(
    path: &Path,
    base_path: &str,
    layout: &SuiteLayout<'_>,
    out: &mut Vec<FileSpec>,
) -> Result<(), AptFlowError> {
    let bytes = std::fs::read(path).map_err(|e| AptFlowError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|e| AptFlowError::Utf8 {
        what: "SHA256SUMS",
        msg: e.to_string(),
    })?;
    let specs = parse_installer_sums(text, base_path, layout)?;
    if out.len().saturating_add(specs.len()) > MAX_FILESPEC_COUNT {
        return Err(AptFlowError::TooManyPoolEntries {
            limit: MAX_FILESPEC_COUNT,
        });
    }
    out.extend(specs);
    Ok(())
}

/// `index` names the Release-relative index in errors.
pub(super) fn parse_packages_into(
    path: &Path,
    index: &str,
    compression: Compression,
    layout: &SuiteLayout<'_>,
    allow_weak: bool,
    out: &mut Vec<FileSpec>,
) -> Result<(), AptFlowError> {
    let reader = compression::open_with(path, compression).map_err(|e| AptFlowError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut deb = Deb822Reader::new(BufReader::new(reader));
    let mut weak = WeakOnly::default();
    while let Some(p) = deb.read_paragraph().map_err(AptFlowError::from)? {
        match paragraph_to_filespec(&p, layout, allow_weak) {
            Ok(spec) => {
                if out.len() >= MAX_FILESPEC_COUNT {
                    return Err(AptFlowError::TooManyPoolEntries {
                        limit: MAX_FILESPEC_COUNT,
                    });
                }
                out.push(spec);
            }
            Err(PackageParseError::WeakDigestOnly { package }) => weak.note(package),
            Err(e) => return Err(AptFlowError::Package(e)),
        }
    }
    weak.into_result(index)
}

/// Collapse the wanted list to one spec per `rel_path` (an `arch: all`
/// file appears in every architecture's Packages). `origins` names the
/// index behind each run of `specs`: `(end, index)` covers every spec
/// before `end` not covered by an earlier pair.
///
/// Entries for one path must agree on size and on every digest they share;
/// their digests are merged. Disagreement means the suite contradicts
/// itself, and no choice of bytes would satisfy both indexes.
pub(super) fn dedupe_by_path(
    specs: Vec<FileSpec>,
    origins: &[(usize, String)],
) -> Result<Vec<FileSpec>, AptFlowError> {
    let mut by_path: BTreeMap<String, (FileSpec, usize)> = BTreeMap::new();
    let mut origin = 0;
    for (i, spec) in specs.into_iter().enumerate() {
        while origins.get(origin).is_some_and(|(end, _)| *end <= i) {
            origin += 1;
        }
        match by_path.entry(spec.rel_path.as_str().to_owned()) {
            Entry::Vacant(slot) => {
                slot.insert((spec, origin));
            }
            Entry::Occupied(mut slot) => {
                let (kept, first) = slot.get_mut();
                if let Err(detail) = merge_spec(kept, &spec) {
                    let name = |o: usize| origins.get(o).map(|(_, n)| n.clone());
                    return Err(AptFlowError::PoolEntryConflict {
                        path: spec.rel_path.as_str().to_owned(),
                        first: name(*first).unwrap_or_default(),
                        second: name(origin).unwrap_or_default(),
                        detail,
                    });
                }
            }
        }
    }
    Ok(by_path.into_values().map(|(spec, _)| spec).collect())
}

fn algos(set: &DigestSet) -> Vec<u8> {
    let mut out: Vec<u8> = set.iter().map(|d| d.algo.strength()).collect();
    out.sort_unstable();
    out
}

/// Fold `other`'s size and digests into `kept`; `Err` describes the clash.
fn merge_spec(kept: &mut FileSpec, other: &FileSpec) -> Result<(), String> {
    // Agreement on a shared digest proves both entries name the same bytes
    // only if that digest is the best one the weaker entry offers: disjoint
    // sets (SHA256 here, SHA512 there) may describe different files, and
    // later checks verify only part of a merged set. A weak floor must
    // cover everything: reuse checks only SHA256, so a weak-only entry
    // merged into a stronger one would never have its digest checked.
    let floor = match (kept.digests.strongest(), other.digests.strongest()) {
        (Some(a), Some(b)) if a.algo.strength() <= b.algo.strength() => a.algo,
        (Some(_), Some(b)) => b.algo,
        _ => return Err("missing digests".to_owned()),
    };
    if kept.digests.get(floor).is_none() || other.digests.get(floor).is_none() {
        return Err(format!("digests: no common {floor:?} digest"));
    }
    if floor.is_weak() && algos(&kept.digests) != algos(&other.digests) {
        return Err(format!("digests: only a weak {floor:?} digest in common"));
    }
    match (kept.size, other.size) {
        (Some(a), Some(b)) if a != b => return Err(format!("size {a} vs {b}")),
        (None, Some(b)) => kept.size = Some(b),
        _ => {}
    }
    for digest in other.digests.iter() {
        kept.digests
            .push(digest.clone())
            .map_err(|e| format!("{:?} digest {} vs {}", e.algo, e.existing, e.incoming))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Digest, DigestAlgo, Layer, RelPath};

    fn spec(path: &str, size: Option<u64>, digests: &[(DigestAlgo, u8)]) -> FileSpec {
        let mut set = DigestSet::new();
        for (algo, fill) in digests {
            let len = match algo {
                DigestAlgo::Md5 => 16,
                DigestAlgo::Sha1 => 20,
                DigestAlgo::Sha256 => 32,
                DigestAlgo::Sha512 => 64,
            };
            set.push(Digest::new(*algo, vec![*fill; len]).unwrap())
                .unwrap();
        }
        FileSpec {
            rel_path: RelPath::new(path).unwrap(),
            digests: set,
            size,
            url: url::Url::parse("http://up.example/")
                .unwrap()
                .join(path)
                .unwrap(),
            layer: Layer::Content,
            immutable: true,
        }
    }

    fn origins() -> Vec<(usize, String)> {
        vec![(1, "amd64/Packages".into()), (2, "arm64/Packages".into())]
    }

    #[test]
    fn identical_entries_from_two_indexes_collapse_to_one() {
        let a = spec("pool/a.deb", Some(4), &[(DigestAlgo::Sha256, 1)]);
        let out = dedupe_by_path(vec![a.clone(), a.clone()], &origins()).unwrap();
        assert_eq!(out, vec![a]);
    }

    #[test]
    fn merged_entry_keeps_every_digest_and_the_known_size() {
        let a = spec("pool/a.deb", None, &[(DigestAlgo::Sha256, 1)]);
        let b = spec(
            "pool/a.deb",
            Some(4),
            &[(DigestAlgo::Sha256, 1), (DigestAlgo::Sha512, 2)],
        );
        let out = dedupe_by_path(vec![a, b], &origins()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].size, Some(4));
        assert!(out[0].digests.get(DigestAlgo::Sha256).is_some());
        assert!(out[0].digests.get(DigestAlgo::Sha512).is_some());
    }

    #[test]
    fn disjoint_strong_digests_are_a_conflict() {
        let a = spec("pool/a.deb", Some(4), &[(DigestAlgo::Sha256, 1)]);
        let b = spec("pool/a.deb", Some(4), &[(DigestAlgo::Sha512, 2)]);
        let err = dedupe_by_path(vec![a, b], &origins()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no common Sha256 digest"), "{msg}");
        assert!(
            msg.contains("amd64/Packages") && msg.contains("arm64/Packages"),
            "{msg}"
        );
    }

    #[test]
    fn strong_entry_without_the_weak_entrys_digest_is_a_conflict() {
        let a = spec("pool/a.deb", Some(4), &[(DigestAlgo::Sha256, 1)]);
        let b = spec("pool/a.deb", Some(4), &[(DigestAlgo::Md5, 1)]);
        let err = dedupe_by_path(vec![a, b], &origins()).unwrap_err();
        assert!(err.to_string().contains("no common Md5 digest"), "{err}");
    }

    #[test]
    fn weak_only_entries_with_the_same_digests_merge() {
        let a = spec("pool/a.deb", Some(4), &[(DigestAlgo::Md5, 3)]);
        let out = dedupe_by_path(vec![a.clone(), a.clone()], &origins()).unwrap();
        assert_eq!(out, vec![a]);
    }

    #[test]
    fn weak_only_entry_does_not_merge_into_a_stronger_one() {
        let a = spec(
            "pool/a.deb",
            Some(4),
            &[(DigestAlgo::Sha256, 1), (DigestAlgo::Md5, 3)],
        );
        let b = spec("pool/a.deb", Some(4), &[(DigestAlgo::Md5, 3)]);
        let err = dedupe_by_path(vec![a, b], &origins()).unwrap_err();
        assert!(
            err.to_string().contains("only a weak Md5 digest in common"),
            "{err}"
        );
    }

    #[test]
    fn output_is_sorted_by_path() {
        let b = spec("pool/b.deb", Some(1), &[(DigestAlgo::Sha256, 1)]);
        let a = spec("pool/a.deb", Some(1), &[(DigestAlgo::Sha256, 2)]);
        let out = dedupe_by_path(vec![b, a], &origins()).unwrap();
        let paths: Vec<&str> = out.iter().map(|s| s.rel_path.as_str()).collect();
        assert_eq!(paths, ["pool/a.deb", "pool/b.deb"]);
    }

    #[test]
    fn differing_digest_names_both_indexes() {
        let a = spec("pool/a.deb", Some(4), &[(DigestAlgo::Sha256, 1)]);
        let b = spec("pool/a.deb", Some(4), &[(DigestAlgo::Sha256, 2)]);
        let err = dedupe_by_path(vec![a, b], &origins()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pool/a.deb"), "{msg}");
        assert!(msg.contains("amd64/Packages"), "{msg}");
        assert!(msg.contains("arm64/Packages"), "{msg}");
    }

    #[test]
    fn differing_size_is_a_conflict() {
        let a = spec("pool/a.deb", Some(4), &[(DigestAlgo::Sha256, 1)]);
        let b = spec("pool/a.deb", Some(5), &[(DigestAlgo::Sha256, 1)]);
        let err = dedupe_by_path(vec![a, b], &origins()).unwrap_err();
        assert!(err.to_string().contains("size 4 vs 5"), "{err}");
    }

    #[test]
    fn conflict_inside_one_index_names_it_twice() {
        let a = spec("pool/a.deb", Some(4), &[(DigestAlgo::Sha256, 1)]);
        let b = spec("pool/a.deb", Some(4), &[(DigestAlgo::Sha256, 2)]);
        let err = dedupe_by_path(vec![a, b], &[(2, "main/Packages".into())]).unwrap_err();
        let AptFlowError::PoolEntryConflict { first, second, .. } = err else {
            panic!("{err}");
        };
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("main/Packages", "main/Packages")
        );
    }

    #[test]
    fn weak_only_report_lists_a_bounded_sample() {
        let mut weak = WeakOnly::default();
        for i in 0..7 {
            weak.note(format!("pkg{i}"));
        }
        let err = weak.into_result("main/binary-amd64/Packages").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("7 entries"), "{msg}");
        assert!(msg.contains("pkg4, ..."), "{msg}");
        assert!(!msg.contains("pkg5"), "{msg}");
        assert!(msg.contains("allow_weak_hash"), "{msg}");
    }

    #[test]
    fn weak_only_examples_are_escaped_and_bounded() {
        let path = std::env::temp_dir().join(format!(
            "tain-weak-examples-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        ));
        let name = format!("\x1b[31mevil{}", "x".repeat(1024 * 1024));
        let packages = (0..7)
            .map(|_| {
                format!(
                    "Package: {name}\nFilename: pool/e.deb\nSize: 1\nMD5sum: {}\n\n",
                    "3".repeat(32)
                )
            })
            .collect::<String>();
        std::fs::write(&path, packages).unwrap();
        let base = url::Url::parse("https://deb.example.org/debian").unwrap();
        let layout = SuiteLayout::new(&base, "bookworm");

        let err = parse_packages_into(
            &path,
            "main/binary-amd64/Packages",
            Compression::None,
            &layout,
            false,
            &mut Vec::new(),
        )
        .unwrap_err();
        let _ = std::fs::remove_file(&path);

        let msg = err.to_string();
        assert!(msg.contains("7 entries"), "{msg}");
        assert!(!msg.contains('\x1b'), "{msg}");
        assert!(msg.contains("\\u{1b}[31mevil"), "{msg}");
        assert!(msg.len() < 4096, "{} bytes", msg.len());
    }

    #[test]
    fn no_weak_entries_is_ok() {
        assert!(WeakOnly::default().into_result("x").is_ok());
    }
}
