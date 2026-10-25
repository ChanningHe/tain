//! Derive the pool wanted set from staged Packages / Sources / SHA256SUMS.
//!
//! Weak-only entries fail the index unless `verify.allow_weak_hash` is set:
//! byte fidelity forbids dropping them from the published index, and
//! skipping their pool files would leave clients with 404s.

use std::io::BufReader;
use std::path::Path;

use crate::backends::apt::compression;
use crate::backends::apt::deb822::Deb822Reader;
use crate::backends::apt::index_selector::Compression;
use crate::backends::apt::installer_sums::parse_installer_sums;
use crate::backends::apt::layout::SuiteLayout;
use crate::backends::apt::packages::{PackageParseError, paragraph_to_filespec};
use crate::backends::apt::sources::{SourceParseError, paragraph_to_sourcespecs};
use crate::core::types::FileSpec;

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn no_weak_entries_is_ok() {
        assert!(WeakOnly::default().into_result("x").is_ok());
    }
}
