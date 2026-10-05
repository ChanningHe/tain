//! Derive the pool wanted set from staged Packages / Sources / SHA256SUMS.
//!
//! Weak-only entries are dropped unless `verify.allow_weak_hash` is set.

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

pub(super) fn parse_sources_into(
    path: &Path,
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
            Err(SourceParseError::WeakDigestOnly { .. }) if !allow_weak => {
                // Dropped by weak-hash policy.
            }
            Err(e) => return Err(AptFlowError::Source(e)),
        }
    }
    Ok(())
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

pub(super) fn parse_packages_into(
    path: &Path,
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
            Err(PackageParseError::WeakDigestOnly { .. }) if !allow_weak => {
                // Dropped by weak-hash policy.
            }
            Err(e) => return Err(AptFlowError::Package(e)),
        }
    }
    Ok(())
}
