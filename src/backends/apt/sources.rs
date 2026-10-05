//! `Sources` paragraph → source pool `FileSpec`s (`.dsc`, `.orig.tar.*`, `.debian.tar.*`, …)
//! under `<Directory>/`. `Checksums-Sha256` is mandatory per the repository format; the
//! MD5 `Files:` block counts only when weak hashes are allowed.

use crate::core::types::{
    Digest, DigestAlgo, DigestError, DigestSet, DuplicateDigest, FileSpec, Layer,
};

use super::checksums::decode_hex;
use super::deb822::Paragraph;
use super::layout::{LayoutError, SuiteLayout};

/// Convert one `Sources` paragraph into every source pool `FileSpec` it references.
///
/// `allow_weak_hash` admits files listed only in the MD5 `Files:` block.
///
/// # Errors
///
/// Each field problem surfaces as a `SourceParseError`.
pub fn paragraph_to_sourcespecs(
    paragraph: &Paragraph,
    layout: &SuiteLayout<'_>,
    allow_weak_hash: bool,
) -> Result<Vec<FileSpec>, SourceParseError> {
    let package = required_str(paragraph, "Package")?;
    let directory = required_str(paragraph, "Directory")?;
    let mut table = FileTable::default();
    if let Some(v) = paragraph.get("Checksums-Sha256") {
        parse_block(v, DigestAlgo::Sha256, package, &mut table)?;
    }
    if let Some(v) = paragraph.get("Checksums-Sha512") {
        parse_block(v, DigestAlgo::Sha512, package, &mut table)?;
    }
    if let Some(v) = paragraph.get("Checksums-Sha1") {
        parse_block(v, DigestAlgo::Sha1, package, &mut table)?;
    }
    if let Some(v) = paragraph.get("Files") {
        parse_block(v, DigestAlgo::Md5, package, &mut table)?;
    }

    if table.is_empty() {
        return Err(SourceParseError::MissingChecksums {
            package: package.to_owned(),
        });
    }

    let mut out = Vec::with_capacity(table.rows.len());
    for row in table.rows {
        if row.digests.is_empty() {
            return Err(SourceParseError::NoDigest {
                package: package.to_owned(),
                filename: row.filename,
            });
        }
        if !allow_weak_hash && row.digests.all_weak() {
            return Err(SourceParseError::WeakDigestOnly {
                package: package.to_owned(),
                filename: row.filename,
            });
        }
        let joined = format!("{}/{}", directory.trim_end_matches('/'), row.filename);
        let rel_path = layout
            .root_rel(&joined)
            .map_err(|e| SourceParseError::UnsafeFilename {
                package: package.to_owned(),
                path: joined.clone(),
                reason: e.to_string(),
            })?;
        let url =
            layout
                .root_url(&joined)
                .map_err(|e: LayoutError| SourceParseError::UrlBuild {
                    package: package.to_owned(),
                    path: joined.clone(),
                    reason: e.to_string(),
                })?;
        out.push(FileSpec {
            rel_path,
            digests: row.digests,
            size: Some(row.size),
            url,
            layer: Layer::Content,
            immutable: true,
        });
    }
    Ok(out)
}

#[derive(Default)]
struct FileTable {
    rows: Vec<Row>,
}

struct Row {
    filename: String,
    size: u64,
    digests: DigestSet,
}

impl FileTable {
    fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    fn upsert(
        &mut self,
        filename: &str,
        size: u64,
        digest: Digest,
        package: &str,
    ) -> Result<(), SourceParseError> {
        for row in self.rows.iter_mut() {
            if row.filename == filename {
                if row.size != size {
                    return Err(SourceParseError::SizeConflict {
                        package: package.to_owned(),
                        filename: filename.to_owned(),
                        previous: row.size,
                        current: size,
                    });
                }
                row.digests
                    .push(digest)
                    .map_err(|dup| SourceParseError::ConflictingDigest {
                        package: package.to_owned(),
                        filename: filename.to_owned(),
                        algo: dup.algo,
                        existing: dup.existing,
                        incoming: dup.incoming,
                    })?;
                return Ok(());
            }
        }
        let mut digests = DigestSet::new();
        digests
            .push(digest)
            .map_err(|dup| SourceParseError::ConflictingDigest {
                package: package.to_owned(),
                filename: filename.to_owned(),
                algo: dup.algo,
                existing: dup.existing,
                incoming: dup.incoming,
            })?;
        self.rows.push(Row {
            filename: filename.to_owned(),
            size,
            digests,
        });
        Ok(())
    }
}

fn parse_block(
    value: &str,
    algo: DigestAlgo,
    package: &str,
    table: &mut FileTable,
) -> Result<(), SourceParseError> {
    for raw in value.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut iter = line.split_whitespace();
        let hex = iter.next().unwrap_or("");
        let size_str = iter.next().unwrap_or("");
        let filename = iter.next().unwrap_or("");
        if hex.is_empty() || size_str.is_empty() || filename.is_empty() {
            return Err(SourceParseError::MalformedLine {
                package: package.to_owned(),
                snippet: line.to_owned(),
            });
        }
        if iter.next().is_some() {
            return Err(SourceParseError::MalformedLine {
                package: package.to_owned(),
                snippet: line.to_owned(),
            });
        }
        let size: u64 = size_str.parse().map_err(|_| SourceParseError::BadSize {
            package: package.to_owned(),
            value: size_str.to_owned(),
        })?;
        validate_filename(filename, package)?;
        let bytes = decode_hex(hex).ok_or_else(|| SourceParseError::BadHex {
            package: package.to_owned(),
            algo,
            hex: hex.to_owned(),
        })?;
        let digest = Digest::new(algo, bytes).map_err(|e| match e {
            DigestError::LengthMismatch { expected, got, .. } => {
                SourceParseError::HexLengthMismatch {
                    package: package.to_owned(),
                    algo,
                    expected,
                    got,
                }
            }
        })?;
        table.upsert(filename, size, digest, package)?;
    }
    Ok(())
}

fn validate_filename(filename: &str, package: &str) -> Result<(), SourceParseError> {
    if filename.contains('/') || filename.contains('\\') {
        return Err(SourceParseError::UnsafeFilename {
            package: package.to_owned(),
            path: filename.to_owned(),
            reason: "filename may not contain path separators".into(),
        });
    }
    if filename == ".." || filename == "." || filename.is_empty() {
        return Err(SourceParseError::UnsafeFilename {
            package: package.to_owned(),
            path: filename.to_owned(),
            reason: "traversal component".into(),
        });
    }
    Ok(())
}

fn required_str<'a>(
    paragraph: &'a Paragraph,
    field: &'static str,
) -> Result<&'a str, SourceParseError> {
    paragraph
        .get(field)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(SourceParseError::MissingField { field })
}

#[derive(Debug, thiserror::Error)]
pub enum SourceParseError {
    #[error("Sources paragraph is missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("Sources paragraph advertises no checksum block (Checksums-Sha256 is mandatory)")]
    MissingChecksums { package: String },
    #[error("package `{package}`: file `{filename}`: no digest recorded")]
    NoDigest { package: String, filename: String },
    #[error("package `{package}`: file `{filename}`: only weak digests (rejected by policy)")]
    WeakDigestOnly { package: String, filename: String },
    #[error("package `{package}`: malformed checksum line `{snippet}`")]
    MalformedLine { package: String, snippet: String },
    #[error("package `{package}`: Size `{value}` is not a valid u64")]
    BadSize { package: String, value: String },
    #[error("package `{package}`: {algo:?} digest `{hex}` is not valid hex")]
    BadHex {
        package: String,
        algo: DigestAlgo,
        hex: String,
    },
    #[error("package `{package}`: {algo:?} digest length mismatch: expected {expected}, got {got}")]
    HexLengthMismatch {
        package: String,
        algo: DigestAlgo,
        expected: usize,
        got: usize,
    },
    #[error("package `{package}`: file `{filename}` size conflicts: {previous} vs {current}")]
    SizeConflict {
        package: String,
        filename: String,
        previous: u64,
        current: u64,
    },
    #[error("package `{package}`: path `{path}` is unsafe ({reason})")]
    UnsafeFilename {
        package: String,
        path: String,
        reason: String,
    },
    #[error("package `{package}`: cannot build URL for `{path}` ({reason})")]
    UrlBuild {
        package: String,
        path: String,
        reason: String,
    },
    #[error(
        "package `{package}`: file `{filename}`: conflicting {algo:?} digest existing {existing} vs incoming {incoming}"
    )]
    ConflictingDigest {
        package: String,
        filename: String,
        algo: DigestAlgo,
        existing: String,
        incoming: String,
    },
}

impl From<DuplicateDigest> for SourceParseError {
    /// For a bare `DigestSet::push` with no package/filename in scope.
    fn from(dup: DuplicateDigest) -> Self {
        Self::ConflictingDigest {
            package: String::new(),
            filename: String::new(),
            algo: dup.algo,
            existing: dup.existing,
            incoming: dup.incoming,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::apt::deb822::Deb822Reader;
    use std::io::Cursor;

    fn hex64() -> String {
        "a".repeat(64)
    }

    fn hex128() -> String {
        "b".repeat(128)
    }

    fn parse_one(text: &str) -> Paragraph {
        let mut r = Deb822Reader::new(Cursor::new(text));
        r.read_paragraph().unwrap().unwrap()
    }

    fn suite_layout() -> (url::Url, &'static str) {
        (
            url::Url::parse("http://example.com/debian").unwrap(),
            "bookworm",
        )
    }

    fn layout<'a>(base: &'a url::Url, suite: &'a str) -> SuiteLayout<'a> {
        SuiteLayout::new(base, suite)
    }

    #[test]
    fn parses_simple_source_with_two_files() {
        let sha256 = hex64();
        let sha512 = hex128();
        let body = format!(
            "Package: hello\n\
             Directory: pool/main/h/hello\n\
             Checksums-Sha256:\n {sha256} 12345 hello_2.10.dsc\n {sha256} 67890 hello_2.10.tar.gz\n\
             Checksums-Sha512:\n {sha512} 12345 hello_2.10.dsc\n {sha512} 67890 hello_2.10.tar.gz\n\
             \n",
        );
        let p = parse_one(&body);
        let (base, suite) = suite_layout();
        let layout = layout(&base, suite);
        let specs = paragraph_to_sourcespecs(&p, &layout, false).unwrap();
        assert_eq!(specs.len(), 2);
        assert!(
            specs
                .iter()
                .any(|s| s.rel_path.as_str() == "pool/main/h/hello/hello_2.10.dsc")
        );
        assert!(
            specs
                .iter()
                .any(|s| s.rel_path.as_str() == "pool/main/h/hello/hello_2.10.tar.gz")
        );
        for s in &specs {
            assert!(s.digests.get(DigestAlgo::Sha256).is_some());
            assert!(s.digests.get(DigestAlgo::Sha512).is_some());
        }
    }

    #[test]
    fn missing_directory_rejected() {
        let sha256 = hex64();
        let body = format!("Package: hello\nChecksums-Sha256:\n {sha256} 100 hello.dsc\n\n",);
        let p = parse_one(&body);
        let (base, suite) = suite_layout();
        let layout = layout(&base, suite);
        let err = paragraph_to_sourcespecs(&p, &layout, false).unwrap_err();
        assert!(matches!(
            err,
            SourceParseError::MissingField { field: "Directory" }
        ));
    }

    #[test]
    fn missing_checksums_rejected() {
        let body = "Package: hello\nDirectory: pool/main/h/hello\n\n";
        let p = parse_one(body);
        let (base, suite) = suite_layout();
        let layout = layout(&base, suite);
        let err = paragraph_to_sourcespecs(&p, &layout, false).unwrap_err();
        assert!(matches!(err, SourceParseError::MissingChecksums { .. }));
    }

    #[test]
    fn size_conflict_across_algos_rejected() {
        let sha256 = hex64();
        let sha512 = hex128();
        let body = format!(
            "Package: hello\n\
             Directory: pool/main/h/hello\n\
             Checksums-Sha256:\n {sha256} 100 hello.dsc\n\
             Checksums-Sha512:\n {sha512} 200 hello.dsc\n\n",
        );
        let p = parse_one(&body);
        let (base, suite) = suite_layout();
        let layout = layout(&base, suite);
        let err = paragraph_to_sourcespecs(&p, &layout, false).unwrap_err();
        assert!(matches!(err, SourceParseError::SizeConflict { .. }));
    }

    #[test]
    fn filename_with_slash_rejected() {
        let sha256 = hex64();
        let body = format!(
            "Package: hello\nDirectory: d\nChecksums-Sha256:\n {sha256} 100 ../etc/passwd\n\n",
        );
        let p = parse_one(&body);
        let (base, suite) = suite_layout();
        let layout = layout(&base, suite);
        let err = paragraph_to_sourcespecs(&p, &layout, false).unwrap_err();
        assert!(matches!(err, SourceParseError::UnsafeFilename { .. }));
    }

    #[test]
    fn weak_only_rejected_by_default() {
        let md5 = "d".repeat(32);
        let body = format!(
            "Package: hello\n\
             Directory: pool/main/h/hello\n\
             Files:\n {md5} 100 hello.dsc\n\n",
        );
        let p = parse_one(&body);
        let (base, suite) = suite_layout();
        let layout = layout(&base, suite);
        let err = paragraph_to_sourcespecs(&p, &layout, false).unwrap_err();
        assert!(matches!(err, SourceParseError::WeakDigestOnly { .. }));
    }

    #[test]
    fn weak_only_accepted_when_allowed() {
        let md5 = "d".repeat(32);
        let body = format!(
            "Package: hello\n\
             Directory: pool/main/h/hello\n\
             Files:\n {md5} 100 hello.dsc\n\n",
        );
        let p = parse_one(&body);
        let (base, suite) = suite_layout();
        let layout = layout(&base, suite);
        let specs = paragraph_to_sourcespecs(&p, &layout, true).unwrap();
        assert_eq!(specs.len(), 1);
    }

    #[test]
    fn multi_space_column_padding_accepted() {
        // Proxmox pads checksum columns with runs of spaces.
        let sha256 = hex64();
        let body = format!(
            "Package: hello\n\
             Directory: d\n\
             Checksums-Sha256:\n {sha256}          100 hello.dsc\n\n",
        );
        let p = parse_one(&body);
        let (base, suite) = suite_layout();
        let layout = layout(&base, suite);
        let specs = paragraph_to_sourcespecs(&p, &layout, false).unwrap();
        assert_eq!(specs.len(), 1);
    }

    #[test]
    fn bad_hex_rejected() {
        let body = "Package: hello\n\
                    Directory: d\n\
                    Checksums-Sha256:\n zzzzzz 100 hello.dsc\n\n";
        let p = parse_one(body);
        let (base, suite) = suite_layout();
        let layout = layout(&base, suite);
        let err = paragraph_to_sourcespecs(&p, &layout, false).unwrap_err();
        assert!(matches!(err, SourceParseError::BadHex { .. }));
    }

    #[test]
    fn digest_length_mismatch_rejected() {
        let short_hex = "a".repeat(60);
        let body = format!(
            "Package: hello\nDirectory: d\nChecksums-Sha256:\n {short_hex} 100 hello.dsc\n\n"
        );
        let p = parse_one(&body);
        let (base, suite) = suite_layout();
        let layout = layout(&base, suite);
        let err = paragraph_to_sourcespecs(&p, &layout, false).unwrap_err();
        assert!(matches!(
            err,
            SourceParseError::BadHex { .. } | SourceParseError::HexLengthMismatch { .. }
        ));
    }
}
