//! `Packages` paragraph → pool `FileSpec`. Hostile `Filename` values (absolute, `..`)
//! and bad digests or sizes are rejected.

use crate::core::types::{Digest, DigestAlgo, DigestError, DigestSet, FileSpec, Layer};

use super::deb822::Paragraph;
use super::layout::{LayoutError, SuiteLayout};

/// Convert one `Packages` paragraph into a `FileSpec`.
///
/// With `allow_weak_hash == false`, packages advertising only SHA-1/MD5 are rejected.
///
/// # Errors
///
/// Each field problem maps to a `PackageParseError` variant.
pub fn paragraph_to_filespec(
    paragraph: &Paragraph,
    layout: &SuiteLayout<'_>,
    allow_weak_hash: bool,
) -> Result<FileSpec, PackageParseError> {
    let package = required_str(paragraph, "Package")?;

    let filename = required_str(paragraph, "Filename")?;
    let rel_path = layout
        .root_rel(filename)
        .map_err(|e| PackageParseError::UnsafeFilename {
            package: package.to_owned(),
            filename: filename.to_owned(),
            reason: e.to_string(),
        })?;

    let size_str = required_str(paragraph, "Size")?;
    let size: u64 = size_str.parse().map_err(|_| PackageParseError::BadSize {
        package: package.to_owned(),
        value: size_str.to_owned(),
    })?;

    let mut digests = DigestSet::new();
    parse_optional_checksum(
        paragraph,
        "SHA512",
        DigestAlgo::Sha512,
        package,
        &mut digests,
    )?;
    parse_optional_checksum(
        paragraph,
        "SHA256",
        DigestAlgo::Sha256,
        package,
        &mut digests,
    )?;
    parse_optional_checksum(paragraph, "SHA1", DigestAlgo::Sha1, package, &mut digests)?;
    parse_optional_checksum(paragraph, "MD5sum", DigestAlgo::Md5, package, &mut digests)?;

    if digests.is_empty() {
        return Err(PackageParseError::NoDigest {
            package: package.to_owned(),
        });
    }
    if !allow_weak_hash && digests.all_weak() {
        return Err(PackageParseError::WeakDigestOnly {
            package: package.to_owned(),
        });
    }

    let url = layout
        .root_url(filename)
        .map_err(|e: LayoutError| PackageParseError::UrlBuild {
            package: package.to_owned(),
            filename: filename.to_owned(),
            reason: e.to_string(),
        })?;

    Ok(FileSpec {
        rel_path,
        digests,
        size: Some(size),
        url,
        layer: Layer::Content,
        // Pool filenames encode name + version, so content never changes.
        immutable: true,
    })
}

fn required_str<'a>(
    paragraph: &'a Paragraph,
    field: &'static str,
) -> Result<&'a str, PackageParseError> {
    paragraph
        .get(field)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(PackageParseError::MissingField { field })
}

fn parse_optional_checksum(
    paragraph: &Paragraph,
    field: &str,
    algo: DigestAlgo,
    package: &str,
    out: &mut DigestSet,
) -> Result<(), PackageParseError> {
    let Some(hex) = paragraph
        .get(field)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(());
    };
    let bytes = super::checksums::decode_hex(hex).ok_or_else(|| PackageParseError::BadHex {
        package: package.to_owned(),
        algo,
        hex: hex.to_owned(),
    })?;
    let digest = Digest::new(algo, bytes).map_err(|e| match e {
        DigestError::LengthMismatch { expected, got, .. } => PackageParseError::HexLengthMismatch {
            package: package.to_owned(),
            algo,
            expected,
            got,
        },
    })?;
    // Each algorithm comes from its own field, read once, so the push cannot conflict.
    out.push(digest)
        .expect("one algo per field, cannot conflict");
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum PackageParseError {
    #[error("Packages paragraph is missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("package `{package}`: Filename `{filename}` is unsafe ({reason})")]
    UnsafeFilename {
        package: String,
        filename: String,
        reason: String,
    },
    #[error("package `{package}`: cannot build pool URL for `{filename}` ({reason})")]
    UrlBuild {
        package: String,
        filename: String,
        reason: String,
    },
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
    #[error("package `{package}`: no digest fields (SHA512/SHA256/SHA1/MD5sum) present")]
    NoDigest { package: String },
    #[error("package `{package}`: only weak digests (SHA-1 / MD5) — rejected by policy")]
    WeakDigestOnly { package: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::apt::deb822::Deb822Reader;
    use std::io::Cursor;
    use url::Url;

    fn read_one(input: &str) -> Paragraph {
        Deb822Reader::new(Cursor::new(input))
            .read_paragraph()
            .unwrap()
            .unwrap()
    }

    fn base() -> Url {
        Url::parse("https://deb.debian.org/debian").unwrap()
    }

    fn layout<'a>(u: &'a Url) -> SuiteLayout<'a> {
        SuiteLayout::new(u, "bookworm")
    }

    fn sha256_hex() -> String {
        "0".repeat(64)
    }
    fn sha512_hex() -> String {
        "1".repeat(128)
    }
    fn sha1_hex() -> String {
        "2".repeat(40)
    }
    fn md5_hex() -> String {
        "3".repeat(32)
    }

    fn good_paragraph() -> String {
        format!(
            "\
Package: nginx
Version: 1.24.0-1
Architecture: amd64
Filename: pool/main/n/nginx/nginx_1.24.0-1_amd64.deb
Size: 1048576
SHA512: {}
SHA256: {}
",
            sha512_hex(),
            sha256_hex()
        )
    }

    #[test]
    fn happy_path_content_layer_immutable_with_all_digests() {
        let base_url = base();
        let layout = layout(&base_url);
        let p = read_one(&good_paragraph());
        let fs = paragraph_to_filespec(&p, &layout, false).unwrap();
        assert_eq!(fs.layer, Layer::Content);
        assert!(fs.immutable);
        assert_eq!(fs.size, Some(1048576));
        assert_eq!(
            fs.rel_path.as_str(),
            "pool/main/n/nginx/nginx_1.24.0-1_amd64.deb"
        );
        assert_eq!(
            fs.url.as_str(),
            "https://deb.debian.org/debian/pool/main/n/nginx/nginx_1.24.0-1_amd64.deb"
        );
        assert_eq!(fs.digests.len(), 2);
        assert_eq!(fs.digests.strongest().unwrap().algo, DigestAlgo::Sha512);
    }

    #[test]
    fn sha256_only_is_ok() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!(
            "Package: p\nFilename: pool/x.deb\nSize: 10\nSHA256: {}\n",
            sha256_hex()
        );
        let p = read_one(&input);
        let fs = paragraph_to_filespec(&p, &layout, false).unwrap();
        assert_eq!(fs.digests.strongest().unwrap().algo, DigestAlgo::Sha256);
    }

    #[test]
    fn weak_only_rejected_by_default() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!(
            "Package: p\nFilename: pool/x.deb\nSize: 10\nSHA1: {}\nMD5sum: {}\n",
            sha1_hex(),
            md5_hex()
        );
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(err, PackageParseError::WeakDigestOnly { .. }));
    }

    #[test]
    fn weak_only_accepted_when_policy_allows() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!(
            "Package: p\nFilename: pool/x.deb\nSize: 10\nSHA1: {}\n",
            sha1_hex()
        );
        let p = read_one(&input);
        paragraph_to_filespec(&p, &layout, true).unwrap();
    }

    #[test]
    fn missing_filename_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!("Package: p\nSize: 10\nSHA256: {}\n", sha256_hex());
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(
            err,
            PackageParseError::MissingField { field: "Filename" }
        ));
    }

    #[test]
    fn missing_size_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!(
            "Package: p\nFilename: pool/x.deb\nSHA256: {}\n",
            sha256_hex()
        );
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(
            err,
            PackageParseError::MissingField { field: "Size" }
        ));
    }

    #[test]
    fn missing_package_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!("Filename: pool/x.deb\nSize: 10\nSHA256: {}\n", sha256_hex());
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(
            err,
            PackageParseError::MissingField { field: "Package" }
        ));
    }

    #[test]
    fn no_digest_fields_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = "Package: p\nFilename: pool/x.deb\nSize: 10\n";
        let p = read_one(input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(err, PackageParseError::NoDigest { .. }));
    }

    #[test]
    fn negative_size_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!(
            "Package: p\nFilename: pool/x.deb\nSize: -10\nSHA256: {}\n",
            sha256_hex()
        );
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(err, PackageParseError::BadSize { .. }));
    }

    #[test]
    fn non_numeric_size_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!(
            "Package: p\nFilename: pool/x.deb\nSize: chicken\nSHA256: {}\n",
            sha256_hex()
        );
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(err, PackageParseError::BadSize { .. }));
    }

    #[test]
    fn non_hex_digest_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let bad = format!("{}zz", "0".repeat(62));
        let input = format!("Package: p\nFilename: pool/x.deb\nSize: 10\nSHA256: {bad}\n");
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(err, PackageParseError::BadHex { .. }));
    }

    #[test]
    fn wrong_length_digest_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let short = "0".repeat(60);
        let input = format!("Package: p\nFilename: pool/x.deb\nSize: 10\nSHA256: {short}\n");
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(
            matches!(
                err,
                PackageParseError::BadHex { .. } | PackageParseError::HexLengthMismatch { .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn path_traversal_in_filename_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!(
            "Package: p\nFilename: ../../etc/passwd\nSize: 10\nSHA256: {}\n",
            sha256_hex()
        );
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(err, PackageParseError::UnsafeFilename { .. }));
    }

    #[test]
    fn absolute_filename_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!(
            "Package: p\nFilename: /etc/passwd\nSize: 10\nSHA256: {}\n",
            sha256_hex()
        );
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(err, PackageParseError::UnsafeFilename { .. }));
    }

    #[test]
    fn backslash_filename_rejected() {
        // Windows-style paths do not exist in APT streams; treat as suspect.
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!(
            "Package: p\nFilename: pool\\evil\nSize: 10\nSHA256: {}\n",
            sha256_hex()
        );
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(err, PackageParseError::UnsafeFilename { .. }));
    }

    #[test]
    fn empty_segment_filename_rejected() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = format!(
            "Package: p\nFilename: pool//nginx.deb\nSize: 10\nSHA256: {}\n",
            sha256_hex()
        );
        let p = read_one(&input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(err, PackageParseError::UnsafeFilename { .. }));
    }

    #[test]
    fn truncated_paragraph_missing_fields_surfaces_as_missing_field() {
        let base_url = base();
        let layout = layout(&base_url);
        let input = "Package: p\nFilename: pool/x.deb\n"; // no Size/digest
        let p = read_one(input);
        let err = paragraph_to_filespec(&p, &layout, false).unwrap_err();
        assert!(matches!(err, PackageParseError::MissingField { .. }));
    }
}
