//! Release header parser: reads the deb822 header of a `Release` (or extracted
//! `InRelease` body) and folds its checksum blocks into `ReleaseChecksums`.

use std::io::Cursor;

use crate::core::types::DigestAlgo;

use super::checksums::{ChecksumError, ReleaseChecksums};
use super::deb822::{self, Deb822Reader};

/// Structured view of a `Release` paragraph. Dates stay raw; the engine parses them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReleaseHeader {
    pub suite: Option<String>,
    pub codename: Option<String>,
    pub architectures: Vec<String>,
    pub components: Vec<String>,
    pub date_raw: Option<String>,
    pub valid_until_raw: Option<String>,
    pub acquire_by_hash: bool,
    pub no_support_for_architecture_all: Option<String>,
    pub origin: Option<String>,
    pub label: Option<String>,
    pub signed_by: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseParseError {
    #[error(transparent)]
    Deb822(#[from] deb822::ParseError),
    #[error("Release contains no paragraph")]
    Empty,
    #[error("Release contains more than one paragraph")]
    ExtraParagraph,
    #[error("checksum line for `{path}` is malformed: `{snippet}`")]
    BadChecksumLine { path: String, snippet: String },
    #[error("checksum size for `{path}` is not an integer: `{value}`")]
    BadChecksumSize { path: String, value: String },
    #[error("checksum path for `{path}` fails safety check: {reason}")]
    UnsafePath { path: String, reason: String },
    #[error(transparent)]
    Checksum(#[from] ChecksumError),
}

/// Parse a plain-or-signed-then-stripped Release body into header + checksums.
///
/// # Errors
///
/// deb822 errors, malformed checksum lines, unsafe paths, and cross-algorithm conflicts.
pub fn parse_release(body: &str) -> Result<(ReleaseHeader, ReleaseChecksums), ReleaseParseError> {
    let mut reader = Deb822Reader::new(Cursor::new(body));
    let paragraph = reader.read_paragraph()?.ok_or(ReleaseParseError::Empty)?;
    if reader.read_paragraph()?.is_some() {
        return Err(ReleaseParseError::ExtraParagraph);
    }

    let mut header = ReleaseHeader::default();
    let mut checksums = ReleaseChecksums::default();

    for (name, value) in paragraph.iter() {
        match name.to_ascii_lowercase().as_str() {
            "suite" => header.suite = Some(value.trim().to_owned()),
            "codename" => header.codename = Some(value.trim().to_owned()),
            "architectures" => header.architectures = split_whitespace_list(value),
            "components" => header.components = split_whitespace_list(value),
            "date" => header.date_raw = Some(value.trim().to_owned()),
            "valid-until" => header.valid_until_raw = Some(value.trim().to_owned()),
            "acquire-by-hash" => {
                header.acquire_by_hash = value.trim().eq_ignore_ascii_case("yes");
            }
            "no-support-for-architecture-all" => {
                header.no_support_for_architecture_all = Some(value.trim().to_owned());
            }
            "origin" => header.origin = Some(value.trim().to_owned()),
            "label" => header.label = Some(value.trim().to_owned()),
            "signed-by" => header.signed_by = split_whitespace_list(value),
            "description" => header.description = Some(value.trim().to_owned()),
            "md5sum" => parse_checksum_block(&mut checksums, DigestAlgo::Md5, value)?,
            "sha1" => parse_checksum_block(&mut checksums, DigestAlgo::Sha1, value)?,
            "sha256" => parse_checksum_block(&mut checksums, DigestAlgo::Sha256, value)?,
            "sha512" => parse_checksum_block(&mut checksums, DigestAlgo::Sha512, value)?,
            _ => {
                // Lenient reading: unknown fields are legal.
            }
        }
    }

    Ok((header, checksums))
}

fn split_whitespace_list(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_owned).collect()
}

fn parse_checksum_block(
    checksums: &mut ReleaseChecksums,
    algo: DigestAlgo,
    value: &str,
) -> Result<(), ReleaseParseError> {
    for raw_line in value.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        // Columns may be padded with runs of spaces (e.g. Proxmox).
        let mut iter = line.split_whitespace();
        let hex = iter.next().unwrap_or("");
        let size_str = iter.next().unwrap_or("");
        let path = iter.next().unwrap_or("");
        if hex.is_empty() || size_str.is_empty() || path.is_empty() {
            return Err(ReleaseParseError::BadChecksumLine {
                path: path.to_owned(),
                snippet: line.to_owned(),
            });
        }
        // APT paths never contain whitespace.
        if iter.next().is_some() {
            return Err(ReleaseParseError::BadChecksumLine {
                path: path.to_owned(),
                snippet: line.to_owned(),
            });
        }
        let size = size_str
            .parse::<u64>()
            .map_err(|_| ReleaseParseError::BadChecksumSize {
                path: path.to_owned(),
                value: size_str.to_owned(),
            })?;
        validate_checksum_path(path)?;
        checksums.upsert(algo, hex, size, path)?;
    }
    Ok(())
}

/// Reject absolute and `..` paths early; the strict check is `core::types::RelPath`.
fn validate_checksum_path(path: &str) -> Result<(), ReleaseParseError> {
    if path.starts_with('/') {
        return Err(ReleaseParseError::UnsafePath {
            path: path.to_owned(),
            reason: "absolute path".into(),
        });
    }
    if path.split('/').any(|seg| seg == "..") {
        return Err(ReleaseParseError::UnsafePath {
            path: path.to_owned(),
            reason: "contains `..` component".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::checksums::ChecksumError;
    use super::super::clearsign::{ReleaseKind, extract_signed_body};
    use super::*;
    use crate::core::types::DigestAlgo;

    fn hex64() -> String {
        "0".repeat(64)
    }
    fn hex128() -> String {
        "0".repeat(128)
    }

    #[test]
    fn parses_key_header_fields() {
        let body = "\
Suite: bookworm
Codename: bookworm
Architectures: amd64 arm64 i386
Components: main contrib non-free
Date: Sat, 03 Feb 2024 09:15:38 UTC
Valid-Until: Sat, 10 Feb 2024 09:15:38 UTC
Acquire-By-Hash: yes
No-Support-for-Architecture-all: Packages
Origin: Debian
Label: Debian
Signed-By: A4285295FC7B1A81600062A9605C66F00D6C9793
Description: Debian 12 Released 10 June 2023
";
        let (h, c) = parse_release(body).unwrap();
        assert_eq!(h.suite.as_deref(), Some("bookworm"));
        assert_eq!(h.codename.as_deref(), Some("bookworm"));
        assert_eq!(h.architectures, vec!["amd64", "arm64", "i386"]);
        assert_eq!(h.components, vec!["main", "contrib", "non-free"]);
        assert_eq!(h.date_raw.as_deref(), Some("Sat, 03 Feb 2024 09:15:38 UTC"));
        assert_eq!(
            h.valid_until_raw.as_deref(),
            Some("Sat, 10 Feb 2024 09:15:38 UTC")
        );
        assert!(h.acquire_by_hash);
        assert_eq!(
            h.no_support_for_architecture_all.as_deref(),
            Some("Packages")
        );
        assert_eq!(h.origin.as_deref(), Some("Debian"));
        assert_eq!(h.label.as_deref(), Some("Debian"));
        assert_eq!(
            h.signed_by,
            vec!["A4285295FC7B1A81600062A9605C66F00D6C9793".to_owned()]
        );
        assert!(c.is_empty());
    }

    #[test]
    fn acquire_by_hash_no_is_false() {
        let (h, _) = parse_release("Suite: x\nAcquire-By-Hash: no\n").unwrap();
        assert!(!h.acquire_by_hash);
    }

    #[test]
    fn missing_acquire_by_hash_defaults_false() {
        let (h, _) = parse_release("Suite: x\n").unwrap();
        assert!(!h.acquire_by_hash);
    }

    #[test]
    fn unknown_fields_are_tolerated() {
        parse_release("Suite: x\nSomethingNew: whatever\n").unwrap();
    }

    #[test]
    fn empty_release_is_error() {
        let err = parse_release("").unwrap_err();
        assert!(matches!(err, ReleaseParseError::Empty));
    }

    #[test]
    fn multiple_paragraphs_rejected() {
        let err = parse_release("Suite: a\n\nSuite: b\n").unwrap_err();
        assert!(matches!(err, ReleaseParseError::ExtraParagraph));
    }

    #[test]
    fn sha256_block_parsed() {
        let hex = hex64();
        let body = format!(
            "Suite: x\nSHA256:\n {hex} 100 dists/x/Contents-amd64.gz\n {hex} 200 dists/x/Release\n"
        );
        let (_, c) = parse_release(&body).unwrap();
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn sha512_and_sha256_merge_into_one_entry() {
        let sha256 = hex64();
        let sha512 = "1".repeat(128);
        let body = format!("Suite: x\nSHA256:\n {sha256} 100 f\nSHA512:\n {sha512} 100 f\n");
        let (_, c) = parse_release(&body).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(
            c.get("f").unwrap().digests.strongest().unwrap().algo,
            DigestAlgo::Sha512
        );
    }

    #[test]
    fn size_conflict_bubbles_up() {
        let sha256 = hex64();
        let sha512 = "1".repeat(128);
        let body = format!("Suite: x\nSHA256:\n {sha256} 100 f\nSHA512:\n {sha512} 200 f\n");
        let err = parse_release(&body).unwrap_err();
        assert!(
            matches!(
                err,
                ReleaseParseError::Checksum(ChecksumError::SizeConflict {
                    previous: 100,
                    current: 200,
                    ..
                })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn checksum_path_absolute_rejected() {
        let hex = hex64();
        let body = format!("Suite: x\nSHA256:\n {hex} 100 /etc/passwd\n");
        let err = parse_release(&body).unwrap_err();
        assert!(matches!(err, ReleaseParseError::UnsafePath { .. }));
    }

    #[test]
    fn checksum_path_traversal_rejected() {
        let hex = hex64();
        let body = format!("Suite: x\nSHA256:\n {hex} 100 ../../../etc/passwd\n");
        let err = parse_release(&body).unwrap_err();
        assert!(matches!(err, ReleaseParseError::UnsafePath { .. }));
    }

    #[test]
    fn bad_size_rejected() {
        let hex = hex64();
        let body = format!("Suite: x\nSHA256:\n {hex} not-an-int f\n");
        let err = parse_release(&body).unwrap_err();
        assert!(matches!(err, ReleaseParseError::BadChecksumSize { .. }));
    }

    #[test]
    fn malformed_checksum_line_missing_size_rejected() {
        let hex = hex64();
        let body = format!("Suite: x\nSHA256:\n {hex}\n");
        let err = parse_release(&body).unwrap_err();
        assert!(matches!(err, ReleaseParseError::BadChecksumLine { .. }));
    }

    #[test]
    fn empty_checksum_block_is_ok() {
        let body = "Suite: x\nSHA256:\n";
        let (_, c) = parse_release(body).unwrap();
        assert!(c.is_empty());
    }

    /// download.proxmox.com pads columns with runs of spaces.
    #[test]
    fn multi_space_padding_between_columns_accepted() {
        let hex = hex64();
        let body = format!(
            "Suite: x\nSHA256:\n {hex}          2960978 pve-no-subscription/binary-amd64/Packages\n"
        );
        let (_, c) = parse_release(&body).unwrap();
        let e = c
            .get("pve-no-subscription/binary-amd64/Packages")
            .expect("padded checksum row parsed");
        assert_eq!(e.size, 2_960_978);
    }

    #[test]
    fn checksum_path_with_embedded_space_rejected() {
        let hex = hex64();
        let body = format!("Suite: x\nSHA256:\n {hex} 100 a b\n");
        let err = parse_release(&body).unwrap_err();
        assert!(matches!(err, ReleaseParseError::BadChecksumLine { .. }));
    }

    #[test]
    fn full_inrelease_end_to_end() {
        let sha256 = hex64();
        let sha512 = hex128();
        let signed_body = format!(
            "Suite: bookworm\nCodename: bookworm\nArchitectures: amd64\nComponents: main\nAcquire-By-Hash: yes\nSHA256:\n {sha256} 100 main/binary-amd64/Packages\nSHA512:\n {sha512} 100 main/binary-amd64/Packages\n"
        );
        let inrelease = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{signed_body}-----BEGIN PGP SIGNATURE-----\n\nsig-bytes\n-----END PGP SIGNATURE-----\n"
        );
        let extracted = extract_signed_body(&inrelease).unwrap();
        assert_eq!(extracted.kind, ReleaseKind::Clearsigned);
        let (h, c) = parse_release(&extracted.body).unwrap();
        assert_eq!(h.suite.as_deref(), Some("bookworm"));
        assert!(h.acquire_by_hash);
        assert_eq!(c.len(), 1);
        assert_eq!(
            c.get("main/binary-amd64/Packages")
                .unwrap()
                .digests
                .strongest()
                .unwrap()
                .algo,
            DigestAlgo::Sha512
        );
    }
}
