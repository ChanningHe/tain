//! d-i `SHA256SUMS` parser (`sha256sum` output: `<hex>  ./<path>`).
//!
//! Entries become immutable Index-layer `FileSpec`s with `size = None`; paths that
//! could escape the images directory are rejected.

use crate::backends::apt::layout::{LayoutError, SuiteLayout};
use crate::core::types::{Digest, DigestAlgo, DigestSet, FileSpec, Layer, PathError};

/// Parse a SHA256SUMS body into one `FileSpec` per listed file.
///
/// `sums_base` is the suite-relative directory holding the SHA256SUMS file
/// (e.g. `main/installer-amd64/20250803+deb13u5/images`); entry paths join onto it.
///
/// # Errors
///
/// The first malformed line, unsafe path, or bad digest.
pub fn parse_installer_sums(
    body: &str,
    sums_base: &str,
    layout: &SuiteLayout<'_>,
) -> Result<Vec<FileSpec>, InstallerSumsError> {
    let base = sums_base.trim_end_matches('/');
    let mut out = Vec::new();
    let mut line_no: u32 = 0;
    for raw in body.lines() {
        line_no = line_no.saturating_add(1);
        // Real d-i SHA256SUMS files occasionally end with a blank line.
        let line = raw.trim_end();
        if line.trim().is_empty() {
            continue;
        }

        // Canonical GNU form uses two spaces; some generators use one. Tabs are not
        // accepted: looser parsing hides tampered lines.
        let (hex_field, path_field) = if let Some(pair) = line.split_once("  ") {
            pair
        } else if let Some(pair) = line.split_once(' ') {
            pair
        } else {
            return Err(InstallerSumsError::MalformedLine {
                line: line_no,
                reason: "no whitespace separator between hash and path".to_owned(),
            });
        };

        // `sha256sum -b` binary-mode marker: `<hex>  *<path>`.
        let path_field = path_field.trim_start().trim_start_matches('*');

        let rel = path_field.strip_prefix("./").unwrap_or(path_field);
        if rel.is_empty() {
            return Err(InstallerSumsError::MalformedLine {
                line: line_no,
                reason: "empty path after stripping `./`".to_owned(),
            });
        }

        let hex_clean = hex_field.trim();
        if hex_clean.len() != 64 || !hex_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(InstallerSumsError::MalformedLine {
                line: line_no,
                reason: format!("expected 64 lowercase hex chars, got `{hex_clean}`"),
            });
        }
        let bytes = decode_hex(hex_clean).ok_or_else(|| InstallerSumsError::MalformedLine {
            line: line_no,
            reason: "non-hex character in digest".to_owned(),
        })?;
        let digest = Digest::new(DigestAlgo::Sha256, bytes).map_err(|e| {
            InstallerSumsError::MalformedLine {
                line: line_no,
                reason: format!("invalid SHA-256 digest: {e}"),
            }
        })?;
        let mut digests = DigestSet::new();
        digests
            .push(digest)
            .expect("fresh DigestSet cannot report duplicate");

        // `RelPath` rejects absolute paths, `..`, `.`, `//`, `\`, and NUL.
        let suite_rel_str = if base.is_empty() {
            rel.to_owned()
        } else {
            format!("{base}/{rel}")
        };
        let rel_path =
            layout
                .suite_rel(&suite_rel_str)
                .map_err(|e| InstallerSumsError::UnsafePath {
                    line: line_no,
                    path: path_field.to_owned(),
                    reason: e.to_string(),
                })?;
        let url = layout
            .suite_url(&suite_rel_str)
            .map_err(|e| InstallerSumsError::UrlBuild {
                line: line_no,
                path: path_field.to_owned(),
                reason: e.to_string(),
            })?;

        out.push(FileSpec {
            rel_path,
            digests,
            // SHA256SUMS has no sizes; a HEAD per image would buy nothing over the hash.
            size: None,
            url,
            // Images live inside the atomic-swap dists tree, not `pool/`.
            layer: Layer::Index,
            // Versioned directory: content at a given path never changes.
            immutable: true,
        });
    }
    Ok(out)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = ascii_hex_value(chunk[0])?;
        let lo = ascii_hex_value(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn ascii_hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InstallerSumsError {
    #[error("SHA256SUMS line {line}: {reason}")]
    MalformedLine { line: u32, reason: String },
    #[error("SHA256SUMS line {line}: refusing unsafe path `{path}`: {reason}")]
    UnsafePath {
        line: u32,
        path: String,
        reason: String,
    },
    #[error("SHA256SUMS line {line}: failed to build URL for `{path}`: {reason}")]
    UrlBuild {
        line: u32,
        path: String,
        reason: String,
    },
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Layout(#[from] LayoutError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn layout() -> Url {
        Url::parse("https://deb.debian.org/debian").unwrap()
    }

    fn sl<'a>(base: &'a Url, suite: &'a str) -> SuiteLayout<'a> {
        SuiteLayout::new(base, suite)
    }

    const H: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    #[test]
    fn parses_canonical_gnu_sha256sum_lines() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let body = format!(
            "{H}  ./netboot/mini.iso\n\
             {H}  ./netboot/gtk/mini.iso\n\
             {H}  ./cdrom/initrd.gz\n"
        );
        let specs =
            parse_installer_sums(&body, "main/installer-amd64/20250803/images", &l).unwrap();
        assert_eq!(specs.len(), 3);
        assert_eq!(
            specs[0].rel_path.as_str(),
            "dists/bookworm/main/installer-amd64/20250803/images/netboot/mini.iso"
        );
        assert_eq!(
            specs[2].rel_path.as_str(),
            "dists/bookworm/main/installer-amd64/20250803/images/cdrom/initrd.gz"
        );
        for s in &specs {
            assert!(s.size.is_none(), "SHA256SUMS omits size");
            assert!(s.immutable);
            assert!(matches!(s.layer, Layer::Index));
            assert_eq!(s.digests.get(DigestAlgo::Sha256).unwrap().bytes.len(), 32);
        }
    }

    #[test]
    fn tolerates_single_space_separator() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let body = format!("{H} ./boot.img.gz\n");
        let specs = parse_installer_sums(&body, "main/installer-amd64/v/images", &l).unwrap();
        assert_eq!(specs.len(), 1);
        assert!(specs[0].rel_path.as_str().ends_with("/boot.img.gz"));
    }

    #[test]
    fn tolerates_missing_dot_slash_prefix() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let body = format!("{H}  boot.img.gz\n");
        let specs = parse_installer_sums(&body, "main/installer-amd64/v/images", &l).unwrap();
        assert_eq!(specs.len(), 1);
        assert!(specs[0].rel_path.as_str().ends_with("/boot.img.gz"));
    }

    #[test]
    fn tolerates_crlf_and_trailing_blank_lines() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let body = format!("{H}  ./a.img\r\n\r\n{H}  ./b.img\r\n\r\n");
        let specs = parse_installer_sums(&body, "main/installer-amd64/v/images", &l).unwrap();
        assert_eq!(specs.len(), 2);
    }

    #[test]
    fn tolerates_binary_mode_star_marker() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let body = format!("{H}  *netboot/mini.iso\n");
        let specs = parse_installer_sums(&body, "main/installer-amd64/v/images", &l).unwrap();
        assert_eq!(specs.len(), 1);
        assert!(specs[0].rel_path.as_str().ends_with("/netboot/mini.iso"));
    }

    #[test]
    fn rejects_parent_traversal() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let body = format!("{H}  ./../../etc/passwd\n");
        let err = parse_installer_sums(&body, "main/installer-amd64/v/images", &l).unwrap_err();
        assert!(
            matches!(err, InstallerSumsError::UnsafePath { .. }),
            "expected UnsafePath, got {err:?}"
        );
    }

    #[test]
    fn rejects_absolute_path() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let body = format!("{H}  /etc/passwd\n");
        let err = parse_installer_sums(&body, "main/installer-amd64/v/images", &l).unwrap_err();
        assert!(
            matches!(err, InstallerSumsError::UnsafePath { .. }),
            "expected UnsafePath, got {err:?}"
        );
    }

    #[test]
    fn rejects_backslash_path() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let body = format!("{H}  ./sub\\evil.img\n");
        let err = parse_installer_sums(&body, "main/installer-amd64/v/images", &l).unwrap_err();
        assert!(
            matches!(err, InstallerSumsError::UnsafePath { .. }),
            "expected UnsafePath, got {err:?}"
        );
    }

    #[test]
    fn rejects_non_hex_digest() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let bad = "z".to_string() + &H[1..];
        let body = format!("{bad}  ./a.img\n");
        let err = parse_installer_sums(&body, "main/installer-amd64/v/images", &l).unwrap_err();
        assert!(
            matches!(err, InstallerSumsError::MalformedLine { .. }),
            "expected MalformedLine, got {err:?}"
        );
    }

    #[test]
    fn rejects_short_digest() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let short = &H[..32];
        let body = format!("{short}  ./a.img\n");
        let err = parse_installer_sums(&body, "main/installer-amd64/v/images", &l).unwrap_err();
        assert!(
            matches!(err, InstallerSumsError::MalformedLine { .. }),
            "expected MalformedLine, got {err:?}"
        );
    }

    #[test]
    fn rejects_line_without_separator() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let body = H.to_owned();
        let err = parse_installer_sums(&body, "main/installer-amd64/v/images", &l).unwrap_err();
        assert!(
            matches!(err, InstallerSumsError::MalformedLine { .. }),
            "expected MalformedLine, got {err:?}"
        );
    }

    #[test]
    fn empty_body_produces_no_specs() {
        let base = layout();
        let l = sl(&base, "bookworm");
        let specs = parse_installer_sums("", "main/installer-amd64/v/images", &l).unwrap();
        assert!(specs.is_empty());
    }
}
