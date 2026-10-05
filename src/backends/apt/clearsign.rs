//! OpenPGP clearsign frame extraction (RFC 4880 §7).
//!
//! Data outside the `BEGIN PGP SIGNED MESSAGE` … `END PGP SIGNATURE` frame is rejected
//! (CVE-2016-1252). Armor markers are found by line-anchored scan: RFC 4880 §7.1
//! dash-escapes body lines starting with `-`, so a fake in-body marker is never at column 0.

use std::borrow::Cow;

const CLEARSIGN_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIGNATURE_HEADER: &str = "-----BEGIN PGP SIGNATURE-----";
const SIGNATURE_FOOTER: &str = "-----END PGP SIGNATURE-----";

/// Which kind of `Release`-family file was on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseKind {
    /// Plain `Release`.
    Plain,
    /// Clearsigned `InRelease`.
    Clearsigned,
}

/// Result of `extract_signed_body`.
#[derive(Debug)]
pub struct ExtractedBody<'a> {
    pub kind: ReleaseKind,
    /// Bytes to feed to `parse_release`.
    pub body: Cow<'a, str>,
    /// Byte range of the signed content, dash-escapes intact. `None` for `Plain`.
    pub signed_span: Option<(usize, usize)>,
}

/// Detect + strip clearsign wrapping.
///
/// # Errors
///
/// `ExternalData` for bytes outside the frame (CVE-2016-1252); the other
/// [`ClearSignError`] variants for a malformed frame.
pub fn extract_signed_body(input: &str) -> Result<ExtractedBody<'_>, ClearSignError> {
    // Line-anchored, so a dash-escaped header in a plain Release stays `Plain`.
    let Some(hdr_start) = find_marker_line(input, CLEARSIGN_HEADER, 0) else {
        return Ok(ExtractedBody {
            kind: ReleaseKind::Plain,
            body: Cow::Borrowed(input),
            signed_span: None,
        });
    };
    if !input[..hdr_start].trim().is_empty() {
        return Err(ClearSignError::ExternalData("before signed message header"));
    }

    let after_hdr = &input[hdr_start + CLEARSIGN_HEADER.len()..];
    let (mut cursor_offset, after_hdr) = trim_leading_newline(after_hdr);
    cursor_offset += hdr_start + CLEARSIGN_HEADER.len();

    let (headers_end_rel, _hash_headers) = read_hash_headers(after_hdr)?;
    let body_start_abs = cursor_offset + headers_end_rel;

    let sig_hdr_abs = find_marker_line(input, SIGNATURE_HEADER, body_start_abs).ok_or(
        ClearSignError::MissingSignatureBoundary("BEGIN PGP SIGNATURE"),
    )?;
    let body_end_abs = sig_hdr_abs;
    // Keep the `\n` before the marker: it ends the deb822 stream.
    let body_slice_end = body_end_abs;

    let sig_hdr_line_end = sig_hdr_abs + SIGNATURE_HEADER.len();
    let sig_footer_abs = find_marker_line(input, SIGNATURE_FOOTER, sig_hdr_line_end).ok_or(
        ClearSignError::MissingSignatureBoundary("END PGP SIGNATURE"),
    )?;
    let sig_footer_end = sig_footer_abs + SIGNATURE_FOOTER.len();
    if !input[sig_footer_end..].trim().is_empty() {
        return Err(ClearSignError::ExternalData("after signature footer"));
    }

    let raw_body = &input[body_start_abs..body_slice_end];
    let body = dash_unescape(raw_body);

    Ok(ExtractedBody {
        kind: ReleaseKind::Clearsigned,
        body: Cow::Owned(body),
        signed_span: Some((body_start_abs, body_slice_end)),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ClearSignError {
    #[error("clearsign frame carries data outside the signed block ({0})")]
    ExternalData(&'static str),
    #[error("clearsign frame is missing `-----{0}-----`")]
    MissingSignatureBoundary(&'static str),
    #[error("clearsign hash-header block is not terminated by a blank line")]
    MissingBlankAfterHeaders,
    #[error("clearsign hash-header line does not match RFC 4880 armor shape")]
    MalformedHashHeader,
}

/// Absolute offset of the first line in `haystack[from..]` starting with `marker`.
/// Only the line start is anchored; trailing noise after the marker is tolerated.
fn find_marker_line(haystack: &str, marker: &str, from: usize) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let marker_bytes = marker.as_bytes();
    let mut i = from;
    while i + marker_bytes.len() <= bytes.len() {
        let at_line_start = i == 0 || bytes[i - 1] == b'\n';
        if at_line_start && bytes[i..i + marker_bytes.len()] == *marker_bytes {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn trim_leading_newline(s: &str) -> (usize, &str) {
    let mut consumed = 0;
    let mut rest = s;
    while let Some(r) = rest.strip_prefix('\r') {
        consumed += 1;
        rest = r;
    }
    if let Some(r) = rest.strip_prefix('\n') {
        consumed += 1;
        rest = r;
    }
    (consumed, rest)
}

fn read_hash_headers(input: &str) -> Result<(usize, Vec<&str>), ClearSignError> {
    let mut headers = Vec::new();
    let mut cursor = 0;
    loop {
        let rem = &input[cursor..];
        let Some(nl) = rem.find('\n') else {
            return Err(ClearSignError::MissingBlankAfterHeaders);
        };
        let line = rem[..nl].trim_end_matches('\r');
        cursor += nl + 1;
        if line.is_empty() {
            return Ok((cursor, headers));
        }
        let colon = line.find(':').ok_or(ClearSignError::MalformedHashHeader)?;
        let name = &line[..colon];
        if name.is_empty()
            || name
                .chars()
                .any(|c| c.is_ascii_control() || c == ' ' || c == '\t' || (c as u32) > 0x7E)
        {
            return Err(ClearSignError::MalformedHashHeader);
        }
        headers.push(line);
    }
}

fn dash_unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut first_char_of_line = true;
    let mut lookahead = raw.chars().peekable();
    while let Some(c) = lookahead.next() {
        if first_char_of_line && c == '-' && lookahead.peek() == Some(&' ') {
            lookahead.next();
            first_char_of_line = false;
            continue;
        }
        out.push(c);
        first_char_of_line = c == '\n';
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_release_passthrough() {
        let input = "Suite: bookworm\nCodename: bookworm\n";
        let out = extract_signed_body(input).unwrap();
        assert_eq!(out.kind, ReleaseKind::Plain);
        assert_eq!(out.body, input);
        assert!(out.signed_span.is_none());
    }

    #[test]
    fn well_formed_inrelease_strips_frame() {
        let body = "Suite: bookworm\nCodename: bookworm\n";
        let input = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{body}-----BEGIN PGP SIGNATURE-----\n\niQIzBAABC…snip…\n-----END PGP SIGNATURE-----\n"
        );
        let out = extract_signed_body(&input).unwrap();
        assert_eq!(out.kind, ReleaseKind::Clearsigned);
        assert_eq!(out.body, body);
        assert!(out.signed_span.is_some());
    }

    #[test]
    fn cve_2016_1252_leading_data_rejected() {
        let body = "Suite: bookworm\n";
        let attack = format!(
            "MALICIOUS DATA\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{body}-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\n"
        );
        let err = extract_signed_body(&attack).unwrap_err();
        assert!(matches!(
            err,
            ClearSignError::ExternalData("before signed message header")
        ));
    }

    #[test]
    fn cve_2016_1252_trailing_data_rejected() {
        let body = "Suite: bookworm\n";
        let attack = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{body}-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\nEXTRA DATA\n"
        );
        let err = extract_signed_body(&attack).unwrap_err();
        assert!(matches!(
            err,
            ClearSignError::ExternalData("after signature footer")
        ));
    }

    #[test]
    fn trailing_whitespace_after_footer_ok() {
        let body = "Suite: bookworm\n";
        let text = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{body}-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\n\n\n"
        );
        extract_signed_body(&text).unwrap();
    }

    #[test]
    fn missing_signature_boundary_rejected() {
        let text = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSuite: bookworm\n";
        let err = extract_signed_body(text).unwrap_err();
        assert!(matches!(
            err,
            ClearSignError::MissingSignatureBoundary("BEGIN PGP SIGNATURE")
        ));
    }

    #[test]
    fn missing_end_signature_rejected() {
        let text = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSuite: bookworm\n-----BEGIN PGP SIGNATURE-----\n\nsig\n";
        let err = extract_signed_body(text).unwrap_err();
        assert!(matches!(
            err,
            ClearSignError::MissingSignatureBoundary("END PGP SIGNATURE")
        ));
    }

    #[test]
    fn missing_blank_after_hash_headers_rejected() {
        let text = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256";
        let err = extract_signed_body(text).unwrap_err();
        assert!(matches!(err, ClearSignError::MissingBlankAfterHeaders));
    }

    #[test]
    fn malformed_hash_header_rejected() {
        let text = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\nnot a header\n\nSuite: bookworm\n-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\n";
        let err = extract_signed_body(text).unwrap_err();
        assert!(
            matches!(err, ClearSignError::MalformedHashHeader),
            "{err:?}"
        );
    }

    #[test]
    fn armor_header_no_value_ok() {
        let body = "Suite: x\n";
        let text = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\nNotDashEscaped:\n\n{body}-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\n"
        );
        extract_signed_body(&text).unwrap();
    }

    #[test]
    fn dash_escape_reversed() {
        let body = "-normal line\n- escaped-dash line\nplain\n";
        let text = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{body}-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\n"
        );
        let out = extract_signed_body(&text).unwrap();
        assert_eq!(out.body, "-normal line\nescaped-dash line\nplain\n");
    }

    #[test]
    fn fake_signature_marker_in_body_rejected() {
        // Dash-escaped `-----BEGIN PGP SIGNATURE-----` line inside the signed body.
        let body = "Suite: bookworm\n- -----BEGIN PGP SIGNATURE-----\nCodename: bookworm\n";
        let input = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{body}-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\n"
        );
        let out = extract_signed_body(&input).unwrap();
        assert_eq!(out.kind, ReleaseKind::Clearsigned);
        assert_eq!(
            out.body.as_ref(),
            "Suite: bookworm\n-----BEGIN PGP SIGNATURE-----\nCodename: bookworm\n"
        );
        let (span_start, span_end) = out.signed_span.unwrap();
        let signed_slice = &input[span_start..span_end];
        assert!(
            signed_slice.contains("Codename: bookworm"),
            "signed span truncated at fake marker: {signed_slice:?}"
        );
    }

    #[test]
    fn fake_signed_message_header_in_body_rejected() {
        // Plain Release containing a dash-escaped clearsign header.
        let plain = "Suite: bookworm\n- -----BEGIN PGP SIGNED MESSAGE-----\nCodename: bookworm\n";
        let out = extract_signed_body(plain).unwrap();
        assert_eq!(out.kind, ReleaseKind::Plain);
        assert_eq!(out.body.as_ref(), plain);
        assert!(out.signed_span.is_none());
    }

    #[test]
    fn non_marker_dash_lines_in_body_ok() {
        let body = "Suite: bookworm\n- -----some other separator-----\n- -abc\n- ---\nplain\n";
        let input = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{body}-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\n"
        );
        let out = extract_signed_body(&input).unwrap();
        assert_eq!(out.kind, ReleaseKind::Clearsigned);
        assert_eq!(
            out.body.as_ref(),
            "Suite: bookworm\n-----some other separator-----\n-abc\n---\nplain\n"
        );
    }

    /// Fuzz over armor-marker fragments and line separators.
    #[test]
    fn extract_signed_body_never_panics_on_random_input() {
        use std::hash::{BuildHasher, Hasher, RandomState};
        let alphabet: &[&str] = &[
            "-",
            "- ",
            "-----",
            "-----BEGIN PGP SIGNED MESSAGE-----",
            "-----BEGIN PGP SIGNATURE-----",
            "-----END PGP SIGNATURE-----",
            "\n",
            "\r\n",
            " ",
            "\t",
            "Hash: SHA256",
            "Suite: x",
            "Codename: y",
            "a",
            "\0",
            "abc",
        ];
        let mut state = RandomState::new().build_hasher();
        for round in 0..100u64 {
            state.write_u64(round);
            let mut rng = state.finish();
            let mut s = String::new();
            for _ in 0..(1 + (rng & 0x1f)) {
                rng = rng
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                s.push_str(alphabet[(rng as usize) % alphabet.len()]);
            }
            let _ = extract_signed_body(&s);
        }
    }

    #[test]
    fn extract_signed_body_stable_around_valid_envelope() {
        let body = "Suite: x\nCodename: y\n";
        let envelope = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{body}-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\n"
        );
        let attacks: &[&str] = &[
            "- -----BEGIN PGP SIGNATURE-----\n",
            "- -----END PGP SIGNATURE-----\n",
            "- -----BEGIN PGP SIGNED MESSAGE-----\n",
            "- -\n",
            "---\n",
        ];
        for a in attacks {
            let poisoned_body = format!("{a}Suite: x\nCodename: y\n");
            let text = format!(
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{poisoned_body}-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\n"
            );
            let out = extract_signed_body(&text).unwrap();
            assert_eq!(out.kind, ReleaseKind::Clearsigned);
            assert!(
                out.body.contains("Codename: y"),
                "attack {a:?} truncated body: {:?}",
                out.body
            );
        }
        extract_signed_body(&envelope).unwrap();
    }
}
