//! Bounded, escaped renderings of upstream-controlled text for error messages.
//!
//! Errors carrying such text are logged, printed by `--dry-run` and stored as
//! status reasons, so they are escaped and clipped where they are built: a
//! hostile index can then neither inject terminal escapes or fake log lines
//! nor blow one message up to megabytes.

/// Escaped bytes kept from one untrusted value.
pub const MAX_UNTRUSTED_BYTES: usize = 256;

/// `s` as a double-quoted, `Debug`-style escaped literal clipped to
/// [`MAX_UNTRUSTED_BYTES`]; a clipped value ends in `…(N bytes)` with the
/// original length.
#[must_use]
pub fn quote_untrusted(s: &str) -> String {
    let (body, clipped) = escape_clipped(s, true);
    let mut out = String::with_capacity(body.len() + 32);
    out.push('"');
    out.push_str(&body);
    out.push('"');
    if clipped {
        out.push_str(&format!("…({} bytes)", s.len()));
    }
    out
}

/// Clip a message that was formatted from untrusted text (for example an
/// error `Display` quoting a path). Control and other non-printable
/// characters are still escaped; quotes and backslashes are left alone.
#[must_use]
pub fn clip_untrusted(s: &str) -> String {
    let (mut body, clipped) = escape_clipped(s, false);
    if clipped {
        body.push_str(&format!("…({} bytes)", s.len()));
    }
    body
}

/// Escape `s` char by char until the next escape would pass the cap.
fn escape_clipped(s: &str, debug_quotes: bool) -> (String, bool) {
    let mut out = String::with_capacity(s.len().min(MAX_UNTRUSTED_BYTES));
    let mut piece = String::with_capacity(12);
    for c in s.chars() {
        piece.clear();
        match c {
            '\'' => piece.push(c),
            '"' | '\\' if !debug_quotes => piece.push(c),
            _ => piece.extend(c.escape_debug()),
        }
        if out.len() + piece.len() > MAX_UNTRUSTED_BYTES {
            return (out, true);
        }
        out.push_str(&piece);
    }
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_value_is_quoted_like_debug() {
        assert_eq!(quote_untrusted("nginx"), "\"nginx\"");
        assert_eq!(quote_untrusted("a\"b\\c"), format!("{:?}", "a\"b\\c"));
    }

    #[test]
    fn control_characters_are_escaped() {
        let q = quote_untrusted("\x1b[31mFAKE\n2026 ERROR x\r");
        assert!(!q.chars().any(char::is_control), "{q}");
        assert!(q.contains("\\u{1b}[31mFAKE\\n2026"), "{q}");
    }

    #[test]
    fn bidi_override_is_escaped() {
        assert!(!quote_untrusted("a\u{202e}b").contains('\u{202e}'));
    }

    #[test]
    fn long_value_is_clipped_with_its_length() {
        let s = "A".repeat(4 * 1024 * 1024);
        let q = quote_untrusted(&s);
        assert!(q.len() <= MAX_UNTRUSTED_BYTES + 32, "{} bytes", q.len());
        assert!(q.ends_with("\"…(4194304 bytes)"), "{q}");
    }

    #[test]
    fn value_at_cap_is_not_clipped() {
        let s = "b".repeat(MAX_UNTRUSTED_BYTES);
        assert_eq!(quote_untrusted(&s), format!("\"{s}\""));
        let over = "b".repeat(MAX_UNTRUSTED_BYTES + 1);
        assert!(quote_untrusted(&over).ends_with("bytes)"));
    }

    #[test]
    fn clipping_never_splits_an_escape_or_a_char() {
        let s = format!(
            "{}\x1b{}",
            "x".repeat(MAX_UNTRUSTED_BYTES - 3),
            "é".repeat(64)
        );
        let q = quote_untrusted(&s);
        assert!(!q.contains("\\u{1"), "partial escape kept: {q}");
        let s = format!("{}é", "x".repeat(MAX_UNTRUSTED_BYTES - 1));
        assert!(quote_untrusted(&s).ends_with("\"…(257 bytes)"));
    }

    #[test]
    fn clip_keeps_quotes_but_escapes_controls() {
        assert_eq!(clip_untrusted("path \"a\\b\""), "path \"a\\b\"");
        assert_eq!(clip_untrusted("a\nb"), "a\\nb");
        let long = "z".repeat(1024);
        let c = clip_untrusted(&long);
        assert!(c.len() <= MAX_UNTRUSTED_BYTES + 32);
        assert!(c.ends_with("…(1024 bytes)"), "{c}");
    }
}
