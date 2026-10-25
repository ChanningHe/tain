//! RFC 2822-ish datetime parsing for Release `Date` / `Valid-Until`.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;

/// Longest accepted value; real ones are ~31 bytes
/// (`Sat, 03 Feb 2024 09:15:38 +0000`).
pub const MAX_DATE_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum DateParseError {
    #[error("date is {len} bytes long (limit {MAX_DATE_LEN})")]
    TooLong { len: usize },
    #[error(transparent)]
    Parse(#[from] time::error::Parse),
}

/// Parse a Release `Date` / `Valid-Until` value.
///
/// # Errors
///
/// [`DateParseError`] when the input is overlong or not RFC 2822.
pub fn parse_release_datetime(s: &str) -> Result<OffsetDateTime, DateParseError> {
    let s = s.trim();
    // Bounds the `time` parser's recursion on nested comments (RUSTSEC-2026-0009).
    if s.len() > MAX_DATE_LEN {
        return Err(DateParseError::TooLong { len: s.len() });
    }
    let normalized: Vec<String> = s.split_whitespace().map(normalize_token).collect();
    Ok(OffsetDateTime::parse(&normalized.join(" "), &Rfc2822)?)
}

/// Bring apt-accepted variants into `time`'s strict RFC 2822 shape: Launchpad
/// writes `Sat, 24 Oct 2026  6:20:18 UTC` (space-padded day/hour, runs of
/// spaces, which `split_whitespace` already folds), and `UTC`/`GMT` zones are
/// common.
fn normalize_token(tok: &str) -> String {
    let zero_pad = |part: &str| {
        if part.len() == 1 && part.as_bytes()[0].is_ascii_digit() {
            format!("0{part}")
        } else {
            part.to_owned()
        }
    };
    match tok {
        "UTC" | "GMT" => "+0000".to_owned(),
        _ if tok.contains(':') => tok.split(':').map(zero_pad).collect::<Vec<_>>().join(":"),
        _ => zero_pad(tok),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn parses_utc_zone() {
        let dt = parse_release_datetime("Sat, 03 Feb 2024 09:15:38 UTC").unwrap();
        assert_eq!(dt, datetime!(2024-02-03 09:15:38 UTC));
    }

    #[test]
    fn parses_gmt_zone() {
        let dt = parse_release_datetime("Sat, 03 Feb 2024 09:15:38 GMT").unwrap();
        assert_eq!(dt, datetime!(2024-02-03 09:15:38 UTC));
    }

    #[test]
    fn parses_numeric_zone() {
        let dt = parse_release_datetime("Sat, 03 Feb 2024 09:15:38 +0000").unwrap();
        assert_eq!(dt, datetime!(2024-02-03 09:15:38 UTC));
    }

    #[test]
    fn parses_non_utc_offset() {
        let dt = parse_release_datetime("Sat, 03 Feb 2024 11:15:38 +0200").unwrap();
        assert_eq!(
            dt.unix_timestamp(),
            datetime!(2024-02-03 09:15:38 UTC).unix_timestamp()
        );
    }

    #[test]
    fn launchpad_ppa_padding_accepted() {
        // Launchpad pads single-digit hours and days with a space, not a zero.
        assert_eq!(
            parse_release_datetime("Sat, 24 Oct 2026  6:20:18 UTC").unwrap(),
            datetime!(2026-10-24 06:20:18 UTC)
        );
        assert_eq!(
            parse_release_datetime("Sun,  4 Oct 2026  6:20:18 UTC").unwrap(),
            datetime!(2026-10-04 06:20:18 UTC)
        );
        assert_eq!(
            parse_release_datetime("Sun, 4 Oct 2026 6:05:09 +0000").unwrap(),
            datetime!(2026-10-04 06:05:09 UTC)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_release_datetime("chicken").is_err());
        assert!(parse_release_datetime("").is_err());
    }

    #[test]
    fn deeply_nested_comment_rejected_without_parsing() {
        // RUSTSEC-2026-0009: nested RFC 2822 comments overflow the stack in `time`.
        let hostile = format!(
            "Sat, 03 Feb 2024 09:15:38 +0000 {}{}",
            "(".repeat(1_000_000),
            ")".repeat(1_000_000)
        );
        let started = std::time::Instant::now();
        let err = parse_release_datetime(&hostile).unwrap_err();
        assert!(matches!(err, DateParseError::TooLong { .. }), "{err:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn length_cap_admits_real_dates_and_rejects_one_past() {
        let real = "Sat, 03 Feb 2024 09:15:38 UTC";
        assert!(parse_release_datetime(real).is_ok());
        let padded = format!("{real}{}", " ".repeat(MAX_DATE_LEN - real.len()));
        assert!(
            parse_release_datetime(&padded).is_ok(),
            "trailing space trims"
        );
        let over = "x".repeat(MAX_DATE_LEN + 1);
        assert!(matches!(
            parse_release_datetime(&over),
            Err(DateParseError::TooLong { .. })
        ));
    }

    #[test]
    fn ordering_used_for_date_monotonicity() {
        let older = parse_release_datetime("Sat, 03 Feb 2024 09:15:38 UTC").unwrap();
        let newer = parse_release_datetime("Sat, 10 Feb 2024 09:15:38 UTC").unwrap();
        assert!(newer > older);
    }

    #[test]
    fn valid_until_can_be_compared_to_now_isoformat() {
        let dt = parse_release_datetime("Sat, 03 Feb 2099 09:15:38 UTC").unwrap();
        let past = datetime!(2000-01-01 00:00:00 UTC);
        assert!(dt > past);
    }
}
