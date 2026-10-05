//! RFC 2822-ish datetime parsing for Release `Date` / `Valid-Until`.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;

/// Parse a Release `Date` / `Valid-Until` value.
///
/// # Errors
///
/// Returns `time::error::Parse` when the input is not RFC 2822.
pub fn parse_release_datetime(s: &str) -> Result<OffsetDateTime, time::error::Parse> {
    let s = s.trim();
    // Release files commonly use `UTC`/`GMT`, which `time`'s strict RFC 2822 parser rejects.
    let normalized = if let Some(prefix) = s.strip_suffix(" UTC") {
        format!("{prefix} +0000")
    } else if let Some(prefix) = s.strip_suffix(" GMT") {
        format!("{prefix} +0000")
    } else {
        s.to_owned()
    };
    OffsetDateTime::parse(&normalized, &Rfc2822)
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
    fn rejects_garbage() {
        assert!(parse_release_datetime("chicken").is_err());
        assert!(parse_release_datetime("").is_err());
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
