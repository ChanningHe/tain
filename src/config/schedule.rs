//! `global.schedule` validation, shared by `tain check` and the daemon.

use std::str::FromStr;

use chrono::Local;
use croner::Cron;

#[derive(Debug, thiserror::Error)]
#[error("invalid cron expression `{raw}`: {reason}")]
pub struct ScheduleError {
    pub raw: String,
    pub reason: String,
}

/// Parse a five-field cron expression and require that it fires at least once
/// from now on (`0 0 30 2 *` parses but never does).
///
/// # Errors
///
/// Unparsable expression, or one with no next occurrence.
pub fn parse(raw: &str) -> Result<Cron, ScheduleError> {
    let err = |reason: String| ScheduleError {
        raw: raw.to_owned(),
        reason,
    };
    let cron = Cron::from_str(raw).map_err(|e| err(e.to_string()))?;
    cron.find_next_occurrence(&Local::now(), false)
        .map_err(|e| err(format!("it never fires ({e})")))?;
    Ok(cron)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_regular_expressions() {
        for raw in ["0 2,8,14,20 * * *", "*/5 * * * *", "0 0 29 2 *"] {
            parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
        }
    }

    #[test]
    fn rejects_garbage() {
        let err = parse("not a cron").unwrap_err();
        assert!(err.to_string().contains("not a cron"), "{err}");
    }

    #[test]
    fn rejects_expression_that_never_fires() {
        for raw in ["0 0 30 2 *", "0 0 31 4 *"] {
            let err = parse(raw).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(raw) && msg.contains("never fires"), "{msg}");
        }
    }
}
