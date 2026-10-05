//! Process exit codes — a stable contract with systemd units and healthchecks.

use std::process::ExitCode as StdExitCode;

/// Exit codes. Numeric values are frozen.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// All requested mirrors synced successfully.
    Success = 0,
    /// One or more mirrors failed but the run completed (suite-level failure).
    PartialMirrorFailure = 1,
    /// Configuration error (bad TOML, empty suite list, conflicting sources, ...).
    ConfigError = 2,
    /// Another instance held the flock past `lock_timeout`.
    LockContention = 3,
    /// Fatal I/O: disk full, target unwritable, publish rename failed.
    FatalIo = 4,
}

impl ExitCode {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<ExitCode> for StdExitCode {
    fn from(code: ExitCode) -> Self {
        Self::from(code.as_u8())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_contract_is_stable() {
        assert_eq!(ExitCode::Success.as_u8(), 0);
        assert_eq!(ExitCode::PartialMirrorFailure.as_u8(), 1);
        assert_eq!(ExitCode::ConfigError.as_u8(), 2);
        assert_eq!(ExitCode::LockContention.as_u8(), 3);
        assert_eq!(ExitCode::FatalIo.as_u8(), 4);
    }
}
