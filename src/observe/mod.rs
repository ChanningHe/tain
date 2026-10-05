//! Logging setup (text or JSON `tracing` subscriber on stderr) and
//! Prometheus textfile metrics.

pub mod metrics;

use std::io;
use std::str::FromStr;

use tracing::Level;
use tracing_subscriber::{
    EnvFilter,
    fmt::{self, format::FmtSpan},
    prelude::*,
};

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl FromStr for LogFormat {
    type Err = LogFormatParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "text" | "plain" | "pretty" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(LogFormatParseError(other.to_owned())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown log format `{0}` (expected `text` or `json`)")]
pub struct LogFormatParseError(String);

/// Subscriber settings.
#[derive(Debug, Clone, Default)]
pub struct LogConfig {
    pub format: LogFormat,
    /// EnvFilter directives, e.g. `info,tain::core=debug`; `None` means `info`.
    pub filter: Option<String>,
}

impl LogConfig {
    /// Read `TAIN_LOG_LEVEL` and `TAIN_LOG_FORMAT`; an unknown format falls
    /// back to text rather than failing before logging exists.
    #[must_use]
    pub fn from_env() -> Self {
        let format = std::env::var("TAIN_LOG_FORMAT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_default();

        let filter = std::env::var("TAIN_LOG_LEVEL")
            .ok()
            .filter(|s| !s.is_empty());

        Self { format, filter }
    }
}

/// Install the global subscriber. A second call returns `Err`.
pub fn init(cfg: &LogConfig) -> Result<(), InitError> {
    build_subscriber(cfg)?
        .try_init()
        .map_err(|e| InitError::Install(e.to_string()))
}

/// Run `f` under a thread-local subscriber, for logging during config load
/// before the global subscriber exists.
pub fn with_scoped<T>(cfg: &LogConfig, f: impl FnOnce() -> T) -> Result<T, InitError> {
    let subscriber = build_subscriber(cfg)?;
    Ok(tracing::subscriber::with_default(subscriber, f))
}

type BoxedSubscriber = Box<dyn tracing::Subscriber + Send + Sync>;

fn build_subscriber(cfg: &LogConfig) -> Result<BoxedSubscriber, InitError> {
    let filter = build_filter(cfg.filter.as_deref())?;
    let registry = tracing_subscriber::registry().with(filter);
    let layer = fmt::layer()
        .with_target(true)
        .with_span_events(FmtSpan::NONE)
        .with_writer(io::stderr as fn() -> io::Stderr);
    Ok(match cfg.format {
        LogFormat::Text => Box::new(registry.with(layer)),
        LogFormat::Json => Box::new(registry.with(layer.json())),
    })
}

fn build_filter(directives: Option<&str>) -> Result<EnvFilter, InitError> {
    let default_level = Level::INFO;
    match directives {
        // Not `from_env_lossy()`: only `TAIN_*` env vars are honored, never `RUST_LOG`.
        None => Ok(EnvFilter::builder()
            .with_default_directive(default_level.into())
            .parse_lossy("")),
        Some(s) => EnvFilter::builder()
            .with_default_directive(default_level.into())
            .parse(s)
            .map_err(|e| InitError::Filter(e.to_string())),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("invalid log level directives (`log_level` / `TAIN_LOG_LEVEL`): {0}")]
    Filter(String),
    #[error("tracing subscriber already installed: {0}")]
    Install(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_formats() {
        assert_eq!("text".parse::<LogFormat>().unwrap(), LogFormat::Text);
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("JSON".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("  text  ".parse::<LogFormat>().unwrap(), LogFormat::Text);
    }

    #[test]
    fn rejects_unknown_format() {
        assert!("yaml".parse::<LogFormat>().is_err());
        assert!("".parse::<LogFormat>().is_err());
    }

    #[test]
    fn default_format_is_text() {
        assert_eq!(LogFormat::default(), LogFormat::Text);
    }

    #[test]
    fn filter_parses_directives() {
        let f = build_filter(Some("info,tain=debug")).unwrap();
        let _ = f;
    }

    #[test]
    fn with_scoped_runs_closure_for_both_formats() {
        for format in [LogFormat::Text, LogFormat::Json] {
            let cfg = LogConfig {
                format,
                filter: Some("debug".to_owned()),
            };
            assert_eq!(with_scoped(&cfg, || 42).unwrap(), 42);
        }
    }

    #[test]
    fn with_scoped_rejects_bad_filter() {
        let cfg = LogConfig {
            format: LogFormat::Text,
            filter: Some("!!invalid!!".to_owned()),
        };
        assert!(matches!(
            with_scoped(&cfg, || ()),
            Err(InitError::Filter(_))
        ));
    }

    #[test]
    fn filter_rejects_garbage() {
        let err = build_filter(Some("!!invalid!!")).unwrap_err();
        assert!(matches!(err, InitError::Filter(_)));
    }
}
