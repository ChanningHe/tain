//! Logging setup (text or JSON `tracing` subscriber on stderr) and
//! Prometheus textfile metrics.

pub mod metrics;

use std::io::{self, IsTerminal};
use std::str::FromStr;

use tracing::Level;
use tracing_subscriber::{
    EnvFilter,
    filter::LevelFilter,
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

/// Colour only on a terminal (never into journald, docker logs or files),
/// and not when `NO_COLOR` is set to a non-empty value (no-color.org).
fn use_ansi(stderr_is_terminal: bool, no_color: Option<&std::ffi::OsStr>) -> bool {
    stderr_is_terminal && no_color.is_none_or(|v| v.is_empty())
}

fn build_subscriber(cfg: &LogConfig) -> Result<BoxedSubscriber, InitError> {
    let filter = build_filter(cfg.filter.as_deref())?;
    let registry = tracing_subscriber::registry().with(filter);
    let layer = fmt::layer()
        .with_target(true)
        .with_span_events(FmtSpan::NONE)
        .with_ansi(use_ansi(
            io::stderr().is_terminal(),
            std::env::var_os("NO_COLOR").as_deref(),
        ))
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
            .parse(normalize_directives(s)?)
            .map_err(|e| InitError::Filter(e.to_string())),
    }
}

/// EnvFilter reads a bare word as a target name, so a misspelled level
/// (`warnn`) would silently filter out every log line. Bare words must be
/// levels; `warning` is accepted for `warn`, also after `target=`.
fn normalize_directives(s: &str) -> Result<String, InitError> {
    s.split(',')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(normalize_directive)
        .collect::<Result<Vec<_>, _>>()
        .map(|v| v.join(","))
}

fn normalize_directive(d: &str) -> Result<String, InitError> {
    if let Some((target, level)) = d.rsplit_once('=') {
        return Ok(if level.eq_ignore_ascii_case("warning") {
            format!("{target}=warn")
        } else {
            d.to_owned()
        });
    }
    if d.eq_ignore_ascii_case("warning") {
        return Ok("warn".to_owned());
    }
    // `[span]` filters and `a::b` targets are deliberate; plain words are not.
    if d.contains("::") || d.contains('[') || d.parse::<LevelFilter>().is_ok() {
        return Ok(d.to_owned());
    }
    Err(InitError::Filter(format!(
        "`{}` is not a level (trace, debug, info, warn, error, off); \
         use `target=level` to filter a module",
        d.escape_debug()
    )))
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
    fn ansi_only_on_terminal_without_no_color() {
        use std::ffi::OsStr;
        assert!(use_ansi(true, None));
        assert!(!use_ansi(false, None));
        assert!(!use_ansi(true, Some(OsStr::new("1"))));
        // https://no-color.org: an empty NO_COLOR does not disable colour.
        assert!(use_ansi(true, Some(OsStr::new(""))));
    }

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
    fn bare_words_must_be_levels() {
        for bad in ["nonsense", "bogus!!", "tain", "info,loud"] {
            let err = build_filter(Some(bad)).unwrap_err();
            assert!(matches!(err, InitError::Filter(_)), "{bad}: {err:?}");
        }
        for good in [
            "info",
            "WARN",
            "off",
            "debug,tain::core=trace",
            "tain=debug",
        ] {
            assert!(build_filter(Some(good)).is_ok(), "{good}");
        }
    }

    #[test]
    fn warning_is_an_alias_for_warn() {
        assert_eq!(normalize_directives("warning").unwrap(), "warn");
        assert_eq!(normalize_directives("WARNING").unwrap(), "warn");
        assert_eq!(
            normalize_directives("info, tain::core=Warning").unwrap(),
            "info,tain::core=warn"
        );
        assert!(build_filter(Some("warning")).is_ok());
    }

    #[test]
    fn filter_rejects_garbage() {
        let err = build_filter(Some("!!invalid!!")).unwrap_err();
        assert!(matches!(err, InitError::Filter(_)));
    }
}
