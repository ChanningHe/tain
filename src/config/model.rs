//! Resolved config model and its Option-ful partial counterparts.
//!
//! Partials compose via `inherit` (fill `None` from another partial) and
//! finalize via `build` (still-`None` fields take hardcoded defaults).

use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use url::Url;

use crate::observe::{LogConfig, LogFormat};

pub const DEFAULT_SEGMENT_MIN_SIZE: u64 = 256 * 1024 * 1024;

/// Global in-flight file budget.
pub const DEFAULT_PARALLEL: usize = 32;

/// Per-host in-flight *request* budget (not a TCP connection count).
pub const DEFAULT_HOST_CONNECTIONS: usize = 8;

pub const DEFAULT_SEGMENTS_PER_FILE: usize = 4;

/// Upper bound of `segments_per_file`; more connections per file only
/// burden the upstream.
pub const MAX_SEGMENTS_PER_FILE: usize = 8;

pub const DEFAULT_RETRY_COUNT: u32 = 3;

/// Covers both the metadata phase and the Release recheck loop.
pub const DEFAULT_INDEX_ROUNDS: u32 = 5;

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub const DEFAULT_GC_GRACE: Duration = Duration::from_secs(72 * 3600);

pub const DEFAULT_GC_MAX_DELETE_RATIO: f64 = 0.3;

pub const DEFAULT_KEEP_GENERATIONS: u32 = 3;

/// Zero = fail fast on lock contention; the timer/cron retries later.
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::ZERO;

#[derive(Debug, Clone)]
pub struct Config {
    pub global: GlobalConfig,
    pub mirrors: Vec<MirrorConfig>,
}

#[derive(Debug, Clone)]
pub struct GlobalConfig {
    pub target: PathBuf,
    pub parallel: usize,
    pub host_connections: usize,
    pub segments_per_file: usize,
    pub segment_min_size: u64,
    pub timeout: TimeoutConfig,
    pub retry: RetryConfig,
    pub bind_address: Option<IpAddr>,
    pub user_agent: String,
    pub log: LogSettings,
    /// Raw cron expression; parsed at daemon start.
    pub schedule: Option<String>,
    pub lock_timeout: Duration,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            target: PathBuf::from("/data"),
            parallel: DEFAULT_PARALLEL,
            host_connections: DEFAULT_HOST_CONNECTIONS,
            segments_per_file: DEFAULT_SEGMENTS_PER_FILE,
            segment_min_size: DEFAULT_SEGMENT_MIN_SIZE,
            timeout: TimeoutConfig::default(),
            retry: RetryConfig::default(),
            bind_address: None,
            user_agent: format!("tain/{}", env!("CARGO_PKG_VERSION")),
            log: LogSettings::default(),
            schedule: None,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutConfig {
    pub connect: Duration,
    pub read_idle: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect: DEFAULT_CONNECT_TIMEOUT,
            read_idle: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryConfig {
    pub count: u32,
    pub index_rounds: u32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            count: DEFAULT_RETRY_COUNT,
            index_rounds: DEFAULT_INDEX_ROUNDS,
        }
    }
}

/// TOML `log_level`/`log_format`, overridden by `TAIN_LOG_*`. Applied once at
/// startup; a daemon reload does not re-read it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSettings {
    pub level: Option<String>,
    pub format: LogFormat,
}

impl From<&LogSettings> for LogConfig {
    fn from(s: &LogSettings) -> Self {
        Self {
            format: s.format,
            filter: s.level.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendKind {
    #[default]
    Apt,
}

impl BackendKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Apt => "apt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MirrorConfig {
    pub name: String,
    pub backend: BackendKind,
    pub url: Url,
    /// Relative to `global.target`; defaults to `name`.
    pub path: PathBuf,
    pub verify: VerifyConfig,
    pub gc: GcConfig,
    /// Skip ALPN/H2 for CDNs that mishandle large H2 transfers.
    pub force_http1: bool,
    pub backend_options: BackendOptions,
}

#[derive(Debug, Clone)]
pub enum BackendOptions {
    Apt(AptOptions),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifyConfig {
    pub pgp: PgpMode,
    pub keyring: Option<PathBuf>,
    pub allow_weak_hash: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PgpMode {
    #[default]
    Off,
    IfPresent,
    Required,
}

impl PgpMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::IfPresent => "if-present",
            Self::Required => "required",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcConfig {
    pub enabled: bool,
    pub grace_period: Duration,
    pub max_delete_ratio: FloatRatio,
    pub keep_generations: u32,
    pub dry_run: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            grace_period: DEFAULT_GC_GRACE,
            max_delete_ratio: FloatRatio::from_default_max_delete(),
            keep_generations: DEFAULT_KEEP_GENERATIONS,
            dry_run: false,
        }
    }
}

/// A ratio in `0.0..=1.0`, stored as parts-per-million so it can be `Eq`.
#[derive(Debug, Clone, Copy)]
pub struct FloatRatio(u32);

impl FloatRatio {
    const SCALE: u32 = 1_000_000;

    pub fn new(v: f64) -> Result<Self, ConfigError> {
        if !v.is_finite() || !(0.0..=1.0).contains(&v) {
            return Err(ConfigError::InvalidRatio(v));
        }
        // In range after the check above, so the cast cannot truncate.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let raw = (v * f64::from(Self::SCALE)).round() as u32;
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_f64(self) -> f64 {
        f64::from(self.0) / f64::from(Self::SCALE)
    }

    fn from_default_max_delete() -> Self {
        Self::new(DEFAULT_GC_MAX_DELETE_RATIO).expect("hardcoded default is in range")
    }
}

impl PartialEq for FloatRatio {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for FloatRatio {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptOptions {
    pub suites: Vec<String>,
    pub components: Vec<String>,
    pub architectures: Vec<String>,
    pub indexes: IndexSelection,
    pub create_suite_symlinks: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSelection {
    /// Always `true`; stored so consumers cannot forget the layer.
    pub packages: bool,
    pub contents: bool,
    pub i18n: I18nSelection,
    pub dep11: bool,
    pub cnf: bool,
    pub sources: bool,
    pub debian_installer: bool,
}

impl Default for IndexSelection {
    fn default() -> Self {
        Self {
            packages: true,
            contents: true,
            i18n: I18nSelection::All,
            dep11: true,
            cnf: true,
            sources: false,
            debian_installer: false,
        }
    }
}

/// TOML `i18n`: `true`, `false`, or a language list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum I18nSelection {
    All,
    None,
    Only(Vec<String>),
}

/// The mergeable part of a mirror, shared by `[defaults]` and `[[mirror]]`.
#[derive(Debug, Clone, Default)]
pub struct MirrorDefaults {
    pub backend: Option<BackendKind>,
    pub path: Option<PathBuf>,
    pub verify: PartialVerifyConfig,
    pub gc: PartialGcConfig,
    pub apt: PartialAptOptions,
}

impl MirrorDefaults {
    /// Fill `None` fields from `other`; `self` wins.
    pub fn inherit(&mut self, other: &Self) {
        if self.backend.is_none() {
            self.backend = other.backend;
        }
        if self.path.is_none() {
            self.path.clone_from(&other.path);
        }
        self.verify.inherit(&other.verify);
        self.gc.inherit(&other.gc);
        self.apt.inherit(&other.apt);
    }
}

/// One `[[mirror]]` block: identity plus mergeable overrides.
#[derive(Debug, Clone)]
pub struct PartialMirror {
    pub name: String,
    pub url: Url,
    pub overrides: MirrorDefaults,
    pub force_http1: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct PartialVerifyConfig {
    pub pgp: Option<PgpMode>,
    pub keyring: Option<PathBuf>,
    pub allow_weak_hash: Option<bool>,
}

impl PartialVerifyConfig {
    pub fn inherit(&mut self, other: &Self) {
        if self.pgp.is_none() {
            self.pgp = other.pgp;
        }
        if self.keyring.is_none() {
            self.keyring.clone_from(&other.keyring);
        }
        if self.allow_weak_hash.is_none() {
            self.allow_weak_hash = other.allow_weak_hash;
        }
    }

    fn build(self) -> VerifyConfig {
        let d = VerifyConfig::default();
        VerifyConfig {
            pgp: self.pgp.unwrap_or(d.pgp),
            keyring: self.keyring.or(d.keyring),
            allow_weak_hash: self.allow_weak_hash.unwrap_or(d.allow_weak_hash),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PartialGcConfig {
    pub enabled: Option<bool>,
    pub grace_period: Option<Duration>,
    pub max_delete_ratio: Option<FloatRatio>,
    pub keep_generations: Option<u32>,
    pub dry_run: Option<bool>,
}

impl PartialGcConfig {
    pub fn inherit(&mut self, other: &Self) {
        if self.enabled.is_none() {
            self.enabled = other.enabled;
        }
        if self.grace_period.is_none() {
            self.grace_period = other.grace_period;
        }
        if self.max_delete_ratio.is_none() {
            self.max_delete_ratio = other.max_delete_ratio;
        }
        if self.keep_generations.is_none() {
            self.keep_generations = other.keep_generations;
        }
        if self.dry_run.is_none() {
            self.dry_run = other.dry_run;
        }
    }

    fn build(self) -> GcConfig {
        let d = GcConfig::default();
        GcConfig {
            enabled: self.enabled.unwrap_or(d.enabled),
            grace_period: self.grace_period.unwrap_or(d.grace_period),
            max_delete_ratio: self.max_delete_ratio.unwrap_or(d.max_delete_ratio),
            keep_generations: self.keep_generations.unwrap_or(d.keep_generations),
            dry_run: self.dry_run.unwrap_or(d.dry_run),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PartialAptOptions {
    pub suites: Option<Vec<String>>,
    pub components: Option<Vec<String>>,
    pub architectures: Option<Vec<String>>,
    pub indexes: PartialIndexSelection,
    pub create_suite_symlinks: Option<bool>,
}

impl PartialAptOptions {
    pub fn inherit(&mut self, other: &Self) {
        if self.suites.is_none() {
            self.suites.clone_from(&other.suites);
        }
        if self.components.is_none() {
            self.components.clone_from(&other.components);
        }
        if self.architectures.is_none() {
            self.architectures.clone_from(&other.architectures);
        }
        self.indexes.inherit(&other.indexes);
        if self.create_suite_symlinks.is_none() {
            self.create_suite_symlinks = other.create_suite_symlinks;
        }
    }

    fn build(self, mirror_name: &str) -> Result<AptOptions, ConfigError> {
        let suites =
            self.suites
                .filter(|s| !s.is_empty())
                .ok_or_else(|| ConfigError::MissingField {
                    mirror: mirror_name.to_owned(),
                    field: "suites",
                })?;
        // Index selection has no flat-repo path; such a suite would never sync.
        if let Some(suite) = suites.iter().find(|s| is_flat_suite(s)) {
            return Err(ConfigError::FlatRepositoryUnsupported {
                mirror: mirror_name.to_owned(),
                suite: suite.clone(),
            });
        }
        let architectures = self
            .architectures
            .filter(|a| !a.is_empty())
            .ok_or_else(|| ConfigError::MissingField {
                mirror: mirror_name.to_owned(),
                field: "architectures",
            })?;
        Ok(AptOptions {
            suites,
            // Empty components are rejected by the backend's `validate_config` at load.
            components: self.components.unwrap_or_default(),
            architectures,
            indexes: self.indexes.build(),
            create_suite_symlinks: self.create_suite_symlinks.unwrap_or(true),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct PartialIndexSelection {
    pub contents: Option<bool>,
    pub i18n: Option<I18nSelection>,
    pub dep11: Option<bool>,
    pub cnf: Option<bool>,
    pub sources: Option<bool>,
    pub debian_installer: Option<bool>,
}

impl PartialIndexSelection {
    pub fn inherit(&mut self, other: &Self) {
        if self.contents.is_none() {
            self.contents = other.contents;
        }
        if self.i18n.is_none() {
            self.i18n.clone_from(&other.i18n);
        }
        if self.dep11.is_none() {
            self.dep11 = other.dep11;
        }
        if self.cnf.is_none() {
            self.cnf = other.cnf;
        }
        if self.sources.is_none() {
            self.sources = other.sources;
        }
        if self.debian_installer.is_none() {
            self.debian_installer = other.debian_installer;
        }
    }

    fn build(self) -> IndexSelection {
        let d = IndexSelection::default();
        IndexSelection {
            packages: true, // always synced
            contents: self.contents.unwrap_or(d.contents),
            i18n: normalize_i18n(self.i18n.unwrap_or(d.i18n)),
            dep11: self.dep11.unwrap_or(d.dep11),
            cnf: self.cnf.unwrap_or(d.cnf),
            sources: self.sources.unwrap_or(d.sources),
            debian_installer: self.debian_installer.unwrap_or(d.debian_installer),
        }
    }
}

/// Dedup `Only` language tags case-insensitively, keeping the first spelling.
/// Upstream tags are mixed-case (`Translation-zh_CN`), so the index selector
/// matches case-insensitively and the configured spelling is kept as written.
#[must_use]
pub fn normalize_i18n(sel: I18nSelection) -> I18nSelection {
    let I18nSelection::Only(langs) = sel else {
        return sel;
    };
    let mut normalized: Vec<String> = Vec::with_capacity(langs.len());
    for lang in langs {
        if !normalized.iter().any(|l| l.eq_ignore_ascii_case(&lang)) {
            normalized.push(lang);
        }
    }
    I18nSelection::Only(normalized)
}

/// Precedence: per-mirror field > `[defaults]` > hardcoded default.
pub fn resolve_mirror(
    mut partial: PartialMirror,
    defaults: &MirrorDefaults,
) -> Result<MirrorConfig, ConfigError> {
    partial.overrides.inherit(defaults);

    let name = partial.name;
    if name.trim().is_empty() {
        return Err(ConfigError::EmptyName);
    }

    let backend = partial.overrides.backend.unwrap_or_default();

    let path = partial
        .overrides
        .path
        .unwrap_or_else(|| PathBuf::from(name.clone()));

    let verify = partial.overrides.verify.build();
    if verify.pgp != PgpMode::Off && verify.keyring.is_none() {
        return Err(ConfigError::PgpWithoutKeyring {
            mirror: name,
            pgp: verify.pgp,
        });
    }
    let gc = partial.overrides.gc.build();

    let backend_options = match backend {
        BackendKind::Apt => BackendOptions::Apt(partial.overrides.apt.build(&name)?),
    };

    Ok(MirrorConfig {
        name,
        backend,
        url: partial.url,
        path,
        verify,
        gc,
        force_http1: partial.force_http1.unwrap_or(false),
        backend_options,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("mirror name is empty or whitespace-only")]
    EmptyName,
    #[error("mirror `{mirror}` is missing required field `{field}`")]
    MissingField { mirror: String, field: &'static str },
    #[error("ratio `{0}` is not finite or is outside 0.0..=1.0")]
    InvalidRatio(f64),
    #[error(
        "mirror name `{0}` is defined more than once — names are the identity used for state, \
         locks, and layout"
    )]
    DuplicateName(String),
    #[error(
        "mirror `{mirror}`: suite `{suite}` is a flat repository; flat repositories are not \
         supported in this release"
    )]
    FlatRepositoryUnsupported { mirror: String, suite: String },
    #[error(
        "mirror `{mirror}`: verify.pgp = \"{}\" requires verify.keyring",
        pgp.as_str()
    )]
    PgpWithoutKeyring { mirror: String, pgp: PgpMode },
    #[error(
        "global.target must be a non-empty absolute path (from TOML or `TAIN_TARGET`), got `{}`",
        .0.display()
    )]
    InvalidTarget(PathBuf),
    #[error("mirror name {0:?} must not contain control characters")]
    InvalidName(String),
    #[error(
        "the configuration defines no mirrors; add a [[mirror]] block or set TAIN_URL + \
         TAIN_DISTS"
    )]
    NoMirrors,
    #[error("mirror `{mirror}`: {field} value {value:?} must not contain control characters")]
    ControlChars {
        mirror: String,
        field: &'static str,
        value: String,
    },
    // Paths print with `{:?}` so control characters arrive escaped.
    #[error(
        "mirror `{mirror}`: path {path:?} {reason} (the path is relative to global.target and \
         defaults to the mirror name)"
    )]
    InvalidPath {
        mirror: String,
        path: PathBuf,
        reason: &'static str,
    },
    #[error(
        "mirrors `{first}` and `{second}` share directory {path:?}; each mirror needs its own path"
    )]
    DuplicatePath {
        first: String,
        second: String,
        path: PathBuf,
    },
    #[error(
        "mirror `{inner}` (path {inner_path:?}) is nested inside mirror `{outer}` (path \
         {outer_path:?}); mirror directories must not overlap"
    )]
    NestedPath {
        outer: String,
        outer_path: PathBuf,
        inner: String,
        inner_path: PathBuf,
    },
    #[error("mirror `{mirror}`: url `{url}` must use http or https")]
    UnsupportedScheme { mirror: String, url: String },
    /// Rejected by the backend's `validate_config`.
    #[error("{0}")]
    Backend(String),
    #[error(
        "segments_per_file (`TAIN_SEGMENTS`) must be between 1 and {MAX_SEGMENTS_PER_FILE}, \
         got {0}"
    )]
    InvalidSegments(usize),
}

impl Config {
    /// Every model-level check: `validate_mirrors` plus an absolute target.
    /// Run on the final config, after env overrides.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.global.target.is_absolute() {
            return Err(ConfigError::InvalidTarget(self.global.target.clone()));
        }
        let segments = self.global.segments_per_file;
        if !(1..=MAX_SEGMENTS_PER_FILE).contains(&segments) {
            return Err(ConfigError::InvalidSegments(segments));
        }
        self.validate_mirrors()
    }

    /// Commands that act on mirrors refuse a config with none.
    pub fn require_mirrors(&self) -> Result<(), ConfigError> {
        if self.mirrors.is_empty() {
            return Err(ConfigError::NoMirrors);
        }
        Ok(())
    }

    /// Unique, printable names, http(s) URLs, and mirror paths that stay
    /// inside the target without sharing or nesting. Target-independent, so
    /// a source can check it before env overrides are applied.
    pub fn validate_mirrors(&self) -> Result<(), ConfigError> {
        let mut seen = std::collections::BTreeSet::new();
        let mut paths: Vec<(PathBuf, &str)> = Vec::with_capacity(self.mirrors.len());
        for m in &self.mirrors {
            if has_control_chars(&m.name) {
                return Err(ConfigError::InvalidName(m.name.clone()));
            }
            check_apt_fields(m)?;
            if !seen.insert(m.name.as_str()) {
                return Err(ConfigError::DuplicateName(m.name.clone()));
            }
            if !matches!(m.url.scheme(), "http" | "https") {
                return Err(ConfigError::UnsupportedScheme {
                    mirror: m.name.clone(),
                    url: m.url.to_string(),
                });
            }
            let path =
                normalize_mirror_path(&m.path).map_err(|reason| ConfigError::InvalidPath {
                    mirror: m.name.clone(),
                    path: m.path.clone(),
                    reason,
                })?;
            paths.push((path, m.name.as_str()));
        }
        check_disjoint_paths(paths)
    }
}

/// The one control-character rule (C0, DEL and C1, e.g. U+0085) for every
/// value that becomes a directory or a log field.
#[must_use]
pub fn has_control_chars(s: &str) -> bool {
    s.chars().any(char::is_control)
}

/// Suites, components and architectures become directory names.
fn check_apt_fields(m: &MirrorConfig) -> Result<(), ConfigError> {
    let BackendOptions::Apt(apt) = &m.backend_options;
    let fields = [
        ("suites", &apt.suites),
        ("components", &apt.components),
        ("architectures", &apt.architectures),
    ];
    for (field, values) in fields {
        if let Some(value) = values.iter().find(|v| has_control_chars(v)) {
            return Err(ConfigError::ControlChars {
                mirror: m.name.clone(),
                field,
                value: value.clone(),
            });
        }
    }
    Ok(())
}

/// Lexically normalize a mirror path: drop `.` components and reject
/// anything absolute, climbing with `..`, naming the target itself, or
/// containing control characters (NUL truncates C paths; others garble logs).
///
/// # Errors
///
/// A short reason, as used by `ConfigError::InvalidPath`.
pub fn normalize_mirror_path(path: &Path) -> Result<PathBuf, &'static str> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(part) if has_control_chars(&part.to_string_lossy()) => {
                return Err("must not contain control characters");
            }
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir => return Err("must not contain `..`"),
            Component::RootDir | Component::Prefix(_) => return Err("must be relative"),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("must name a subdirectory, not the target itself");
    }
    Ok(out)
}

/// Reject duplicate or nested mirror directories. Sorting puts every
/// ancestor before its descendants (component-wise order).
fn check_disjoint_paths(mut paths: Vec<(PathBuf, &str)>) -> Result<(), ConfigError> {
    paths.sort();
    for (i, (path, name)) in paths.iter().enumerate() {
        let Some((outer_path, outer)) = paths[..i].iter().find(|(p, _)| path.starts_with(p)) else {
            continue;
        };
        return Err(if outer_path == path {
            ConfigError::DuplicatePath {
                first: (*outer).to_owned(),
                second: (*name).to_owned(),
                path: path.clone(),
            }
        } else {
            ConfigError::NestedPath {
                outer: (*outer).to_owned(),
                outer_path: outer_path.clone(),
                inner: (*name).to_owned(),
                inner_path: path.clone(),
            }
        });
    }
    Ok(())
}

/// Apt's rule: a suite ending in `/`, or a bare `.`, is a flat-repo path.
/// `stable/updates` is not flat.
#[must_use]
pub fn is_flat_suite(s: &str) -> bool {
    s == "." || s.ends_with('/')
}

impl AptOptions {
    #[cfg(test)]
    pub(crate) fn test_new(
        suites: Vec<String>,
        components: Vec<String>,
        architectures: Vec<String>,
    ) -> Self {
        Self {
            suites,
            components,
            architectures,
            indexes: IndexSelection::default(),
            create_suite_symlinks: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_defaults_match_docs() {
        // Tripwire: keep in sync with the documented defaults table.
        let g = GlobalConfig::default();
        assert_eq!(g.target, PathBuf::from("/data"));
        assert_eq!(g.parallel, 32);
        assert_eq!(g.host_connections, 8);
        assert_eq!(g.segments_per_file, 4);
        assert_eq!(g.segment_min_size, 256 * 1024 * 1024);
        assert_eq!(g.timeout.connect, Duration::from_secs(30));
        assert_eq!(g.timeout.read_idle, Duration::from_secs(60));
        assert_eq!(g.retry.count, 3);
        assert_eq!(g.retry.index_rounds, 5);
        assert!(g.bind_address.is_none());
        assert!(g.user_agent.starts_with("tain/"));
        assert!(g.schedule.is_none());
        assert_eq!(g.lock_timeout, Duration::ZERO);
    }

    #[test]
    fn log_settings_convert_to_subscriber_config() {
        let default = LogConfig::from(&LogSettings::default());
        assert_eq!(default.format, LogFormat::Text);
        assert!(default.filter.is_none());

        let s = LogSettings {
            level: Some("debug,tain::core=trace".to_owned()),
            format: LogFormat::Json,
        };
        let c = LogConfig::from(&s);
        assert_eq!(c.format, LogFormat::Json);
        assert_eq!(c.filter.as_deref(), Some("debug,tain::core=trace"));
    }

    #[test]
    fn verify_defaults() {
        let v = VerifyConfig::default();
        assert_eq!(v.pgp, PgpMode::Off);
        assert!(v.keyring.is_none());
        assert!(!v.allow_weak_hash);
    }

    #[test]
    fn gc_defaults() {
        let g = GcConfig::default();
        assert!(!g.enabled, "enabled=false is the safe-side default");
        assert_eq!(g.grace_period, Duration::from_secs(72 * 3600));
        assert!((g.max_delete_ratio.as_f64() - 0.3).abs() < 1e-9);
        assert_eq!(g.keep_generations, 3);
        assert!(!g.dry_run);
    }

    #[test]
    fn index_defaults() {
        let i = IndexSelection::default();
        assert!(i.packages);
        assert!(i.contents);
        assert_eq!(i.i18n, I18nSelection::All);
        assert!(i.dep11);
        assert!(i.cnf);
        assert!(!i.sources);
        assert!(!i.debian_installer);
    }

    fn build_i18n(sel: I18nSelection) -> I18nSelection {
        let partial = PartialIndexSelection {
            i18n: Some(sel),
            ..Default::default()
        };
        partial.build().i18n
    }

    #[test]
    fn i18n_only_langs_keep_configured_case() {
        let out = build_i18n(I18nSelection::Only(vec!["zh_CN".into(), "pt_BR".into()]));
        assert_eq!(
            out,
            I18nSelection::Only(vec!["zh_CN".into(), "pt_BR".into()])
        );
    }

    #[test]
    fn i18n_only_duplicate_case_variants_collapse_to_first_spelling() {
        let out = build_i18n(I18nSelection::Only(vec![
            "zh_CN".into(),
            "zh_cn".into(),
            "ZH_CN".into(),
        ]));
        assert_eq!(out, I18nSelection::Only(vec!["zh_CN".into()]));
    }

    #[test]
    fn i18n_all_and_none_untouched_by_normalizer() {
        assert_eq!(build_i18n(I18nSelection::All), I18nSelection::All);
        assert_eq!(build_i18n(I18nSelection::None), I18nSelection::None);
    }

    #[test]
    fn i18n_only_already_lowercase_preserves_order() {
        let out = build_i18n(I18nSelection::Only(vec![
            "en".into(),
            "zh_cn".into(),
            "de".into(),
        ]));
        assert_eq!(
            out,
            I18nSelection::Only(vec!["en".into(), "zh_cn".into(), "de".into()])
        );
    }

    #[test]
    fn float_ratio_rejects_out_of_range() {
        assert!(FloatRatio::new(-0.1).is_err());
        assert!(FloatRatio::new(1.1).is_err());
        assert!(FloatRatio::new(f64::NAN).is_err());
        assert!(FloatRatio::new(f64::INFINITY).is_err());
        assert!(FloatRatio::new(0.0).is_ok());
        assert!(FloatRatio::new(1.0).is_ok());
        assert!(FloatRatio::new(0.5).is_ok());
    }

    #[test]
    fn float_ratio_roundtrips() {
        let r = FloatRatio::new(0.25).unwrap();
        assert!((r.as_f64() - 0.25).abs() < 1e-9);
    }

    fn partial_mirror(name: &str, url: &str) -> PartialMirror {
        PartialMirror {
            name: name.to_owned(),
            url: Url::parse(url).unwrap(),
            overrides: MirrorDefaults::default(),
            force_http1: None,
        }
    }

    fn apt_only(mut p: PartialMirror, suites: &[&str], archs: &[&str]) -> PartialMirror {
        p.overrides.apt.suites = Some(suites.iter().map(|s| (*s).to_owned()).collect());
        p.overrides.apt.architectures = Some(archs.iter().map(|s| (*s).to_owned()).collect());
        p
    }

    #[test]
    fn resolve_mirror_uses_hardcoded_defaults_when_nothing_overrides() {
        let p = apt_only(
            partial_mirror("proxmox", "https://example.com/"),
            &["bookworm"],
            &["amd64"],
        );
        let m = resolve_mirror(p, &MirrorDefaults::default()).unwrap();
        assert_eq!(m.name, "proxmox");
        assert_eq!(m.backend, BackendKind::Apt);
        assert_eq!(m.path, PathBuf::from("proxmox"));
        assert_eq!(m.verify, VerifyConfig::default());
        assert_eq!(m.gc, GcConfig::default());
        match m.backend_options {
            BackendOptions::Apt(apt) => {
                assert_eq!(apt.suites, vec!["bookworm".to_owned()]);
                assert_eq!(apt.architectures, vec!["amd64".to_owned()]);
                assert!(apt.components.is_empty());
                assert!(apt.create_suite_symlinks);
                assert_eq!(apt.indexes, IndexSelection::default());
            }
        }
    }

    #[test]
    fn defaults_flow_into_mirror() {
        let mut defaults = MirrorDefaults::default();
        defaults.apt.architectures = Some(vec!["amd64".to_owned(), "arm64".to_owned()]);
        defaults.gc.enabled = Some(true);
        defaults.gc.grace_period = Some(Duration::from_secs(48 * 3600));
        defaults.verify.pgp = Some(PgpMode::Required);
        defaults.verify.keyring = Some(PathBuf::from("/etc/keys.gpg"));

        let mut p = partial_mirror("debian", "https://deb.debian.org/debian");
        p.overrides.apt.suites = Some(vec!["bookworm".to_owned()]);

        let m = resolve_mirror(p, &defaults).unwrap();
        match &m.backend_options {
            BackendOptions::Apt(apt) => {
                assert_eq!(
                    apt.architectures,
                    vec!["amd64".to_owned(), "arm64".to_owned()]
                );
            }
        }
        assert!(m.gc.enabled);
        assert_eq!(m.gc.grace_period, Duration::from_secs(48 * 3600));
        assert_eq!(m.verify.pgp, PgpMode::Required);
        assert_eq!(
            m.verify.keyring.as_deref(),
            Some(std::path::Path::new("/etc/keys.gpg"))
        );
    }

    #[test]
    fn per_mirror_wins_over_defaults() {
        let mut defaults = MirrorDefaults::default();
        defaults.apt.architectures = Some(vec!["amd64".to_owned()]);
        defaults.verify.pgp = Some(PgpMode::Required);

        let mut p = partial_mirror("proxmox", "https://example.com/");
        p.overrides.apt.suites = Some(vec!["bookworm".to_owned()]);
        p.overrides.apt.architectures = Some(vec!["arm64".to_owned()]);
        p.overrides.verify.pgp = Some(PgpMode::Off);

        let m = resolve_mirror(p, &defaults).unwrap();
        match &m.backend_options {
            BackendOptions::Apt(apt) => {
                assert_eq!(apt.architectures, vec!["arm64".to_owned()]);
            }
        }
        assert_eq!(m.verify.pgp, PgpMode::Off);
    }

    #[test]
    fn missing_suites_errors() {
        let mut p = partial_mirror("proxmox", "https://example.com/");
        p.overrides.apt.architectures = Some(vec!["amd64".to_owned()]);
        let err = resolve_mirror(p, &MirrorDefaults::default()).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::MissingField {
                field: "suites",
                ..
            }
        ));
    }

    #[test]
    fn missing_architectures_errors() {
        let mut p = partial_mirror("proxmox", "https://example.com/");
        p.overrides.apt.suites = Some(vec!["bookworm".to_owned()]);
        let err = resolve_mirror(p, &MirrorDefaults::default()).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::MissingField {
                field: "architectures",
                ..
            }
        ));
    }

    #[test]
    fn empty_name_rejected() {
        let mut p = partial_mirror("   ", "https://example.com/");
        p.overrides.apt.suites = Some(vec!["bookworm".to_owned()]);
        p.overrides.apt.architectures = Some(vec!["amd64".to_owned()]);
        let err = resolve_mirror(p, &MirrorDefaults::default()).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyName));
    }

    #[test]
    fn empty_suites_treated_as_missing() {
        let mut p = partial_mirror("proxmox", "https://example.com/");
        p.overrides.apt.suites = Some(vec![]);
        p.overrides.apt.architectures = Some(vec!["amd64".to_owned()]);
        let err = resolve_mirror(p, &MirrorDefaults::default()).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::MissingField {
                field: "suites",
                ..
            }
        ));
    }

    fn flat_suite_error(suites: &[&str]) -> ConfigError {
        let mut p = partial_mirror("vendor-flat", "https://example.com/");
        p.overrides.apt.suites = Some(suites.iter().map(|s| (*s).to_owned()).collect());
        p.overrides.apt.architectures = Some(vec!["amd64".to_owned()]);
        resolve_mirror(p, &MirrorDefaults::default()).unwrap_err()
    }

    #[test]
    fn flat_suites_rejected_at_config_load() {
        for suite in ["./", ".", "repo/./", "stable/"] {
            match flat_suite_error(&[suite]) {
                ConfigError::FlatRepositoryUnsupported { mirror, suite: got } => {
                    assert_eq!(mirror, "vendor-flat");
                    assert_eq!(got, suite);
                }
                other => panic!("expected FlatRepositoryUnsupported for {suite}, got {other:?}"),
            }
        }
    }

    #[test]
    fn flat_suite_error_message_is_explicit() {
        let msg = flat_suite_error(&["repo/./"]).to_string();
        assert!(msg.contains("vendor-flat"), "{msg}");
        assert!(msg.contains("repo/./"), "{msg}");
        assert!(msg.contains("flat repositories are not supported"), "{msg}");
    }

    #[test]
    fn mixed_flat_and_dists_suites_rejected() {
        let err = flat_suite_error(&["bookworm", "repo/./"]);
        assert!(
            matches!(&err, ConfigError::FlatRepositoryUnsupported { suite, .. } if suite == "repo/./"),
            "{err:?}"
        );
    }

    #[test]
    fn slash_suites_are_not_flat() {
        let p = apt_only(
            partial_mirror("security", "https://example.com/"),
            &["stable/updates", "bookworm-security"],
            &["amd64"],
        );
        resolve_mirror(p, &MirrorDefaults::default()).unwrap();
    }

    fn pgp_mirror(pgp: PgpMode, keyring: Option<&str>) -> PartialMirror {
        let mut p = apt_only(
            partial_mirror("signed", "https://example.com/"),
            &["bookworm"],
            &["amd64"],
        );
        p.overrides.verify.pgp = Some(pgp);
        p.overrides.verify.keyring = keyring.map(PathBuf::from);
        p
    }

    #[test]
    fn pgp_without_keyring_rejected() {
        for mode in [PgpMode::IfPresent, PgpMode::Required] {
            let err =
                resolve_mirror(pgp_mirror(mode, None), &MirrorDefaults::default()).unwrap_err();
            match &err {
                ConfigError::PgpWithoutKeyring { mirror, pgp } => {
                    assert_eq!(mirror, "signed");
                    assert_eq!(*pgp, mode);
                }
                other => panic!("expected PgpWithoutKeyring, got {other:?}"),
            }
            let msg = err.to_string();
            assert!(msg.contains("signed") && msg.contains("keyring"), "{msg}");
            assert!(msg.contains(mode.as_str()), "{msg}");
        }
    }

    #[test]
    fn pgp_with_keyring_accepted() {
        for mode in [PgpMode::IfPresent, PgpMode::Required] {
            let m = resolve_mirror(
                pgp_mirror(mode, Some("/etc/keys.gpg")),
                &MirrorDefaults::default(),
            )
            .unwrap();
            assert_eq!(m.verify.pgp, mode);
        }
    }

    #[test]
    fn pgp_off_needs_no_keyring() {
        resolve_mirror(pgp_mirror(PgpMode::Off, None), &MirrorDefaults::default()).unwrap();
    }

    /// The check runs on the merged mirror, so `[defaults]` values count.
    #[test]
    fn pgp_keyring_check_sees_inherited_values() {
        let mut defaults = MirrorDefaults::default();
        defaults.verify.keyring = Some(PathBuf::from("/etc/keys.gpg"));
        let mut p = pgp_mirror(PgpMode::Required, None);
        p.overrides.verify.keyring = None;
        resolve_mirror(p, &defaults).unwrap();

        let mut defaults = MirrorDefaults::default();
        defaults.verify.pgp = Some(PgpMode::IfPresent);
        let p = apt_only(
            partial_mirror("inherits", "https://example.com/"),
            &["bookworm"],
            &["amd64"],
        );
        let err = resolve_mirror(p, &defaults).unwrap_err();
        assert!(
            matches!(&err, ConfigError::PgpWithoutKeyring { mirror, .. } if mirror == "inherits"),
            "{err:?}"
        );
    }

    #[test]
    fn path_defaults_to_name() {
        let p = apt_only(
            partial_mirror("proxmox", "https://example.com/"),
            &["bookworm"],
            &["amd64"],
        );
        let m = resolve_mirror(p, &MirrorDefaults::default()).unwrap();
        assert_eq!(m.path, PathBuf::from("proxmox"));
    }

    #[test]
    fn explicit_path_wins() {
        let mut p = apt_only(
            partial_mirror("proxmox", "https://example.com/"),
            &["bookworm"],
            &["amd64"],
        );
        p.overrides.path = Some(PathBuf::from("debian/pve"));
        let m = resolve_mirror(p, &MirrorDefaults::default()).unwrap();
        assert_eq!(m.path, PathBuf::from("debian/pve"));
    }

    #[test]
    fn indexes_inherit_and_override_individually() {
        let mut defaults = MirrorDefaults::default();
        defaults.apt.architectures = Some(vec!["amd64".to_owned()]);
        defaults.apt.indexes.contents = Some(false);
        defaults.apt.indexes.i18n = Some(I18nSelection::Only(vec!["en".to_owned()]));

        let mut p = partial_mirror("d", "https://example.com/");
        p.overrides.apt.suites = Some(vec!["bookworm".to_owned()]);
        // Override just sources — inherit contents (false) and i18n (Only[en]).
        p.overrides.apt.indexes.sources = Some(true);

        let m = resolve_mirror(p, &defaults).unwrap();
        match m.backend_options {
            BackendOptions::Apt(apt) => {
                assert!(!apt.indexes.contents);
                assert_eq!(apt.indexes.i18n, I18nSelection::Only(vec!["en".to_owned()]));
                assert!(apt.indexes.sources);
                // untouched fields keep hardcoded defaults
                assert!(apt.indexes.dep11);
                assert!(apt.indexes.cnf);
                assert!(!apt.indexes.debian_installer);
                assert!(apt.indexes.packages);
            }
        }
    }

    fn cfg_with(target: &str, mirrors: &[(&str, &str, Option<&str>)]) -> Config {
        let mirrors = mirrors
            .iter()
            .map(|(name, url, path)| {
                let mut p = apt_only(partial_mirror(name, url), &["bookworm"], &["amd64"]);
                p.overrides.path = path.map(PathBuf::from);
                resolve_mirror(p, &MirrorDefaults::default()).unwrap()
            })
            .collect();
        Config {
            global: GlobalConfig {
                target: PathBuf::from(target),
                ..GlobalConfig::default()
            },
            mirrors,
        }
    }

    const URL: &str = "https://example.com/";

    #[test]
    fn validate_accepts_disjoint_relative_paths() {
        let cfg = cfg_with(
            "/srv/mirrors",
            &[
                ("debian", URL, None),
                ("pve", URL, Some("proxmox/pve")),
                ("ceph", URL, Some("./proxmox/ceph")),
                ("debian-security", "http://example.com/", None),
            ],
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_bad_mirror_paths() {
        let cases: &[(&str, Option<&str>, &str)] = &[
            ("abs", Some("/etc"), "must be relative"),
            ("up", Some("../x"), "`..`"),
            ("mid-up", Some("a/../../x"), "`..`"),
            ("empty", Some(""), "subdirectory"),
            ("dot", Some("."), "subdirectory"),
            ("dot-slash", Some("./"), "subdirectory"),
            ("nul", Some("a\0b"), "control characters"),
            ("newline", Some("a/b\nc"), "control characters"),
            ("c1", Some("a\u{85}b"), "control characters"),
            // The name is the default path, so it obeys the same rules.
            ("../../etc", None, "`..`"),
            ("..", None, "`..`"),
            (".", None, "subdirectory"),
        ];
        for (name, path, reason) in cases {
            let err = cfg_with("/data", &[(name, URL, *path)])
                .validate()
                .unwrap_err();
            assert!(
                matches!(&err, ConfigError::InvalidPath { mirror, .. } if mirror == name),
                "{name}/{path:?}: {err:?}"
            );
            assert!(err.to_string().contains(reason), "{err}");
        }
    }

    #[test]
    fn validate_rejects_shared_paths_after_normalization() {
        for (a, b) in [
            (None, Some("debian")),
            (None, Some("./debian/")),
            (Some("x/y"), Some("x/./y")),
        ] {
            let err = cfg_with("/data", &[("debian", URL, a), ("other", URL, b)])
                .validate()
                .unwrap_err();
            assert!(
                matches!(&err, ConfigError::DuplicatePath { .. }),
                "{a:?}/{b:?}: {err:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_nested_paths_in_either_order() {
        for mirrors in [
            [
                ("outer", URL, Some("debian")),
                ("inner", URL, Some("debian/pve")),
            ],
            [
                ("inner", URL, Some("debian/pve")),
                ("outer", URL, Some("debian")),
            ],
        ] {
            let err = cfg_with("/data", &mirrors).validate().unwrap_err();
            match &err {
                ConfigError::NestedPath { outer, inner, .. } => {
                    assert_eq!((outer.as_str(), inner.as_str()), ("outer", "inner"));
                }
                other => panic!("expected NestedPath, got {other:?}"),
            }
        }
        // A shared prefix that is not a path component is not nesting.
        cfg_with(
            "/data",
            &[
                ("a", URL, Some("debian")),
                ("b", URL, Some("debian-security")),
            ],
        )
        .validate()
        .unwrap();
    }

    #[test]
    fn validate_rejects_empty_or_relative_target() {
        for target in ["", "data", "./data"] {
            let err = cfg_with(target, &[]).validate().unwrap_err();
            assert!(
                matches!(&err, ConfigError::InvalidTarget(_)),
                "{target}: {err:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_segments_per_file_out_of_range() {
        for segments in [0, MAX_SEGMENTS_PER_FILE + 1, 64] {
            let mut cfg = cfg_with("/data", &[]);
            cfg.global.segments_per_file = segments;
            let err = cfg.validate().unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidSegments(n) if n == segments),
                "{segments}: {err:?}"
            );
        }
        for segments in [1, MAX_SEGMENTS_PER_FILE] {
            let mut cfg = cfg_with("/data", &[]);
            cfg.global.segments_per_file = segments;
            cfg.validate().unwrap();
        }
    }

    #[test]
    fn validate_rejects_control_characters_in_names() {
        for name in ["a\0b", "deb\nian", "x\u{7f}", "c1\u{85}"] {
            let err = cfg_with("/data", &[(name, URL, Some("ok"))])
                .validate()
                .unwrap_err();
            assert!(
                matches!(&err, ConfigError::InvalidName(n) if n == name),
                "{name:?}: {err:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_control_characters_in_apt_fields() {
        for (field, value) in [
            ("suites", "book\u{85}worm"),
            ("components", "main\u{7f}"),
            ("architectures", "amd\n64"),
        ] {
            let mut cfg = cfg_with("/data", &[("d", URL, None)]);
            let BackendOptions::Apt(apt) = &mut cfg.mirrors[0].backend_options;
            let target = match field {
                "suites" => &mut apt.suites,
                "components" => &mut apt.components,
                _ => &mut apt.architectures,
            };
            *target = vec![value.to_owned()];
            let err = cfg.validate().unwrap_err();
            assert!(
                matches!(&err, ConfigError::ControlChars { field: f, value: v, .. }
                    if *f == field && v == value),
                "{field}: {err:?}"
            );
            // Escaped in the message.
            assert!(!has_control_chars(&err.to_string()), "{err}");
        }
    }

    #[test]
    fn path_errors_escape_control_characters() {
        let err = cfg_with("/data", &[("d", URL, Some("a\nb"))])
            .validate()
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(r#""a\nb""#), "{msg}");
    }

    #[test]
    fn validate_mirrors_ignores_target_and_require_mirrors_needs_one() {
        let empty = cfg_with("relative", &[]);
        empty.validate_mirrors().unwrap();
        assert!(matches!(
            empty.require_mirrors(),
            Err(ConfigError::NoMirrors)
        ));
        cfg_with("/data", &[("d", URL, None)])
            .require_mirrors()
            .unwrap();
    }

    #[test]
    fn validate_rejects_non_http_url() {
        for url in ["ftp://example.com/debian", "file:///srv/debian"] {
            let err = cfg_with("/data", &[("d", url, None)])
                .validate()
                .unwrap_err();
            assert!(
                matches!(&err, ConfigError::UnsupportedScheme { mirror, .. } if mirror == "d"),
                "{url}: {err:?}"
            );
        }
    }

    #[test]
    fn backend_kind_name() {
        assert_eq!(BackendKind::Apt.name(), "apt");
        assert_eq!(BackendKind::default(), BackendKind::Apt);
    }

    #[test]
    fn test_new_apt_options() {
        let apt = AptOptions::test_new(
            vec!["bookworm".to_owned()],
            vec!["main".to_owned()],
            vec!["amd64".to_owned()],
        );
        assert_eq!(apt.suites.len(), 1);
    }
}
