//! Environment variable config source.
//!
//! `TAIN_*` globals override `GlobalConfig` whatever the primary source;
//! `TAIN_URL` + `TAIN_DISTS` define single-source mirrors when there is no TOML.
//! Legacy names (`APTSYNC_*`, `TO`, `CRON`, …) only warn — no compatibility aliases.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

use crate::observe::LogFormat;

use super::model::{
    FloatRatio, GlobalConfig, I18nSelection, MirrorDefaults, PartialAptOptions, PartialGcConfig,
    PartialIndexSelection, PartialMirror, PartialVerifyConfig, PgpMode,
};

// ---------- EnvSource abstraction ----------

/// Read-only env lookup; tests use `HashMap`, production `ProcessEnv`.
pub trait EnvSource {
    fn get(&self, key: &str) -> Option<String>;
}

impl EnvSource for HashMap<String, String> {
    fn get(&self, key: &str) -> Option<String> {
        HashMap::get(self, key).cloned()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

// ---------- Errors ----------

#[derive(Debug, thiserror::Error)]
pub enum EnvError {
    #[error("`{var}` value is invalid: {msg}")]
    Invalid { var: &'static str, msg: String },
    #[error("`TAIN_DISTS` group `{group}`: {msg}")]
    Dists { group: String, msg: String },
    #[error("`TAIN_INDEXES` token `{token}` is unknown")]
    UnknownIndex { token: String },
    #[error("`TAIN_DISTS` must be set when no TOML config is available")]
    MissingDists,
}

// ---------- Legacy names ----------

/// Legacy env variable name → `TAIN_*` replacement.
pub const LEGACY_ENV_NAMES: &[(&str, &str)] = &[
    ("APTSYNC_URL", "TAIN_URL"),
    ("APTSYNC_DISTS", "TAIN_DISTS"),
    ("APTSYNC_UNLINK", "TAIN_GC"),
    ("APTSYNC_USER_AGENT", "TAIN_USER_AGENT"),
    ("TO", "TAIN_TARGET"),
    ("CRON", "TAIN_SCHEDULE"),
    ("PARALLEL_DOWNLOADS", "TAIN_PARALLEL"),
];

/// Removed `TAIN_*` variables with a note on what to do instead; they only warn.
pub const REMOVED_ENV_NAMES: &[(&str, &str)] = &[(
    "TAIN_LOG_FILE",
    "logs are written to stderr; redirect it or let the service manager collect it",
)];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyWarning {
    pub legacy: &'static str,
    pub kind: LegacyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyKind {
    /// Old name; the value is the `TAIN_*` replacement.
    Renamed(&'static str),
    /// Removed without replacement; the value says what to do instead.
    Removed(&'static str),
}

impl LegacyWarning {
    #[must_use]
    pub fn message(&self) -> String {
        let legacy = self.legacy;
        match self.kind {
            LegacyKind::Renamed(modern) => format!(
                "environment variable `{legacy}` is not honored — use `{modern}` \
                 (run `tain import mirrors-list` to migrate an apt-mirror config)"
            ),
            LegacyKind::Removed(note) => {
                format!(
                    "environment variable `{legacy}` is not supported and has no effect — {note}"
                )
            }
        }
    }
}

/// One warning per legacy or removed name present in `env`.
pub fn detect_legacy(env: &dyn EnvSource) -> Vec<LegacyWarning> {
    let renamed = LEGACY_ENV_NAMES
        .iter()
        .map(|&(legacy, modern)| (legacy, LegacyKind::Renamed(modern)));
    let removed = REMOVED_ENV_NAMES
        .iter()
        .map(|&(legacy, note)| (legacy, LegacyKind::Removed(note)));
    renamed
        .chain(removed)
        .filter(|(legacy, _)| env.get(legacy).is_some())
        .map(|(legacy, kind)| LegacyWarning { legacy, kind })
        .collect()
}

// ---------- `TAIN_DISTS` parser ----------

/// One `suites|components|architectures[|path]` group from `TAIN_DISTS`.
/// `path` only changes the local layout; the URL is always `TAIN_URL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistGroup {
    pub suites: Vec<String>,
    pub components: Vec<String>,
    pub architectures: Vec<String>,
    pub path: Option<PathBuf>,
}

/// Parse `TAIN_DISTS` (groups separated by `;` or newline, lists by `,`).
/// Empty groups are skipped rather than rejected.
pub fn parse_dists(raw: &str) -> Result<Vec<DistGroup>, EnvError> {
    let mut out = Vec::new();
    for group_str in raw.split([';', '\n']) {
        let group_str = group_str.trim();
        if group_str.is_empty() {
            continue;
        }
        let parts: Vec<&str> = group_str.split('|').collect();
        if !(3..=4).contains(&parts.len()) {
            return Err(EnvError::Dists {
                group: group_str.to_owned(),
                msg: format!(
                    "expected `suites|components|architectures[|path]`, got {} parts",
                    parts.len()
                ),
            });
        }
        let suites = split_csv(parts[0]);
        if suites.is_empty() {
            return Err(EnvError::Dists {
                group: group_str.to_owned(),
                msg: "suites part is empty".into(),
            });
        }
        // Empty components parse here; flat suites are rejected at mirror resolution.
        let components = split_csv(parts[1]);
        let architectures = split_csv(parts[2]);
        if architectures.is_empty() {
            return Err(EnvError::Dists {
                group: group_str.to_owned(),
                msg: "architectures part is empty".into(),
            });
        }
        let path = parts
            .get(3)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        out.push(DistGroup {
            suites,
            components,
            architectures,
            path,
        });
    }
    if out.is_empty() {
        return Err(EnvError::Dists {
            group: String::new(),
            msg: "no groups parsed".into(),
        });
    }
    Ok(out)
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

// ---------- `TAIN_INDEXES` parser ----------

/// Parse `TAIN_INDEXES`: baselines `default`/`all`/`minimal` plus `+X`/`-X` toggles.
pub fn parse_indexes(raw: &str) -> Result<PartialIndexSelection, EnvError> {
    let mut out = PartialIndexSelection::default();
    let tokens: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if tokens.is_empty() {
        return Err(EnvError::UnknownIndex {
            token: raw.to_owned(),
        });
    }
    for tok in tokens {
        apply_index_token(tok, &mut out)?;
    }
    Ok(out)
}

fn apply_index_token(tok: &str, out: &mut PartialIndexSelection) -> Result<(), EnvError> {
    let (op, name) = if let Some(name) = tok.strip_prefix('+') {
        (Some(true), name)
    } else if let Some(name) = tok.strip_prefix('-') {
        (Some(false), name)
    } else {
        (None, tok)
    };

    // Baselines are only valid without a +/- prefix.
    if op.is_none() {
        match name {
            "default" => {
                set_baseline_default(out);
                return Ok(());
            }
            "all" => {
                set_baseline_all(out);
                return Ok(());
            }
            "minimal" => {
                set_baseline_minimal(out);
                return Ok(());
            }
            _ => {}
        }
    }

    let val = op.unwrap_or(true);
    match name {
        "packages" => {
            // Packages are always mirrored; `-packages` is rejected.
            if !val {
                return Err(EnvError::UnknownIndex {
                    token: tok.to_owned(),
                });
            }
        }
        "contents" => out.contents = Some(val),
        "i18n" => {
            out.i18n = Some(if val {
                I18nSelection::All
            } else {
                I18nSelection::None
            });
        }
        "dep11" => out.dep11 = Some(val),
        "cnf" => out.cnf = Some(val),
        "sources" => out.sources = Some(val),
        "di" | "debian_installer" => out.debian_installer = Some(val),
        _ => {
            return Err(EnvError::UnknownIndex {
                token: tok.to_owned(),
            });
        }
    }
    Ok(())
}

fn set_baseline_default(out: &mut PartialIndexSelection) {
    out.contents = Some(true);
    out.i18n = Some(I18nSelection::All);
    out.dep11 = Some(true);
    out.cnf = Some(true);
    // Unlike `all`/`minimal`, keep any explicit sources/debian_installer toggle.
    out.sources.get_or_insert(false);
    out.debian_installer.get_or_insert(false);
}

fn set_baseline_all(out: &mut PartialIndexSelection) {
    out.contents = Some(true);
    out.i18n = Some(I18nSelection::All);
    out.dep11 = Some(true);
    out.cnf = Some(true);
    out.sources = Some(true);
    out.debian_installer = Some(true);
}

fn set_baseline_minimal(out: &mut PartialIndexSelection) {
    out.contents = Some(false);
    out.i18n = Some(I18nSelection::None);
    out.dep11 = Some(false);
    out.cnf = Some(false);
    out.sources = Some(false);
    out.debian_installer = Some(false);
}

// ---------- Global overrides ----------

/// Env overrides for `GlobalConfig`; `None` leaves the base value untouched.
#[derive(Debug, Clone, Default)]
pub struct GlobalOverrides {
    pub target: Option<PathBuf>,
    pub parallel: Option<usize>,
    pub host_connections: Option<usize>,
    pub segments_per_file: Option<usize>,
    // No `segment_min_size`: TOML-only by design.
    pub connect_timeout: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    pub retry_count: Option<u32>,
    pub retry_index_rounds: Option<u32>,
    pub bind_address: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
    pub log_level: Option<String>,
    pub log_format: Option<LogFormat>,
    pub schedule: Option<String>,
    pub lock_timeout: Option<Duration>,
}

impl GlobalOverrides {
    pub fn from_env(env: &dyn EnvSource) -> Result<Self, EnvError> {
        Ok(Self {
            target: env.get("TAIN_TARGET").map(PathBuf::from),
            parallel: parse_usize(env, "TAIN_PARALLEL", |n| n > 0)?,
            host_connections: parse_usize(env, "TAIN_HOST_CONNECTIONS", |n| n > 0)?,
            segments_per_file: parse_usize(env, "TAIN_SEGMENTS", |_| true)?,
            connect_timeout: parse_nonzero_duration(env, "TAIN_CONNECT_TIMEOUT")?,
            idle_timeout: parse_nonzero_duration(env, "TAIN_IDLE_TIMEOUT")?,
            retry_count: parse_u32(env, "TAIN_RETRY", |_| true)?,
            retry_index_rounds: parse_u32(env, "TAIN_INDEX_RETRY", |_| true)?,
            bind_address: parse_ip(env, "TAIN_BIND_ADDRESS")?,
            user_agent: env.get("TAIN_USER_AGENT").filter(|s| !s.is_empty()),
            log_level: env.get("TAIN_LOG_LEVEL").filter(|s| !s.is_empty()),
            log_format: parse_log_format(env)?,
            schedule: env.get("TAIN_SCHEDULE").filter(|s| !s.is_empty()),
            lock_timeout: parse_duration(env, "TAIN_LOCK_TIMEOUT")?,
        })
    }

    pub fn apply(self, base: &mut GlobalConfig) {
        if let Some(v) = self.target {
            base.target = v;
        }
        if let Some(v) = self.parallel {
            base.parallel = v;
        }
        if let Some(v) = self.host_connections {
            base.host_connections = v;
        }
        if let Some(v) = self.segments_per_file {
            base.segments_per_file = v;
        }
        if let Some(v) = self.connect_timeout {
            base.timeout.connect = v;
        }
        if let Some(v) = self.idle_timeout {
            base.timeout.read_idle = v;
        }
        if let Some(v) = self.retry_count {
            base.retry.count = v;
        }
        if let Some(v) = self.retry_index_rounds {
            base.retry.index_rounds = v;
        }
        if let Some(v) = self.bind_address {
            base.bind_address = Some(v);
        }
        if let Some(v) = self.user_agent {
            base.user_agent = v;
        }
        if self.log_level.is_some() {
            base.log.level = self.log_level;
        }
        if let Some(v) = self.log_format {
            base.log.format = v;
        }
        if self.schedule.is_some() {
            base.schedule = self.schedule;
        }
        if let Some(v) = self.lock_timeout {
            base.lock_timeout = v;
        }
    }
}

// ---------- Single-source mirror mode ----------

/// Single-source env config: overrides plus one mirror per `TAIN_DISTS` group.
#[derive(Debug, Clone)]
pub struct EnvSingleSource {
    pub globals: GlobalOverrides,
    pub mirrors: Vec<PartialMirror>,
}

/// Build single-source mirrors from `TAIN_URL`; `None` if it is unset.
pub fn try_single_source(env: &dyn EnvSource) -> Result<Option<EnvSingleSource>, EnvError> {
    let Some(url_str) = env.get("TAIN_URL").filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let dists_raw = env
        .get("TAIN_DISTS")
        .filter(|s| !s.is_empty())
        .ok_or(EnvError::MissingDists)?;
    let url = Url::parse(&url_str).map_err(|e| EnvError::Invalid {
        var: "TAIN_URL",
        msg: e.to_string(),
    })?;

    let globals = GlobalOverrides::from_env(env)?;
    let groups = parse_dists(&dists_raw)?;
    let name = derive_name_from_url(&url);

    let shared_overrides = read_shared_mirror_overrides(env)?;

    let mut mirrors = Vec::with_capacity(groups.len());
    let single_group = groups.len() == 1;
    let explicit_path = env
        .get("TAIN_PATH")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    for (idx, group) in groups.into_iter().enumerate() {
        let apt = PartialAptOptions {
            suites: Some(group.suites),
            components: Some(group.components),
            architectures: Some(group.architectures),
            indexes: shared_overrides.indexes.clone(),
            create_suite_symlinks: shared_overrides.create_suite_symlinks,
        };

        let mut overrides = MirrorDefaults {
            backend: None,
            path: None,
            verify: shared_overrides.verify.clone(),
            gc: shared_overrides.gc.clone(),
            apt,
        };
        // Path precedence: per-group path > TAIN_PATH (single group only; it
        // would be ambiguous otherwise) > derived from URL.
        overrides.path = if let Some(p) = group.path {
            Some(p)
        } else if let Some(p) = explicit_path.as_ref() {
            if !single_group {
                return Err(EnvError::Invalid {
                    var: "TAIN_PATH",
                    msg: "cannot be set when TAIN_DISTS has more than one group; \
                          put the per-group path in the 4th `|` field instead"
                        .into(),
                });
            }
            Some(p.clone())
        } else {
            None
        };

        let mirror_name = if single_group {
            name.clone()
        } else {
            format!("{name}-{idx}")
        };
        mirrors.push(PartialMirror {
            name: mirror_name,
            url: url.clone(),
            overrides,
            force_http1: None,
        });
    }

    Ok(Some(EnvSingleSource { globals, mirrors }))
}

#[derive(Debug, Clone, Default)]
struct SharedMirrorOverrides {
    verify: PartialVerifyConfig,
    gc: PartialGcConfig,
    indexes: PartialIndexSelection,
    create_suite_symlinks: Option<bool>,
}

fn read_shared_mirror_overrides(env: &dyn EnvSource) -> Result<SharedMirrorOverrides, EnvError> {
    let verify = PartialVerifyConfig {
        pgp: parse_pgp(env)?,
        keyring: env
            .get("TAIN_KEYRING")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
        allow_weak_hash: None,
    };
    let gc = PartialGcConfig {
        enabled: parse_bool(env, "TAIN_GC")?,
        grace_period: parse_duration(env, "TAIN_GC_GRACE")?,
        max_delete_ratio: parse_ratio(env, "TAIN_GC_MAX_DELETE_RATIO")?,
        keep_generations: parse_u32(env, "TAIN_GC_KEEP_GENERATIONS", |_| true)?,
        dry_run: None,
    };
    let indexes = match env.get("TAIN_INDEXES").filter(|s| !s.is_empty()) {
        Some(s) => parse_indexes(&s)?,
        None => PartialIndexSelection::default(),
    };
    Ok(SharedMirrorOverrides {
        verify,
        gc,
        indexes,
        create_suite_symlinks: None,
    })
}

// ---------- Name derivation ----------

/// Slug `host-path` to `[a-z0-9._-]` with collapsed dashes; `mirror` if empty.
pub fn derive_name_from_url(url: &Url) -> String {
    let host = url.host_str().unwrap_or("mirror");
    let path = url.path().trim_matches('/');
    let raw = if path.is_empty() {
        host.to_owned()
    } else {
        format!("{host}-{path}")
    };
    let mut out = String::with_capacity(raw.len());
    let mut last_dash = false;
    for c in raw.chars() {
        let sane = if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            c.to_ascii_lowercase()
        } else {
            '-'
        };
        if sane == '-' {
            if !last_dash {
                out.push(sane);
            }
            last_dash = true;
        } else {
            out.push(sane);
            last_dash = false;
        }
    }
    let trimmed = out.trim_matches('-').to_owned();
    if trimmed.is_empty() {
        "mirror".to_owned()
    } else {
        trimmed
    }
}

// ---------- primitive parsers ----------

fn parse_usize(
    env: &dyn EnvSource,
    var: &'static str,
    valid: impl Fn(usize) -> bool,
) -> Result<Option<usize>, EnvError> {
    let Some(s) = env.get(var).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let n = s.parse::<usize>().map_err(|e| EnvError::Invalid {
        var,
        msg: e.to_string(),
    })?;
    if !valid(n) {
        return Err(EnvError::Invalid {
            var,
            msg: "value out of allowed range".into(),
        });
    }
    Ok(Some(n))
}

fn parse_u32(
    env: &dyn EnvSource,
    var: &'static str,
    valid: impl Fn(u32) -> bool,
) -> Result<Option<u32>, EnvError> {
    let Some(s) = env.get(var).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let n = s.parse::<u32>().map_err(|e| EnvError::Invalid {
        var,
        msg: e.to_string(),
    })?;
    if !valid(n) {
        return Err(EnvError::Invalid {
            var,
            msg: "value out of allowed range".into(),
        });
    }
    Ok(Some(n))
}

fn parse_duration(env: &dyn EnvSource, var: &'static str) -> Result<Option<Duration>, EnvError> {
    let Some(s) = env.get(var).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let d = humantime::parse_duration(&s).map_err(|e| EnvError::Invalid {
        var,
        msg: e.to_string(),
    })?;
    Ok(Some(d))
}

/// Like `parse_duration` but rejects zero, which would fail every request.
fn parse_nonzero_duration(
    env: &dyn EnvSource,
    var: &'static str,
) -> Result<Option<Duration>, EnvError> {
    match parse_duration(env, var)? {
        Some(d) if d.is_zero() => Err(EnvError::Invalid {
            var,
            msg: "must be > 0".into(),
        }),
        d => Ok(d),
    }
}

fn parse_ip(env: &dyn EnvSource, var: &'static str) -> Result<Option<std::net::IpAddr>, EnvError> {
    let Some(s) = env.get(var).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let ip = s
        .parse()
        .map_err(|e: std::net::AddrParseError| EnvError::Invalid {
            var,
            msg: e.to_string(),
        })?;
    Ok(Some(ip))
}

fn parse_log_format(env: &dyn EnvSource) -> Result<Option<LogFormat>, EnvError> {
    let Some(s) = env.get("TAIN_LOG_FORMAT").filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let f = s
        .parse()
        .map_err(|e: crate::observe::LogFormatParseError| EnvError::Invalid {
            var: "TAIN_LOG_FORMAT",
            msg: e.to_string(),
        })?;
    Ok(Some(f))
}

fn parse_bool(env: &dyn EnvSource, var: &'static str) -> Result<Option<bool>, EnvError> {
    let Some(s) = env.get(var).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => Err(EnvError::Invalid {
            var,
            msg: format!("expected a boolean, got `{s}`"),
        }),
    }
}

fn parse_pgp(env: &dyn EnvSource) -> Result<Option<PgpMode>, EnvError> {
    let Some(s) = env.get("TAIN_VERIFY_PGP").filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    match s.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(Some(PgpMode::Off)),
        "if-present" => Ok(Some(PgpMode::IfPresent)),
        "required" => Ok(Some(PgpMode::Required)),
        _ => Err(EnvError::Invalid {
            var: "TAIN_VERIFY_PGP",
            msg: format!("expected off | if-present | required, got `{s}`"),
        }),
    }
}

fn parse_ratio(env: &dyn EnvSource, var: &'static str) -> Result<Option<FloatRatio>, EnvError> {
    let Some(s) = env.get(var).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let f = s.parse::<f64>().map_err(|e| EnvError::Invalid {
        var,
        msg: e.to_string(),
    })?;
    let r = FloatRatio::new(f).map_err(|e| EnvError::Invalid {
        var,
        msg: e.to_string(),
    })?;
    Ok(Some(r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn dists_single_group() {
        let g = parse_dists("bookworm|main,contrib|amd64,arm64").unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].suites, vec!["bookworm"]);
        assert_eq!(g[0].components, vec!["main", "contrib"]);
        assert_eq!(g[0].architectures, vec!["amd64", "arm64"]);
        assert!(g[0].path.is_none());
    }

    #[test]
    fn dists_multi_group_semicolon() {
        let g = parse_dists("bookworm|main|amd64;bullseye|main|amd64").unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g[1].suites, vec!["bullseye"]);
    }

    #[test]
    fn dists_multi_group_newline() {
        let g = parse_dists("bookworm|main|amd64\nbullseye|main|amd64").unwrap();
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn dists_with_path() {
        let g = parse_dists("bookworm|main|amd64|debian/pve").unwrap();
        assert_eq!(
            g[0].path.as_deref(),
            Some(std::path::Path::new("debian/pve"))
        );
    }

    #[test]
    fn dists_empty_components_parse() {
        let g = parse_dists("bookworm||amd64").unwrap();
        assert_eq!(g[0].suites, vec!["bookworm"]);
        assert!(g[0].components.is_empty());
    }

    #[test]
    fn dists_rejects_wrong_shape() {
        let e = parse_dists("only|two").unwrap_err();
        assert!(matches!(e, EnvError::Dists { .. }));
    }

    #[test]
    fn dists_rejects_empty_suites() {
        let e = parse_dists("|main|amd64").unwrap_err();
        assert!(matches!(e, EnvError::Dists { .. }));
    }

    #[test]
    fn dists_rejects_empty_arch() {
        let e = parse_dists("bookworm|main|").unwrap_err();
        assert!(matches!(e, EnvError::Dists { .. }));
    }

    #[test]
    fn dists_rejects_all_empty() {
        let e = parse_dists("   \n   ").unwrap_err();
        assert!(matches!(e, EnvError::Dists { .. }));
    }

    #[test]
    fn dists_skips_blank_groups() {
        let g = parse_dists(";;bookworm|main|amd64;;").unwrap();
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn indexes_default_baseline() {
        let p = parse_indexes("default").unwrap();
        assert_eq!(p.contents, Some(true));
        assert_eq!(p.i18n, Some(I18nSelection::All));
        assert_eq!(p.dep11, Some(true));
        assert_eq!(p.cnf, Some(true));
        assert_eq!(p.sources, Some(false));
        assert_eq!(p.debian_installer, Some(false));
    }

    #[test]
    fn indexes_all() {
        let p = parse_indexes("all").unwrap();
        assert_eq!(p.sources, Some(true));
        assert_eq!(p.debian_installer, Some(true));
    }

    #[test]
    fn indexes_minimal() {
        let p = parse_indexes("minimal").unwrap();
        assert_eq!(p.contents, Some(false));
        assert_eq!(p.i18n, Some(I18nSelection::None));
        assert_eq!(p.dep11, Some(false));
        assert_eq!(p.cnf, Some(false));
    }

    #[test]
    fn indexes_default_minus_contents() {
        let p = parse_indexes("default,-contents").unwrap();
        assert_eq!(p.contents, Some(false));
        assert_eq!(p.dep11, Some(true));
    }

    #[test]
    fn indexes_default_plus_sources_plus_di() {
        let p = parse_indexes("default,+sources,+di").unwrap();
        assert_eq!(p.sources, Some(true));
        assert_eq!(p.debian_installer, Some(true));
    }

    #[test]
    fn indexes_reject_unknown_token() {
        let e = parse_indexes("+banana").unwrap_err();
        assert!(matches!(e, EnvError::UnknownIndex { .. }));
    }

    #[test]
    fn indexes_reject_disable_packages() {
        let e = parse_indexes("-packages").unwrap_err();
        assert!(matches!(e, EnvError::UnknownIndex { .. }));
    }

    #[test]
    fn indexes_empty_string_rejected() {
        let e = parse_indexes("").unwrap_err();
        assert!(matches!(e, EnvError::UnknownIndex { .. }));
    }

    #[test]
    fn globals_empty_env_leaves_base_alone() {
        let e = env(&[]);
        let ov = GlobalOverrides::from_env(&e).unwrap();
        let mut base = GlobalConfig::default();
        let snapshot = base.parallel;
        ov.apply(&mut base);
        assert_eq!(base.parallel, snapshot);
    }

    #[test]
    fn globals_apply_full_set() {
        let e = env(&[
            ("TAIN_TARGET", "/srv/mirrors"),
            ("TAIN_PARALLEL", "16"),
            ("TAIN_HOST_CONNECTIONS", "4"),
            ("TAIN_SEGMENTS", "2"),
            ("TAIN_CONNECT_TIMEOUT", "45s"),
            ("TAIN_IDLE_TIMEOUT", "90s"),
            ("TAIN_RETRY", "5"),
            ("TAIN_INDEX_RETRY", "7"),
            ("TAIN_BIND_ADDRESS", "192.0.2.10"),
            ("TAIN_USER_AGENT", "tain-test/1"),
            ("TAIN_LOG_LEVEL", "debug"),
            ("TAIN_LOG_FORMAT", "json"),
            ("TAIN_SCHEDULE", "0 * * * *"),
            ("TAIN_LOCK_TIMEOUT", "5s"),
        ]);
        let ov = GlobalOverrides::from_env(&e).unwrap();
        let mut base = GlobalConfig::default();
        ov.apply(&mut base);
        assert_eq!(base.target, PathBuf::from("/srv/mirrors"));
        assert_eq!(base.parallel, 16);
        assert_eq!(base.host_connections, 4);
        assert_eq!(base.segments_per_file, 2);
        assert_eq!(base.timeout.connect, Duration::from_secs(45));
        assert_eq!(base.timeout.read_idle, Duration::from_secs(90));
        assert_eq!(base.retry.count, 5);
        assert_eq!(base.retry.index_rounds, 7);
        assert_eq!(
            base.bind_address.map(|ip| ip.to_string()),
            Some("192.0.2.10".to_owned())
        );
        assert_eq!(base.user_agent, "tain-test/1");
        assert_eq!(base.log.level.as_deref(), Some("debug"));
        assert_eq!(base.log.format, LogFormat::Json);
        assert_eq!(base.schedule.as_deref(), Some("0 * * * *"));
        assert_eq!(base.lock_timeout, Duration::from_secs(5));
    }

    #[test]
    fn globals_parallel_zero_rejected() {
        let e = env(&[("TAIN_PARALLEL", "0")]);
        let err = GlobalOverrides::from_env(&e).unwrap_err();
        assert!(matches!(
            err,
            EnvError::Invalid {
                var: "TAIN_PARALLEL",
                ..
            }
        ));
    }

    #[test]
    fn globals_bad_duration_rejected() {
        let e = env(&[("TAIN_CONNECT_TIMEOUT", "chicken")]);
        let err = GlobalOverrides::from_env(&e).unwrap_err();
        assert!(matches!(
            err,
            EnvError::Invalid {
                var: "TAIN_CONNECT_TIMEOUT",
                ..
            }
        ));
    }

    #[test]
    fn globals_zero_timeouts_rejected() {
        for var in ["TAIN_CONNECT_TIMEOUT", "TAIN_IDLE_TIMEOUT"] {
            let e = env(&[(var, "0s")]);
            let err = GlobalOverrides::from_env(&e).unwrap_err();
            assert!(
                matches!(&err, EnvError::Invalid { var: v, .. } if *v == var),
                "{var}: {err:?}"
            );
        }
    }

    #[test]
    fn globals_bad_log_format_rejected() {
        let e = env(&[("TAIN_LOG_FORMAT", "yaml")]);
        let err = GlobalOverrides::from_env(&e).unwrap_err();
        assert!(matches!(
            err,
            EnvError::Invalid {
                var: "TAIN_LOG_FORMAT",
                ..
            }
        ));
    }

    #[test]
    fn segment_min_size_env_intentionally_absent() {
        let e = env(&[("TAIN_SEGMENT_MIN_SIZE", "1MiB")]);
        let ov = GlobalOverrides::from_env(&e).unwrap();
        let mut base = GlobalConfig::default();
        let baseline = base.segment_min_size;
        ov.apply(&mut base);
        assert_eq!(
            base.segment_min_size, baseline,
            "TAIN_SEGMENT_MIN_SIZE is deliberately not honored"
        );
    }

    #[test]
    fn single_source_absent_when_no_url() {
        let e = env(&[]);
        assert!(try_single_source(&e).unwrap().is_none());
    }

    #[test]
    fn single_source_requires_dists() {
        let e = env(&[("TAIN_URL", "http://example.com/repo")]);
        let err = try_single_source(&e).unwrap_err();
        assert!(matches!(err, EnvError::MissingDists));
    }

    #[test]
    fn single_source_builds_one_mirror_from_one_group() {
        let e = env(&[
            ("TAIN_URL", "http://download.proxmox.com/debian/pve"),
            ("TAIN_DISTS", "bookworm|pve-no-subscription|amd64"),
            ("TAIN_GC", "1"),
            ("TAIN_GC_GRACE", "48h"),
            ("TAIN_INDEXES", "default,-contents"),
            ("TAIN_VERIFY_PGP", "required"),
            ("TAIN_KEYRING", "/etc/apt/keyrings/proxmox.gpg"),
        ]);
        let ss = try_single_source(&e).unwrap().unwrap();
        assert_eq!(ss.mirrors.len(), 1);
        let m = &ss.mirrors[0];
        assert!(m.name.starts_with("download.proxmox.com"));
        assert_eq!(
            m.overrides.apt.suites.as_deref(),
            Some(&["bookworm".to_owned()][..])
        );
        assert_eq!(m.overrides.apt.indexes.contents, Some(false));
        assert_eq!(m.overrides.apt.indexes.dep11, Some(true));
        assert_eq!(m.overrides.gc.enabled, Some(true));
        assert_eq!(
            m.overrides.gc.grace_period,
            Some(Duration::from_secs(48 * 3600))
        );
        assert_eq!(m.overrides.verify.pgp, Some(PgpMode::Required));
        assert_eq!(
            m.overrides.verify.keyring.as_deref(),
            Some(std::path::Path::new("/etc/apt/keyrings/proxmox.gpg"))
        );
    }

    #[test]
    fn single_source_multi_group_names_indexed() {
        let e = env(&[
            ("TAIN_URL", "http://download.proxmox.com/debian/pve"),
            ("TAIN_DISTS", "bookworm|main|amd64;bullseye|main|amd64"),
        ]);
        let ss = try_single_source(&e).unwrap().unwrap();
        assert_eq!(ss.mirrors.len(), 2);
        assert!(ss.mirrors[0].name.ends_with("-0"));
        assert!(ss.mirrors[1].name.ends_with("-1"));
    }

    #[test]
    fn single_source_tain_path_rejected_multi_group() {
        let e = env(&[
            ("TAIN_URL", "http://example.com"),
            ("TAIN_DISTS", "a|main|amd64;b|main|amd64"),
            ("TAIN_PATH", "explicit"),
        ]);
        let err = try_single_source(&e).unwrap_err();
        assert!(matches!(
            err,
            EnvError::Invalid {
                var: "TAIN_PATH",
                ..
            }
        ));
    }

    #[test]
    fn single_source_tain_path_single_group_ok() {
        let e = env(&[
            ("TAIN_URL", "http://example.com"),
            ("TAIN_DISTS", "bookworm|main|amd64"),
            ("TAIN_PATH", "explicit"),
        ]);
        let ss = try_single_source(&e).unwrap().unwrap();
        assert_eq!(
            ss.mirrors[0].overrides.path,
            Some(PathBuf::from("explicit"))
        );
    }

    #[test]
    fn single_source_per_group_path_wins() {
        let e = env(&[
            ("TAIN_URL", "http://example.com"),
            ("TAIN_DISTS", "bookworm|main|amd64|from-dists"),
            ("TAIN_PATH", "should-be-ignored-because-group-path-is-set"),
        ]);
        let ss = try_single_source(&e).unwrap().unwrap();
        assert_eq!(
            ss.mirrors[0].overrides.path,
            Some(PathBuf::from("from-dists"))
        );
    }

    #[test]
    fn single_source_bad_url_rejected() {
        let e = env(&[
            ("TAIN_URL", "not a url"),
            ("TAIN_DISTS", "bookworm|main|amd64"),
        ]);
        let err = try_single_source(&e).unwrap_err();
        assert!(matches!(
            err,
            EnvError::Invalid {
                var: "TAIN_URL",
                ..
            }
        ));
    }

    #[test]
    fn detect_legacy_finds_known_names() {
        let e = env(&[
            ("APTSYNC_URL", "http://old"),
            ("CRON", "*/5 * * * *"),
            ("TAIN_URL", "http://new"), // should not fire
        ]);
        let warns = detect_legacy(&e);
        assert_eq!(warns.len(), 2);
        let names: Vec<_> = warns.iter().map(|w| w.legacy).collect();
        assert!(names.contains(&"APTSYNC_URL"));
        assert!(names.contains(&"CRON"));
    }

    #[test]
    fn removed_tain_log_file_warns_and_is_not_applied() {
        let e = env(&[("TAIN_LOG_FILE", "/var/log/tain.log")]);
        let warns = detect_legacy(&e);
        assert_eq!(warns.len(), 1);
        assert_eq!(warns[0].legacy, "TAIN_LOG_FILE");
        let msg = warns[0].message();
        assert!(msg.contains("TAIN_LOG_FILE"), "{msg}");
        assert!(msg.contains("stderr"), "{msg}");
        assert!(!msg.contains("tain import"), "{msg}");
    }

    #[test]
    fn legacy_warning_message_mentions_both_names() {
        let w = LegacyWarning {
            legacy: "APTSYNC_URL",
            kind: LegacyKind::Renamed("TAIN_URL"),
        };
        let msg = w.message();
        assert!(msg.contains("APTSYNC_URL"));
        assert!(msg.contains("TAIN_URL"));
        assert!(msg.contains("tain import"));
    }

    #[test]
    fn name_from_url_slugifies() {
        let u = Url::parse("http://download.proxmox.com/debian/pve").unwrap();
        let n = derive_name_from_url(&u);
        assert_eq!(n, "download.proxmox.com-debian-pve");
    }

    #[test]
    fn name_from_url_collapses_dashes() {
        let u = Url::parse("http://example.com/a//b").unwrap();
        let n = derive_name_from_url(&u);
        assert!(!n.contains("--"));
    }

    #[test]
    fn name_from_url_falls_back() {
        let u = Url::parse("file:///data").unwrap();
        let n = derive_name_from_url(&u);
        assert!(!n.is_empty());
    }

    #[test]
    fn parse_bool_accepts_common_forms() {
        for &(k, v) in &[
            ("1", true),
            ("true", true),
            ("YES", true),
            ("On", true),
            ("0", false),
            ("false", false),
            ("no", false),
            ("off", false),
        ] {
            let e = env(&[("TAIN_GC", k)]);
            assert_eq!(parse_bool(&e, "TAIN_GC").unwrap(), Some(v), "for {k}");
        }
    }

    #[test]
    fn parse_bool_rejects_garbage() {
        let e = env(&[("TAIN_GC", "maybe")]);
        assert!(parse_bool(&e, "TAIN_GC").is_err());
    }
}
