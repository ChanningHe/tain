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
    FloatRatio, GlobalConfig, I18nSelection, MAX_FILE_NAME_BYTES, MirrorDefaults,
    PartialAptOptions, PartialGcConfig, PartialIndexSelection, PartialMirror, PartialVerifyConfig,
    PgpMode,
};

// ---------- EnvSource abstraction ----------

/// Read-only env lookup; tests use `HashMap`, production `ProcessEnv`.
pub trait EnvSource {
    fn get(&self, key: &str) -> Option<String>;

    /// Every variable name, used only to warn about unknown `TAIN_*` names.
    /// A source that cannot enumerate returns nothing.
    fn names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Whether `key` is set to a value that is not valid UTF-8 (which `get`
    /// reports as unset).
    fn is_non_unicode(&self, _key: &str) -> bool {
        false
    }
}

impl EnvSource for HashMap<String, String> {
    fn get(&self, key: &str) -> Option<String> {
        HashMap::get(self, key).cloned()
    }

    fn names(&self) -> Vec<String> {
        self.keys().cloned().collect()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn names(&self) -> Vec<String> {
        std::env::vars_os()
            .filter_map(|(k, _)| k.into_string().ok())
            .collect()
    }

    fn is_non_unicode(&self, key: &str) -> bool {
        matches!(std::env::var(key), Err(std::env::VarError::NotUnicode(_)))
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

/// Variables read only in single-mirror mode (no TOML file).
pub const SINGLE_SOURCE_ENV_NAMES: &[&str] = &[
    "TAIN_URL",
    "TAIN_DISTS",
    "TAIN_PATH",
    "TAIN_INDEXES",
    "TAIN_VERIFY_PGP",
    "TAIN_KEYRING",
    "TAIN_GC",
    "TAIN_GC_GRACE",
    "TAIN_GC_MAX_DELETE_RATIO",
    "TAIN_GC_KEEP_GENERATIONS",
];

/// Variables that apply in every mode (`TAIN_CONFIG` and the global overrides).
pub const GLOBAL_ENV_NAMES: &[&str] = &[
    "TAIN_CONFIG",
    "TAIN_TARGET",
    "TAIN_PARALLEL",
    "TAIN_HOST_CONNECTIONS",
    "TAIN_SEGMENTS",
    "TAIN_CONNECT_TIMEOUT",
    "TAIN_IDLE_TIMEOUT",
    "TAIN_RETRY",
    "TAIN_INDEX_RETRY",
    "TAIN_BIND_ADDRESS",
    "TAIN_USER_AGENT",
    "TAIN_LOG_LEVEL",
    "TAIN_LOG_FORMAT",
    "TAIN_SCHEDULE",
    "TAIN_LOCK_TIMEOUT",
];

/// An unknown `TAIN_*` variable, with the closest known name if one is near.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownVar {
    pub name: String,
    pub suggestion: Option<&'static str>,
}

impl UnknownVar {
    #[must_use]
    pub fn message(&self) -> String {
        let name = self.name.escape_debug();
        match self.suggestion {
            Some(known) => format!(
                "environment variable `{name}` is not a tain variable and has no effect — did \
                 you mean `{known}`?"
            ),
            None => {
                format!("environment variable `{name}` is not a tain variable and has no effect")
            }
        }
    }
}

/// Largest edit distance at which a known name is offered as a suggestion;
/// shorter names allow less (one edit per three characters after `TAIN_`).
const MAX_SUGGESTION_DISTANCE: usize = 3;

/// Every variable tain reads, plus the removed ones `detect_legacy` reports.
fn known_env_names() -> impl Iterator<Item = &'static str> {
    let removed = REMOVED_ENV_NAMES.iter().map(|&(name, _)| name);
    GLOBAL_ENV_NAMES
        .iter()
        .chain(SINGLE_SOURCE_ENV_NAMES)
        .copied()
        .chain(removed)
}

/// Names that Kubernetes service links and docker `--link` inject for a
/// service or container called `tain`; they are not meant for tain.
fn is_injected_link_name(name: &str) -> bool {
    name == "TAIN_PORT"
        || name == "TAIN_NAME"
        || ["TAIN_PORT_", "TAIN_SERVICE_", "TAIN_ENV_"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// `TAIN_*` names in `env` that tain does not read, sorted. Removed names
/// (reported by `detect_legacy`) and service-link names are excluded.
pub fn detect_unknown(env: &dyn EnvSource) -> Vec<UnknownVar> {
    let known: Vec<&'static str> = known_env_names().collect();
    let mut names: Vec<String> = env
        .names()
        .into_iter()
        .filter(|n| n.starts_with("TAIN_") && !known.contains(&n.as_str()))
        .filter(|n| !is_injected_link_name(n))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let suffix_len = name.len() - "TAIN_".len();
            let max = (suffix_len / 3).clamp(1, MAX_SUGGESTION_DISTANCE);
            let suggestion = known
                .iter()
                .map(|k| (edit_distance(&name, k), *k))
                .min()
                .filter(|(d, _)| *d <= max)
                .map(|(_, k)| k);
            UnknownVar { name, suggestion }
        })
        .collect()
}

/// The first known variable that is set but not valid UTF-8. Such a value
/// would otherwise read as unset and silently fall back to a default.
pub fn non_unicode_var(env: &dyn EnvSource) -> Option<EnvError> {
    known_env_names()
        .find(|name| env.is_non_unicode(name))
        .map(|var| EnvError::Invalid {
            var,
            msg: "is not valid UTF-8".into(),
        })
}

/// Levenshtein distance over chars.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut row = Vec::with_capacity(b.len() + 1);
        row.push(i + 1);
        for (j, cb) in b.iter().enumerate() {
            let substitute = prev[j] + usize::from(ca != *cb);
            row.push(substitute.min(prev[j + 1] + 1).min(row[j] + 1));
        }
        prev = row;
    }
    prev[b.len()]
}

/// Single-mirror variables set to a non-empty value; ignored in TOML mode.
pub fn single_source_vars_set(env: &dyn EnvSource) -> Vec<&'static str> {
    SINGLE_SOURCE_ENV_NAMES
        .iter()
        .copied()
        .filter(|name| env.get(name).is_some_and(|v| !v.is_empty()))
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
            let suffix = format!("-{idx}");
            format!(
                "{}{suffix}",
                truncate_slug(&name, MAX_FILE_NAME_BYTES - suffix.len())
            )
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

/// Slug `host-path` to `[a-z0-9._-]` with collapsed dashes, cut to
/// `MAX_FILE_NAME_BYTES`; `mirror` if empty.
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
    let trimmed = truncate_slug(out.trim_matches('-'), MAX_FILE_NAME_BYTES);
    if trimmed.is_empty() {
        "mirror".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// First `max` bytes of an ASCII slug, without a trailing `-`.
pub(crate) fn truncate_slug(slug: &str, max: usize) -> &str {
    slug.get(..max).unwrap_or(slug).trim_end_matches('-')
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
    fn unknown_tain_names_warn_with_a_near_suggestion_only() {
        let e = env(&[
            ("TAIN_PARALEL", "4"),
            ("TAIN_LOGLEVEL", "debug"),
            ("TAIN_ZZZZZZZZZZZZ", "1"),
            ("TAIN_PARALLEL", "4"),
            ("TAIN_LOG_FILE", "/x"),
            ("PATH", "/bin"),
        ]);
        let found = detect_unknown(&e);
        let pairs: Vec<(&str, Option<&str>)> = found
            .iter()
            .map(|u| (u.name.as_str(), u.suggestion))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("TAIN_LOGLEVEL", Some("TAIN_LOG_LEVEL")),
                ("TAIN_PARALEL", Some("TAIN_PARALLEL")),
                ("TAIN_ZZZZZZZZZZZZ", None),
            ]
        );
        assert!(found[0].message().contains("did you mean `TAIN_LOG_LEVEL`"));
        assert!(!found[2].message().contains("did you mean"));
    }

    #[test]
    fn short_unknown_names_get_a_suggestion_only_one_edit_away() {
        let e = env(&[("TAIN_PATX", "1"), ("TAIN_PXRX", "1")]);
        let pairs: Vec<(String, Option<&str>)> = detect_unknown(&e)
            .into_iter()
            .map(|u| (u.name, u.suggestion))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("TAIN_PATX".to_owned(), Some("TAIN_PATH")),
                ("TAIN_PXRX".to_owned(), None),
            ]
        );
    }

    #[test]
    fn service_link_names_are_not_reported() {
        let e = env(&[
            ("TAIN_SERVICE_HOST", "10.0.0.1"),
            ("TAIN_SERVICE_PORT", "80"),
            ("TAIN_PORT", "tcp://10.0.0.1:80"),
            ("TAIN_PORT_80_TCP_ADDR", "10.0.0.1"),
            ("TAIN_NAME", "/web/tain"),
            ("TAIN_ENV_FOO", "bar"),
        ]);
        assert_eq!(detect_unknown(&e), vec![]);
    }

    /// Records every key looked up; answers only the single-mirror basics.
    #[derive(Default)]
    struct RecordingEnv(std::cell::RefCell<Vec<String>>);

    impl EnvSource for RecordingEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.borrow_mut().push(key.to_owned());
            match key {
                "TAIN_URL" => Some("http://example.com/debian".to_owned()),
                "TAIN_DISTS" => Some("bookworm|main|amd64".to_owned()),
                _ => None,
            }
        }
    }

    #[test]
    fn every_variable_read_is_a_known_name() {
        let e = RecordingEnv::default();
        GlobalOverrides::from_env(&e).unwrap();
        try_single_source(&e).unwrap().unwrap();
        let known: Vec<&str> = known_env_names().collect();
        let read = e.0.borrow();
        assert!(read.len() > 10, "{read:?}");
        for key in read.iter().filter(|k| k.starts_with("TAIN_")) {
            assert!(known.contains(&key.as_str()), "{key} is read but not known");
        }
    }

    struct NonUnicodeEnv(&'static str);

    impl EnvSource for NonUnicodeEnv {
        fn get(&self, _key: &str) -> Option<String> {
            None
        }

        fn is_non_unicode(&self, key: &str) -> bool {
            key == self.0
        }
    }

    #[test]
    fn non_unicode_known_variable_is_an_error() {
        let err = non_unicode_var(&NonUnicodeEnv("TAIN_CONFIG")).unwrap();
        assert!(err.to_string().contains("TAIN_CONFIG"), "{err}");
        assert!(non_unicode_var(&NonUnicodeEnv("OTHER")).is_none());
    }

    #[test]
    fn unknown_name_is_escaped_in_the_message() {
        let u = UnknownVar {
            name: "TAIN_\u{1b}[31m".to_owned(),
            suggestion: None,
        };
        assert!(!u.message().contains('\u{1b}'), "{}", u.message());
    }

    #[test]
    fn every_known_variable_is_documented() {
        let docs = include_str!("../../docs/configuration.md");
        for name in GLOBAL_ENV_NAMES.iter().chain(SINGLE_SOURCE_ENV_NAMES) {
            assert!(
                docs.contains(&format!("`{name}`")),
                "{name} is undocumented"
            );
        }
    }

    #[test]
    fn edit_distance_counts_single_edits() {
        assert_eq!(edit_distance("TAIN_GC", "TAIN_GC"), 0);
        assert_eq!(edit_distance("TAIN_PARALEL", "TAIN_PARALLEL"), 1);
        assert_eq!(edit_distance("TAIN_SHEDULE", "TAIN_SCHEDULE"), 1);
        assert_eq!(edit_distance("abc", ""), 3);
    }

    #[test]
    fn derived_names_fit_in_a_file_name() {
        let long = Url::parse(&format!("http://example.com/{}", "segment/".repeat(60))).unwrap();
        let name = derive_name_from_url(&long);
        assert!(name.len() <= MAX_FILE_NAME_BYTES, "{}", name.len());
        assert!(!name.ends_with('-'), "{name}");

        let e = env(&[
            ("TAIN_URL", long.as_str()),
            ("TAIN_DISTS", "bookworm|main|amd64;trixie|main|amd64"),
        ]);
        let single = try_single_source(&e).unwrap().unwrap();
        for (idx, m) in single.mirrors.iter().enumerate() {
            assert!(m.name.len() <= MAX_FILE_NAME_BYTES, "{}", m.name.len());
            assert!(m.name.ends_with(&format!("-{idx}")), "{}", m.name);
        }
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
    fn single_source_vars_set_lists_non_empty_mirror_vars_only() {
        let e = env(&[
            ("TAIN_URL", "http://x"),
            ("TAIN_GC", "1"),
            ("TAIN_PATH", ""),
            ("TAIN_PARALLEL", "4"), // global override, honored in TOML mode
        ]);
        assert_eq!(single_source_vars_set(&e), vec!["TAIN_URL", "TAIN_GC"]);
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
