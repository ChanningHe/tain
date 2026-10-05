//! TOML config source: strict serde shape (`deny_unknown_fields`), then
//! `[defaults]` merged into each mirror via `resolve_mirror`. Every field here
//! must be documented in the configuration reference.

use std::path::PathBuf;
use std::time::Duration;

use bytesize::ByteSize;
use serde::Deserialize;
use url::Url;

use crate::observe::LogFormat;

use super::model::{
    BackendKind, Config, ConfigError, FloatRatio, GlobalConfig, I18nSelection, LogSettings,
    MirrorDefaults, PartialAptOptions, PartialGcConfig, PartialIndexSelection, PartialMirror,
    PartialVerifyConfig, PgpMode, RetryConfig, TimeoutConfig, resolve_mirror,
};

/// Parse a TOML string into a fully resolved `Config`.
///
/// # Errors
///
/// `TomlParse` for bad syntax or shape (including unknown fields), `Invalid`
/// for an out-of-range value, `Model` for model-level rejections.
pub fn parse(text: &str) -> Result<Config, TomlError> {
    let raw: TomlRoot = toml::from_str(text).map_err(|e| TomlError::TomlParse(e.to_string()))?;

    let global = raw.global.into_global()?;
    let mirror_defaults: MirrorDefaults = raw.defaults.into_defaults()?;

    let mut mirrors = Vec::with_capacity(raw.mirrors.len());
    for mirror in raw.mirrors {
        let partial = mirror.into_partial()?;
        let resolved = resolve_mirror(partial, &mirror_defaults).map_err(TomlError::Model)?;
        mirrors.push(resolved);
    }

    let cfg = Config { global, mirrors };
    cfg.validate().map_err(TomlError::Model)?;
    Ok(cfg)
}

#[derive(Debug, thiserror::Error)]
pub enum TomlError {
    #[error("TOML parse: {0}")]
    TomlParse(String),
    #[error("field `{field}` is invalid: {msg}")]
    Invalid { field: &'static str, msg: String },
    #[error(transparent)]
    Model(#[from] ConfigError),
}

fn invalid<T>(field: &'static str, msg: impl Into<String>) -> Result<T, TomlError> {
    Err(TomlError::Invalid {
        field,
        msg: msg.into(),
    })
}

// ---------- TOML shape (Serde) ----------

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TomlRoot {
    global: TomlGlobal,
    defaults: TomlDefaults,
    #[serde(rename = "mirror")]
    mirrors: Vec<TomlMirror>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TomlGlobal {
    target: Option<PathBuf>,
    parallel: Option<usize>,
    host_connections: Option<usize>,
    segments_per_file: Option<usize>,
    segment_min_size: Option<ByteSize>,
    #[serde(with = "humantime_serde")]
    connect_timeout: Option<Duration>,
    #[serde(with = "humantime_serde")]
    idle_timeout: Option<Duration>,
    retry: TomlRetry,
    bind_address: Option<String>,
    user_agent: Option<String>,
    log_level: Option<String>,
    log_format: Option<LogFormat>,
    schedule: Option<String>,
    #[serde(with = "humantime_serde")]
    lock_timeout: Option<Duration>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TomlRetry {
    count: Option<u32>,
    index_rounds: Option<u32>,
}

impl TomlGlobal {
    fn into_global(self) -> Result<GlobalConfig, TomlError> {
        let d = GlobalConfig::default();
        let bind_address = match self.bind_address {
            Some(s) => {
                let ip = s
                    .parse()
                    .map_err(|e: std::net::AddrParseError| TomlError::Invalid {
                        field: "global.bind_address",
                        msg: e.to_string(),
                    })?;
                Some(ip)
            }
            None => d.bind_address,
        };

        let retry_d = RetryConfig::default();
        let retry = RetryConfig {
            count: self.retry.count.unwrap_or(retry_d.count),
            index_rounds: self.retry.index_rounds.unwrap_or(retry_d.index_rounds),
        };

        let timeout_d = TimeoutConfig::default();
        let timeout = TimeoutConfig {
            connect: self.connect_timeout.unwrap_or(timeout_d.connect),
            read_idle: self.idle_timeout.unwrap_or(timeout_d.read_idle),
        };
        if timeout.connect.is_zero() {
            return invalid("global.connect_timeout", "must be > 0");
        }
        if timeout.read_idle.is_zero() {
            return invalid("global.idle_timeout", "must be > 0");
        }

        let segment_min_size = self
            .segment_min_size
            .map_or(d.segment_min_size, |b| b.as_u64());

        let parallel = self.parallel.unwrap_or(d.parallel);
        if parallel == 0 {
            return invalid("global.parallel", "must be > 0");
        }
        let host_connections = self.host_connections.unwrap_or(d.host_connections);
        if host_connections == 0 {
            return invalid("global.host_connections", "must be > 0");
        }

        let log = LogSettings {
            level: self.log_level.filter(|s| !s.is_empty()),
            format: self.log_format.unwrap_or_default(),
        };

        Ok(GlobalConfig {
            target: self.target.unwrap_or(d.target),
            parallel,
            host_connections,
            segments_per_file: self.segments_per_file.unwrap_or(d.segments_per_file),
            segment_min_size,
            timeout,
            retry,
            bind_address,
            user_agent: self.user_agent.unwrap_or(d.user_agent),
            log,
            schedule: self.schedule.filter(|s| !s.is_empty()),
            lock_timeout: self.lock_timeout.unwrap_or(d.lock_timeout),
        })
    }
}

// ---------- Defaults & mirror sections ----------

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TomlDefaults {
    backend: Option<BackendKind>,
    path: Option<PathBuf>,
    architectures: Option<Vec<String>>,
    components: Option<Vec<String>>,
    verify: TomlVerify,
    gc: TomlGc,
    indexes: TomlIndexes,
    create_suite_symlinks: Option<bool>,
}

impl TomlDefaults {
    fn into_defaults(self) -> Result<MirrorDefaults, TomlError> {
        Ok(MirrorDefaults {
            backend: self.backend,
            path: self.path,
            verify: self.verify.into_partial()?,
            gc: self.gc.into_partial()?,
            apt: PartialAptOptions {
                suites: None,
                components: self.components,
                architectures: self.architectures,
                indexes: self.indexes.into_partial(),
                create_suite_symlinks: self.create_suite_symlinks,
            },
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlMirror {
    name: String,
    backend: Option<BackendKind>,
    url: Url,
    path: Option<PathBuf>,
    suites: Option<Vec<String>>,
    components: Option<Vec<String>>,
    architectures: Option<Vec<String>>,
    #[serde(default)]
    verify: TomlVerify,
    #[serde(default)]
    gc: TomlGc,
    #[serde(default)]
    indexes: TomlIndexes,
    create_suite_symlinks: Option<bool>,
    force_http1: Option<bool>,
}

impl TomlMirror {
    fn into_partial(self) -> Result<PartialMirror, TomlError> {
        let overrides = MirrorDefaults {
            backend: self.backend,
            path: self.path,
            verify: self.verify.into_partial()?,
            gc: self.gc.into_partial()?,
            apt: PartialAptOptions {
                suites: self.suites,
                components: self.components,
                architectures: self.architectures,
                indexes: self.indexes.into_partial(),
                create_suite_symlinks: self.create_suite_symlinks,
            },
        };

        Ok(PartialMirror {
            name: self.name,
            url: self.url,
            overrides,
            force_http1: self.force_http1,
        })
    }
}

// ---------- Sub-tables ----------

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TomlVerify {
    pgp: Option<PgpMode>,
    keyring: Option<PathBuf>,
    allow_weak_hash: Option<bool>,
}

impl TomlVerify {
    fn into_partial(self) -> Result<PartialVerifyConfig, TomlError> {
        Ok(PartialVerifyConfig {
            pgp: self.pgp,
            keyring: self.keyring.filter(|p| !p.as_os_str().is_empty()),
            allow_weak_hash: self.allow_weak_hash,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TomlGc {
    enabled: Option<bool>,
    #[serde(with = "humantime_serde")]
    grace_period: Option<Duration>,
    max_delete_ratio: Option<f64>,
    keep_generations: Option<u32>,
    dry_run: Option<bool>,
}

impl TomlGc {
    fn into_partial(self) -> Result<PartialGcConfig, TomlError> {
        let ratio = match self.max_delete_ratio {
            None => None,
            Some(r) => Some(FloatRatio::new(r).map_err(TomlError::Model)?),
        };
        Ok(PartialGcConfig {
            enabled: self.enabled,
            grace_period: self.grace_period,
            max_delete_ratio: ratio,
            keep_generations: self.keep_generations,
            dry_run: self.dry_run,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TomlIndexes {
    contents: Option<bool>,
    i18n: Option<TomlI18n>,
    dep11: Option<bool>,
    cnf: Option<bool>,
    sources: Option<bool>,
    debian_installer: Option<bool>,
}

impl TomlIndexes {
    fn into_partial(self) -> PartialIndexSelection {
        PartialIndexSelection {
            contents: self.contents,
            i18n: self.i18n.map(TomlI18n::into_selection),
            dep11: self.dep11,
            cnf: self.cnf,
            sources: self.sources,
            debian_installer: self.debian_installer,
        }
    }
}

/// `true` (all), `false` (none) or a language list; an empty list means none.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TomlI18n {
    Toggle(bool),
    List(Vec<String>),
}

impl TomlI18n {
    fn into_selection(self) -> I18nSelection {
        match self {
            Self::Toggle(true) => I18nSelection::All,
            Self::Toggle(false) => I18nSelection::None,
            Self::List(v) => {
                if v.is_empty() {
                    I18nSelection::None
                } else {
                    I18nSelection::Only(v)
                }
            }
        }
    }
}

// Hand-written deserializers keep serde out of the model module.

impl<'de> Deserialize<'de> for BackendKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "apt" => Ok(Self::Apt),
            other => Err(serde::de::Error::unknown_variant(other, &["apt"])),
        }
    }
}

impl<'de> Deserialize<'de> for PgpMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "off" => Ok(Self::Off),
            "if-present" => Ok(Self::IfPresent),
            "required" => Ok(Self::Required),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["off", "if-present", "required"],
            )),
        }
    }
}

impl<'de> Deserialize<'de> for LogFormat {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{BackendOptions, I18nSelection};

    #[test]
    fn empty_toml_yields_defaults() {
        let cfg = parse("").unwrap();
        assert_eq!(cfg.global.parallel, 32);
        assert_eq!(cfg.global.target, PathBuf::from("/data"));
        assert!(cfg.mirrors.is_empty());
    }

    #[test]
    fn parses_full_documented_example() {
        let text = r#"
[global]
target = "/data"
parallel = 16
log_format = "text"
schedule = "0 2,8,14,20 * * *"

[global.retry]
count = 3

[defaults]
architectures = ["amd64"]
gc = { enabled = true, grace_period = "72h", max_delete_ratio = 0.3 }
verify = { pgp = "off" }

[[mirror]]
name = "debian"
backend = "apt"
url = "https://deb.debian.org/debian"
suites = ["bookworm", "bookworm-updates", "bookworm-backports"]
components = ["main", "contrib", "non-free", "non-free-firmware"]
architectures = ["amd64", "arm64"]

[mirror.indexes]
contents = true
i18n = ["en", "zh"]
dep11 = true
cnf = true
sources = false
debian_installer = false

[mirror.verify]
pgp = "required"
keyring = "/usr/share/keyrings/debian-archive-keyring.gpg"

[[mirror]]
name = "proxmox"
url = "http://download.proxmox.com/debian/pve"
suites = ["bookworm"]
components = ["pve-no-subscription"]

"#;
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.global.parallel, 16);
        assert_eq!(cfg.global.retry.count, 3);
        assert_eq!(cfg.global.log.format, LogFormat::Text);
        assert_eq!(cfg.global.schedule.as_deref(), Some("0 2,8,14,20 * * *"));
        assert_eq!(cfg.mirrors.len(), 2);

        let debian = &cfg.mirrors[0];
        assert_eq!(debian.name, "debian");
        assert_eq!(debian.backend, BackendKind::Apt);
        assert!(debian.gc.enabled, "gc from defaults");
        assert_eq!(
            debian.verify.pgp,
            PgpMode::Required,
            "per-mirror override wins"
        );
        assert_eq!(
            debian.verify.keyring.as_deref(),
            Some(std::path::Path::new(
                "/usr/share/keyrings/debian-archive-keyring.gpg"
            ))
        );

        match &debian.backend_options {
            BackendOptions::Apt(a) => {
                assert_eq!(a.suites.len(), 3);
                assert_eq!(a.architectures, vec!["amd64", "arm64"]);
                assert_eq!(
                    a.indexes.i18n,
                    I18nSelection::Only(vec!["en".into(), "zh".into()])
                );
                assert!(!a.indexes.sources);
            }
        }

        let proxmox = &cfg.mirrors[1];
        match &proxmox.backend_options {
            BackendOptions::Apt(a) => {
                assert_eq!(a.architectures, vec!["amd64".to_owned()]);
                // Set by neither [defaults] nor the mirror: hardcoded default.
                assert_eq!(a.indexes.i18n, I18nSelection::All);
            }
        }
        assert!(proxmox.gc.enabled);
    }

    #[test]
    fn flat_suites_rejected_in_toml() {
        for suites in [
            r#"["./"]"#,
            r#"["repo/./"]"#,
            r#"["stable/"]"#,
            r#"["bookworm", "repo/./"]"#,
        ] {
            let text = format!(
                "[[mirror]]\nname = \"vendor-flat\"\nurl = \"https://example.com/repo\"\n\
                 suites = {suites}\narchitectures = [\"amd64\"]\n"
            );
            let err = parse(&text).unwrap_err();
            assert!(
                matches!(
                    &err,
                    TomlError::Model(ConfigError::FlatRepositoryUnsupported { mirror, .. })
                        if mirror == "vendor-flat"
                ),
                "{suites}: {err:?}"
            );
            assert!(
                err.to_string()
                    .contains("flat repositories are not supported"),
                "{err}"
            );
        }
    }

    #[test]
    fn pgp_without_keyring_rejected_in_mirror_verify() {
        let text = r#"
[[mirror]]
name = "signed"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.verify]
pgp = "if-present"
"#;
        let err = parse(text).unwrap_err();
        assert!(
            matches!(
                &err,
                TomlError::Model(ConfigError::PgpWithoutKeyring { mirror, pgp: PgpMode::IfPresent })
                    if mirror == "signed"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn pgp_with_empty_keyring_rejected() {
        let text = r#"
[[mirror]]
name = "signed"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.verify]
pgp = "required"
keyring = ""
"#;
        let err = parse(text).unwrap_err();
        assert!(
            matches!(
                &err,
                TomlError::Model(ConfigError::PgpWithoutKeyring { mirror, pgp: PgpMode::Required })
                    if mirror == "signed"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn pgp_without_keyring_rejected_in_defaults_verify() {
        let text = r#"
[defaults.verify]
pgp = "required"

[[mirror]]
name = "inherits"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
"#;
        let err = parse(text).unwrap_err();
        assert!(
            matches!(
                &err,
                TomlError::Model(ConfigError::PgpWithoutKeyring { mirror, pgp: PgpMode::Required })
                    if mirror == "inherits"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn pgp_with_keyring_from_defaults_accepted() {
        let text = r#"
[defaults.verify]
pgp = "if-present"
keyring = "/etc/keys.gpg"

[[mirror]]
name = "d"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
"#;
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.mirrors[0].verify.pgp, PgpMode::IfPresent);
    }

    #[test]
    fn i18n_bool_true_means_all() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.indexes]
i18n = true
"#;
        let cfg = parse(text).unwrap();
        match &cfg.mirrors[0].backend_options {
            BackendOptions::Apt(a) => assert_eq!(a.indexes.i18n, I18nSelection::All),
        }
    }

    #[test]
    fn i18n_bool_false_means_none() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.indexes]
i18n = false
"#;
        let cfg = parse(text).unwrap();
        match &cfg.mirrors[0].backend_options {
            BackendOptions::Apt(a) => assert_eq!(a.indexes.i18n, I18nSelection::None),
        }
    }

    #[test]
    fn i18n_empty_array_means_none() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.indexes]
i18n = []
"#;
        let cfg = parse(text).unwrap();
        match &cfg.mirrors[0].backend_options {
            BackendOptions::Apt(a) => assert_eq!(a.indexes.i18n, I18nSelection::None),
        }
    }

    #[test]
    fn segment_min_size_accepts_human_units() {
        let text = r#"
[global]
segment_min_size = "512MiB"
"#;
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.global.segment_min_size, 512 * 1024 * 1024);
    }

    #[test]
    fn durations_accept_human_units() {
        let text = r#"
[global]
connect_timeout = "45s"
idle_timeout = "90s"
lock_timeout = "10s"
"#;
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.global.timeout.connect, Duration::from_secs(45));
        assert_eq!(cfg.global.timeout.read_idle, Duration::from_secs(90));
        assert_eq!(cfg.global.lock_timeout, Duration::from_secs(10));
    }

    #[test]
    fn unknown_top_level_key_rejected() {
        let text = "wat = 1\n";
        let err = parse(text).unwrap_err();
        assert!(matches!(err, TomlError::TomlParse(_)));
    }

    #[test]
    fn unknown_mirror_key_rejected() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
banana = true
"#;
        let err = parse(text).unwrap_err();
        assert!(matches!(err, TomlError::TomlParse(_)), "err={err:?}");
    }

    #[test]
    fn removed_keys_are_unknown_fields() {
        const MIRROR: &str = "[[mirror]]\nname = \"d\"\nurl = \"https://example.com\"\n\
                              suites = [\"bookworm\"]\narchitectures = [\"amd64\"]\n";
        let cases = [
            (
                "[global]\nlog_file = \"/var/log/tain.log\"\n".to_owned(),
                "log_file",
            ),
            (
                "[global.retry]\nbackoff_base = \"2s\"\n".to_owned(),
                "backoff_base",
            ),
            (
                "[defaults]\nallow_missing_suite = true\n".to_owned(),
                "allow_missing_suite",
            ),
            ("[defaults.verify]\nlocal = \"hash\"\n".to_owned(), "local"),
            (
                format!("{MIRROR}allow_missing_suite = true\n"),
                "allow_missing_suite",
            ),
            (
                format!("{MIRROR}[mirror.verify]\nlocal = \"size\"\n"),
                "local",
            ),
        ];
        for (text, key) in cases {
            let err = parse(&text).unwrap_err();
            assert!(
                matches!(&err, TomlError::TomlParse(msg) if msg.contains(&format!("unknown field `{key}`"))),
                "{key}: {err:?}"
            );
        }
    }

    #[test]
    fn parallel_zero_rejected() {
        let text = "[global]\nparallel = 0\n";
        let err = parse(text).unwrap_err();
        assert!(
            matches!(
                err,
                TomlError::Invalid {
                    field: "global.parallel",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn host_connections_zero_rejected() {
        let text = "[global]\nhost_connections = 0\n";
        let err = parse(text).unwrap_err();
        assert!(
            matches!(
                err,
                TomlError::Invalid {
                    field: "global.host_connections",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn zero_timeouts_rejected() {
        for (key, field) in [
            ("connect_timeout", "global.connect_timeout"),
            ("idle_timeout", "global.idle_timeout"),
        ] {
            let text = format!("[global]\n{key} = \"0s\"\n");
            let err = parse(&text).unwrap_err();
            assert!(
                matches!(&err, TomlError::Invalid { field: f, .. } if *f == field),
                "{key}: {err:?}"
            );
        }
    }

    #[test]
    fn missing_suites_bubbles_model_error() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
architectures = ["amd64"]
"#;
        let err = parse(text).unwrap_err();
        assert!(
            matches!(
                err,
                TomlError::Model(ConfigError::MissingField {
                    field: "suites",
                    ..
                })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn missing_architectures_when_neither_mirror_nor_defaults_set_it() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
suites = ["bookworm"]
"#;
        let err = parse(text).unwrap_err();
        assert!(
            matches!(
                err,
                TomlError::Model(ConfigError::MissingField {
                    field: "architectures",
                    ..
                })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn invalid_pgp_string_rejected() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.verify]
pgp = "maybe"
"#;
        let err = parse(text).unwrap_err();
        assert!(matches!(err, TomlError::TomlParse(_)), "{err:?}");
    }

    #[test]
    fn invalid_backend_rejected() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
backend = "yum"
suites = ["bookworm"]
architectures = ["amd64"]
"#;
        let err = parse(text).unwrap_err();
        assert!(matches!(err, TomlError::TomlParse(_)), "{err:?}");
    }

    #[test]
    fn bind_address_parsed_from_string() {
        let text = r#"
[global]
bind_address = "192.0.2.10"
"#;
        let cfg = parse(text).unwrap();
        assert_eq!(
            cfg.global.bind_address.map(|ip| ip.to_string()),
            Some("192.0.2.10".to_owned())
        );
    }

    #[test]
    fn invalid_bind_address_rejected() {
        let text = r#"
[global]
bind_address = "not-an-ip"
"#;
        let err = parse(text).unwrap_err();
        assert!(
            matches!(
                err,
                TomlError::Invalid {
                    field: "global.bind_address",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn max_delete_ratio_out_of_range_rejected() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.gc]
max_delete_ratio = 1.5
"#;
        let err = parse(text).unwrap_err();
        assert!(
            matches!(err, TomlError::Model(ConfigError::InvalidRatio(_))),
            "{err:?}"
        );
    }

    #[test]
    fn per_mirror_overrides_defaults_ratio() {
        let text = r#"
[defaults.gc]
max_delete_ratio = 0.1

[[mirror]]
name = "d"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.gc]
max_delete_ratio = 0.5
"#;
        let cfg = parse(text).unwrap();
        assert!((cfg.mirrors[0].gc.max_delete_ratio.as_f64() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn nonexistent_i18n_variant_falls_through_serde() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.indexes]
i18n = 42
"#;
        let err = parse(text).unwrap_err();
        assert!(matches!(err, TomlError::TomlParse(_)), "{err:?}");
    }

    #[test]
    fn duplicate_mirror_names_rejected() {
        let text = r#"
[[mirror]]
name = "twin"
url = "http://a"
suites = ["bookworm"]
architectures = ["amd64"]

[[mirror]]
name = "twin"
url = "http://b"
suites = ["bookworm"]
architectures = ["amd64"]
"#;
        let err = parse(text).unwrap_err();
        assert!(
            matches!(err, TomlError::Model(ConfigError::DuplicateName(ref n)) if n == "twin"),
            "{err:?}"
        );
    }

    #[test]
    fn parse_reports_mirror_error_via_error_display() {
        let text = r#"
[[mirror]]
name = "d"
url = "https://example.com"
architectures = ["amd64"]
"#;
        let err = parse(text).unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("suites"), "err display = {s}");
    }
}
