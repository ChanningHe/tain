//! Config source resolution.
//!
//! Primary source precedence: `--config` > `TAIN_CONFIG` > default path (if it
//! exists) > `TAIN_URL` + `TAIN_DISTS` single-source mode > `NoSource`.
//! `TAIN_*` globals then override whichever was chosen. Legacy variable names
//! only trigger a `warn!`; they never affect config.

use std::path::{Path, PathBuf};

use super::env::{self, EnvError, EnvSingleSource, EnvSource, GlobalOverrides};
use super::model::{Config, ConfigError, GlobalConfig, MirrorDefaults, resolve_mirror};
use super::toml::{self as toml_source, TomlError};

/// Production fallback for `LoadOptions::default_config_path`.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/tain/config.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadMode {
    Toml(PathBuf),
    EnvSingleSource,
}

/// Input for `load`. `default_config_path` is consulted only when neither
/// `--config` nor `TAIN_CONFIG` is set; tests pass `None` to disable it.
pub struct LoadOptions<'a> {
    pub cli_config: Option<&'a Path>,
    pub env: &'a dyn EnvSource,
    pub default_config_path: Option<&'a Path>,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(
        "no config source found — set `--config <path>` (or `TAIN_CONFIG`) to point at a TOML \
         file, or provide `TAIN_URL` + `TAIN_DISTS` for the single-source env mode. \
         Run `tain import mirrors-list <file>` to convert a legacy apt-mirror config."
    )]
    NoSource,
    #[error("cannot read config file `{path}`: {err}")]
    Io {
        path: PathBuf,
        #[source]
        err: std::io::Error,
    },
    #[error(transparent)]
    Toml(#[from] TomlError),
    #[error(transparent)]
    Env(#[from] EnvError),
    #[error(transparent)]
    Model(#[from] ConfigError),
}

/// Resolve the config from all available sources. Expects `tracing` to be
/// initialized (legacy env vars are reported via `warn!`).
pub fn load(opts: LoadOptions<'_>) -> Result<(Config, LoadMode), LoadError> {
    for w in env::detect_legacy(opts.env) {
        tracing::warn!("{}", w.message());
    }

    // An explicit path that is missing is an I/O error, never a silent fallthrough.
    let explicit_path = opts.cli_config.map(Path::to_path_buf).or_else(|| {
        opts.env
            .get("TAIN_CONFIG")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    });

    let default_path = opts
        .default_config_path
        .filter(|p| p.exists())
        .map(Path::to_path_buf);

    let config_path = explicit_path.or(default_path);

    let (mut cfg, mode) = if let Some(path) = config_path {
        let text = std::fs::read_to_string(&path).map_err(|err| LoadError::Io {
            path: path.clone(),
            err,
        })?;
        let cfg = toml_source::parse(&text)?;
        (cfg, LoadMode::Toml(path))
    } else if opts.env.get("TAIN_URL").is_some_and(|s| !s.is_empty()) {
        let single = env::try_single_source(opts.env)?
            .expect("TAIN_URL present but try_single_source returned None");
        (build_from_single_source(single)?, LoadMode::EnvSingleSource)
    } else {
        return Err(LoadError::NoSource);
    };

    GlobalOverrides::from_env(opts.env)?.apply(&mut cfg.global);

    Ok((cfg, mode))
}

fn build_from_single_source(single: EnvSingleSource) -> Result<Config, LoadError> {
    let mut global = GlobalConfig::default();
    single.globals.apply(&mut global);
    let mut mirrors = Vec::with_capacity(single.mirrors.len());
    let defaults = MirrorDefaults::default();
    for partial in single.mirrors {
        mirrors.push(resolve_mirror(partial, &defaults)?);
    }
    let cfg = Config { global, mirrors };
    cfg.validate()?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn errors_when_no_source() {
        let e = env(&[]);
        let opts = LoadOptions {
            cli_config: None,
            env: &e,
            default_config_path: None,
        };
        let err = load(opts).unwrap_err();
        assert!(matches!(err, LoadError::NoSource));
        let msg = format!("{err}");
        assert!(msg.contains("--config"));
        assert!(msg.contains("TAIN_URL"));
        assert!(msg.contains("tain import"));
    }

    #[test]
    fn loads_env_single_source_mode() {
        let e = env(&[
            ("TAIN_URL", "http://download.proxmox.com/debian/pve"),
            ("TAIN_DISTS", "bookworm|pve-no-subscription|amd64"),
            ("TAIN_PARALLEL", "8"),
        ]);
        let opts = LoadOptions {
            cli_config: None,
            env: &e,
            default_config_path: None,
        };
        let (cfg, mode) = load(opts).unwrap();
        assert_eq!(mode, LoadMode::EnvSingleSource);
        assert_eq!(cfg.global.parallel, 8);
        assert_eq!(cfg.mirrors.len(), 1);
        assert_eq!(
            cfg.mirrors[0].backend_options_apt().unwrap().suites,
            vec!["bookworm"]
        );
    }

    fn load_env_only(pairs: &[(&str, &str)]) -> Result<(Config, LoadMode), LoadError> {
        let e = env(pairs);
        load(LoadOptions {
            cli_config: None,
            env: &e,
            default_config_path: None,
        })
    }

    #[test]
    fn env_flat_suite_rejected_with_mirror_name() {
        for dists in [
            "./||amd64",
            ".||amd64",
            "repo/./||amd64",
            "stable/|main|amd64",
            "bookworm,repo/./|main|amd64",
        ] {
            let err = load_env_only(&[
                ("TAIN_URL", "http://example.com/repo"),
                ("TAIN_DISTS", dists),
            ])
            .unwrap_err();
            match &err {
                LoadError::Model(ConfigError::FlatRepositoryUnsupported { mirror, .. }) => {
                    assert_eq!(mirror, "example.com-repo", "{dists}");
                }
                other => panic!("expected FlatRepositoryUnsupported for {dists}, got {other:?}"),
            }
        }
    }

    #[test]
    fn env_pgp_without_keyring_rejected() {
        for mode in ["if-present", "required"] {
            let err = load_env_only(&[
                ("TAIN_URL", "http://example.com/repo"),
                ("TAIN_DISTS", "bookworm|main|amd64"),
                ("TAIN_VERIFY_PGP", mode),
            ])
            .unwrap_err();
            assert!(
                matches!(&err, LoadError::Model(ConfigError::PgpWithoutKeyring { mirror, .. }) if mirror == "example.com-repo"),
                "{mode}: {err:?}"
            );
        }
    }

    #[test]
    fn env_pgp_with_empty_keyring_rejected() {
        let err = load_env_only(&[
            ("TAIN_URL", "http://example.com/repo"),
            ("TAIN_DISTS", "bookworm|main|amd64"),
            ("TAIN_VERIFY_PGP", "required"),
            ("TAIN_KEYRING", ""),
        ])
        .unwrap_err();
        assert!(
            matches!(
                &err,
                LoadError::Model(ConfigError::PgpWithoutKeyring { .. })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn env_pgp_with_keyring_accepted() {
        let (cfg, _) = load_env_only(&[
            ("TAIN_URL", "http://example.com/repo"),
            ("TAIN_DISTS", "bookworm|main|amd64"),
            ("TAIN_VERIFY_PGP", "if-present"),
            ("TAIN_KEYRING", "/etc/keys.gpg"),
        ])
        .unwrap();
        assert_eq!(
            cfg.mirrors[0].verify.keyring.as_deref(),
            Some(Path::new("/etc/keys.gpg"))
        );
    }

    #[test]
    fn loads_toml_when_present() {
        let dir = tempdir();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[global]\ntarget = \"/data\"\nparallel = 16\n\n\
             [[mirror]]\nname = \"d\"\nurl = \"http://x\"\nsuites = [\"bookworm\"]\narchitectures = [\"amd64\"]\n",
        )
        .unwrap();
        let e = env(&[]);
        let opts = LoadOptions {
            cli_config: Some(&path),
            env: &e,
            default_config_path: None,
        };
        let (cfg, mode) = load(opts).unwrap();
        assert_eq!(mode, LoadMode::Toml(path));
        assert_eq!(cfg.global.parallel, 16);
        assert_eq!(cfg.mirrors.len(), 1);
    }

    #[test]
    fn env_globals_override_toml() {
        let dir = tempdir();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[global]\nparallel = 32\n\n\
             [[mirror]]\nname = \"d\"\nurl = \"http://x\"\nsuites = [\"bookworm\"]\narchitectures = [\"amd64\"]\n",
        )
        .unwrap();
        let e = env(&[("TAIN_PARALLEL", "4")]);
        let opts = LoadOptions {
            cli_config: Some(&path),
            env: &e,
            default_config_path: None,
        };
        let (cfg, _) = load(opts).unwrap();
        assert_eq!(cfg.global.parallel, 4, "env should override the TOML value");
    }

    #[test]
    fn toml_log_settings_apply_and_env_overrides_them() {
        let dir = tempdir();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[global]\nlog_level = \"debug\"\nlog_format = \"json\"\n",
        )
        .unwrap();
        let load_with = |pairs: &[(&str, &str)]| {
            let e = env(pairs);
            load(LoadOptions {
                cli_config: Some(&path),
                env: &e,
                default_config_path: None,
            })
            .unwrap()
            .0
        };

        let cfg = load_with(&[]);
        let log = crate::observe::LogConfig::from(&cfg.global.log);
        assert_eq!(log.filter.as_deref(), Some("debug"));
        assert_eq!(log.format, crate::observe::LogFormat::Json);

        let cfg = load_with(&[("TAIN_LOG_LEVEL", "warn"), ("TAIN_LOG_FORMAT", "text")]);
        let log = crate::observe::LogConfig::from(&cfg.global.log);
        assert_eq!(log.filter.as_deref(), Some("warn"));
        assert_eq!(log.format, crate::observe::LogFormat::Text);
    }

    #[test]
    fn tain_config_env_used_when_cli_flag_absent() {
        let dir = tempdir();
        let path = dir.path().join("via-env.toml");
        std::fs::write(
            &path,
            "[[mirror]]\nname = \"d\"\nurl = \"http://x\"\nsuites = [\"bookworm\"]\narchitectures = [\"amd64\"]\n",
        )
        .unwrap();
        let e = env(&[("TAIN_CONFIG", path.to_str().unwrap())]);
        let opts = LoadOptions {
            cli_config: None,
            env: &e,
            default_config_path: None,
        };
        let (_, mode) = load(opts).unwrap();
        assert_eq!(mode, LoadMode::Toml(path));
    }

    #[test]
    fn cli_flag_takes_precedence_over_tain_config() {
        let dir = tempdir();
        let cli_path = dir.path().join("cli.toml");
        let env_path = dir.path().join("env.toml");
        std::fs::write(&cli_path, "[global]\nparallel = 3\n").unwrap();
        std::fs::write(&env_path, "[global]\nparallel = 5\n").unwrap();
        let e = env(&[("TAIN_CONFIG", env_path.to_str().unwrap())]);
        let opts = LoadOptions {
            cli_config: Some(&cli_path),
            env: &e,
            default_config_path: None,
        };
        let (cfg, mode) = load(opts).unwrap();
        assert_eq!(mode, LoadMode::Toml(cli_path));
        assert_eq!(cfg.global.parallel, 3);
    }

    #[test]
    fn default_config_path_is_consulted_when_nothing_else_is_set() {
        let dir = tempdir();
        let path = dir.path().join("default.toml");
        std::fs::write(
            &path,
            "[[mirror]]\nname = \"d\"\nurl = \"http://x\"\nsuites = [\"bookworm\"]\narchitectures = [\"amd64\"]\n",
        )
        .unwrap();
        let e = env(&[]);
        let opts = LoadOptions {
            cli_config: None,
            env: &e,
            default_config_path: Some(&path),
        };
        let (_, mode) = load(opts).unwrap();
        assert_eq!(mode, LoadMode::Toml(path));
    }

    #[test]
    fn default_config_path_missing_falls_through_to_env_single_source() {
        let dir = tempdir();
        let missing = dir.path().join("does-not-exist.toml");
        let e = env(&[
            ("TAIN_URL", "http://x"),
            ("TAIN_DISTS", "bookworm|main|amd64"),
        ]);
        let opts = LoadOptions {
            cli_config: None,
            env: &e,
            default_config_path: Some(&missing),
        };
        let (_, mode) = load(opts).unwrap();
        assert_eq!(mode, LoadMode::EnvSingleSource);
    }

    #[test]
    fn default_config_path_missing_and_no_env_yields_no_source() {
        let dir = tempdir();
        let missing = dir.path().join("does-not-exist.toml");
        let e = env(&[]);
        let opts = LoadOptions {
            cli_config: None,
            env: &e,
            default_config_path: Some(&missing),
        };
        let err = load(opts).unwrap_err();
        assert!(matches!(err, LoadError::NoSource));
    }

    #[test]
    fn explicit_cli_config_wins_over_existing_default_path() {
        let dir = tempdir();
        let default_path = dir.path().join("default.toml");
        let cli_path = dir.path().join("cli.toml");
        std::fs::write(&default_path, "[global]\nparallel = 99\n").unwrap();
        std::fs::write(&cli_path, "[global]\nparallel = 7\n").unwrap();
        let e = env(&[]);
        let opts = LoadOptions {
            cli_config: Some(&cli_path),
            env: &e,
            default_config_path: Some(&default_path),
        };
        let (cfg, mode) = load(opts).unwrap();
        assert_eq!(mode, LoadMode::Toml(cli_path));
        assert_eq!(cfg.global.parallel, 7);
    }

    #[test]
    fn missing_toml_file_reports_io_error() {
        let e = env(&[]);
        let bad = PathBuf::from("/no/such/tain-config.toml");
        let opts = LoadOptions {
            cli_config: Some(&bad),
            env: &e,
            default_config_path: None,
        };
        let err = load(opts).unwrap_err();
        assert!(matches!(err, LoadError::Io { .. }));
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tempdir() -> TempDir {
        let base = std::env::temp_dir();
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let p = base.join(format!("tain-test-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    // Keeps the `Write` import used.
    #[allow(dead_code)]
    fn _touch(_w: &mut dyn Write) {}

    #[allow(dead_code)]
    impl super::super::model::MirrorConfig {
        fn backend_options_apt(&self) -> Option<&super::super::model::AptOptions> {
            match &self.backend_options {
                super::super::model::BackendOptions::Apt(a) => Some(a),
            }
        }
    }
}
