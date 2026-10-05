//! Built-in scheduler for `tain daemon`: cron ticks, `SIGHUP` reload,
//! `SIGTERM`/`SIGINT` graceful shutdown.
//!
//! Schedules use the system local timezone (`TZ`); set `TZ=UTC` for UTC.
//!
//! Shutdown never interrupts an in-flight sync; it takes effect at the next
//! loop check. Hard-killing a sync is safe because syncs are failure-neutral
//! and crash recovery converges.
//!
//! Overlap protection: an in-process mutex skips a tick while the previous
//! cycle runs; the on-disk flock still guards against a foreign `tain sync`.
//! A failed reload keeps the current config.

#![cfg(unix)]

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Local;
use croner::Cron;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, watch};
use tokio::time::sleep;

use crate::config::env::EnvSource;
use crate::config::load::{LoadError, LoadMode, LoadOptions, load};
use crate::config::model::Config;
use crate::core::engine::{self, SyncOverrides};
use crate::core::fetch::budget::{Budget, BudgetConfig};
use crate::exit::ExitCode;

/// `tain daemon` CLI options.
#[derive(Debug, Clone, Copy, Default)]
pub struct DaemonOpts {
    /// Skip the startup sync; wait for the first cron tick.
    pub no_initial_sync: bool,
}

/// Inputs to [`run`].
pub struct DaemonRunOptions<'a> {
    pub config: Config,
    /// Must match the source that produced `config`.
    pub reload_source: ReloadSource,
    pub env: &'a dyn EnvSource,
    pub opts: DaemonOpts,
}

/// Where to re-read the config from on SIGHUP.
#[derive(Debug, Clone)]
pub enum ReloadSource {
    /// Re-run [`crate::config::load::load`] with these options.
    LoadOptions {
        cli_config: Option<PathBuf>,
        default_config_path: Option<PathBuf>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error(
        "`tain daemon` requires `global.schedule` in the config (or `TAIN_SCHEDULE`) — got none"
    )]
    NoSchedule,
    #[error("invalid cron expression `{raw}`: {err}")]
    InvalidSchedule { raw: String, err: String },
    #[error("cannot install {signal} handler: {source}")]
    SignalInstall {
        signal: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot build tokio runtime: {source}")]
    Runtime {
        #[source]
        source: std::io::Error,
    },
}

impl DaemonError {
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::NoSchedule | Self::InvalidSchedule { .. } => ExitCode::ConfigError,
            Self::SignalInstall { .. } | Self::Runtime { .. } => ExitCode::FatalIo,
        }
    }
}

/// Blocking entry point: builds a tokio runtime and runs [`run_async`].
///
/// # Errors
///
/// Missing or invalid schedule, signal-handler install failure, or runtime
/// build failure.
pub fn run(run_opts: DaemonRunOptions<'_>) -> Result<ExitCode, DaemonError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|source| DaemonError::Runtime { source })?;
    rt.block_on(run_async(run_opts))
}

/// Async body of [`run`].
///
/// # Errors
///
/// Same taxonomy as [`run`].
pub async fn run_async(mut run_opts: DaemonRunOptions<'_>) -> Result<ExitCode, DaemonError> {
    let schedule = parse_schedule(&run_opts.config)?;

    // A daemon that cannot hear shutdown signals must not start.
    let mut sigterm =
        signal(SignalKind::terminate()).map_err(|source| DaemonError::SignalInstall {
            signal: "SIGTERM",
            source,
        })?;
    let mut sigint =
        signal(SignalKind::interrupt()).map_err(|source| DaemonError::SignalInstall {
            signal: "SIGINT",
            source,
        })?;
    let mut sighup = signal(SignalKind::hangup()).map_err(|source| DaemonError::SignalInstall {
        signal: "SIGHUP",
        source,
    })?;

    let in_progress: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tracing::info!(
        mirrors = run_opts.config.mirrors.len(),
        schedule = %run_opts
            .config
            .global
            .schedule
            .as_deref()
            .unwrap_or("<none>"),
        initial_sync = !run_opts.opts.no_initial_sync,
        "daemon start"
    );

    if !run_opts.opts.no_initial_sync {
        if *shutdown_rx.borrow() {
            return Ok(ExitCode::Success);
        }
        run_one_cycle(&run_opts.config, &in_progress).await;
    }

    let mut current_schedule = schedule;

    loop {
        if *shutdown_rx.borrow() {
            tracing::info!("daemon exiting after signal");
            return Ok(ExitCode::Success);
        }

        let now = Local::now();
        let next = match current_schedule.find_next_occurrence(&now, false) {
            Ok(next) => next,
            Err(err) => {
                tracing::error!(%err, "cron scheduler returned no next occurrence; exiting");
                return Ok(ExitCode::Success);
            }
        };
        let wait = (next - now).to_std().unwrap_or(Duration::from_secs(0));
        tracing::info!(next = %next.to_rfc3339(), wait_secs = wait.as_secs(), "next tick");

        tokio::select! {
            biased;
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received");
                let _ = shutdown_tx.send(true);
                continue;
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT received");
                let _ = shutdown_tx.send(true);
                continue;
            }
            _ = sighup.recv() => {
                tracing::info!("SIGHUP received — reloading config");
                match reload_config(&run_opts.reload_source, run_opts.env) {
                    Ok(new_cfg) => {
                        match parse_schedule(&new_cfg) {
                            Ok(sched) => {
                                current_schedule = sched;
                                run_opts.config = new_cfg;
                                tracing::info!(
                                    schedule = %run_opts
                                        .config
                                        .global
                                        .schedule
                                        .as_deref()
                                        .unwrap_or("<none>"),
                                    "config reloaded"
                                );
                            }
                            Err(err) => {
                                tracing::warn!(%err, "reloaded config has invalid schedule — keeping previous config");
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(%err, "config reload failed — keeping previous config");
                    }
                }
                continue;
            }
            () = sleep(wait) => {}
        }

        if *shutdown_rx.borrow() {
            continue;
        }

        run_one_cycle(&run_opts.config, &in_progress).await;
    }
}

async fn run_one_cycle(cfg: &Config, in_progress: &Arc<Mutex<()>>) {
    let guard = match in_progress.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            tracing::warn!(
                "previous sync still running, skipping this tick (belt-and-braces flock inside sync_mirror_with_budget will also fire)"
            );
            return;
        }
    };
    let started = Instant::now();
    let n_mirrors = cfg.mirrors.len();
    tracing::info!(mirrors = n_mirrors, "tick — starting sync cycle");
    sync_all(cfg).await;
    tracing::info!(
        mirrors = n_mirrors,
        secs = started.elapsed().as_secs(),
        "tick — cycle done"
    );
    drop(guard);
}

async fn sync_all(cfg: &Config) {
    // Shared across mirrors so one CDN host sees a single 429/503 pacer.
    let budget = Budget::new(BudgetConfig::from(&cfg.global));
    let overrides = SyncOverrides::default();
    for mirror in &cfg.mirrors {
        tracing::info!(mirror = %mirror.name, url = %mirror.url, "syncing (daemon tick)");
        match engine::sync_mirror_with_budget(
            &cfg.global,
            mirror,
            &cfg.global.target,
            overrides,
            &budget,
        )
        .await
        {
            Ok(outcome) => {
                tracing::info!(
                    mirror = %outcome.mirror_name,
                    succeeded = ?outcome.suites_succeeded,
                    unchanged = ?outcome.suites_unchanged,
                    failed = ?outcome.suites_failed,
                    gen = outcome.new_generation,
                    "daemon mirror outcome"
                );
            }
            Err(err) => {
                if matches!(err, engine::EngineError::LockContended(_)) {
                    tracing::warn!(mirror = %mirror.name, %err, "daemon: lock contended — foreign sync running");
                } else {
                    tracing::error!(mirror = %mirror.name, %err, "daemon: mirror sync failed");
                }
            }
        }
    }
}

/// Parse `global.schedule` into a [`Cron`].
///
/// # Errors
///
/// `NoSchedule` if unset, `InvalidSchedule` if unparsable.
pub fn parse_schedule(cfg: &Config) -> Result<Cron, DaemonError> {
    let raw = cfg
        .global
        .schedule
        .as_deref()
        .ok_or(DaemonError::NoSchedule)?;
    Cron::from_str(raw).map_err(|err| DaemonError::InvalidSchedule {
        raw: raw.to_owned(),
        err: err.to_string(),
    })
}

fn reload_config(source: &ReloadSource, env: &dyn EnvSource) -> Result<Config, LoadError> {
    match source {
        ReloadSource::LoadOptions {
            cli_config,
            default_config_path,
        } => {
            let opts = LoadOptions {
                cli_config: cli_config.as_deref(),
                env,
                default_config_path: default_config_path.as_deref(),
            };
            let (cfg, mode) = load(opts)?;
            match mode {
                LoadMode::Toml(path) => {
                    tracing::debug!(config = %path.display(), "reloaded from TOML");
                }
                LoadMode::EnvSingleSource => {
                    tracing::debug!("reloaded from TAIN_URL + TAIN_DISTS");
                }
            }
            Ok(cfg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::GlobalConfig;

    fn cfg_with_schedule(sched: Option<&str>) -> Config {
        let global = GlobalConfig {
            schedule: sched.map(str::to_owned),
            ..GlobalConfig::default()
        };
        Config {
            global,
            mirrors: vec![],
        }
    }

    #[test]
    fn parse_schedule_accepts_five_field_expression() {
        let cfg = cfg_with_schedule(Some("0 2,8,14,20 * * *"));
        parse_schedule(&cfg).expect("valid cron must parse");
    }

    #[test]
    fn parse_schedule_rejects_garbage() {
        let cfg = cfg_with_schedule(Some("not a cron"));
        let err = parse_schedule(&cfg).unwrap_err();
        assert!(
            matches!(err, DaemonError::InvalidSchedule { .. }),
            "wanted InvalidSchedule, got {err:?}"
        );
    }

    #[test]
    fn parse_schedule_flags_missing_schedule() {
        let cfg = cfg_with_schedule(None);
        let err = parse_schedule(&cfg).unwrap_err();
        assert!(matches!(err, DaemonError::NoSchedule), "got {err:?}");
    }

    #[test]
    fn daemon_error_exit_codes_match_cli_contract() {
        assert_eq!(DaemonError::NoSchedule.exit_code(), ExitCode::ConfigError);
        assert_eq!(
            DaemonError::InvalidSchedule {
                raw: "x".to_owned(),
                err: "y".to_owned()
            }
            .exit_code(),
            ExitCode::ConfigError
        );
    }

    /// Pins the `try_lock` semantics the tick-skip relies on.
    #[tokio::test]
    async fn in_progress_mutex_semantics() {
        let m: Mutex<()> = Mutex::new(());
        let held = m.lock().await;
        assert!(m.try_lock().is_err(), "second try_lock must fail");
        drop(held);
        assert!(m.try_lock().is_ok(), "released mutex must relock");
    }

    /// Catches the tokio `signal` feature going missing.
    #[cfg(unix)]
    #[tokio::test]
    async fn signal_handlers_install_cleanly() {
        let _t = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let _i = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let _h = signal(SignalKind::hangup()).expect("SIGHUP handler");
    }

    #[test]
    fn different_schedules_yield_different_next_ticks() {
        let every_minute = Cron::from_str("* * * * *").unwrap();
        let daily = Cron::from_str("0 0 * * *").unwrap();
        let now = Local::now();
        let next_min = every_minute.find_next_occurrence(&now, false).unwrap();
        let next_day = daily.find_next_occurrence(&now, false).unwrap();
        assert!(
            (next_day - now).num_seconds() > (next_min - now).num_seconds(),
            "daily should be strictly further out than every-minute"
        );
    }
}
