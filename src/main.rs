use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

use clap::Parser;

use tain::cli::{Cli, Command, DaemonArgs, ImportCommand, StatusArgs, SyncArgs, VerifyArgs};
use tain::config::env::ProcessEnv;
use tain::config::load::{DEFAULT_CONFIG_PATH, LoadError, LoadMode, LoadOptions, load};
use tain::config::{Config, display as config_display, mirrors_list};
use tain::core::engine;
use tain::exit::ExitCode as TainExit;
use tain::observe::metrics::{GcMetrics, PgpMetric, SyncMetrics, write_textfile};
use tain::observe::{self, LogConfig};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let env_log = LogConfig::from_env();

    if let Command::Import(ImportCommand::MirrorsList { file }) = &cli.command {
        if let Err(code) = init_logging(&env_log, &cli) {
            return code;
        }
        return run_import_mirrors_list(file);
    }

    // The config carries log settings, so load it under a temporary
    // `TAIN_LOG_*`-only subscriber before installing the global one.
    let loaded = match observe::with_scoped(&env_log, || load_config(cli.config.as_deref())) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("tain: failed to install tracing subscriber: {err}");
            return TainExit::ConfigError.into();
        }
    };
    // `load` already folded `TAIN_LOG_*` overrides into `cfg.global.log`.
    let log_cfg = match &loaded {
        Ok((cfg, _)) => LogConfig::from(&cfg.global.log),
        Err(_) => env_log,
    };
    if let Err(code) = init_logging(&log_cfg, &cli) {
        return code;
    }
    match loaded {
        Ok((cfg, mode)) => dispatch(&cli, cfg, mode),
        Err(err) => {
            tracing::error!(%err, "config load failed");
            check_exit_code(&err).into()
        }
    }
}

fn init_logging(cfg: &LogConfig, cli: &Cli) -> Result<(), ExitCode> {
    if let Err(err) = observe::init(cfg) {
        eprintln!("tain: failed to install tracing subscriber: {err}");
        return Err(TainExit::ConfigError.into());
    }
    tracing::debug!(
        version = env!("CARGO_PKG_VERSION"),
        subcommand = cli.command.name(),
        "tain start"
    );
    Ok(())
}

fn load_config(cli_config: Option<&Path>) -> Result<(Config, LoadMode), LoadError> {
    load(LoadOptions {
        cli_config,
        env: &ProcessEnv,
        default_config_path: Some(Path::new(DEFAULT_CONFIG_PATH)),
    })
}

fn dispatch(cli: &Cli, cfg: Config, mode: LoadMode) -> ExitCode {
    match &cli.command {
        Command::Import(ImportCommand::MirrorsList { file }) => run_import_mirrors_list(file),
        Command::Check => run_check(&cfg, mode),
        Command::Sync(args) => run_sync(&cfg, args),
        Command::Verify(args) => run_verify(&cfg, args),
        Command::Status(args) => run_status(&cfg, args),
        Command::Daemon(args) => run_daemon(cli.config.as_deref(), cfg, args),
    }
}

fn run_sync(cfg: &Config, args: &SyncArgs) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(%e, "cannot build tokio runtime");
            return TainExit::FatalIo.into();
        }
    };

    let filter: Vec<&str> = args.mirrors.iter().map(String::as_str).collect();
    let mut any_success = false;
    let mut any_failure = false;
    let mut lock_contention = false;
    let mut fatal_io = false;
    let mut metrics: Vec<SyncMetrics> = Vec::new();
    let mut dry_run_reports: Vec<tain::core::engine::apt_flow::DryRunReport> = Vec::new();

    let overrides = engine::SyncOverrides {
        dry_run: args.dry_run,
        gc_dry_run: args.gc_dry_run,
    };
    if args.dry_run {
        tracing::info!(
            "--dry-run: planner mode — no pool downloads, no publish, no state / manifest writes"
        );
    }
    if args.gc_dry_run {
        tracing::info!("--gc-dry-run: GC will report candidates but not delete");
    }
    // One budget for the run so mirrors sharing a host share its pacer.
    let budget = tain::core::fetch::budget::Budget::new(
        tain::core::fetch::budget::BudgetConfig::from(&cfg.global),
    );
    rt.block_on(async {
        for mirror in &cfg.mirrors {
            if !filter.is_empty() && !filter.iter().any(|f| *f == mirror.name) {
                continue;
            }
            tracing::info!(mirror = %mirror.name, url = %mirror.url, "syncing");
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
                        "mirror outcome"
                    );
                    if outcome.is_success() {
                        any_success = true;
                    } else {
                        any_failure = true;
                    }
                    if let Some(report) = outcome.dry_run.clone() {
                        dry_run_reports.push(report);
                    }
                    metrics.push(build_metrics(mirror, &outcome));
                }
                Err(err) => {
                    if matches!(err, engine::EngineError::LockContended(_)) {
                        lock_contention = true;
                    }
                    if engine::is_fatal_io(&err) {
                        fatal_io = true;
                    }
                    tracing::error!(mirror = %mirror.name, %err, "mirror sync failed");
                    any_failure = true;
                }
            }
        }
    });

    // Dry-run report is data, so stdout; logs stay on stderr.
    if args.dry_run {
        for report in &dry_run_reports {
            print!("{}", report.text());
        }
    }

    // Metrics write errors never change the exit code.
    if let Some(path) = args.metrics_file.as_deref() {
        if let Err(e) = write_textfile(path, &metrics) {
            tracing::warn!(
                path = %path.display(),
                %e,
                "failed to write --metrics-file (sync result unaffected)"
            );
        } else {
            tracing::debug!(
                path = %path.display(),
                mirrors = metrics.len(),
                "metrics textfile written"
            );
        }
    }

    // Fatal I/O wins: it is an environment problem, not an upstream one.
    if fatal_io {
        TainExit::FatalIo.into()
    } else if any_failure && !any_success {
        if lock_contention {
            TainExit::LockContention.into()
        } else {
            TainExit::PartialMirrorFailure.into()
        }
    } else if any_failure {
        TainExit::PartialMirrorFailure.into()
    } else {
        TainExit::Success.into()
    }
}

#[cfg(unix)]
fn run_daemon(cli_config: Option<&Path>, cfg: Config, args: &DaemonArgs) -> ExitCode {
    use tain::core::daemon::{DaemonOpts, DaemonRunOptions, ReloadSource, run as daemon_run};

    let env = ProcessEnv;
    let default_path = Path::new(DEFAULT_CONFIG_PATH);
    let reload_source = ReloadSource::LoadOptions {
        cli_config: cli_config.map(Path::to_path_buf),
        default_config_path: Some(default_path.to_path_buf()),
    };
    let run_opts = DaemonRunOptions {
        config: cfg,
        reload_source,
        env: &env,
        opts: DaemonOpts {
            no_initial_sync: args.no_initial_sync,
        },
    };
    match daemon_run(run_opts) {
        Ok(code) => code.into(),
        Err(err) => {
            tracing::error!(%err, "daemon failed");
            err.exit_code().into()
        }
    }
}

#[cfg(not(unix))]
fn run_daemon(_cli_config: Option<&Path>, _cfg: Config, _args: &DaemonArgs) -> ExitCode {
    tracing::error!("`tain daemon` requires Unix (SIGTERM/SIGINT/SIGHUP handling)");
    TainExit::ConfigError.into()
}

fn run_verify(cfg: &Config, args: &VerifyArgs) -> ExitCode {
    let filter: Vec<&str> = args.mirrors.iter().map(String::as_str).collect();
    let mut any_problem = false;
    for mirror in &cfg.mirrors {
        if !filter.is_empty() && !filter.iter().any(|f| *f == mirror.name) {
            continue;
        }
        let mirror_root = cfg.global.target.join(&mirror.path);
        match tain::core::engine::verify::scrub_latest(&mirror_root) {
            Ok(report) => {
                if report.is_clean() {
                    tracing::info!(
                        mirror = %mirror.name,
                        ok = report.ok,
                        "verify clean"
                    );
                } else {
                    any_problem = true;
                    tracing::warn!(
                        mirror = %mirror.name,
                        ok = report.ok,
                        problems = report.problems.len(),
                        "verify found problems"
                    );
                    for (rel, verdict) in &report.problems {
                        tracing::warn!(mirror = %mirror.name, %rel, ?verdict);
                    }
                }
            }
            Err(err) => {
                any_problem = true;
                tracing::error!(mirror = %mirror.name, %err, "verify failed");
            }
        }
    }
    if any_problem {
        TainExit::PartialMirrorFailure.into()
    } else {
        TainExit::Success.into()
    }
}

fn run_status(cfg: &Config, args: &StatusArgs) -> ExitCode {
    let window = match args.healthy_within.as_deref() {
        None => None,
        Some(raw) => match tain::core::engine::status::parse_healthy_within(raw) {
            Ok(d) => Some(d),
            Err(err) => {
                tracing::error!(%err, "cannot parse --healthy-within");
                return TainExit::ConfigError.into();
            }
        },
    };
    let now = std::time::SystemTime::now();
    let mut report = tain::core::engine::status::StatusReport { mirrors: vec![] };
    for mirror in &cfg.mirrors {
        let mirror_root = cfg.global.target.join(&mirror.path);
        match tain::core::engine::status::snapshot(&mirror.name, &mirror_root, now, window) {
            Ok(s) => report.mirrors.push(s),
            Err(err) => {
                tracing::error!(mirror = %mirror.name, %err, "status failed");
                return TainExit::PartialMirrorFailure.into();
            }
        }
    }
    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                tracing::error!(%e, "cannot serialize status");
                return TainExit::FatalIo.into();
            }
        }
    } else {
        for m in &report.mirrors {
            println!("{}", tain::core::engine::status::format_line(m));
        }
    }
    if report.all_healthy() {
        TainExit::Success.into()
    } else {
        TainExit::PartialMirrorFailure.into()
    }
}

fn run_check(cfg: &Config, mode: LoadMode) -> ExitCode {
    match mode {
        LoadMode::Toml(path) => {
            tracing::info!(config = %path.display(), "config loaded from TOML");
        }
        LoadMode::EnvSingleSource => {
            tracing::info!("config assembled from TAIN_URL + TAIN_DISTS");
        }
    }
    print!("{}", config_display::format_config(cfg));
    TainExit::Success.into()
}

fn check_exit_code(err: &LoadError) -> TainExit {
    match err {
        LoadError::Io { .. } => TainExit::FatalIo,
        _ => TainExit::ConfigError,
    }
}

fn run_import_mirrors_list(path: &Path) -> ExitCode {
    let text = match read_file_or_stdin(path) {
        Ok(t) => t,
        Err(err) => {
            tracing::error!(path = %path.display(), %err, "cannot read mirrors.list");
            return TainExit::FatalIo.into();
        }
    };
    match mirrors_list::parse(&text) {
        Ok(entries) => {
            for d in mirrors_list::flat_entries(&entries) {
                tracing::warn!(
                    line = d.line,
                    "flat repositories are not supported yet; the line is commented out in \
                     the generated TOML"
                );
            }
            let toml = mirrors_list::to_toml(&entries);
            print!("{toml}");
            TainExit::Success.into()
        }
        Err(err) => {
            tracing::error!(%err, "mirrors.list parse failed");
            TainExit::ConfigError.into()
        }
    }
}

/// Map an engine outcome to metrics; keeps `observe::metrics` engine-agnostic.
fn build_metrics(
    mirror: &tain::config::model::MirrorConfig,
    outcome: &engine::MirrorOutcome,
) -> SyncMetrics {
    use tain::backends::apt::pgp::VerifyOutcome;
    let pgp_by_suite = outcome
        .pgp_by_suite
        .iter()
        .map(|(suite, o)| {
            let m = match o {
                VerifyOutcome::Verified => PgpMetric::Verified,
                VerifyOutcome::Skipped => PgpMetric::Skipped,
                VerifyOutcome::AbsentInIfPresent => PgpMetric::Absent,
            };
            (suite.clone(), m)
        })
        .collect();
    let gc = outcome.gc.as_ref().map(|g| GcMetrics {
        deleted_files: g.deleted.len() as u64,
        circuit_broken: g.circuit_broken,
    });
    SyncMetrics {
        mirror: mirror.name.clone(),
        backend: mirror.backend.name().to_owned(),
        pool_files: outcome.pool_files,
        pool_bytes: outcome.pool_bytes,
        last_success_unix: outcome.last_success_unix,
        gc,
        sync_duration_secs: outcome.sync_duration.as_secs_f64(),
        pgp_by_suite,
    }
}

fn read_file_or_stdin(path: &Path) -> io::Result<String> {
    if path == Path::new("-") {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path)
    }
}
