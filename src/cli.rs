//! Command-line interface. `///` docs here are the `--help` text.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "tain",
    about = "General-purpose repository mirror sync framework",
    version,
    long_about = None,
    propagate_version = true,
)]
pub struct Cli {
    /// Path to the TOML config file (overrides `TAIN_CONFIG`).
    #[arg(long, global = true, env = "TAIN_CONFIG")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a single sync pass and exit.
    Sync(SyncArgs),
    /// Long-running daemon with the built-in cron scheduler.
    Daemon(DaemonArgs),
    /// Validate config and print the normalized model, then exit.
    Check,
    /// Rehash local files against the last-published manifest.
    Verify(VerifyArgs),
    /// Report last-run state; supports `--healthy-within` for compose healthchecks.
    Status(StatusArgs),
    /// One-shot migration helpers.
    #[command(subcommand)]
    Import(ImportCommand),
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    /// Restrict the run to specific mirrors by name (repeatable).
    #[arg(long = "mirror", value_name = "NAME")]
    pub mirrors: Vec<String>,
    /// Plan and log the diff without downloading or publishing.
    #[arg(long)]
    pub dry_run: bool,
    /// Log GC candidates without deleting anything.
    #[arg(long)]
    pub gc_dry_run: bool,
    /// Write Prometheus textfile metrics to this path.
    #[arg(long, value_name = "PATH")]
    pub metrics_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Skip the sync at startup; wait for the first scheduled tick.
    #[arg(long)]
    pub no_initial_sync: bool,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Restrict verification to specific mirrors.
    #[arg(long = "mirror", value_name = "NAME")]
    pub mirrors: Vec<String>,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Emit machine-readable JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
    /// Exit 0 only if the last successful sync is within this duration (e.g. `48h`).
    #[arg(long, value_name = "DUR")]
    pub healthy_within: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum ImportCommand {
    /// Convert an apt-mirror style `mirrors.list` to Tain TOML on stdout.
    #[command(name = "mirrors-list")]
    MirrorsList {
        /// Source file. Use `-` to read from stdin.
        file: PathBuf,
    },
}

impl Command {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Sync(_) => "sync",
            Self::Daemon(_) => "daemon",
            Self::Check => "check",
            Self::Verify(_) => "verify",
            Self::Status(_) => "status",
            Self::Import(_) => "import",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_tree_parses() {
        Cli::command().debug_assert();
    }

    #[test]
    fn sync_parses_all_flags() {
        let cli = Cli::try_parse_from([
            "tain",
            "--config",
            "/etc/tain/config.toml",
            "sync",
            "--mirror",
            "debian",
            "--mirror",
            "ubuntu",
            "--dry-run",
            "--gc-dry-run",
            "--metrics-file",
            "/var/lib/tain/metrics.prom",
        ])
        .unwrap();
        match cli.command {
            Command::Sync(args) => {
                assert_eq!(args.mirrors, vec!["debian", "ubuntu"]);
                assert!(args.dry_run);
                assert!(args.gc_dry_run);
                assert_eq!(
                    args.metrics_file.as_deref(),
                    Some(std::path::Path::new("/var/lib/tain/metrics.prom"))
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/etc/tain/config.toml"))
        );
    }

    #[test]
    fn daemon_no_initial_sync() {
        let cli = Cli::try_parse_from(["tain", "daemon", "--no-initial-sync"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Daemon(DaemonArgs {
                no_initial_sync: true
            })
        ));
    }

    #[test]
    fn check_takes_no_args() {
        let cli = Cli::try_parse_from(["tain", "check"]).unwrap();
        assert!(matches!(cli.command, Command::Check));
    }

    #[test]
    fn verify_multiple_mirrors() {
        let cli =
            Cli::try_parse_from(["tain", "verify", "--mirror", "a", "--mirror", "b"]).unwrap();
        match cli.command {
            Command::Verify(args) => assert_eq!(args.mirrors, vec!["a", "b"]),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn status_json_and_healthy() {
        let cli =
            Cli::try_parse_from(["tain", "status", "--json", "--healthy-within", "48h"]).unwrap();
        match cli.command {
            Command::Status(args) => {
                assert!(args.json);
                assert_eq!(args.healthy_within.as_deref(), Some("48h"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn import_mirrors_list_positional() {
        let cli = Cli::try_parse_from(["tain", "import", "mirrors-list", "/etc/apt/mirrors.list"])
            .unwrap();
        match cli.command {
            Command::Import(ImportCommand::MirrorsList { file }) => {
                assert_eq!(file, std::path::PathBuf::from("/etc/apt/mirrors.list"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn unknown_subcommand_is_error() {
        let err = Cli::try_parse_from(["tain", "wat"]).unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "kind was {:?}",
            err.kind()
        );
    }
}
