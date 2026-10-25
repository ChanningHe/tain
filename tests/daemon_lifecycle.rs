//! `tain daemon` lifecycle tests. They send real signals to this process,
//! so every test serializes on `SIGNAL_TESTS`.

#![cfg(unix)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use tokio::sync::Mutex;

use tain::config::env::EnvSource;
use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, Config, GcConfig, GlobalConfig, I18nSelection,
    IndexSelection, MirrorConfig, VerifyConfig,
};
use tain::core::daemon::{
    DaemonError, DaemonOpts, DaemonRunOptions, ReloadSource, parse_schedule, run_async,
};

mod common;
use common::{StaticServer, SyntheticRepo, TempDir};

/// Process-wide serializer — signals ignore thread boundaries.
static SIGNAL_TESTS: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

struct EmptyEnv;

impl EnvSource for EmptyEnv {
    fn get(&self, _key: &str) -> Option<String> {
        None
    }
}

fn build_mirror(base_url: &url::Url, name: &str) -> MirrorConfig {
    let apt = AptOptions {
        suites: vec!["bookworm".to_owned()],
        components: vec!["main".to_owned()],
        architectures: vec!["amd64".to_owned()],
        indexes: IndexSelection {
            packages: true,
            contents: false,
            i18n: I18nSelection::None,
            dep11: false,
            cnf: false,
            sources: false,
            debian_installer: false,
        },
        create_suite_symlinks: false,
    };
    MirrorConfig {
        name: name.to_owned(),
        backend: BackendKind::Apt,
        url: base_url.clone(),
        path: PathBuf::from(name),
        verify: VerifyConfig::default(),
        gc: GcConfig::default(),
        force_http1: false,
        backend_options: BackendOptions::Apt(apt),
    }
}

fn build_global(target_root: PathBuf, schedule: &str) -> GlobalConfig {
    let mut g = GlobalConfig {
        target: target_root,
        parallel: 4,
        host_connections: 2,
        ..GlobalConfig::default()
    };
    g.schedule = Some(schedule.to_owned());
    g
}

fn kill_self(sig: libc::c_int) {
    // SAFETY: getpid is always safe; kill on our own PID with a handled signal is well-defined.
    unsafe {
        let pid = libc::getpid();
        assert_eq!(libc::kill(pid, sig), 0, "kill returned nonzero");
    }
}

async fn later_signal(sig: libc::c_int, delay_ms: u64) {
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    kill_self(sig);
}

#[tokio::test]
async fn no_initial_sync_then_sigterm_exits_cleanly_without_syncing() {
    let _guard = SIGNAL_TESTS.lock().await;

    // Unreachable upstream: no sync may run before SIGTERM.
    let target = TempDir::new("daemon-no-initial");
    let global = build_global(target.path().to_path_buf(), "0 0 1 1 *");
    let fake_url: url::Url = "http://127.0.0.1:1/never-contacted".parse().unwrap();
    let mirror = build_mirror(&fake_url, "unused");
    let cfg = Config {
        global,
        mirrors: vec![mirror],
    };

    let env = EmptyEnv;
    let run_opts = DaemonRunOptions {
        config: cfg,
        reload_source: ReloadSource::LoadOptions {
            cli_config: None,
            default_config_path: None,
        },
        env: &env,
        opts: DaemonOpts {
            no_initial_sync: true,
        },
    };

    tokio::spawn(later_signal(libc::SIGTERM, 200));
    let code = tokio::time::timeout(Duration::from_secs(5), run_async(run_opts))
        .await
        .expect("daemon must exit within 5s of SIGTERM")
        .expect("daemon must return Ok");
    assert_eq!(code, tain::exit::ExitCode::Success);

    let mirror_root = target.path().join("unused");
    assert!(
        !mirror_root.join(".tain").exists(),
        "daemon must not touch the mirror when --no-initial-sync and immediate SIGTERM"
    );
}

#[tokio::test]
async fn initial_sync_completes_then_sigterm_exits_zero() {
    let _guard = SIGNAL_TESTS.lock().await;

    let serve_dir = TempDir::new("daemon-initial-serve");
    let _repo = SyntheticRepo::new(serve_dir.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"fake nginx bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve_dir.path().to_path_buf()).await;

    let target = TempDir::new("daemon-initial-target");
    let global = build_global(target.path().to_path_buf(), "0 0 1 1 *"); // never fires
    let mirror = build_mirror(&server.base_url(), "upstream");
    let cfg = Config {
        global,
        mirrors: vec![mirror],
    };

    let env = EmptyEnv;
    let run_opts = DaemonRunOptions {
        config: cfg,
        reload_source: ReloadSource::LoadOptions {
            cli_config: None,
            default_config_path: None,
        },
        env: &env,
        opts: DaemonOpts::default(),
    };

    tokio::spawn(later_signal(libc::SIGTERM, 1500));
    let code = tokio::time::timeout(Duration::from_secs(10), run_async(run_opts))
        .await
        .expect("daemon must exit within 10s of SIGTERM")
        .expect("daemon must return Ok");
    assert_eq!(code, tain::exit::ExitCode::Success);

    let mirror_root = target.path().join("upstream");
    let dists = mirror_root.join("dists/bookworm");
    assert!(
        dists.join("InRelease").exists(),
        "initial sync must publish"
    );
    assert!(
        mirror_root.join(".tain/state.json").exists(),
        "state.json must be written by the initial sync before SIGTERM"
    );
}

#[tokio::test]
async fn missing_schedule_is_exit_2() {
    let _guard = SIGNAL_TESTS.lock().await;

    let target = TempDir::new("daemon-no-schedule");
    let mut global = GlobalConfig {
        target: target.path().to_path_buf(),
        parallel: 4,
        host_connections: 2,
        ..GlobalConfig::default()
    };
    global.schedule = None;
    let cfg = Config {
        global,
        mirrors: vec![],
    };
    let err = parse_schedule(&cfg).unwrap_err();
    assert!(matches!(err, DaemonError::NoSchedule));
    assert_eq!(err.exit_code(), tain::exit::ExitCode::ConfigError);
}

/// `io::Write` sink shared with the test, for asserting on daemon logs.
#[derive(Clone, Default)]
struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn daemon_toml(target: &std::path::Path, schedule: &str) -> String {
    format!(
        r#"[global]
target = "{}"
parallel = 4
host_connections = 2
schedule = "{schedule}"

[[mirror]]
name = "debian"
url = "http://127.0.0.1:1/debian"
suites = ["bookworm"]
components = ["main"]
architectures = ["amd64"]
"#,
        target.display()
    )
}

/// Start the daemon on `initial`, rewrite the file to `reloaded`, send
/// SIGHUP then SIGTERM, and return the daemon's log output.
async fn run_with_reload(tag: &str, initial: &str, reloaded: &str) -> String {
    let cfg_dir = TempDir::new(&format!("daemon-{tag}-cfg"));
    let target = TempDir::new(&format!("daemon-{tag}-target"));
    let cfg_path = cfg_dir.path().join("tain.toml");
    std::fs::write(&cfg_path, daemon_toml(target.path(), initial)).unwrap();

    // Reload locates the TOML via TAIN_CONFIG.
    let mut env: HashMap<String, String> = HashMap::new();
    env.insert(
        "TAIN_CONFIG".to_owned(),
        cfg_path.to_string_lossy().into_owned(),
    );
    let (cfg, _mode) = tain::config::load::load(tain::config::load::LoadOptions {
        cli_config: None,
        env: &env,
        default_config_path: None,
    })
    .unwrap();
    let run_opts = DaemonRunOptions {
        config: cfg,
        reload_source: ReloadSource::LoadOptions {
            cli_config: None,
            default_config_path: None,
        },
        env: &env,
        opts: DaemonOpts {
            no_initial_sync: true,
        },
    };

    let reloaded_toml = daemon_toml(target.path(), reloaded);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::fs::write(&cfg_path, &reloaded_toml).unwrap();
        kill_self(libc::SIGHUP);
        tokio::time::sleep(Duration::from_millis(400)).await;
        kill_self(libc::SIGTERM);
    });

    // `#[tokio::test]` is single-threaded, so a thread-local subscriber
    // sees everything the daemon logs.
    let capture = Capture::default();
    let sink = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    let _log = tracing::subscriber::set_default(subscriber);

    let code = tokio::time::timeout(Duration::from_secs(5), run_async(run_opts))
        .await
        .expect("daemon must exit within 5s")
        .expect("daemon must return Ok");
    assert_eq!(code, tain::exit::ExitCode::Success);
    let logs = capture.0.lock().unwrap().clone();
    String::from_utf8(logs).unwrap()
}

/// `next` timestamp (local RFC 3339) of the last `next tick` line.
fn last_next_tick(logs: &str) -> &str {
    let line = logs
        .lines()
        .rfind(|l| l.contains("next tick"))
        .unwrap_or_else(|| panic!("no `next tick` line:\n{logs}"));
    let value = line.split("next=").nth(1).unwrap();
    value.split_whitespace().next().unwrap()
}

// Far-future schedules (Jan 1 / Feb 29) so no real tick races the test;
// the next-tick date shows which schedule is active.
const JAN_1: &str = "0 0 1 1 *";

#[tokio::test]
async fn sighup_reloads_and_swaps_schedule() {
    let _guard = SIGNAL_TESTS.lock().await;
    let logs = run_with_reload("sighup-ok", JAN_1, "0 0 29 2 *").await;
    assert!(logs.contains("config reloaded"), "{logs}");
    assert!(logs.contains("schedule=0 0 29 2 *"), "{logs}");
    assert!(!logs.contains("config reload failed"), "{logs}");
    assert_eq!(logs.matches("next tick").count(), 2, "{logs}");
    assert!(last_next_tick(&logs).contains("-02-29T00:00:00"), "{logs}");
}

#[tokio::test]
async fn sighup_with_never_firing_schedule_keeps_old_config() {
    let _guard = SIGNAL_TESTS.lock().await;
    let logs = run_with_reload("sighup-bad", JAN_1, "0 0 30 2 *").await;
    assert!(logs.contains("config reload failed"), "{logs}");
    assert!(logs.contains("0 0 30 2 *"), "{logs}");
    assert!(!logs.contains("config reloaded"), "{logs}");
    assert_eq!(logs.matches("next tick").count(), 2, "{logs}");
    assert!(last_next_tick(&logs).contains("-01-01T00:00:00"), "{logs}");
}

#[tokio::test]
async fn sigint_shuts_down_between_ticks() {
    let _guard = SIGNAL_TESTS.lock().await;

    let target = TempDir::new("daemon-sigint");
    let global = build_global(target.path().to_path_buf(), "0 0 1 1 *");
    let fake_url: url::Url = "http://127.0.0.1:1/never".parse().unwrap();
    let mirror = build_mirror(&fake_url, "never");
    let cfg = Config {
        global,
        mirrors: vec![mirror],
    };
    let env = EmptyEnv;
    let run_opts = DaemonRunOptions {
        config: cfg,
        reload_source: ReloadSource::LoadOptions {
            cli_config: None,
            default_config_path: None,
        },
        env: &env,
        opts: DaemonOpts {
            no_initial_sync: true,
        },
    };
    tokio::spawn(later_signal(libc::SIGINT, 200));
    let code = tokio::time::timeout(Duration::from_secs(5), run_async(run_opts))
        .await
        .expect("daemon must exit within 5s of SIGINT")
        .expect("daemon must return Ok");
    assert_eq!(code, tain::exit::ExitCode::Success);
}
