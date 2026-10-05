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

#[tokio::test]
async fn sighup_reloads_and_swaps_schedule() {
    let _guard = SIGNAL_TESTS.lock().await;

    let cfg_dir = TempDir::new("daemon-sighup-cfg");
    let target = TempDir::new("daemon-sighup-target");
    let cfg_path = cfg_dir.path().join("tain.toml");
    let initial_toml = format!(
        r#"[global]
target = "{}"
parallel = 4
host_connections = 2
schedule = "0 * * * *"
"#,
        target.path().display()
    );
    std::fs::write(&cfg_path, &initial_toml).unwrap();

    // Reload locates the TOML via TAIN_CONFIG.
    struct EnvWithConfig(HashMap<String, String>);
    impl EnvSource for EnvWithConfig {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }
    let mut env_map = HashMap::new();
    env_map.insert(
        "TAIN_CONFIG".to_owned(),
        cfg_path.to_string_lossy().into_owned(),
    );
    let env = EnvWithConfig(env_map);

    let load_opts = tain::config::load::LoadOptions {
        cli_config: None,
        env: &env,
        default_config_path: None,
    };
    let (cfg, _mode) = tain::config::load::load(load_opts).unwrap();
    assert_eq!(cfg.global.schedule.as_deref(), Some("0 * * * *"));

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

    let reloaded_toml = format!(
        r#"[global]
target = "{}"
parallel = 4
host_connections = 2
schedule = "0 0 1 1 *"
"#,
        target.path().display()
    );
    let cfg_path_clone = cfg_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::fs::write(&cfg_path_clone, &reloaded_toml).unwrap();
        kill_self(libc::SIGHUP);
        tokio::time::sleep(Duration::from_millis(400)).await;
        kill_self(libc::SIGTERM);
    });

    let code = tokio::time::timeout(Duration::from_secs(5), run_async(run_opts))
        .await
        .expect("daemon must exit within 5s")
        .expect("daemon must return Ok");
    assert_eq!(code, tain::exit::ExitCode::Success);
    // Only proves SIGHUP -> reload -> parse runs end to end; a failed
    // reload keeps the old config and would also exit cleanly.
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
