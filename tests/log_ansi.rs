//! Logs written to a non-terminal stderr (journald, `docker logs`, files)
//! must be plain text without ANSI escape codes.

use std::process::Command;

#[test]
fn piped_stderr_logs_contain_no_ansi_escapes() {
    // Arrange: a mirror whose upstream refuses connections, so `sync` logs
    // a few lines and fails fast without touching the network.
    let dir = std::env::temp_dir().join(format!("tain-log-ansi-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let config = dir.join("tain.toml");
    std::fs::write(
        &config,
        format!(
            "[global]\ntarget = {:?}\n\n[[mirror]]\nname = \"m\"\nurl = \"http://127.0.0.1:9/debian\"\n\
             suites = [\"bookworm\"]\ncomponents = [\"main\"]\narchitectures = [\"amd64\"]\n",
            dir.join("data").display().to_string()
        ),
    )
    .expect("write config");

    // Act
    let out = Command::new(env!("CARGO_BIN_EXE_tain"))
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .env_clear()
        .output()
        .expect("spawn tain");
    let _ = std::fs::remove_dir_all(&dir);

    // Assert
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("INFO"),
        "expected log output on stderr, got: {stderr}"
    );
    assert!(
        !stderr.contains('\x1b'),
        "ANSI escape in non-TTY log output: {stderr:?}"
    );
}
