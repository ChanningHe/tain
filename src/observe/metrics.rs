//! Prometheus textfile metrics for node_exporter's textfile collector.
//!
//! One file per run covers all mirrors (labelled `mirror=`, `backend=`) and is
//! written atomically so the collector never reads a partial file. Write
//! failures must never fail a sync: callers log and continue.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// One mirror's aggregated metrics for a single sync pass.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncMetrics {
    pub mirror: String,
    pub backend: String,
    /// Files under `pool/` in the latest successful manifest.
    pub pool_files: u64,
    pub pool_bytes: u64,
    /// Newest published Release `Date`; `None` if never synced.
    pub last_success_unix: Option<i64>,
    /// `None` when GC did not run.
    pub gc: Option<GcMetrics>,
    pub sync_duration_secs: f64,
    /// Only suites verified this run.
    pub pgp_by_suite: Vec<(String, PgpMetric)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcMetrics {
    pub deleted_files: u64,
    pub circuit_broken: bool,
}

/// PGP outcome; only `Verified` emits 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgpMetric {
    Verified,
    Skipped,
    Absent,
}

impl PgpMetric {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Verified => 1,
            Self::Skipped | Self::Absent => 0,
        }
    }
}

/// Render `metrics` and atomically replace `path` (tmp, fsync, rename).
///
/// # Errors
///
/// I/O failure. Callers must log it, not fail the sync.
pub fn write_textfile(path: &Path, metrics: &[SyncMetrics]) -> io::Result<()> {
    let payload = render(metrics);
    let tmp = tmp_path(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&tmp, payload.as_bytes())?;
    let f = fs::File::open(&tmp)?;
    f.sync_data()?;
    drop(f);
    fs::rename(&tmp, path)
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tain-tmp~");
    PathBuf::from(s)
}

/// Render the textfile payload.
#[must_use]
pub fn render(metrics: &[SyncMetrics]) -> String {
    let mut out = String::with_capacity(metrics.len() * 512);

    render_gauge(
        &mut out,
        "tain_pool_files",
        "Current pool file count per mirror.",
        metrics,
        |m| Some(fmt_u64(m.pool_files)),
        &base_labels,
    );
    render_gauge(
        &mut out,
        "tain_pool_bytes",
        "Current pool total bytes per mirror.",
        metrics,
        |m| Some(fmt_u64(m.pool_bytes)),
        &base_labels,
    );
    render_gauge(
        &mut out,
        "tain_last_success_seconds",
        "Unix time of last successful sync per mirror.",
        metrics,
        |m| m.last_success_unix.map(fmt_i64),
        &base_labels,
    );
    render_counter(
        &mut out,
        "tain_gc_deleted_files_total",
        "Cumulative GC deletions this sync per mirror.",
        metrics,
        |m| m.gc.map(|g| fmt_u64(g.deleted_files)),
        &base_labels,
    );
    render_gauge(
        &mut out,
        "tain_gc_circuit_broken",
        "GC circuit breaker tripped this sync (1 = yes).",
        metrics,
        |m| m.gc.map(|g| fmt_bool(g.circuit_broken)),
        &base_labels,
    );
    render_gauge(
        &mut out,
        "tain_sync_duration_seconds",
        "Wall-clock duration of this sync per mirror.",
        metrics,
        |m| Some(fmt_f64_3(m.sync_duration_secs)),
        &base_labels,
    );
    render_pgp(&mut out, metrics);

    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn render_gauge<F, L>(
    out: &mut String,
    name: &str,
    help: &str,
    metrics: &[SyncMetrics],
    value: F,
    labels: &L,
) where
    F: Fn(&SyncMetrics) -> Option<String>,
    L: Fn(&SyncMetrics) -> Vec<(&'static str, &str)>,
{
    render_metric(out, name, help, "gauge", metrics, value, labels);
}

fn render_counter<F, L>(
    out: &mut String,
    name: &str,
    help: &str,
    metrics: &[SyncMetrics],
    value: F,
    labels: &L,
) where
    F: Fn(&SyncMetrics) -> Option<String>,
    L: Fn(&SyncMetrics) -> Vec<(&'static str, &str)>,
{
    render_metric(out, name, help, "counter", metrics, value, labels);
}

fn render_metric<F, L>(
    out: &mut String,
    name: &str,
    help: &str,
    kind: &str,
    metrics: &[SyncMetrics],
    value: F,
    labels: &L,
) where
    F: Fn(&SyncMetrics) -> Option<String>,
    L: Fn(&SyncMetrics) -> Vec<(&'static str, &str)>,
{
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    for m in metrics {
        if let Some(v) = value(m) {
            let labels_str = format_labels(&labels(m));
            let _ = writeln!(out, "{name}{labels_str} {v}");
        }
    }
}

fn render_pgp(out: &mut String, metrics: &[SyncMetrics]) {
    let name = "tain_pgp_verified";
    let _ = writeln!(
        out,
        "# HELP {name} InRelease/Release.gpg PGP verify outcome (1 = verified, 0 = skipped/absent)."
    );
    let _ = writeln!(out, "# TYPE {name} gauge");
    for m in metrics {
        for (suite, outcome) in &m.pgp_by_suite {
            let labels = [
                ("mirror", m.mirror.as_str()),
                ("suite", suite.as_str()),
                ("backend", m.backend.as_str()),
            ];
            let labels_str = format_labels(&labels);
            let _ = writeln!(out, "{name}{labels_str} {}", outcome.as_u8());
        }
    }
}

fn base_labels(m: &SyncMetrics) -> Vec<(&'static str, &str)> {
    vec![
        ("mirror", m.mirror.as_str()),
        ("backend", m.backend.as_str()),
    ]
}

fn format_labels(labels: &[(&'static str, &str)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let mut out = String::from("{");
    for (i, (k, v)) in labels.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(k);
        out.push_str("=\"");
        push_escaped(&mut out, v);
        out.push('"');
    }
    out.push('}');
    out
}

/// Prometheus label-value escaping; only `\\`, `"` and newline need it.
fn push_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
}

fn fmt_u64(v: u64) -> String {
    v.to_string()
}

fn fmt_i64(v: i64) -> String {
    v.to_string()
}

fn fmt_bool(v: bool) -> String {
    if v { "1" } else { "0" }.to_owned()
}

/// At most 3 decimals, trailing zeros trimmed (`18700.400` -> `18700.4`).
fn fmt_f64_3(v: f64) -> String {
    let raw = format!("{v:.3}");
    let trimmed = raw.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn tmpdir(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("tain-metrics-{name}-{pid}-{n}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn sample(mirror: &str) -> SyncMetrics {
        SyncMetrics {
            mirror: mirror.to_owned(),
            backend: "apt".to_owned(),
            pool_files: 63441,
            pool_bytes: 95_611_281_408,
            last_success_unix: Some(1_751_234_567),
            gc: Some(GcMetrics {
                deleted_files: 42,
                circuit_broken: false,
            }),
            sync_duration_secs: 18700.4,
            pgp_by_suite: vec![
                ("bookworm".to_owned(), PgpMetric::Verified),
                ("bookworm-security".to_owned(), PgpMetric::Verified),
            ],
        }
    }

    #[test]
    fn single_mirror_full_shape() {
        let out = render(&[sample("debian")]);
        for name in [
            "tain_pool_files",
            "tain_pool_bytes",
            "tain_last_success_seconds",
            "tain_gc_deleted_files_total",
            "tain_gc_circuit_broken",
            "tain_sync_duration_seconds",
            "tain_pgp_verified",
        ] {
            assert!(
                out.contains(&format!("# HELP {name} ")),
                "missing HELP for {name}\n{out}"
            );
            assert!(
                out.contains(&format!("# TYPE {name} ")),
                "missing TYPE for {name}\n{out}"
            );
        }
        assert!(out.contains(r#"tain_pool_files{mirror="debian",backend="apt"} 63441"#));
        assert!(out.contains(r#"tain_pool_bytes{mirror="debian",backend="apt"} 95611281408"#));
        assert!(
            out.contains(r#"tain_last_success_seconds{mirror="debian",backend="apt"} 1751234567"#)
        );
        assert!(out.contains(r#"tain_gc_deleted_files_total{mirror="debian",backend="apt"} 42"#));
        assert!(out.contains(r#"tain_gc_circuit_broken{mirror="debian",backend="apt"} 0"#));
        assert!(
            out.contains(r#"tain_sync_duration_seconds{mirror="debian",backend="apt"} 18700.4"#)
        );
        assert!(
            out.contains(r#"tain_pgp_verified{mirror="debian",suite="bookworm",backend="apt"} 1"#)
        );
        assert!(out.contains(
            r#"tain_pgp_verified{mirror="debian",suite="bookworm-security",backend="apt"} 1"#
        ));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn multi_mirror_shape() {
        let out = render(&[sample("debian"), sample("ubuntu")]);
        assert!(out.contains(r#"tain_pool_files{mirror="debian",backend="apt"} 63441"#));
        assert!(out.contains(r#"tain_pool_files{mirror="ubuntu",backend="apt"} 63441"#));
        let help_count = out.matches("# HELP tain_pool_files ").count();
        assert_eq!(help_count, 1, "HELP emitted more than once");
    }

    #[test]
    fn omits_optional_lines_when_absent() {
        let mut m = sample("debian");
        m.last_success_unix = None;
        m.gc = None;
        m.pgp_by_suite = vec![];
        let out = render(&[m]);
        assert!(out.contains("# HELP tain_last_success_seconds "));
        assert!(
            !out.lines()
                .any(|l| l.starts_with("tain_last_success_seconds{"))
        );
        assert!(
            !out.lines()
                .any(|l| l.starts_with("tain_gc_deleted_files_total{"))
        );
        assert!(
            !out.lines()
                .any(|l| l.starts_with("tain_gc_circuit_broken{"))
        );
        assert!(!out.lines().any(|l| l.starts_with("tain_pgp_verified{")));
    }

    #[test]
    fn label_value_escapes_backslash_quote_newline() {
        let mut out = String::new();
        push_escaped(&mut out, "weird\\name\"here\nnext");
        assert_eq!(out, r#"weird\\name\"here\nnext"#);
    }

    #[test]
    fn label_value_escape_flows_through_render() {
        let mut m = sample(r#"weird\name"here"#);
        m.pgp_by_suite = vec![("suite\nlf".to_owned(), PgpMetric::Verified)];
        let out = render(&[m]);
        assert!(
            out.contains(r#"mirror="weird\\name\"here""#),
            "escaped mirror missing: {out}"
        );
        assert!(
            out.contains(r#"suite="suite\nlf""#),
            "escaped suite missing: {out}"
        );
    }

    #[test]
    fn suffix_conventions_match_prometheus() {
        let out = render(&[sample("debian")]);
        assert!(out.contains("tain_pool_bytes"));
        assert!(out.contains("tain_last_success_seconds"));
        assert!(out.contains("tain_gc_deleted_files_total"));
        assert!(out.contains("tain_sync_duration_seconds"));
    }

    #[test]
    fn empty_metrics_list_yields_help_type_only() {
        let out = render(&[]);
        assert!(out.ends_with('\n'));
        for line in out.lines() {
            assert!(
                line.starts_with('#') || line.is_empty(),
                "unexpected data line for empty input: {line}"
            );
        }
    }

    #[test]
    fn pgp_metric_maps_to_correct_gauge() {
        assert_eq!(PgpMetric::Verified.as_u8(), 1);
        assert_eq!(PgpMetric::Skipped.as_u8(), 0);
        assert_eq!(PgpMetric::Absent.as_u8(), 0);
    }

    #[test]
    fn fmt_f64_trims_trailing_zeros() {
        assert_eq!(fmt_f64_3(18700.4), "18700.4");
        assert_eq!(fmt_f64_3(18700.0), "18700");
        assert_eq!(fmt_f64_3(0.0), "0");
        assert_eq!(fmt_f64_3(1.234_567), "1.235");
        assert_eq!(fmt_f64_3(0.001), "0.001");
    }

    #[test]
    fn write_textfile_atomic_rename_creates_final_no_tmp() {
        let dir = tmpdir("atomic");
        let path = dir.join("sub").join("tain.prom");
        write_textfile(&path, &[sample("debian")]).unwrap();
        assert!(path.exists(), "final path missing");
        let tmp = tmp_path(&path);
        assert!(!tmp.exists(), "tmp sidecar lingered: {tmp:?}");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("tain_pool_files"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_textfile_overwrites_existing_atomically() {
        let dir = tmpdir("overwrite");
        let path = dir.join("tain.prom");
        fs::write(&path, b"stale contents\n").unwrap();
        write_textfile(&path, &[sample("debian")]).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("stale"));
        assert!(contents.contains("tain_pool_files"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tmp_path_appends_suffix() {
        assert_eq!(
            tmp_path(Path::new("/x/y/tain.prom")),
            PathBuf::from("/x/y/tain.prom.tain-tmp~")
        );
    }

    #[test]
    fn write_textfile_no_lingering_tmp_on_success() {
        let dir = tmpdir("no-tmp");
        let path = dir.join("tain.prom");
        for _ in 0..5 {
            write_textfile(&path, &[sample("debian"), sample("ubuntu")]).unwrap();
        }
        let entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(entries, vec!["tain.prom".to_owned()]);
        fs::remove_dir_all(&dir).ok();
    }
}
