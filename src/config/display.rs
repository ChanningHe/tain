//! Human-readable `check` output: every setting as resolved (defaults and env
//! overrides applied), laid out like the TOML input for easy comparison.

use std::fmt::Write as _;
use std::time::Duration;

use crate::config::model::{
    AptOptions, BackendOptions, Config, GcConfig, I18nSelection, MirrorConfig, VerifyConfig,
};
use crate::observe::LogFormat;

/// Format the resolved `Config`; always ends with a single newline.
#[must_use]
pub fn format_config(cfg: &Config) -> String {
    let mut out = String::new();
    write_global(&mut out, cfg);
    for m in &cfg.mirrors {
        out.push('\n');
        write_mirror(&mut out, m);
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn write_global(out: &mut String, cfg: &Config) {
    let g = &cfg.global;
    writeln!(out, "[global]").unwrap();
    writeln!(out, "target = {}", quote(&g.target.to_string_lossy())).unwrap();
    writeln!(out, "parallel = {}", g.parallel).unwrap();
    writeln!(out, "host_connections = {}", g.host_connections).unwrap();
    writeln!(out, "segments_per_file = {}", g.segments_per_file).unwrap();
    writeln!(
        out,
        "segment_min_size = {}",
        quote(&format_bytes(g.segment_min_size))
    )
    .unwrap();
    writeln!(
        out,
        "connect_timeout = {}",
        quote(&format_duration(g.timeout.connect))
    )
    .unwrap();
    writeln!(
        out,
        "idle_timeout = {}",
        quote(&format_duration(g.timeout.read_idle))
    )
    .unwrap();
    if let Some(ip) = g.bind_address {
        writeln!(out, "bind_address = {}", quote(&ip.to_string())).unwrap();
    }
    writeln!(out, "user_agent = {}", quote(&g.user_agent)).unwrap();
    writeln!(
        out,
        "log_format = {}",
        quote(match g.log.format {
            LogFormat::Text => "text",
            LogFormat::Json => "json",
        })
    )
    .unwrap();
    if let Some(lvl) = &g.log.level {
        writeln!(out, "log_level = {}", quote(lvl)).unwrap();
    }
    if let Some(s) = &g.schedule {
        writeln!(out, "schedule = {}", quote(s)).unwrap();
    }
    writeln!(
        out,
        "lock_timeout = {}",
        quote(&format_duration(g.lock_timeout))
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "[global.retry]").unwrap();
    writeln!(out, "count = {}", g.retry.count).unwrap();
    writeln!(out, "index_rounds = {}", g.retry.index_rounds).unwrap();
}

fn write_mirror(out: &mut String, m: &MirrorConfig) {
    writeln!(out, "[[mirror]]").unwrap();
    writeln!(out, "name = {}", quote(&m.name)).unwrap();
    writeln!(out, "backend = {}", quote(m.backend.name())).unwrap();
    writeln!(out, "url = {}", quote(m.url.as_str())).unwrap();
    writeln!(out, "path = {}", quote(&m.path.to_string_lossy())).unwrap();
    writeln!(out, "force_http1 = {}", m.force_http1).unwrap();
    match &m.backend_options {
        BackendOptions::Apt(a) => write_apt(out, a),
    }
    writeln!(out).unwrap();
    write_verify(out, &m.verify);
    writeln!(out).unwrap();
    write_gc(out, &m.gc);
}

fn write_apt(out: &mut String, a: &AptOptions) {
    writeln!(out, "suites = {}", string_list(&a.suites)).unwrap();
    writeln!(out, "components = {}", string_list(&a.components)).unwrap();
    writeln!(out, "architectures = {}", string_list(&a.architectures)).unwrap();
    writeln!(out, "create_suite_symlinks = {}", a.create_suite_symlinks).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "[mirror.indexes]").unwrap();
    writeln!(out, "contents = {}", a.indexes.contents).unwrap();
    writeln!(
        out,
        "i18n = {}",
        match &a.indexes.i18n {
            I18nSelection::All => "true".to_owned(),
            I18nSelection::None => "false".to_owned(),
            I18nSelection::Only(v) => string_list(v),
        }
    )
    .unwrap();
    writeln!(out, "dep11 = {}", a.indexes.dep11).unwrap();
    writeln!(out, "cnf = {}", a.indexes.cnf).unwrap();
    writeln!(out, "sources = {}", a.indexes.sources).unwrap();
    writeln!(out, "debian_installer = {}", a.indexes.debian_installer).unwrap();
}

fn write_verify(out: &mut String, v: &VerifyConfig) {
    writeln!(out, "[mirror.verify]").unwrap();
    writeln!(out, "pgp = {}", quote(v.pgp.as_str())).unwrap();
    if let Some(kr) = &v.keyring {
        writeln!(out, "keyring = {}", quote(&kr.to_string_lossy())).unwrap();
    }
    writeln!(out, "allow_weak_hash = {}", v.allow_weak_hash).unwrap();
}

fn write_gc(out: &mut String, g: &GcConfig) {
    writeln!(out, "[mirror.gc]").unwrap();
    writeln!(out, "enabled = {}", g.enabled).unwrap();
    writeln!(
        out,
        "grace_period = {}",
        quote(&format_duration(g.grace_period))
    )
    .unwrap();
    writeln!(out, "max_delete_ratio = {}", g.max_delete_ratio.as_f64()).unwrap();
    writeln!(out, "keep_generations = {}", g.keep_generations).unwrap();
    writeln!(out, "dry_run = {}", g.dry_run).unwrap();
}

fn format_duration(d: Duration) -> String {
    // Single unit where possible (not humantime's "1h 30m 12s") to match input style.
    let secs = d.as_secs();
    let nanos = d.subsec_nanos();
    if nanos != 0 {
        return format!("{}ms", d.as_millis());
    }
    if secs == 0 {
        return "0s".into();
    }
    for (unit, mul) in [("h", 3600u64), ("m", 60u64)] {
        if secs.is_multiple_of(mul) && secs / mul > 0 {
            return format!("{}{}", secs / mul, unit);
        }
    }
    format!("{secs}s")
}

fn format_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if n >= GIB && n.is_multiple_of(GIB) {
        format!("{}GiB", n / GIB)
    } else if n >= MIB && n.is_multiple_of(MIB) {
        format!("{}MiB", n / MIB)
    } else if n >= KIB && n.is_multiple_of(KIB) {
        format!("{}KiB", n / KIB)
    } else {
        format!("{n}")
    }
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn string_list(v: &[String]) -> String {
    let mut out = String::from("[");
    for (i, s) in v.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&quote(s));
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::toml as toml_source;

    #[test]
    fn formats_documented_example() {
        let text = r#"
[global]
target = "/data"
parallel = 16
log_format = "text"

[[mirror]]
name = "debian"
url = "https://deb.debian.org/debian"
suites = ["bookworm"]
components = ["main", "contrib"]
architectures = ["amd64"]

[mirror.indexes]
i18n = ["en"]
"#;
        let cfg = toml_source::parse(text).unwrap();
        let out = format_config(&cfg);
        assert!(out.contains("[global]"));
        assert!(out.contains("target = \"/data\""));
        assert!(out.contains("parallel = 16"));
        assert!(out.contains("log_format = \"text\""));
        assert!(out.contains("[[mirror]]"));
        assert!(out.contains("name = \"debian\""));
        assert!(out.contains("backend = \"apt\""));
        assert!(out.contains("suites = [\"bookworm\"]"));
        assert!(out.contains("[mirror.indexes]"));
        assert!(out.contains("i18n = [\"en\"]"));
        assert!(out.contains("[mirror.verify]"));
        assert!(out.contains("pgp = \"off\""));
        assert!(out.contains("[mirror.gc]"));
        assert!(out.contains("enabled = false"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn output_is_valid_input_and_round_trips() {
        let text = r#"
[global]
segments_per_file = 2
segment_min_size = "64MiB"
idle_timeout = "90s"
bind_address = "192.0.2.10"
log_level = "debug"
log_format = "json"

[[mirror]]
name = "signed"
url = "https://example.com/debian"
suites = ["bookworm"]
components = ["main"]
architectures = ["amd64"]
force_http1 = true
[mirror.indexes]
i18n = false
[mirror.verify]
pgp = "if-present"
keyring = "/etc/keys.gpg"
"#;
        let out = format_config(&toml_source::parse(text).unwrap());
        assert!(!out.contains("packages"), "{out}");
        assert!(out.contains("force_http1 = true"), "{out}");
        let reparsed = toml_source::parse(&out)
            .unwrap_or_else(|e| panic!("check output rejected as input: {e}\n---\n{out}"));
        assert_eq!(format_config(&reparsed), out);
    }

    #[test]
    fn i18n_all_and_none_render_as_bools() {
        let all = r#"
[[mirror]]
name = "d"
url = "http://x"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.indexes]
i18n = true
"#;
        let none = r#"
[[mirror]]
name = "d"
url = "http://x"
suites = ["bookworm"]
architectures = ["amd64"]
[mirror.indexes]
i18n = false
"#;
        let out_all = format_config(&toml_source::parse(all).unwrap());
        let out_none = format_config(&toml_source::parse(none).unwrap());
        assert!(out_all.contains("i18n = true"));
        assert!(out_none.contains("i18n = false"));
    }

    #[test]
    fn duration_formatting_prefers_single_unit() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(72 * 3600)), "72h");
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::ZERO), "0s");
    }

    #[test]
    fn bytes_formatting_prefers_binary_units() {
        assert_eq!(format_bytes(1024), "1KiB");
        assert_eq!(format_bytes(256 * 1024 * 1024), "256MiB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2GiB");
        assert_eq!(format_bytes(3), "3");
    }
}
