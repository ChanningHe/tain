//! Manifest-diff GC.
//!
//! Referenced = files in the newest `keep_generations` manifests plus the
//! newest `keep_generations` `.tain/prev/**/<gen>/` dirs. Candidates are
//! unreferenced files under `pool/`, `dists/`, `.tain/prev/` older than
//! `grace_period`. If candidates exceed `max_delete_ratio` of the scan (by
//! count or bytes) nothing is deleted, so an empty-index publish can't wipe
//! the mirror.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::core::store::manifest;

#[derive(Debug, Clone)]
pub struct GcOptions {
    pub enabled: bool,
    pub grace_period: Duration,
    /// Circuit breaker on candidate/scanned file count.
    pub max_delete_ratio: f64,
    /// Circuit breaker on candidate/scanned bytes, so one huge orphan trips.
    pub max_delete_byte_ratio: f64,
    pub keep_generations: u32,
    /// Report only, never delete.
    pub dry_run: bool,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            grace_period: Duration::from_secs(72 * 3600),
            max_delete_ratio: 0.3,
            max_delete_byte_ratio: 0.3,
            keep_generations: 3,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcResult {
    pub scanned: usize,
    pub scanned_bytes: u64,
    pub referenced: usize,
    pub candidates: Vec<PathBuf>,
    pub candidate_bytes: u64,
    pub deleted: Vec<PathBuf>,
    pub skipped_grace: usize,
    pub circuit_broken: bool,
    pub circuit_reason: Option<String>,
    pub disabled: bool,
    pub dry_run: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum GcError {
    #[error("I/O on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Manifest(#[from] manifest::ManifestError),
}

/// Run one GC pass against `mirror_root`.
///
/// # Errors
///
/// Manifest load, tree scan or `remove_file` failure.
pub fn run_gc(mirror_root: &Path, opts: &GcOptions, now: SystemTime) -> Result<GcResult, GcError> {
    let mut result = GcResult {
        disabled: !opts.enabled,
        dry_run: opts.dry_run,
        ..GcResult::default()
    };
    let mut referenced = load_reference_set(mirror_root, opts.keep_generations)?;
    extend_with_prev_generations(&mut referenced, mirror_root, opts.keep_generations)?;
    result.referenced = referenced.len();
    let scan = scan_disk(mirror_root)?;
    result.scanned = scan.len();
    if scan.is_empty() {
        return Ok(result);
    }
    let (candidates, skipped_grace, scan_bytes, candidate_bytes) =
        compute_candidates(&scan, &referenced, mirror_root, opts.grace_period, now);
    result.skipped_grace = skipped_grace;
    result.candidates = candidates.clone();
    result.scanned_bytes = scan_bytes;
    result.candidate_bytes = candidate_bytes;

    let count_ratio = candidates.len() as f64 / scan.len() as f64;
    let byte_ratio = if scan_bytes == 0 {
        0.0
    } else {
        candidate_bytes as f64 / scan_bytes as f64
    };
    if count_ratio > opts.max_delete_ratio {
        result.circuit_broken = true;
        result.circuit_reason = Some(format!(
            "count ratio {count_ratio:.3} > max_delete_ratio {}",
            opts.max_delete_ratio
        ));
        return Ok(result);
    }
    if byte_ratio > opts.max_delete_byte_ratio {
        result.circuit_broken = true;
        result.circuit_reason = Some(format!(
            "byte ratio {byte_ratio:.3} > max_delete_byte_ratio {}",
            opts.max_delete_byte_ratio
        ));
        return Ok(result);
    }
    if result.disabled || result.dry_run {
        return Ok(result);
    }
    // Empty-dir pruning never reaches `mirror_root` or `.tain/` state.
    let allow_prune_roots = [
        mirror_root.join("pool"),
        mirror_root.join("dists"),
        mirror_root.join(".tain/prev"),
    ];
    for path in &candidates {
        match std::fs::remove_file(path) {
            Ok(()) => {
                result.deleted.push(path.clone());
                prune_empty_ancestors(path, &allow_prune_roots);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                result.deleted.push(path.clone());
            }
            Err(e) => {
                return Err(GcError::Io {
                    path: path.clone(),
                    source: e,
                });
            }
        }
    }
    Ok(result)
}

fn load_reference_set(
    mirror_root: &Path,
    keep_generations: u32,
) -> Result<HashSet<String>, GcError> {
    let mut all = manifest::list_generations(mirror_root)?;
    all.sort_unstable();
    let cutoff = if all.len() as u32 > keep_generations {
        all.len() - keep_generations as usize
    } else {
        0
    };
    let mut out = HashSet::new();
    for generation in &all[cutoff..] {
        let m = manifest::load(mirror_root, *generation)?;
        for rel in m.files.keys() {
            out.insert(rel.clone());
        }
    }
    Ok(out)
}

/// Mark every file in the newest `keep_generations` retired generation
/// dirs under `.tain/prev/` as referenced.
fn extend_with_prev_generations(
    referenced: &mut HashSet<String>,
    mirror_root: &Path,
    keep_generations: u32,
) -> Result<(), GcError> {
    if keep_generations == 0 {
        return Ok(());
    }
    let prev_root = mirror_root.join(".tain/prev");
    let mut gen_dirs = collect_generation_dirs(&prev_root)?;
    gen_dirs.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
    let take = (keep_generations as usize).min(gen_dirs.len());
    for (_gen, dir) in &gen_dirs[..take] {
        for file in walk_files(dir)? {
            if let Ok(rel) = file.strip_prefix(mirror_root) {
                referenced.insert(rel.to_string_lossy().into_owned());
            }
        }
    }
    Ok(())
}

/// Collect dirs under `prev_root` whose name parses as a `u64` generation.
/// Non-numeric dirs (suite names) are recursed into; numeric ones are not.
fn collect_generation_dirs(prev_root: &Path) -> Result<Vec<(u64, PathBuf)>, GcError> {
    let mut out = Vec::new();
    let mut stack = vec![prev_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(GcError::Io {
                    path: dir,
                    source: e,
                });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|e| GcError::Io {
                path: dir.clone(),
                source: e,
            })?;
            let ft = entry.file_type().map_err(|e| GcError::Io {
                path: entry.path(),
                source: e,
            })?;
            if !ft.is_dir() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(gen_num) = name_str.parse::<u64>() {
                out.push((gen_num, path));
            } else {
                stack.push(path);
            }
        }
    }
    Ok(out)
}

fn walk_files(dir: &Path) -> Result<Vec<PathBuf>, GcError> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(GcError::Io { path: d, source: e });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|e| GcError::Io {
                path: d.clone(),
                source: e,
            })?;
            let path = entry.path();
            let ft = entry.file_type().map_err(|e| GcError::Io {
                path: path.clone(),
                source: e,
            })?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    Ok(out)
}

fn scan_disk(mirror_root: &Path) -> Result<Vec<PathBuf>, GcError> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = Vec::new();
    for name in ["pool", "dists", ".tain/prev"] {
        stack.push(mirror_root.join(name));
    }
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(GcError::Io {
                    path: dir,
                    source: e,
                });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|e| GcError::Io {
                path: dir.clone(),
                source: e,
            })?;
            let path = entry.path();
            let ft = entry.file_type().map_err(|e| GcError::Io {
                path: path.clone(),
                source: e,
            })?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    Ok(out)
}

fn compute_candidates(
    scan: &[PathBuf],
    referenced: &HashSet<String>,
    mirror_root: &Path,
    grace: Duration,
    now: SystemTime,
) -> (Vec<PathBuf>, usize, u64, u64) {
    let mut candidates = Vec::new();
    let mut grace_skipped = 0;
    let mut scan_bytes: u64 = 0;
    let mut candidate_bytes: u64 = 0;
    for path in scan {
        let rel = match path.strip_prefix(mirror_root) {
            Ok(r) => r.to_string_lossy().into_owned(),
            Err(_) => continue,
        };
        let (size, mtime) = match std::fs::metadata(path) {
            Ok(m) => (m.len(), m.modified().ok()),
            Err(_) => (0, None),
        };
        scan_bytes = scan_bytes.saturating_add(size);
        if referenced.contains(&rel) {
            continue;
        }
        if let Some(mtime) = mtime
            && let Ok(age) = now.duration_since(mtime)
            && age < grace
        {
            grace_skipped += 1;
            continue;
        }
        candidate_bytes = candidate_bytes.saturating_add(size);
        candidates.push(path.clone());
    }
    (candidates, grace_skipped, scan_bytes, candidate_bytes)
}

fn prune_empty_ancestors(path: &Path, allow_roots: &[PathBuf]) {
    let mut current = path.parent();
    while let Some(dir) = current {
        // Strictly inside an allowed root; the roots themselves survive.
        let inside = allow_roots
            .iter()
            .any(|root| dir.starts_with(root) && dir != root);
        if !inside {
            break;
        }
        if std::fs::remove_dir(dir).is_err() {
            break;
        }
        current = dir.parent();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::store::manifest::{GenerationManifest, ManifestEntry};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_root(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("tain-gc-{name}-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn manifest_with(mirror_root: &Path, generation: u64, rel_paths: &[&str]) {
        let mut m = GenerationManifest::new(generation);
        for rel in rel_paths {
            m.insert(ManifestEntry {
                rel_path: (*rel).to_owned(),
                size: 1,
                sha256_hex: Some("aa".repeat(32)),
                sha512_hex: None,
            });
        }
        manifest::save(mirror_root, &m).unwrap();
    }

    fn opts(enabled: bool, grace_secs: u64, ratio: f64) -> GcOptions {
        GcOptions {
            enabled,
            grace_period: Duration::from_secs(grace_secs),
            max_delete_ratio: ratio,
            max_delete_byte_ratio: ratio,
            keep_generations: 3,
            dry_run: false,
        }
    }

    fn set_mtime(path: &Path, when: SystemTime) {
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let _ = file.set_modified(when);
    }

    #[test]
    fn dry_run_produces_report_without_deletion() {
        let root = temp_root("dry");
        manifest_with(&root, 1, &["pool/main/x/x.deb"]);
        write(&root.join("pool/main/x/x.deb"), b"kept");
        write(&root.join("pool/main/y/orphan.deb"), b"orphan");
        set_mtime(
            &root.join("pool/main/y/orphan.deb"),
            SystemTime::now() - Duration::from_secs(200_000),
        );
        let mut o = opts(true, 100, 0.9);
        o.dry_run = true;
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert_eq!(r.candidates.len(), 1);
        assert_eq!(r.deleted.len(), 0);
        assert!(root.join("pool/main/y/orphan.deb").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn disabled_prevents_deletion_but_reports() {
        let root = temp_root("disabled");
        manifest_with(&root, 1, &["pool/keep.deb"]);
        write(&root.join("pool/keep.deb"), b"keep");
        write(&root.join("pool/orphan.deb"), b"orph");
        set_mtime(
            &root.join("pool/orphan.deb"),
            SystemTime::now() - Duration::from_secs(200_000),
        );
        let o = opts(false, 100, 0.9);
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert_eq!(r.candidates.len(), 1);
        assert!(r.disabled);
        assert!(root.join("pool/orphan.deb").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn grace_period_defers_recent_files() {
        let root = temp_root("grace");
        manifest_with(&root, 1, &[]);
        write(&root.join("pool/orphan.deb"), b"orph");
        let o = opts(true, 3600, 0.9);
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert_eq!(r.candidates.len(), 0);
        assert_eq!(r.skipped_grace, 1);
        assert!(root.join("pool/orphan.deb").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn circuit_breaker_aborts_bulk_delete() {
        let root = temp_root("fuse");
        manifest_with(&root, 1, &["pool/keep.deb"]);
        for i in 0..10 {
            let p = root.join(format!("pool/orph{i}.deb"));
            write(&p, b"orph");
            set_mtime(&p, SystemTime::now() - Duration::from_secs(500_000));
        }
        write(&root.join("pool/keep.deb"), b"keep");
        let o = opts(true, 100, 0.3);
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert!(r.circuit_broken, "must break: {r:?}");
        assert!(r.candidates.len() >= 10);
        assert!(r.deleted.is_empty());
        assert!(root.join("pool/orph0.deb").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn happy_path_deletes_orphans_and_prunes_dirs() {
        let root = temp_root("happy");
        manifest_with(&root, 1, &["pool/main/k/keep.deb"]);
        write(&root.join("pool/main/k/keep.deb"), b"keep");
        write(&root.join("pool/main/y/orph.deb"), b"orph");
        set_mtime(
            &root.join("pool/main/y/orph.deb"),
            SystemTime::now() - Duration::from_secs(500_000),
        );
        let o = opts(true, 100, 0.9);
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert_eq!(r.deleted.len(), 1);
        assert!(!root.join("pool/main/y/orph.deb").exists());
        assert!(
            !root.join("pool/main/y").exists(),
            "empty parent dirs must prune"
        );
        assert!(root.join("pool/main/k/keep.deb").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn newest_n_generations_form_reference_union() {
        let root = temp_root("gens");
        manifest_with(&root, 1, &["pool/gen1.deb"]);
        manifest_with(&root, 2, &["pool/gen2.deb"]);
        manifest_with(&root, 3, &["pool/gen3.deb"]);
        manifest_with(&root, 4, &["pool/gen4.deb"]);
        manifest_with(&root, 5, &["pool/gen5.deb"]);
        for i in 1..=5 {
            let p = root.join(format!("pool/gen{i}.deb"));
            write(&p, b"file");
            set_mtime(&p, SystemTime::now() - Duration::from_secs(500_000));
        }
        let o = opts(true, 100, 0.9);
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert_eq!(r.deleted.len(), 2);
        assert!(!root.join("pool/gen1.deb").exists());
        assert!(!root.join("pool/gen2.deb").exists());
        assert!(root.join("pool/gen3.deb").exists());
        assert!(root.join("pool/gen5.deb").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn byte_ratio_circuit_breaker_trips_on_one_huge_orphan() {
        let root = temp_root("byte-ratio");
        let mut keep_paths: Vec<String> = Vec::new();
        for i in 0..10 {
            let rel = format!("pool/tiny{i}.deb");
            let p = root.join(&rel);
            write(&p, &[0; 16]);
            set_mtime(&p, SystemTime::now() - Duration::from_secs(500_000));
            keep_paths.push(rel);
        }
        let keeps: Vec<&str> = keep_paths.iter().map(String::as_str).collect();
        manifest_with(&root, 1, &keeps);
        let big = root.join("pool/huge.iso");
        write(&big, &vec![0u8; 1024 * 1024]);
        set_mtime(&big, SystemTime::now() - Duration::from_secs(500_000));

        // Count ratio ≈ 0.09, byte ratio ≈ 0.9998: only the byte fuse fires.
        let mut o = opts(true, 100, 0.99);
        o.max_delete_byte_ratio = 0.5;
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert!(r.circuit_broken);
        assert!(
            r.circuit_reason.as_deref().unwrap_or("").contains("byte"),
            "reason: {:?}",
            r.circuit_reason
        );
        assert!(big.exists(), "huge orphan preserved by byte-ratio fuse");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn prune_stops_at_pool_root() {
        let root = temp_root("prune-root");
        manifest_with(&root, 1, &["pool/keep.deb"]);
        write(&root.join("pool/keep.deb"), b"keep");
        let orph_dir = root.join("pool/main/y");
        write(&orph_dir.join("orph.deb"), b"orph");
        set_mtime(
            &orph_dir.join("orph.deb"),
            SystemTime::now() - Duration::from_secs(500_000),
        );
        let o = opts(true, 100, 0.99);
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert_eq!(r.deleted.len(), 1);
        assert!(!orph_dir.exists(), "empty deepest dir pruned");
        assert!(root.join("pool").exists(), "pool root must survive");
        assert!(root.join(".tain").exists(), ".tain safe");
        std::fs::remove_dir_all(&root).ok();
    }

    // ---- prev-generation retention ----

    /// Write a back-dated `.tain/prev/<suite>/<gen>/<rel>`.
    fn write_prev(root: &Path, suite: &str, gen_num: u64, rel: &str, bytes: &[u8]) {
        let path = root
            .join(".tain/prev")
            .join(suite)
            .join(gen_num.to_string())
            .join(rel);
        write(&path, bytes);
        set_mtime(&path, SystemTime::now() - Duration::from_secs(500_000));
    }

    #[test]
    fn prev_generations_within_window_are_protected() {
        let root = temp_root("prev-3-in-window");
        manifest_with(&root, 4, &["pool/keep.deb"]);
        write(&root.join("pool/keep.deb"), b"keep");
        write_prev(&root, "bookworm", 1, "InRelease", b"gen1");
        write_prev(&root, "bookworm", 2, "InRelease", b"gen2");
        write_prev(&root, "bookworm", 3, "InRelease", b"gen3");

        let mut o = opts(true, 100, 0.99);
        o.max_delete_byte_ratio = 0.99;
        o.keep_generations = 3;
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert!(r.deleted.is_empty(), "protected prev deleted: {r:?}");
        for g in 1..=3u64 {
            assert!(
                root.join(format!(".tain/prev/bookworm/{g}/InRelease"))
                    .exists(),
                "prev gen{g} must survive"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn oldest_prev_generation_evicted_when_window_slides() {
        let root = temp_root("prev-4-evict");
        manifest_with(&root, 5, &["pool/keep.deb"]);
        write(&root.join("pool/keep.deb"), b"keep");
        for g in 1..=4u64 {
            write_prev(&root, "bookworm", g, "InRelease", b"snap");
        }

        let mut o = opts(true, 100, 0.99);
        o.max_delete_byte_ratio = 0.99;
        o.keep_generations = 3;
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert_eq!(r.deleted.len(), 1, "exactly gen 1 evicted: {r:?}");
        assert!(
            !root.join(".tain/prev/bookworm/1/InRelease").exists(),
            "oldest prev gen must be gone"
        );
        assert!(
            !root.join(".tain/prev/bookworm/1").exists(),
            "empty prev generation dir must be pruned"
        );
        for g in 2..=4u64 {
            assert!(
                root.join(format!(".tain/prev/bookworm/{g}/InRelease"))
                    .exists(),
                "prev gen{g} within window"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn circuit_breaker_preserves_even_expired_prev_generations() {
        // Wipe protection outranks retention expiry.
        let root = temp_root("prev-fuse");
        manifest_with(&root, 5, &["pool/tiny.deb"]);
        let tiny = root.join("pool/tiny.deb");
        write(&tiny, &[0; 32]);
        set_mtime(&tiny, SystemTime::now() - Duration::from_secs(500_000));
        for g in 2..=4u64 {
            write_prev(&root, "bookworm", g, "InRelease", b"snap");
        }
        write_prev(&root, "bookworm", 1, "d-i.iso", &vec![0u8; 1024 * 1024]);

        let mut o = opts(true, 100, 0.99);
        o.max_delete_byte_ratio = 0.3;
        o.keep_generations = 3;
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert!(r.circuit_broken, "byte ratio must trip: {r:?}");
        assert!(r.deleted.is_empty());
        assert!(root.join(".tain/prev/bookworm/1/d-i.iso").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn keep_generations_zero_disables_prev_protection() {
        let root = temp_root("prev-zero");
        manifest_with(&root, 3, &["pool/keep.deb"]);
        write(&root.join("pool/keep.deb"), b"keep");
        write_prev(&root, "bookworm", 1, "InRelease", b"snap");
        write_prev(&root, "bookworm", 2, "InRelease", b"snap");

        let mut o = opts(true, 100, 0.99);
        o.max_delete_byte_ratio = 0.99;
        o.keep_generations = 0;
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert_eq!(r.deleted.len(), 2, "both prev gens must be swept");
        assert!(!root.join(".tain/prev/bookworm/1").exists());
        assert!(!root.join(".tain/prev/bookworm/2").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn keep_generations_larger_than_available_protects_all() {
        let root = temp_root("prev-oversize-k");
        manifest_with(&root, 3, &["pool/keep.deb"]);
        write(&root.join("pool/keep.deb"), b"keep");
        write_prev(&root, "bookworm", 1, "InRelease", b"snap");
        write_prev(&root, "bookworm", 2, "InRelease", b"snap");

        let mut o = opts(true, 100, 0.99);
        o.max_delete_byte_ratio = 0.99;
        o.keep_generations = 5;
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert!(r.deleted.is_empty(), "K > available must not delete");
        assert!(root.join(".tain/prev/bookworm/1/InRelease").exists());
        assert!(root.join(".tain/prev/bookworm/2/InRelease").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn non_numeric_prev_dirs_are_skipped_not_panicking() {
        let root = temp_root("prev-nonnumeric");
        manifest_with(&root, 3, &["pool/keep.deb"]);
        write(&root.join("pool/keep.deb"), b"keep");
        write_prev(&root, "bookworm", 1, "InRelease", b"snap");
        write_prev(&root, "bookworm", 2, "InRelease", b"snap");
        let junk = root.join(".tain/prev/bookworm/not-a-generation/InRelease");
        write(&junk, b"junk");
        set_mtime(&junk, SystemTime::now() - Duration::from_secs(500_000));

        let mut o = opts(true, 100, 0.99);
        o.max_delete_byte_ratio = 0.99;
        o.keep_generations = 3;
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert!(root.join(".tain/prev/bookworm/1/InRelease").exists());
        assert!(root.join(".tain/prev/bookworm/2/InRelease").exists());
        assert!(
            !junk.exists(),
            "non-numeric prev sub-tree not protected: {r:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flat_prev_layout_without_suite_dir_is_supported() {
        let root = temp_root("prev-flat");
        manifest_with(&root, 3, &["pool/keep.deb"]);
        write(&root.join("pool/keep.deb"), b"keep");
        let flat_gen = root.join(".tain/prev/7/Release");
        write(&flat_gen, b"flat");
        set_mtime(&flat_gen, SystemTime::now() - Duration::from_secs(500_000));

        let mut o = opts(true, 100, 0.99);
        o.max_delete_byte_ratio = 0.99;
        o.keep_generations = 3;
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert!(r.deleted.is_empty(), "flat prev gen must be protected");
        assert!(flat_gen.exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn staging_files_are_ignored() {
        let root = temp_root("staging");
        manifest_with(&root, 1, &["pool/keep.deb"]);
        write(&root.join("pool/keep.deb"), b"keep");
        write(&root.join(".tain/staging/bookworm/InRelease"), b"midsync");
        set_mtime(
            &root.join(".tain/staging/bookworm/InRelease"),
            SystemTime::now() - Duration::from_secs(500_000),
        );
        let o = opts(true, 100, 0.9);
        let r = run_gc(&root, &o, SystemTime::now()).unwrap();
        assert!(
            root.join(".tain/staging/bookworm/InRelease").exists(),
            "staging is off-limits to GC"
        );
        assert!(r.deleted.is_empty());
        std::fs::remove_dir_all(&root).ok();
    }
}
