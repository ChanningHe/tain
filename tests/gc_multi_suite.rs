//! GC over the published set across rounds: unchanged suites stay in the
//! manifest, current by-hash objects stay referenced, old manifests are
//! pruned, and `verify` covers every suite.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};
use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, FloatRatio, GcConfig, GlobalConfig, I18nSelection,
    IndexSelection, MirrorConfig, VerifyConfig,
};
use tain::core::engine::verify::{EntryVerdict, scrub_latest};
use tain::core::engine::{MirrorOutcome, sync_mirror};
use tain::core::store::manifest;

mod common;
use common::{PackagesVariantKind, StaticServer, SyntheticRepo, TempDir};

const KEEP: u32 = 3;
const PAST_GRACE: Duration = Duration::from_secs(30 * 24 * 3600);

fn build_mirror(base_url: &url::Url, suites: &[&str]) -> MirrorConfig {
    let apt = AptOptions {
        suites: suites.iter().map(|s| (*s).to_owned()).collect(),
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
        name: "upstream".to_owned(),
        backend: BackendKind::Apt,
        url: base_url.clone(),
        path: PathBuf::from("upstream"),
        verify: VerifyConfig::default(),
        // Default grace/keep; loose fuse so wrong deletions actually happen.
        gc: GcConfig {
            enabled: true,
            keep_generations: KEEP,
            max_delete_ratio: FloatRatio::new(0.95).expect("valid ratio"),
            ..GcConfig::default()
        },
        force_http1: false,
        backend_options: BackendOptions::Apt(apt),
    }
}

fn build_global(target: PathBuf) -> GlobalConfig {
    GlobalConfig {
        target,
        parallel: 4,
        host_connections: 2,
        ..GlobalConfig::default()
    }
}

/// Rewrite `suite` upstream with one package named after `round`. Release
/// mtimes are pinned per round so `If-Modified-Since` never masks a change.
fn write_moving(serve: &Path, suite: &str, round: u64) {
    SyntheticRepo::new(serve.to_path_buf(), suite)
        .add_package(format!("mov{round}"), format!("mov {round}").into_bytes())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    let when = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000 + round * 3600);
    for name in ["InRelease", "Release"] {
        set_mtime(&serve.join(format!("dists/{suite}/{name}")), when);
    }
}

fn set_mtime(path: &Path, when: SystemTime) {
    let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_modified(when).unwrap();
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .flat_map(|e| {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => files_under(&p),
                Ok(t) if t.is_file() => vec![p],
                _ => Vec::new(),
            }
        })
        .collect()
}

/// Back-date everything GC scans past the default grace period.
fn age_mirror(mirror_root: &Path) {
    let past = SystemTime::now() - PAST_GRACE;
    for sub in ["pool", "dists", ".tain/prev"] {
        for f in files_under(&mirror_root.join(sub)) {
            set_mtime(&f, past);
        }
    }
}

fn by_hash_objects(dist: &Path) -> Vec<PathBuf> {
    files_under(dist)
        .into_iter()
        .filter(|p| p.components().any(|c| c.as_os_str() == "by-hash"))
        .collect()
}

fn sha256_hex(path: &Path) -> String {
    Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn gc_candidates(outcome: &MirrorOutcome) -> Vec<PathBuf> {
    outcome
        .gc
        .as_ref()
        .map(|g| g.candidates.clone())
        .unwrap_or_default()
}

/// A static suite next to one that changes KEEP+1 times
/// keeps its dists and pool files; old manifests are pruned; verify sees
/// both suites.
#[tokio::test]
async fn unchanged_suite_survives_gc_across_generations() {
    let serve = TempDir::new("multi-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "stable")
        .add_package("solid", b"solid bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    write_moving(serve.path(), "moving", 0);
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("multi-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), &["stable", "moving"]);
    let mirror_root = target.path().join("upstream");

    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(first.suites_succeeded.len(), 2, "{first:?}");

    let stable_dist = mirror_root.join("dists/stable");
    let solid_deb = mirror_root.join("pool/main/s/solid/solid_1.0_amd64.deb");
    let stable_files: Vec<PathBuf> = files_under(&stable_dist);
    assert!(
        stable_files.len() >= 4,
        "stable dists populated: {stable_files:?}"
    );
    assert!(!by_hash_objects(&stable_dist).is_empty());

    for round in 1..=u64::from(KEEP) {
        write_moving(serve.path(), "moving", round);
        age_mirror(&mirror_root);
        let out = sync_mirror(&global, &mirror, &global.target).await.unwrap();
        assert!(out.is_success(), "{out:?}");
        assert_eq!(out.suites_unchanged, vec!["stable".to_owned()], "{out:?}");
        assert_eq!(out.suites_succeeded, vec!["moving".to_owned()], "{out:?}");
        let candidates = gc_candidates(&out);
        for f in stable_files.iter().chain([&solid_deb]) {
            assert!(
                !candidates.contains(f),
                "round {round}: published {} is a GC candidate",
                f.display()
            );
        }
    }

    for f in stable_files.iter().chain([&solid_deb]) {
        assert!(f.exists(), "published {} deleted", f.display());
    }
    // GC still works: the round-0 moving package left every retained manifest.
    assert!(
        !mirror_root
            .join("pool/main/m/mov0/mov0_1.0_amd64.deb")
            .exists(),
        "superseded pool file must be collected"
    );

    // Only the retention window is kept on disk.
    let gens = manifest::list_generations(&mirror_root).unwrap();
    assert_eq!(gens.len(), KEEP as usize, "manifests: {gens:?}");

    let latest = manifest::load(&mirror_root, *gens.last().unwrap()).unwrap();
    for key in [
        "dists/stable/InRelease",
        "dists/moving/InRelease",
        "pool/main/s/solid/solid_1.0_amd64.deb",
    ] {
        assert!(
            latest.files.contains_key(key),
            "latest manifest lacks {key}"
        );
    }

    let report = scrub_latest(&mirror_root).unwrap();
    assert!(report.is_clean(), "{report:?}");
    std::fs::write(&solid_deb, b"bitrot!!!!!").unwrap();
    let report = scrub_latest(&mirror_root).unwrap();
    assert!(
        report
            .problems
            .iter()
            .any(|(rel, v)| rel == "pool/main/s/solid/solid_1.0_amd64.deb"
                && matches!(v, EntryVerdict::DigestMismatch { .. })),
        "verify must cover the unchanged suite: {report:?}"
    );
}

/// By-hash objects of the currently published indexes survive GC on a
/// quiet suite; superseded ones still age out after KEEP generations.
#[tokio::test]
async fn current_by_hash_objects_survive_and_superseded_age_out() {
    let serve = TempDir::new("byhash-serve");
    write_moving(serve.path(), "bookworm", 0);
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("byhash-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), &["bookworm"]);
    let mirror_root = target.path().join("upstream");
    let dist = mirror_root.join("dists/bookworm");

    sync_mirror(&global, &mirror, &global.target).await.unwrap();
    let original = by_hash_objects(&dist);
    assert!(original.len() >= 4, "by-hash written: {original:?}");

    age_mirror(&mirror_root);
    let quiet = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(quiet.suites_unchanged, vec!["bookworm".to_owned()]);
    for f in &original {
        assert!(f.exists(), "current by-hash {} deleted", f.display());
    }

    for round in 1..=u64::from(KEEP) {
        write_moving(serve.path(), "bookworm", round);
        age_mirror(&mirror_root);
        let out = sync_mirror(&global, &mirror, &global.target).await.unwrap();
        assert_eq!(out.suites_succeeded, vec!["bookworm".to_owned()], "{out:?}");
    }
    age_mirror(&mirror_root);
    sync_mirror(&global, &mirror, &global.target).await.unwrap();

    for f in &original {
        assert!(!f.exists(), "superseded by-hash {} kept", f.display());
    }
    let packages = dist.join("main/binary-amd64/Packages.xz");
    let current = dist.join(format!(
        "main/binary-amd64/by-hash/SHA256/{}",
        sha256_hex(&packages)
    ));
    assert!(current.exists(), "current by-hash object missing");
    assert!(scrub_latest(&mirror_root).unwrap().is_clean());
}

/// `stable` (static, one package) + `moving` (rewritten per round), synced once.
struct TwoSuites {
    serve: TempDir,
    _server: StaticServer,
    _target: TempDir,
    global: GlobalConfig,
    mirror: MirrorConfig,
    root: PathBuf,
}

const SOLID_DEB: &str = "pool/main/s/solid/solid_1.0_amd64.deb";

impl TwoSuites {
    async fn new(prefix: &str) -> Self {
        let serve = TempDir::new(&format!("{prefix}-serve"));
        write_stable(serve.path());
        write_moving(serve.path(), "moving", 0);
        let server = StaticServer::spawn(serve.path().to_path_buf()).await;
        let target = TempDir::new(&format!("{prefix}-target"));
        let global = build_global(target.path().to_path_buf());
        let mirror = build_mirror(&server.base_url(), &["stable", "moving"]);
        let root = target.path().join("upstream");
        let me = Self {
            serve,
            _server: server,
            _target: target,
            global,
            mirror,
            root,
        };
        let first = me.sync().await;
        assert_eq!(first.suites_succeeded.len(), 2, "{first:?}");
        me
    }

    async fn sync(&self) -> MirrorOutcome {
        sync_mirror(&self.global, &self.mirror, &self.global.target)
            .await
            .unwrap()
    }

    fn latest(&self) -> manifest::GenerationManifest {
        let gens = manifest::list_generations(&self.root).unwrap();
        manifest::load(&self.root, *gens.last().unwrap()).unwrap()
    }
}

fn write_stable(serve: &Path) {
    SyntheticRepo::new(serve.to_path_buf(), "stable")
        .add_package("solid", b"solid bytes".to_vec())
        .write();
}

fn stable_keys(m: &manifest::GenerationManifest) -> Vec<String> {
    m.suites["stable"].iter().cloned().collect()
}

/// Upgrade from unattributed manifests: the quiet suite re-syncs once to
/// get exact attribution (no foreign keys), and the busy suite's
/// superseded files are still collected afterwards.
#[tokio::test]
async fn unattributed_manifests_converge_to_exact_attribution() {
    let fx = TwoSuites::new("legacy").await;
    write_moving(fx.serve.path(), "moving", 1);
    assert_eq!(fx.sync().await.new_generation, 2);
    // As the old engine wrote them: no attribution, gen2 lists only `moving`.
    let mut gen1 = manifest::load(&fx.root, 1).unwrap();
    gen1.suites.clear();
    manifest::save(&fx.root, &gen1).unwrap();
    let mut gen2 = manifest::load(&fx.root, 2).unwrap();
    let moving = gen2.suites.remove("moving").unwrap();
    gen2.files.retain(|k, _| moving.contains(k));
    gen2.suites.clear();
    manifest::save(&fx.root, &gen2).unwrap();

    let stable_files = files_under(&fx.root.join("dists/stable"));
    write_moving(fx.serve.path(), "moving", 2);
    age_mirror(&fx.root);
    let upgrade = fx.sync().await;
    assert!(
        upgrade.suites_succeeded.contains(&"stable".to_owned()),
        "unattributed suite must re-sync: {upgrade:?}"
    );
    let exact = stable_keys(&fx.latest());
    assert!(
        exact.iter().all(|k| !k.contains("mov")),
        "foreign keys: {exact:?}"
    );
    assert!(exact.contains(&SOLID_DEB.to_owned()));

    for round in 3..=3 + u64::from(KEEP) {
        write_moving(fx.serve.path(), "moving", round);
        age_mirror(&fx.root);
        let out = fx.sync().await;
        assert_eq!(out.suites_unchanged, vec!["stable".to_owned()], "{out:?}");
        assert!(out.gc.is_some(), "{out:?}");
    }
    assert_eq!(
        stable_keys(&fx.latest()),
        exact,
        "carried set must not grow"
    );
    for old in ["mov0", "mov1", "mov2"] {
        let p = fx
            .root
            .join(format!("pool/main/m/{old}/{old}_1.0_amd64.deb"));
        assert!(!p.exists(), "superseded {old} pinned");
    }
    for f in stable_files.iter().chain([&fx.root.join(SOLID_DEB)]) {
        assert!(f.exists(), "published {} deleted", f.display());
    }
    assert!(scrub_latest(&fx.root).unwrap().is_clean());
}

/// A suite missing from the latest manifest's attribution re-syncs in the
/// same round, so live GC is not disabled while it stays frozen.
#[tokio::test]
async fn lost_attribution_is_recovered_within_one_round() {
    let fx = TwoSuites::new("lost-attr").await;
    let mut latest = fx.latest();
    let keys = latest.suites.remove("stable").unwrap();
    latest.files.retain(|k, _| !keys.contains(k));
    manifest::save(&fx.root, &latest).unwrap();

    let out = fx.sync().await;
    assert_eq!(out.suites_succeeded, vec!["stable".to_owned()], "{out:?}");
    assert_eq!(out.suites_unchanged, vec!["moving".to_owned()], "{out:?}");
    assert!(out.gc.is_some(), "gc must run: {out:?}");
    assert!(fx.latest().suites.contains_key("stable"));

    let quiet = fx.sync().await;
    assert_eq!(quiet.suites_unchanged.len(), 2, "{quiet:?}");
    assert!(quiet.gc.is_some());
}

/// A failed suite keeps its published files in the manifest.
#[tokio::test]
async fn failed_suite_is_carried_forward() {
    let fx = TwoSuites::new("failed").await;
    let before = stable_keys(&fx.latest());
    for name in ["InRelease", "Release"] {
        std::fs::remove_file(fx.serve.path().join(format!("dists/stable/{name}"))).unwrap();
    }
    write_moving(fx.serve.path(), "moving", 1);
    let out = fx.sync().await;
    assert_eq!(out.suites_failed, vec!["stable".to_owned()], "{out:?}");
    assert!(out.gc.is_none(), "{out:?}");
    assert_eq!(fx.latest().generation, 2);
    assert_eq!(stable_keys(&fx.latest()), before);

    write_stable(fx.serve.path());
    age_mirror(&fx.root);
    let healed = fx.sync().await;
    assert_eq!(healed.suites_unchanged.len(), 2, "{healed:?}");
    assert!(healed.gc.is_some());
    assert!(fx.root.join(SOLID_DEB).exists());
    assert!(fx.root.join("dists/stable/InRelease").exists());
}

/// Generations never reuse a number on disk: lost state.json, or a crash
/// between manifest save and state save.
#[tokio::test]
async fn generations_are_numbered_past_every_manifest() {
    let fx = TwoSuites::new("gen-num").await;
    std::fs::remove_file(fx.root.join(".tain/state.json")).unwrap();
    let out = fx.sync().await;
    assert_eq!(out.new_generation, 2, "{out:?}");

    let mut orphan = fx.latest();
    orphan.generation = 3;
    manifest::save(&fx.root, &orphan).unwrap();
    write_moving(fx.serve.path(), "moving", 1);
    let out = fx.sync().await;
    assert_eq!(out.new_generation, 4, "{out:?}");
    assert_eq!(fx.latest().generation, 4);
}

/// A quiet round reports pool gauges from the standing manifest.
#[tokio::test]
async fn quiet_round_keeps_pool_gauges() {
    let fx = TwoSuites::new("gauges").await;
    let quiet = fx.sync().await;
    assert_eq!(quiet.suites_unchanged.len(), 2);
    assert_eq!(quiet.pool_files, 2, "{quiet:?}");
}
