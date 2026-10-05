//! Release-checksum-driven index selection.
//!
//! The fetch set is derived from the Release checksum block, not a hardcoded path list,
//! so layout quirks (legacy `binary-<arch>/Release`, `i18n/Index`, dep11) are picked up.
//! Only Packages, Sources and d-i `SHA256SUMS` are parsed; everything else is verbatim.

use crate::backends::apt::checksums::{ChecksumEntry, ReleaseChecksums};
use crate::backends::apt::release::ReleaseHeader;
use crate::config::model::{AptOptions, I18nSelection};

/// All compression variants of one logical index file, in fetch-preference order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexGroup<'a> {
    /// Suite-relative path without compression suffix, e.g. `main/binary-amd64/Packages`.
    pub base_path: String,
    pub variants: Vec<PackagesVariant<'a>>,
    pub role: IndexRole,
    /// Under a `debian-installer/` subtree.
    pub udeb: bool,
    /// `None` for archive-root Contents.
    pub component: Option<String>,
    /// `None` for arch-agnostic indices such as Translations.
    pub arch: Option<String>,
    /// Translation language tag (`en`, `zh_CN`, …).
    pub language: Option<String>,
}

/// One concrete file inside an `IndexGroup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagesVariant<'a> {
    pub entry: &'a ChecksumEntry,
    pub compression: Compression,
}

/// What the engine does with an index group after staging its variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexRole {
    /// Parse to derive the binary pool wanted set.
    PackagesParse,
    /// Parse to derive the source pool wanted set.
    SourcesParse,
    /// Legacy `<c>/[debian-installer/]binary-<a>/Release`, mirrored for completeness.
    LegacyRelease,
    /// d-i `SHA256SUMS`: published verbatim and parsed for the image files it lists.
    InstallerSumsParse,
    /// Published verbatim (Contents, i18n, dep11, cnf, …).
    Verbatim,
}

/// Compression of an index file, determined solely by filename suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Xz,
    Gz,
    Bz2,
    None,
}

impl Compression {
    /// Fetch and parse preference: xz → gz → bz2 → uncompressed.
    #[must_use]
    pub fn preference_rank(self) -> u8 {
        match self {
            Compression::Xz => 0,
            Compression::Gz => 1,
            Compression::Bz2 => 2,
            Compression::None => 3,
        }
    }

    /// Detect from a Release checksum path's suffix.
    #[must_use]
    pub fn detect_from_path(path: &str) -> Self {
        if path.ends_with(".xz") {
            Compression::Xz
        } else if path.ends_with(".gz") {
            Compression::Gz
        } else if path.ends_with(".bz2") {
            Compression::Bz2
        } else {
            Compression::None
        }
    }

    /// Strip this compression's suffix from `path`.
    fn strip_suffix(self, path: &str) -> String {
        let ext = match self {
            Compression::Xz => ".xz",
            Compression::Gz => ".gz",
            Compression::Bz2 => ".bz2",
            Compression::None => "",
        };
        if ext.is_empty() {
            path.to_owned()
        } else {
            path.strip_suffix(ext).unwrap_or(path).to_owned()
        }
    }
}

/// Full selection output for one suite.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexSelection<'a> {
    pub groups: Vec<IndexGroup<'a>>,
}

impl<'a> IndexSelection<'a> {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// All Packages-parseable groups (binary), in order.
    pub fn packages_groups(&self) -> impl Iterator<Item = &IndexGroup<'a>> {
        self.groups
            .iter()
            .filter(|g| g.role == IndexRole::PackagesParse)
    }

    /// All Sources-parseable groups.
    pub fn sources_groups(&self) -> impl Iterator<Item = &IndexGroup<'a>> {
        self.groups
            .iter()
            .filter(|g| g.role == IndexRole::SourcesParse)
    }

    /// All d-i `SHA256SUMS` groups.
    pub fn installer_sums_groups(&self) -> impl Iterator<Item = &IndexGroup<'a>> {
        self.groups
            .iter()
            .filter(|g| g.role == IndexRole::InstallerSumsParse)
    }

    /// Every checksum entry this selection covers.
    pub fn all_entries(&self) -> impl Iterator<Item = &ChecksumEntry> {
        self.groups
            .iter()
            .flat_map(|g| g.variants.iter().map(|v| v.entry))
    }
}

/// What a Release checksum path "means" once parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathKind {
    Packages {
        component: String,
        arch: String,
        udeb: bool,
    },
    LegacyRelease {
        component: String,
        arch: String,
        udeb: bool,
    },
    Sources {
        component: String,
    },
    Contents {
        component: Option<String>,
        arch: String,
        udeb: bool,
    },
    Translation {
        component: String,
        language: String,
    },
    I18nIndex {
        component: String,
    },
    Dep11Components {
        component: String,
        arch: String,
    },
    Dep11Icons {
        component: String,
        icons_ident: String,
    },
    Dep11CidIndex {
        component: String,
        arch: String,
    },
    Cnf {
        component: String,
        arch: String,
    },
    /// Any file under `installer-<arch>/<version>/images/`.
    InstallerImages {
        component: String,
        arch: String,
        version: String,
    },
    Unknown,
}

impl PathKind {
    fn key(&self) -> Option<GroupKey<'_>> {
        match self {
            PathKind::Packages {
                component,
                arch,
                udeb,
            } => Some(GroupKey::Packages {
                component,
                arch,
                udeb: *udeb,
            }),
            PathKind::LegacyRelease {
                component,
                arch,
                udeb,
            } => Some(GroupKey::LegacyRelease {
                component,
                arch,
                udeb: *udeb,
            }),
            PathKind::Sources { component } => Some(GroupKey::Sources { component }),
            PathKind::Contents {
                component,
                arch,
                udeb,
            } => Some(GroupKey::Contents {
                component: component.as_deref(),
                arch,
                udeb: *udeb,
            }),
            PathKind::Translation {
                component,
                language,
            } => Some(GroupKey::Translation {
                component,
                language,
            }),
            PathKind::I18nIndex { component } => Some(GroupKey::I18nIndex { component }),
            PathKind::Dep11Components { component, arch } => {
                Some(GroupKey::Dep11Components { component, arch })
            }
            PathKind::Dep11Icons {
                component,
                icons_ident,
            } => Some(GroupKey::Dep11Icons {
                component,
                icons_ident,
            }),
            PathKind::Dep11CidIndex { component, arch } => {
                Some(GroupKey::Dep11CidIndex { component, arch })
            }
            PathKind::Cnf { component, arch } => Some(GroupKey::Cnf { component, arch }),
            PathKind::InstallerImages {
                component,
                arch,
                version,
            } => Some(GroupKey::InstallerImages {
                component,
                arch,
                version,
            }),
            PathKind::Unknown => None,
        }
    }
}

/// Borrowed grouping identity for variants of one index.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GroupKey<'a> {
    Packages {
        component: &'a str,
        arch: &'a str,
        udeb: bool,
    },
    LegacyRelease {
        component: &'a str,
        arch: &'a str,
        udeb: bool,
    },
    Sources {
        component: &'a str,
    },
    Contents {
        component: Option<&'a str>,
        arch: &'a str,
        udeb: bool,
    },
    Translation {
        component: &'a str,
        language: &'a str,
    },
    I18nIndex {
        component: &'a str,
    },
    Dep11Components {
        component: &'a str,
        arch: &'a str,
    },
    Dep11Icons {
        component: &'a str,
        icons_ident: &'a str,
    },
    Dep11CidIndex {
        component: &'a str,
        arch: &'a str,
    },
    Cnf {
        component: &'a str,
        arch: &'a str,
    },
    InstallerImages {
        component: &'a str,
        arch: &'a str,
        version: &'a str,
    },
}

fn classify(path: &str) -> (String, Compression, PathKind) {
    let compression = Compression::detect_from_path(path);
    let base = compression.strip_suffix(path);
    let kind = classify_base(&base);
    (base, compression, kind)
}

fn classify_base(base: &str) -> PathKind {
    let segments: Vec<&str> = base.split('/').collect();
    if segments.is_empty() {
        return PathKind::Unknown;
    }

    // Archive-root `Contents-<arch>` / `Contents-udeb-<arch>` / `Contents-source`.
    if segments.len() == 1 {
        if let Some(rest) = segments[0].strip_prefix("Contents-") {
            let (udeb, arch) = if let Some(a) = rest.strip_prefix("udeb-") {
                (true, a.to_owned())
            } else {
                (false, rest.to_owned())
            };
            return PathKind::Contents {
                component: None,
                arch,
                udeb,
            };
        }
        return PathKind::Unknown;
    }

    let component = segments[0].to_owned();
    let tail = &segments[1..];

    // 2-segment: <c>/Contents-<arch> or <c>/Contents-udeb-<arch>
    if tail.len() == 1 {
        if let Some(rest) = tail[0].strip_prefix("Contents-") {
            let (udeb, arch) = if let Some(a) = rest.strip_prefix("udeb-") {
                (true, a.to_owned())
            } else {
                (false, rest.to_owned())
            };
            return PathKind::Contents {
                component: Some(component),
                arch,
                udeb,
            };
        }
        return PathKind::Unknown;
    }

    // <c>/[debian-installer/]<subdir>/<leaf>
    let (udeb, mid) = if tail[0] == "debian-installer" {
        (true, &tail[1..])
    } else {
        (false, tail)
    };
    if mid.is_empty() {
        return PathKind::Unknown;
    }

    // binary-<arch>/{Packages,Release}
    if let Some(arch) = mid[0].strip_prefix("binary-") {
        if mid.len() == 2 {
            match mid[1] {
                "Packages" => {
                    return PathKind::Packages {
                        component,
                        arch: arch.to_owned(),
                        udeb,
                    };
                }
                "Release" => {
                    return PathKind::LegacyRelease {
                        component,
                        arch: arch.to_owned(),
                        udeb,
                    };
                }
                _ => return PathKind::Unknown,
            }
        }
        return PathKind::Unknown;
    }

    // source/{Sources,Release}  — udeb never applies here
    if mid[0] == "source" && !udeb && mid.len() == 2 {
        return match mid[1] {
            "Sources" => PathKind::Sources { component },
            "Release" => PathKind::LegacyRelease {
                component,
                arch: "source".to_owned(),
                udeb: false,
            },
            _ => PathKind::Unknown,
        };
    }

    // i18n/dep11/cnf never live under debian-installer/.
    if udeb {
        return PathKind::Unknown;
    }

    // i18n/{Index, Translation-<lang>}
    if mid[0] == "i18n" && mid.len() == 2 {
        if mid[1] == "Index" {
            return PathKind::I18nIndex { component };
        }
        if let Some(lang) = mid[1].strip_prefix("Translation-") {
            return PathKind::Translation {
                component,
                language: lang.to_owned(),
            };
        }
        return PathKind::Unknown;
    }

    // dep11/{Components-<arch>.yml, icons-<size>.tar.gz, CID-Index-<arch>.json.gz}
    if mid[0] == "dep11" && mid.len() == 2 {
        let leaf = mid[1];
        if let Some(rest) = leaf.strip_prefix("Components-")
            && let Some(arch) = rest.strip_suffix(".yml")
        {
            return PathKind::Dep11Components {
                component,
                arch: arch.to_owned(),
            };
        }
        if leaf.starts_with("icons-") {
            // `icons-64x64@2.tar` identity folds its compression variants together.
            let ident = leaf.strip_suffix(".tar").unwrap_or(leaf).to_owned();
            return PathKind::Dep11Icons {
                component,
                icons_ident: ident,
            };
        }
        if let Some(rest) = leaf.strip_prefix("CID-Index-")
            && let Some(arch) = rest.strip_suffix(".json")
        {
            return PathKind::Dep11CidIndex {
                component,
                arch: arch.to_owned(),
            };
        }
        return PathKind::Unknown;
    }

    // cnf/Commands-<arch>
    if mid[0] == "cnf"
        && mid.len() == 2
        && let Some(arch) = mid[1].strip_prefix("Commands-")
    {
        return PathKind::Cnf {
            component,
            arch: arch.to_owned(),
        };
    }

    // installer-<arch>/<version>/images/...; each file is its own group.
    if let Some(di_arch) = mid[0].strip_prefix("installer-")
        && mid.len() >= 4
        && mid[2] == "images"
    {
        return PathKind::InstallerImages {
            component,
            arch: di_arch.to_owned(),
            version: mid[1].to_owned(),
        };
    }

    PathKind::Unknown
}

/// Choose which entries in `checksums` to fetch for this (mirror, suite).
///
/// Applies the component/architecture filters, `apt.indexes` toggles, and the
/// `No-Support-for-Architecture-all` hint.
#[must_use]
pub fn select_indexes<'a>(
    header: &ReleaseHeader,
    checksums: &'a ReleaseChecksums,
    apt: &AptOptions,
) -> IndexSelection<'a> {
    let inline_all = header
        .no_support_for_architecture_all
        .as_deref()
        .map(str::trim)
        .is_some_and(|v| !v.is_empty());
    let archs = wanted_arch_set(apt, inline_all);
    let mut groups: Vec<(String, PathKind, Vec<PackagesVariant<'a>>)> = Vec::new();

    for entry in checksums.iter() {
        let (base, compression, kind) = classify(&entry.path);
        if matches!(kind, PathKind::Unknown) {
            continue;
        }
        if !kind_included(&kind, apt, &archs) {
            continue;
        }
        push_variant(&mut groups, base, kind, entry, compression);
    }

    let mut selection = IndexSelection::default();
    for (base_path, kind, mut variants) in groups {
        variants.sort_by_key(|v| v.compression.preference_rank());
        let role = role_of(&kind, &base_path);
        let (component, arch, udeb, language) = kind_public_facets(&kind);
        selection.groups.push(IndexGroup {
            base_path,
            variants,
            role,
            component,
            arch,
            udeb,
            language,
        });
    }
    selection
}

fn kind_included(kind: &PathKind, apt: &AptOptions, archs: &[String]) -> bool {
    let component_ok = |c: &str| apt.components.iter().any(|cc| cc == c);
    match kind {
        PathKind::Packages {
            component,
            arch,
            udeb,
        } => {
            if !apt.indexes.packages {
                return false;
            }
            if *udeb && !apt.indexes.debian_installer {
                return false;
            }
            component_ok(component) && archs.iter().any(|a| a == arch)
        }
        PathKind::LegacyRelease {
            component,
            arch,
            udeb,
        } => {
            if *udeb && !apt.indexes.debian_installer {
                return false;
            }
            component_ok(component) && (arch == "source" || archs.iter().any(|a| a == arch))
        }
        PathKind::Sources { component } => apt.indexes.sources && component_ok(component),
        PathKind::Contents {
            component,
            arch,
            udeb,
        } => {
            if !apt.indexes.contents {
                return false;
            }
            if *udeb && !apt.indexes.debian_installer {
                return false;
            }
            let comp_ok = component.as_deref().is_none_or(component_ok);
            let arch_ok = arch == "source" || archs.iter().any(|a| a == arch);
            comp_ok && arch_ok
        }
        PathKind::Translation {
            component,
            language,
        } => component_ok(component) && translation_wanted(&apt.indexes.i18n, language),
        PathKind::I18nIndex { component } => {
            component_ok(component) && !matches!(apt.indexes.i18n, I18nSelection::None)
        }
        PathKind::Dep11Components { component, arch } => {
            apt.indexes.dep11 && component_ok(component) && archs.iter().any(|a| a == arch)
        }
        PathKind::Dep11Icons { component, .. } => apt.indexes.dep11 && component_ok(component),
        PathKind::Dep11CidIndex { component, arch } => {
            apt.indexes.dep11 && component_ok(component) && archs.iter().any(|a| a == arch)
        }
        PathKind::Cnf { component, arch } => {
            apt.indexes.cnf && component_ok(component) && archs.iter().any(|a| a == arch)
        }
        PathKind::InstallerImages {
            component, arch, ..
        } => {
            apt.indexes.debian_installer
                && component_ok(component)
                && archs.iter().any(|a| a == arch)
        }
        PathKind::Unknown => false,
    }
}

fn translation_wanted(sel: &I18nSelection, lang: &str) -> bool {
    match sel {
        I18nSelection::None => false,
        I18nSelection::All => true,
        I18nSelection::Only(langs) => langs.iter().any(|l| l == lang),
    }
}

fn role_of(kind: &PathKind, base_path: &str) -> IndexRole {
    match kind {
        PathKind::Packages { .. } => IndexRole::PackagesParse,
        PathKind::Sources { .. } => IndexRole::SourcesParse,
        PathKind::LegacyRelease { .. } => IndexRole::LegacyRelease,
        // Only SHA256SUMS is parsed; MD5SUMS stays verbatim since MD5 alone is a weak hash.
        PathKind::InstallerImages { .. } if is_sha256sums_base(base_path) => {
            IndexRole::InstallerSumsParse
        }
        _ => IndexRole::Verbatim,
    }
}

fn is_sha256sums_base(base_path: &str) -> bool {
    base_path
        .rsplit_once('/')
        .is_some_and(|(_, leaf)| leaf == "SHA256SUMS")
}

fn kind_public_facets(kind: &PathKind) -> (Option<String>, Option<String>, bool, Option<String>) {
    match kind {
        PathKind::Packages {
            component,
            arch,
            udeb,
        }
        | PathKind::LegacyRelease {
            component,
            arch,
            udeb,
        } => (Some(component.clone()), Some(arch.clone()), *udeb, None),
        PathKind::Sources { component } => {
            (Some(component.clone()), Some("source".into()), false, None)
        }
        PathKind::Contents {
            component,
            arch,
            udeb,
        } => (component.clone(), Some(arch.clone()), *udeb, None),
        PathKind::Translation {
            component,
            language,
        } => (Some(component.clone()), None, false, Some(language.clone())),
        PathKind::I18nIndex { component } => (Some(component.clone()), None, false, None),
        PathKind::Dep11Components { component, arch }
        | PathKind::Dep11CidIndex { component, arch }
        | PathKind::Cnf { component, arch } => {
            (Some(component.clone()), Some(arch.clone()), false, None)
        }
        PathKind::Dep11Icons { component, .. } => (Some(component.clone()), None, false, None),
        PathKind::InstallerImages {
            component, arch, ..
        } => (Some(component.clone()), Some(arch.clone()), false, None),
        PathKind::Unknown => (None, None, false, None),
    }
}

fn wanted_arch_set(apt: &AptOptions, inline_all: bool) -> Vec<String> {
    let mut out: Vec<String> = apt
        .architectures
        .iter()
        .filter(|&a| a != "all")
        .cloned()
        .collect();
    if !inline_all && !out.iter().any(|a| a == "all") {
        out.push("all".to_owned());
    }
    out.sort();
    out.dedup();
    out
}

fn push_variant<'a>(
    groups: &mut Vec<(String, PathKind, Vec<PackagesVariant<'a>>)>,
    base: String,
    kind: PathKind,
    entry: &'a ChecksumEntry,
    compression: Compression,
) {
    for slot in groups.iter_mut() {
        if slot.0 == base && slot.1.key() == kind.key() {
            slot.2.push(PackagesVariant { entry, compression });
            return;
        }
    }
    groups.push((base, kind, vec![PackagesVariant { entry, compression }]));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::AptOptions;
    use crate::core::types::DigestAlgo;

    fn h(n: usize) -> String {
        "a".repeat(n)
    }

    fn mk_checksums(paths: &[(&str, u64)]) -> ReleaseChecksums {
        let mut c = ReleaseChecksums::default();
        for (p, size) in paths {
            c.upsert(DigestAlgo::Sha256, &h(64), *size, p).unwrap();
        }
        c
    }

    fn apt_opts(components: &[&str], architectures: &[&str]) -> AptOptions {
        AptOptions::test_new(
            vec!["bookworm".to_owned()],
            components.iter().copied().map(str::to_owned).collect(),
            architectures.iter().copied().map(str::to_owned).collect(),
        )
    }

    fn base_paths(sel: &IndexSelection<'_>) -> Vec<String> {
        let mut v: Vec<_> = sel.groups.iter().map(|g| g.base_path.clone()).collect();
        v.sort();
        v
    }

    #[test]
    fn compression_from_suffix() {
        assert_eq!(
            Compression::detect_from_path("a/Packages.xz"),
            Compression::Xz
        );
        assert_eq!(
            Compression::detect_from_path("a/Packages.gz"),
            Compression::Gz
        );
        assert_eq!(
            Compression::detect_from_path("a/Packages.bz2"),
            Compression::Bz2
        );
        assert_eq!(
            Compression::detect_from_path("a/Packages"),
            Compression::None
        );
    }

    #[test]
    fn preference_orders_xz_first() {
        let ranks = [
            Compression::Xz.preference_rank(),
            Compression::Gz.preference_rank(),
            Compression::Bz2.preference_rank(),
            Compression::None.preference_rank(),
        ];
        assert_eq!(ranks, [0, 1, 2, 3]);
    }

    #[test]
    fn selects_all_packages_variants_for_one_component_arch() {
        let checksums = mk_checksums(&[
            ("main/binary-amd64/Packages", 100),
            ("main/binary-amd64/Packages.xz", 40),
            ("main/binary-amd64/Packages.gz", 50),
            ("main/binary-amd64/Packages.bz2", 60),
        ]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        let packages: Vec<_> = sel.packages_groups().collect();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].variants.len(), 4);
        assert_eq!(packages[0].variants[0].compression, Compression::Xz);
    }

    #[test]
    fn selects_legacy_binary_release_when_flag_default() {
        let checksums = mk_checksums(&[
            ("main/binary-amd64/Packages", 100),
            ("main/binary-amd64/Release", 200),
        ]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        assert!(
            sel.groups.iter().any(|g| g.role == IndexRole::LegacyRelease
                && g.base_path == "main/binary-amd64/Release")
        );
    }

    #[test]
    fn no_support_for_architecture_all_skips_all_group() {
        let checksums = mk_checksums(&[
            ("main/binary-amd64/Packages.xz", 40),
            ("main/binary-all/Packages.xz", 20),
        ]);
        let header = ReleaseHeader {
            no_support_for_architecture_all: Some("Packages".into()),
            ..ReleaseHeader::default()
        };
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        let packages: Vec<_> = sel.packages_groups().collect();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].arch.as_deref(), Some("amd64"));
    }

    #[test]
    fn default_includes_all_arch_group_when_upstream_lists_it() {
        let checksums = mk_checksums(&[
            ("main/binary-amd64/Packages.xz", 40),
            ("main/binary-all/Packages.xz", 20),
        ]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        let arches: Vec<&str> = sel
            .packages_groups()
            .map(|g| g.arch.as_deref().unwrap())
            .collect();
        assert!(arches.contains(&"amd64"));
        assert!(arches.contains(&"all"));
    }

    #[test]
    fn installer_images_flagged_on_produces_verbatim_groups() {
        let checksums = mk_checksums(&[
            (
                "main/installer-amd64/20250803+deb13u5/images/SHA256SUMS",
                8000,
            ),
            ("main/installer-amd64/20250803+deb13u5/images/MD5SUMS", 4000),
            (
                "main/installer-amd64/20250803+deb13u5/images/netboot/mini.iso",
                50_000_000,
            ),
            (
                "main/installer-arm64/20250803+deb13u5/images/SHA256SUMS",
                8000,
            ),
        ]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.debian_installer = true;
        let sel = select_indexes(&header, &checksums, &apt);
        let installer: Vec<_> = sel
            .groups
            .iter()
            .filter(|g| g.base_path.contains("/installer-"))
            .collect();
        assert_eq!(
            installer.len(),
            3,
            "amd64 SHA256SUMS + MD5SUMS + mini.iso should land, arm64 filtered out"
        );
        for g in &installer {
            assert_eq!(g.arch.as_deref(), Some("amd64"));
            assert_eq!(g.component.as_deref(), Some("main"));
            assert!(!g.udeb);
        }
    }

    #[test]
    fn installer_sha256sums_gets_installer_sums_parse_role() {
        let checksums = mk_checksums(&[
            (
                "main/installer-amd64/20250803+deb13u5/images/SHA256SUMS",
                8000,
            ),
            ("main/installer-amd64/20250803+deb13u5/images/MD5SUMS", 4000),
            (
                "main/installer-amd64/20250803+deb13u5/images/netboot/mini.iso",
                50_000_000,
            ),
        ]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.debian_installer = true;
        let sel = select_indexes(&header, &checksums, &apt);

        let sums_groups: Vec<_> = sel.installer_sums_groups().collect();
        assert_eq!(
            sums_groups.len(),
            1,
            "exactly one SHA256SUMS group per (comp, arch, ver) combo"
        );
        assert_eq!(
            sums_groups[0].base_path,
            "main/installer-amd64/20250803+deb13u5/images/SHA256SUMS"
        );

        let md5 = sel
            .groups
            .iter()
            .find(|g| g.base_path.ends_with("/MD5SUMS"))
            .expect("MD5SUMS group present");
        assert_eq!(md5.role, IndexRole::Verbatim);

        let iso = sel
            .groups
            .iter()
            .find(|g| g.base_path.ends_with("/netboot/mini.iso"))
            .expect("mini.iso group present");
        assert_eq!(iso.role, IndexRole::Verbatim);
    }

    #[test]
    fn installer_sha256sums_dropped_when_flag_off() {
        let checksums = mk_checksums(&[("main/installer-amd64/20250803/images/SHA256SUMS", 8000)]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        assert!(!apt.indexes.debian_installer);
        let sel = select_indexes(&header, &checksums, &apt);
        assert!(sel.installer_sums_groups().next().is_none());
        assert!(sel.is_empty());
    }

    #[test]
    fn installer_images_flag_off_is_dropped() {
        let checksums = mk_checksums(&[("main/installer-amd64/20250803/images/SHA256SUMS", 8000)]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        assert!(!apt.indexes.debian_installer);
        let sel = select_indexes(&header, &checksums, &apt);
        assert!(
            sel.groups
                .iter()
                .all(|g| !g.base_path.contains("/installer-")),
            "installer entries must be filtered when debian_installer=false"
        );
    }

    #[test]
    fn selects_udeb_packages_when_flag_on() {
        let checksums = mk_checksums(&[("main/debian-installer/binary-amd64/Packages.xz", 30)]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.debian_installer = true;
        let sel = select_indexes(&header, &checksums, &apt);
        let packages: Vec<_> = sel.packages_groups().collect();
        assert_eq!(packages.len(), 1);
        assert!(packages[0].udeb);
    }

    #[test]
    fn skips_udeb_packages_when_flag_off() {
        let checksums = mk_checksums(&[("main/debian-installer/binary-amd64/Packages.xz", 30)]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.debian_installer = false;
        let sel = select_indexes(&header, &checksums, &apt);
        assert!(sel.packages_groups().next().is_none());
    }

    #[test]
    fn contents_component_scoped() {
        let checksums = mk_checksums(&[
            ("main/Contents-amd64", 100),
            ("main/Contents-amd64.gz", 30),
            ("main/Contents-amd64.xz", 25),
        ]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        let contents: Vec<_> = sel
            .groups
            .iter()
            .filter(|g| g.base_path == "main/Contents-amd64")
            .collect();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].variants.len(), 3);
        assert_eq!(contents[0].role, IndexRole::Verbatim);
    }

    #[test]
    fn contents_archive_root_and_udeb_variants() {
        let checksums = mk_checksums(&[
            ("Contents-amd64.gz", 30),
            ("main/Contents-udeb-amd64.gz", 20),
        ]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.debian_installer = true;
        let sel = select_indexes(&header, &checksums, &apt);
        let bp = base_paths(&sel);
        assert!(bp.contains(&"Contents-amd64".to_string()));
        assert!(bp.contains(&"main/Contents-udeb-amd64".to_string()));
    }

    #[test]
    fn contents_gated_by_flag() {
        let checksums = mk_checksums(&[("main/Contents-amd64.gz", 30)]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.contents = false;
        let sel = select_indexes(&header, &checksums, &apt);
        assert!(sel.is_empty());
    }

    #[test]
    fn i18n_translations_by_lang_whitelist() {
        let checksums = mk_checksums(&[
            ("main/i18n/Translation-en.xz", 100),
            ("main/i18n/Translation-zh_cn.xz", 60),
            ("main/i18n/Translation-de.xz", 50),
        ]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        // The config layer lowercases `Only` tags, matching Debian filenames.
        apt.indexes.i18n = I18nSelection::Only(vec!["en".into(), "zh_cn".into()]);
        let sel = select_indexes(&header, &checksums, &apt);
        let langs: Vec<Option<&str>> = sel
            .groups
            .iter()
            .filter(|g| g.base_path.contains("Translation-"))
            .map(|g| g.language.as_deref())
            .collect();
        assert!(langs.contains(&Some("en")));
        assert!(langs.contains(&Some("zh_cn")));
        assert!(!langs.contains(&Some("de")));
    }

    /// The selector relies on the config layer to lowercase `Only` tags.
    #[test]
    fn i18n_only_selector_is_case_sensitive_after_normalization() {
        let checksums = mk_checksums(&[("main/i18n/Translation-zh_cn.xz", 60)]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.i18n = I18nSelection::Only(vec!["zh_CN".into()]);
        let sel = select_indexes(&header, &checksums, &apt);
        let translations = sel
            .groups
            .iter()
            .filter(|g| g.base_path.contains("Translation-"))
            .count();
        assert_eq!(translations, 0);
    }

    #[test]
    fn i18n_all_matches_every_translation() {
        let checksums = mk_checksums(&[
            ("main/i18n/Translation-en.xz", 100),
            ("main/i18n/Translation-fr.xz", 90),
        ]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.i18n = I18nSelection::All;
        let sel = select_indexes(&header, &checksums, &apt);
        let translations = sel
            .groups
            .iter()
            .filter(|g| g.base_path.contains("Translation-"))
            .count();
        assert_eq!(translations, 2);
    }

    #[test]
    fn i18n_index_picked_up_when_lang_selection_nonempty() {
        let checksums = mk_checksums(&[("main/i18n/Index", 100)]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        let idx = sel.groups.iter().find(|g| g.base_path == "main/i18n/Index");
        assert!(idx.is_some());
    }

    #[test]
    fn i18n_index_dropped_when_i18n_none() {
        let checksums = mk_checksums(&[("main/i18n/Index", 100)]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.i18n = I18nSelection::None;
        let sel = select_indexes(&header, &checksums, &apt);
        assert!(sel.is_empty());
    }

    #[test]
    fn dep11_components_arch_scoped() {
        let checksums = mk_checksums(&[
            ("main/dep11/Components-amd64.yml", 200),
            ("main/dep11/Components-amd64.yml.xz", 60),
            ("main/dep11/Components-amd64.yml.gz", 80),
            ("main/dep11/Components-i386.yml.xz", 60),
        ]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        let dep11: Vec<_> = sel
            .groups
            .iter()
            .filter(|g| g.base_path.starts_with("main/dep11/Components-"))
            .collect();
        assert_eq!(dep11.len(), 1);
        assert_eq!(dep11[0].variants.len(), 3);
    }

    #[test]
    fn dep11_icons_and_cid_index() {
        let checksums = mk_checksums(&[
            ("main/dep11/icons-48x48.tar", 500),
            ("main/dep11/icons-48x48.tar.gz", 400),
            ("main/dep11/icons-64x64@2.tar.gz", 500),
            ("main/dep11/CID-Index-amd64.json.gz", 100),
        ]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        let bp = base_paths(&sel);
        assert!(bp.contains(&"main/dep11/icons-48x48.tar".to_string()));
        assert!(bp.contains(&"main/dep11/icons-64x64@2.tar".to_string()));
        assert!(bp.contains(&"main/dep11/CID-Index-amd64.json".to_string()));
    }

    #[test]
    fn dep11_gated_by_flag() {
        let checksums = mk_checksums(&[("main/dep11/Components-amd64.yml.xz", 30)]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.dep11 = false;
        let sel = select_indexes(&header, &checksums, &apt);
        assert!(sel.is_empty());
    }

    #[test]
    fn cnf_commands_arch_scoped() {
        let checksums = mk_checksums(&[
            ("main/cnf/Commands-amd64.xz", 20),
            ("main/cnf/Commands-i386.xz", 20),
        ]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        let cnf: Vec<_> = sel
            .groups
            .iter()
            .filter(|g| g.base_path.starts_with("main/cnf/"))
            .collect();
        assert_eq!(cnf.len(), 1);
        assert_eq!(cnf[0].base_path, "main/cnf/Commands-amd64");
    }

    #[test]
    fn sources_group_when_flag_on() {
        let checksums = mk_checksums(&[
            ("main/source/Sources", 100),
            ("main/source/Sources.xz", 40),
            ("main/source/Release", 50),
        ]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.sources = true;
        let sel = select_indexes(&header, &checksums, &apt);
        let sources: Vec<_> = sel.sources_groups().collect();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].variants.len(), 2);
        assert!(
            sel.groups
                .iter()
                .any(|g| g.base_path == "main/source/Release"
                    && g.role == IndexRole::LegacyRelease)
        );
    }

    #[test]
    fn sources_skipped_when_flag_off() {
        let checksums = mk_checksums(&[("main/source/Sources.xz", 40)]);
        let header = ReleaseHeader::default();
        let mut apt = apt_opts(&["main"], &["amd64"]);
        apt.indexes.sources = false;
        let sel = select_indexes(&header, &checksums, &apt);
        assert!(sel.sources_groups().next().is_none());
    }

    #[test]
    fn unknown_path_shape_ignored() {
        let checksums = mk_checksums(&[("main/random-junk", 50), ("nested/deep/thing.xz", 40)]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        assert!(sel.is_empty());
    }

    #[test]
    fn all_entries_iterates_everything_selected() {
        let checksums = mk_checksums(&[
            ("main/binary-amd64/Packages.xz", 40),
            ("main/binary-amd64/Packages.gz", 50),
            ("main/binary-amd64/Release", 300),
            ("main/Contents-amd64.gz", 30),
        ]);
        let header = ReleaseHeader::default();
        let apt = apt_opts(&["main"], &["amd64"]);
        let sel = select_indexes(&header, &checksums, &apt);
        let entries: Vec<&str> = sel.all_entries().map(|e| e.path.as_str()).collect();
        assert!(entries.len() >= 4);
    }
}
