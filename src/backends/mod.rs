//! Backend registry: an explicit `match` on `BackendKind`, no plugin loading.

pub mod apt;

use crate::config::model::{BackendKind, MirrorConfig};
use crate::core::backend::{Backend, BackendError};

/// Instantiate the backend for a resolved mirror config.
///
/// # Errors
///
/// Returns `BackendError::Config` when the backend's `validate_config` rejects the mirror.
pub fn dispatch(mirror: &MirrorConfig) -> Result<Box<dyn Backend>, BackendError> {
    let backend: Box<dyn Backend> = match mirror.backend {
        BackendKind::Apt => Box::new(apt::AptBackend::new()),
    };
    backend.validate_config(mirror)?;
    Ok(backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{
        AptOptions, BackendKind, BackendOptions, GcConfig, MirrorConfig, VerifyConfig,
    };
    use crate::core::backend::SyncStrategy;
    use std::path::PathBuf;
    use url::Url;

    fn apt_mirror() -> MirrorConfig {
        MirrorConfig {
            name: "debian".to_owned(),
            backend: BackendKind::Apt,
            url: Url::parse("https://deb.debian.org/debian").unwrap(),
            path: PathBuf::from("debian"),
            verify: VerifyConfig::default(),
            gc: GcConfig::default(),
            force_http1: false,
            backend_options: BackendOptions::Apt(AptOptions::test_new(
                vec!["bookworm".to_owned()],
                vec!["main".to_owned()],
                vec!["amd64".to_owned()],
            )),
        }
    }

    #[test]
    fn dispatch_returns_apt_backend() {
        let mirror = apt_mirror();
        let b = dispatch(&mirror).unwrap();
        assert_eq!(b.name(), "apt");
        assert!(matches!(b.strategy(), SyncStrategy::Manifest(_)));
    }
}
