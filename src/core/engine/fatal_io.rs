//! Classification of fatal local I/O errors.

use super::EngineError;

/// True for fatal local I/O (disk full, quota, unwritable target), which
/// maps to exit 4 rather than a partial-failure exit 1.
#[must_use]
pub fn is_fatal_io(err: &EngineError) -> bool {
    walk_for_fatal_io(err)
}

pub(super) fn walk_for_fatal_io(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = source {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && is_fatal_io_kind(io)
        {
            return true;
        }
        source = e.source();
    }
    false
}

fn is_fatal_io_kind(io: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(
        io.kind(),
        ErrorKind::StorageFull
            | ErrorKind::QuotaExceeded
            | ErrorKind::ReadOnlyFilesystem
            | ErrorKind::PermissionDenied
    ) {
        return true;
    }
    // Raw errno fallback where ErrorKind stays generic: EACCES 13, ENOSPC 28,
    // EROFS 30, EDQUOT 69 (BSD) / 122 (Linux).
    if let Some(raw) = io.raw_os_error() {
        return matches!(raw, 13 | 28 | 30 | 69 | 122);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn wrap_io(kind: std::io::ErrorKind) -> EngineError {
        EngineError::Io {
            path: PathBuf::from("/tmp/x"),
            source: std::io::Error::new(kind, "synthetic"),
        }
    }

    fn wrap_raw(errno: i32) -> EngineError {
        EngineError::Io {
            path: PathBuf::from("/tmp/x"),
            source: std::io::Error::from_raw_os_error(errno),
        }
    }

    #[test]
    fn classifies_storage_full_as_fatal() {
        assert!(is_fatal_io(&wrap_io(std::io::ErrorKind::StorageFull)));
    }

    #[test]
    fn classifies_permission_denied_as_fatal() {
        assert!(is_fatal_io(&wrap_io(std::io::ErrorKind::PermissionDenied)));
    }

    #[test]
    fn classifies_read_only_fs_as_fatal() {
        assert!(is_fatal_io(&wrap_io(
            std::io::ErrorKind::ReadOnlyFilesystem
        )));
    }

    #[test]
    fn classifies_enospc_by_errno() {
        assert!(is_fatal_io(&wrap_raw(28))); // ENOSPC
    }

    #[test]
    fn classifies_eacces_by_errno() {
        assert!(is_fatal_io(&wrap_raw(13))); // EACCES
    }

    #[test]
    fn does_not_classify_generic_not_found() {
        assert!(!is_fatal_io(&wrap_io(std::io::ErrorKind::NotFound)));
    }

    #[test]
    fn does_not_classify_generic_broken_pipe() {
        assert!(!is_fatal_io(&wrap_io(std::io::ErrorKind::BrokenPipe)));
    }
}
