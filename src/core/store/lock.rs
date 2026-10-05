//! Per-mirror exclusive `flock(2)` on `.tain/lock`.
//!
//! The kernel releases it when the process dies, so there are no stale lock
//! files. With the default `lock_timeout = 0`, an overlapping run exits 3
//! immediately instead of racing.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{STATE_DIR, ensure_state_dir};

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("I/O opening `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("another `tain` instance holds the lock on `{path}`; waited {waited:?}")]
    Contended { path: PathBuf, waited: Duration },
}

/// A held mirror lock; dropping it closes the fd and releases the `flock`.
#[derive(Debug)]
pub struct MirrorLock {
    path: PathBuf,
    _file: File,
}

impl MirrorLock {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Acquire `<mirror_root>/.tain/lock`, polling every 100 ms up to `timeout`
/// (zero: fail immediately).
///
/// # Errors
///
/// `Contended` (exit 3) if still held after `timeout`; `Io` on open or
/// unexpected `flock` errors.
#[cfg(unix)]
pub fn acquire(mirror_root: &Path, timeout: Duration) -> Result<MirrorLock, LockError> {
    ensure_state_dir(mirror_root).map_err(|e| LockError::Io {
        path: mirror_root.join(STATE_DIR),
        source: e,
    })?;
    let path = mirror_root.join(STATE_DIR).join("lock");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| LockError::Io {
            path: path.clone(),
            source: e,
        })?;

    let deadline = Instant::now().checked_add(timeout);
    let fd = file.as_raw_fd();

    loop {
        // Non-blocking so `timeout` can cap the wait.
        // SAFETY: `fd` is owned by `file`, which outlives the call.
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(MirrorLock { path, _file: file });
        }
        let err = std::io::Error::last_os_error();
        let raw = err.raw_os_error();
        let is_contended = raw == Some(libc::EWOULDBLOCK) || raw == Some(libc::EAGAIN);
        if !is_contended {
            return Err(LockError::Io { path, source: err });
        }
        if timeout == Duration::ZERO {
            return Err(LockError::Contended {
                path,
                waited: Duration::ZERO,
            });
        }
        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            return Err(LockError::Contended {
                path,
                waited: timeout,
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_root(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("tain-lock-{name}-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn acquire_creates_state_dir_and_lock_file() {
        let root = temp_root("create");
        let g = acquire(&root, Duration::ZERO).unwrap();
        assert!(root.join(STATE_DIR).exists());
        assert!(g.path().exists());
        drop(g);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn second_zero_timeout_acquire_fails_immediately() {
        let root = temp_root("contend0");
        let g = acquire(&root, Duration::ZERO).unwrap();
        let err = acquire(&root, Duration::ZERO).unwrap_err();
        assert!(matches!(err, LockError::Contended { .. }));
        drop(g);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn second_finite_timeout_acquires_after_first_releases() {
        use std::sync::mpsc;
        let root = temp_root("contend-wait");
        let root_c = root.clone();
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            let g = acquire(&root_c, Duration::ZERO).unwrap();
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(g);
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            acquire(&root, Duration::ZERO).unwrap_err(),
            LockError::Contended { .. }
        ));
        release_tx.send(()).unwrap();
        h.join().unwrap();
        let g = acquire(&root, Duration::from_secs(2)).unwrap();
        drop(g);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn finite_timeout_expires_when_lock_stays_held() {
        use std::sync::mpsc;
        let root = temp_root("expire");
        let root_c = root.clone();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            let g = acquire(&root_c, Duration::ZERO).unwrap();
            release_rx.recv().unwrap();
            drop(g);
        });
        std::thread::sleep(Duration::from_millis(50));
        let start = Instant::now();
        let err = acquire(&root, Duration::from_millis(300)).unwrap_err();
        let elapsed = start.elapsed();
        assert!(matches!(err, LockError::Contended { .. }));
        assert!(elapsed >= Duration::from_millis(250), "waited {elapsed:?}");
        release_tx.send(()).unwrap();
        h.join().unwrap();
        std::fs::remove_dir_all(&root).ok();
    }
}
