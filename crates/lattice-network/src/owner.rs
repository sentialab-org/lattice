use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

/// Kernel-held ownership survives stale PID files and is released on process death.
pub struct HostLock {
    _file: File,
}
impl HostLock {
    pub fn acquire(path: &Path) -> Result<Self, String> {
        let parent = path.parent().ok_or("network owner directory required")?;
        std::fs::create_dir_all(parent).map_err(|_| "network owner directory unavailable")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta =
                std::fs::metadata(parent).map_err(|_| "network owner directory unavailable")?;
            if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
                return Err("network owner directory ownership rejected".into());
            }
        }
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err("network owner path is not a regular file".into());
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let mut file = options
            .open(path)
            .map_err(|_| "another network owner is active or the lock is inaccessible")?;
        let meta = file
            .metadata()
            .map_err(|_| "network owner metadata unavailable")?;
        if !meta.is_file() || meta.len() > 96 {
            return Err("network owner marker rejected".into());
        }
        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
            if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
                return Err("network owner lock requires private ownership".into());
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err("another Base Node already owns host networking".into());
            }
        }
        #[cfg(not(any(unix, windows)))]
        return Err("host network ownership is unsupported on this platform".into());
        let mut previous = String::new();
        file.read_to_string(&mut previous)
            .map_err(|_| "network owner marker unreadable")?;
        if !previous.is_empty()
            && !previous
                .strip_prefix("lattice-network-owner-v1:")
                .is_some_and(|pid| {
                    !pid.trim().is_empty() && pid.trim().bytes().all(|b| b.is_ascii_digit())
                })
        {
            return Err("unrecognized network owner marker; preserve and inspect it".into());
        }
        file.set_len(0)
            .map_err(|_| "network owner marker unavailable")?;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))
            .map_err(|_| "network owner marker unavailable")?;
        writeln!(file, "lattice-network-owner-v1:{}", std::process::id())
            .map_err(|_| "network owner marker unavailable")?;
        file.sync_all()
            .map_err(|_| "network owner marker unavailable")?;
        Ok(Self { _file: file })
    }
}
