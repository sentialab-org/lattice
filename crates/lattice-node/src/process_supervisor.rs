use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

pub struct ProcessSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub current_dir: PathBuf,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
}

pub struct ManagedProcess {
    child: Child,
    stdout_task: Option<JoinHandle<()>>,
    stderr_task: Option<JoinHandle<()>>,
}

impl ManagedProcess {
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, String> {
        self.child.try_wait().map_err(|error| error.to_string())
    }

    pub async fn finish(mut self) -> Result<ExitStatus, String> {
        let status = self.child.wait().await.map_err(|error| error.to_string())?;
        self.finish_logs().await;
        Ok(status)
    }

    pub async fn stop(mut self, grace: Duration) -> Result<ExitStatus, String> {
        if let Some(pid) = self.id() {
            let _ = signal_graceful(pid);
        }

        let deadline = tokio::time::Instant::now() + grace;
        loop {
            if let Some(status) = self.try_wait()? {
                self.finish_logs().await;
                return Ok(status);
            }

            if tokio::time::Instant::now() >= deadline {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        self.child.kill().await.map_err(|error| error.to_string())?;
        let status = self.child.wait().await.map_err(|error| error.to_string())?;
        self.finish_logs().await;
        Ok(status)
    }

    async fn finish_logs(&mut self) {
        if let Some(task) = self.stdout_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.stderr_task.take() {
            let _ = task.await;
        }
    }
}

pub async fn spawn(spec: &ProcessSpec) -> Result<ManagedProcess, String> {
    if !spec.executable.is_absolute() {
        return Err("managed executable path must be absolute".to_string());
    }
    if !spec.current_dir.is_absolute() {
        return Err("managed working directory must be absolute".to_string());
    }

    tokio::fs::create_dir_all(&spec.current_dir)
        .await
        .map_err(|error| error.to_string())?;

    let mut command = Command::new(&spec.executable);
    command
        .args(&spec.args)
        .current_dir(&spec.current_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear();

    copy_allowed_environment(&mut command);

    #[cfg(windows)]
    command.creation_flags(0x0000_0200);

    #[cfg(unix)]
    command.process_group(0);

    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let stdout_task = child
        .stdout
        .take()
        .map(|stdout| capture(stdout, spec.stdout_path.clone()));
    let stderr_task = child
        .stderr
        .take()
        .map(|stderr| capture(stderr, spec.stderr_path.clone()));

    Ok(ManagedProcess {
        child,
        stdout_task,
        stderr_task,
    })
}

fn capture<R>(mut reader: R, path: PathBuf) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await;
        let Ok(mut file) = file else {
            return;
        };
        let _ = tokio::io::copy(&mut reader, &mut file).await;
    })
}

fn copy_allowed_environment(command: &mut Command) {
    const KEYS: [&str; 10] = [
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
    ];

    for key in KEYS {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

#[cfg(windows)]
fn signal_graceful(pid: u32) -> Result<(), String> {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};

    let result = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) };
    if result == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn signal_graceful(pid: u32) -> Result<(), String> {
    let result = unsafe { libc::kill(-(pid as i32), libc::SIGTERM) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn signal_graceful(_pid: u32) -> Result<(), String> {
    Err("graceful process signaling is unsupported on this platform".to_string())
}

pub fn managed_path(root: &Path, name: &str) -> Result<PathBuf, String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err("invalid managed path component".to_string());
    }
    Ok(root.join(name))
}
