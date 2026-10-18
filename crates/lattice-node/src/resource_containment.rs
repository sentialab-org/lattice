use lattice_protocol::ResourceLimits;
#[cfg(unix)]
use std::time::Duration;

#[cfg(windows)]
#[derive(Debug)]
pub struct OwnedJobHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
unsafe impl Send for OwnedJobHandle {}
#[cfg(windows)]
unsafe impl Sync for OwnedJobHandle {}

#[cfg(windows)]
impl OwnedJobHandle {
    pub fn new(handle: windows_sys::Win32::Foundation::HANDLE) -> Self {
        Self(handle)
    }

    pub fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for OwnedJobHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != -1isize as windows_sys::Win32::Foundation::HANDLE {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

pub struct OsResourceBoundary {
    limits: ResourceLimits,
    #[cfg(unix)]
    pgid: Option<i32>,
    #[cfg(windows)]
    job_handle: Option<OwnedJobHandle>,
    #[cfg(target_os = "linux")]
    cgroup_path: Option<std::path::PathBuf>,
}

impl OsResourceBoundary {
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            #[cfg(unix)]
            pgid: None,
            #[cfg(windows)]
            job_handle: None,
            #[cfg(target_os = "linux")]
            cgroup_path: None,
        }
    }

    /// Updates authoritative OS resource limits (CRIT-10).
    pub fn update_limits(&mut self, limits: ResourceLimits) -> Result<(), String> {
        #[cfg(windows)]
        if let Some(job) = &self.job_handle {
            unsafe {
                use windows_sys::Win32::System::JobObjects::*;

                // Apply CPU rate control: CpuRate in basis points (100 = 1%, 10_000 = 100%)
                let mut cpu_info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = std::mem::zeroed();
                cpu_info.ControlFlags =
                    JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
                cpu_info.Anonymous.CpuRate = (limits.cpu_percent as u32).min(100) * 100;

                let set_cpu_res = SetInformationJobObject(
                    job.raw(),
                    JobObjectCpuRateControlInformation,
                    &cpu_info as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                );
                if set_cpu_res == 0 {
                    return Err(format!(
                        "failed to update JobObject CPU rate limit: {}",
                        std::io::Error::last_os_error()
                    ));
                }

                // Apply Job memory limit
                let mut ext_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                ext_info.BasicLimitInformation.LimitFlags =
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY;
                ext_info.JobMemoryLimit = (limits.memory_mb as usize) * 1024 * 1024;

                let set_mem_res = SetInformationJobObject(
                    job.raw(),
                    JobObjectExtendedLimitInformation,
                    &ext_info as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if set_mem_res == 0 {
                    return Err(format!(
                        "failed to update JobObject memory limit: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
        }

        #[cfg(target_os = "linux")]
        if let Some(cgroup) = &self.cgroup_path {
            apply_cgroup_limits(cgroup, &limits)?;
        }
        self.limits = limits;

        Ok(())
    }

    /// Prepares process spawning parameters so child and its descendants are isolated.
    pub fn prepare_command(&self, cmd: &mut tokio::process::Command) {
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }

        #[cfg(windows)]
        {
            let _ = cmd;
        }
    }

    /// Binds a newly spawned child process to the OS containment boundary.
    pub fn attach_process(&mut self, child_pid: u32) -> Result<(), String> {
        #[cfg(unix)]
        {
            self.pgid = Some(child_pid as i32);
        }

        #[cfg(target_os = "linux")]
        {
            // Linux execution requires actual cgroup v2 enforcement, never best-effort files.
            let root = std::path::Path::new("/sys/fs/cgroup");
            enable_cgroup_controllers(root)?;
            let lattice = root.join("lattice");
            match std::fs::create_dir(&lattice) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err("cgroup hierarchy unavailable".into()),
            }
            if std::fs::symlink_metadata(&lattice)
                .map_err(|_| "cgroup hierarchy unavailable")?
                .file_type()
                .is_symlink()
            {
                return Err("cgroup hierarchy cannot be a symlink".into());
            }
            enable_cgroup_controllers(&lattice)?;
            let worker = lattice.join(format!(
                "worker-{child_pid}-{}",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir(&worker).map_err(|_| "worker cgroup unavailable")?;
            self.cgroup_path = Some(worker.clone());
            apply_cgroup_limits(&worker, &self.limits)?;
            write_existing_cgroup_file(&worker.join("cgroup.procs"), &child_pid.to_string())?;
            let members = std::fs::read_to_string(worker.join("cgroup.procs"))
                .map_err(|_| "worker containment verification failed")?;
            if !members
                .lines()
                .any(|line| line.trim() == child_pid.to_string())
            {
                return Err("worker did not enter its enforced cgroup".into());
            }
        }

        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
            use windows_sys::Win32::System::JobObjects::*;
            use windows_sys::Win32::System::Threading::*;

            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job == 0 as HANDLE {
                return Err(format!(
                    "CreateJobObjectW failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // Configure kill on close + memory limit
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY;
            info.JobMemoryLimit = (self.limits.memory_mb as usize) * 1024 * 1024;

            let set_info_res = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if set_info_res == 0 {
                CloseHandle(job);
                return Err(format!(
                    "SetInformationJobObject (memory) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // Configure CPU rate limit (CRIT-10)
            let mut cpu_info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = std::mem::zeroed();
            cpu_info.ControlFlags =
                JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
            cpu_info.Anonymous.CpuRate = (self.limits.cpu_percent as u32).min(100) * 100;

            let set_cpu_res = SetInformationJobObject(
                job,
                JobObjectCpuRateControlInformation,
                &cpu_info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            );
            if set_cpu_res == 0 {
                CloseHandle(job);
                return Err(format!(
                    "SetInformationJobObject (CPU) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let proc_handle = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, child_pid);
            if proc_handle == 0 as HANDLE {
                CloseHandle(job);
                return Err(format!(
                    "OpenProcess failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let assign_res = AssignProcessToJobObject(job, proc_handle);
            CloseHandle(proc_handle);

            if assign_res == 0 {
                CloseHandle(job);
                return Err(format!(
                    "AssignProcessToJobObject failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            self.job_handle = Some(OwnedJobHandle::new(job));
        }

        Ok(())
    }

    /// Terminates the entire process tree enclosed in this boundary.
    pub async fn terminate(&mut self) -> Result<(), String> {
        let mut clean = true;

        #[cfg(unix)]
        if let Some(pgid) = self.pgid.take()
            && pgid > 1
        {
            unsafe {
                libc::kill(-pgid, libc::SIGTERM);
            }

            tokio::time::sleep(Duration::from_millis(300)).await;

            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }

            tokio::time::sleep(Duration::from_millis(100)).await;

            // Confirm process tree has been reaped/terminated (HIGH-18)
            let still_alive = unsafe { libc::kill(-pgid, 0) == 0 };
            if still_alive {
                clean = false;
            }
        }

        #[cfg(target_os = "linux")]
        if let Some(cgroup) = self.cgroup_path.take() {
            let kill_file = cgroup.join("cgroup.kill");
            if kill_file.exists() {
                let _ = std::fs::write(&kill_file, "1");
            }
            let _ = std::fs::remove_dir(cgroup);
        }

        #[cfg(windows)]
        if let Some(job) = self.job_handle.take() {
            unsafe {
                use windows_sys::Win32::System::JobObjects::TerminateJobObject;

                let res = TerminateJobObject(job.raw(), 1);
                if res == 0 {
                    clean = false;
                }
            }
            // OwnedJobHandle will close the handle on drop
        }

        if clean {
            Ok(())
        } else {
            Err("failed to cleanly terminate process tree".to_string())
        }
    }
}

impl Drop for OsResourceBoundary {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            let _ = self.job_handle.take();
        }

        #[cfg(target_os = "linux")]
        if let Some(cgroup) = self.cgroup_path.take() {
            let _ = std::fs::remove_dir(cgroup);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn write_existing_cgroup_file(path: &std::path::Path, value: &str) -> Result<(), String> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|_| "required kernel cgroup control unavailable")?;
    file.write_all(value.as_bytes())
        .map_err(|_| "kernel cgroup control rejected".to_string())
}

#[cfg(any(target_os = "linux", test))]
fn apply_cgroup_limits(path: &std::path::Path, limits: &ResourceLimits) -> Result<(), String> {
    let cpu = path.join("cpu.max");
    let memory = path.join("memory.max");
    for file in [&cpu, &memory] {
        if !std::fs::symlink_metadata(file)
            .map_err(|_| "required kernel quota unavailable")?
            .is_file()
        {
            return Err("required kernel quota is invalid".into());
        }
    }
    if limits.cpu_percent == 0 || limits.cpu_percent > 100 || limits.memory_mb == 0 {
        return Err("nonzero bounded CPU and memory quotas required".into());
    }
    let cpu_max = format!("{} 100000", u64::from(limits.cpu_percent) * 1000);
    let memory_max = limits
        .memory_mb
        .checked_mul(1024 * 1024)
        .ok_or("memory quota overflow")?
        .to_string();
    write_existing_cgroup_file(&cpu, &cpu_max)?;
    write_existing_cgroup_file(&memory, &memory_max)?;
    let actual_cpu =
        std::fs::read_to_string(cpu).map_err(|_| "CPU quota verification unavailable")?;
    let actual_memory =
        std::fs::read_to_string(memory).map_err(|_| "memory quota verification unavailable")?;
    if actual_cpu.split_whitespace().collect::<Vec<_>>()
        != cpu_max.split_whitespace().collect::<Vec<_>>()
        || actual_memory.trim() != memory_max
    {
        return Err("kernel quotas do not match the requested configuration".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn enable_cgroup_controllers(path: &std::path::Path) -> Result<(), String> {
    let available = std::fs::read_to_string(path.join("cgroup.controllers"))
        .map_err(|_| "cgroup v2 CPU and memory controllers required")?;
    if !["cpu", "memory"].iter().all(|controller| {
        available
            .split_whitespace()
            .any(|value| value == *controller)
    }) {
        return Err("cgroup v2 CPU and memory controllers unavailable".into());
    }
    let enabled = std::fs::read_to_string(path.join("cgroup.subtree_control"))
        .map_err(|_| "cgroup controller state unavailable")?;
    if !["cpu", "memory"]
        .iter()
        .all(|controller| enabled.split_whitespace().any(|value| value == *controller))
    {
        write_existing_cgroup_file(&path.join("cgroup.subtree_control"), "+cpu +memory")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_kernel_quota_files_cannot_be_mistaken_for_enforced_limits() {
        let root = tempfile::tempdir().unwrap();
        assert!(apply_cgroup_limits(root.path(), &ResourceLimits::default()).is_err());
        assert!(!root.path().join("cpu.max").exists());
        assert!(!root.path().join("memory.max").exists());
    }
    #[test]
    fn quota_readback_matches_requested_cpu_and_memory() {
        let root = tempfile::tempdir().unwrap();
        for file in ["cpu.max", "memory.max"] {
            std::fs::write(root.path().join(file), "max").unwrap();
        }
        let limits = ResourceLimits {
            cpu_percent: 17,
            memory_mb: 128,
            gpu_percent: None,
            gpu_memory_mb: None,
        };
        apply_cgroup_limits(root.path(), &limits).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("cpu.max")).unwrap(),
            "17000 100000"
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("memory.max")).unwrap(),
            "134217728"
        );
    }
}
