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
        self.limits = limits.clone();

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
            let cpu_max = format!("{} 100000", (limits.cpu_percent as u64) * 1000);
            let mem_max = format!("{}", limits.memory_mb * 1024 * 1024);
            std::fs::write(cgroup.join("cpu.max"), cpu_max)
                .map_err(|e| format!("failed to write cgroup cpu.max: {e}"))?;
            std::fs::write(cgroup.join("memory.max"), mem_max)
                .map_err(|e| format!("failed to write cgroup memory.max: {e}"))?;
        }

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
            // Attempt cgroups v2 containment if cgroup hierarchy is writable
            let root_cgroup = std::path::PathBuf::from("/sys/fs/cgroup");
            if root_cgroup.exists() {
                let lattice_cgroup = root_cgroup.join("lattice");
                let _ = std::fs::create_dir_all(&lattice_cgroup);
                if lattice_cgroup.exists() {
                    let lease_cgroup = lattice_cgroup.join(format!("worker-{}", child_pid));
                    if std::fs::create_dir_all(&lease_cgroup).is_ok() {
                        let _ = std::fs::write(
                            lease_cgroup.join("cgroup.procs"),
                            child_pid.to_string(),
                        );
                        let cpu_max = format!("{} 100000", (self.limits.cpu_percent as u64) * 1000);
                        let mem_max = format!("{}", self.limits.memory_mb * 1024 * 1024);
                        let _ = std::fs::write(lease_cgroup.join("cpu.max"), cpu_max);
                        let _ = std::fs::write(lease_cgroup.join("memory.max"), mem_max);
                        self.cgroup_path = Some(lease_cgroup);
                    }
                }
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
