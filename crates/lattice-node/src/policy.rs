use lattice_protocol::{NodePolicy, PolicySnapshot, ResourceLimits};
use std::path::{Path, PathBuf};

pub fn remote_policy_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("remote-policy.json")
}

pub async fn load(path: &Path) -> Result<Option<PolicySnapshot>, String> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };

    serde_json::from_str(&content)
        .map(Some)
        .map_err(|error| error.to_string())
}

pub async fn save(path: &Path, policy: &PolicySnapshot) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| error.to_string())?;
    }

    let content = serde_json::to_vec_pretty(policy).map_err(|error| error.to_string())?;
    tokio::fs::write(path, content)
        .await
        .map_err(|error| error.to_string())
}

pub async fn clear(path: &Path) -> Result<(), String> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

pub fn effective(local: &NodePolicy, remote: Option<&PolicySnapshot>) -> NodePolicy {
    let Some(remote) = remote else {
        return local.clone();
    };
    let constraints = &remote.constraints;

    NodePolicy {
        enabled: local.enabled && constraints.enabled,
        allow_ai: local.allow_ai && constraints.allow_ai,
        allow_rendering: local.allow_rendering && constraints.allow_rendering,
        allow_media: local.allow_media && constraints.allow_media,
        allow_mining: local.allow_mining && constraints.allow_mining,
        allow_research: local.allow_research && constraints.allow_research,
        allow_generic: local.allow_generic && constraints.allow_generic,
        limits: ResourceLimits {
            cpu_percent: local.limits.cpu_percent.min(constraints.max_cpu_percent),
            memory_mb: constraints
                .max_memory_mb
                .map_or(local.limits.memory_mb, |limit| {
                    local.limits.memory_mb.min(limit)
                }),
            gpu_percent: intersect_optional_limit(
                local.limits.gpu_percent,
                constraints.max_gpu_percent,
            ),
            gpu_memory_mb: intersect_optional_limit(
                local.limits.gpu_memory_mb,
                constraints.max_gpu_memory_mb,
            ),
        },
    }
}

fn intersect_optional_limit<T: Ord + Copy>(local: Option<T>, remote: Option<T>) -> Option<T> {
    match (local, remote) {
        (Some(local), Some(remote)) => Some(local.min(remote)),
        (Some(local), None) => Some(local),
        (None, _) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_protocol::{PolicyConstraints, PolicySnapshot};

    #[test]
    fn remote_policy_cannot_expand_local_permissions() {
        let local = NodePolicy {
            enabled: true,
            allow_ai: true,
            allow_rendering: false,
            allow_media: true,
            allow_mining: false,
            allow_research: true,
            allow_generic: false,
            limits: ResourceLimits {
                cpu_percent: 50,
                memory_mb: 4096,
                gpu_percent: Some(60),
                gpu_memory_mb: Some(8192),
            },
        };
        let remote = PolicySnapshot {
            revision: 2,
            constraints: PolicyConstraints::default(),
        };

        let result = effective(&local, Some(&remote));

        assert_eq!(result, local);
    }

    #[test]
    fn remote_policy_can_only_restrict_local_policy() {
        let local = NodePolicy {
            enabled: true,
            allow_ai: true,
            allow_rendering: true,
            allow_media: true,
            allow_mining: true,
            allow_research: true,
            allow_generic: true,
            limits: ResourceLimits {
                cpu_percent: 80,
                memory_mb: 16384,
                gpu_percent: Some(90),
                gpu_memory_mb: Some(12288),
            },
        };
        let remote = PolicySnapshot {
            revision: 3,
            constraints: PolicyConstraints {
                enabled: true,
                allow_ai: true,
                allow_rendering: false,
                allow_media: true,
                allow_mining: false,
                allow_research: true,
                allow_generic: false,
                max_cpu_percent: 45,
                max_memory_mb: Some(8192),
                max_gpu_percent: Some(55),
                max_gpu_memory_mb: Some(6144),
            },
        };

        let result = effective(&local, Some(&remote));

        assert_eq!(result.limits.cpu_percent, 45);
        assert_eq!(result.limits.memory_mb, 8192);
        assert_eq!(result.limits.gpu_percent, Some(55));
        assert_eq!(result.limits.gpu_memory_mb, Some(6144));
        assert!(!result.allow_rendering);
        assert!(!result.allow_mining);
        assert!(!result.allow_generic);
    }
}
