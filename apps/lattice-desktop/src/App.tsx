import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type ResourceLimits = {
  cpu_percent: number;
  memory_mb: number;
  gpu_percent: number | null;
  gpu_memory_mb: number | null;
};

type NodePolicy = {
  enabled: boolean;
  allow_ai: boolean;
  allow_rendering: boolean;
  allow_media: boolean;
  allow_mining: boolean;
  allow_research: boolean;
  allow_generic: boolean;
  limits: ResourceLimits;
};

type NodeConfig = {
  control_url: string | null;
  policy: NodePolicy;
};

type PolicyConstraints = {
  enabled: boolean;
  allow_ai: boolean;
  allow_rendering: boolean;
  allow_media: boolean;
  allow_mining: boolean;
  allow_research: boolean;
  allow_generic: boolean;
  max_cpu_percent: number;
  max_memory_mb: number | null;
  max_gpu_percent: number | null;
  max_gpu_memory_mb: number | null;
};

type PolicySnapshot = {
  revision: number;
  constraints: PolicyConstraints;
};

type NodeIdentity = {
  node_id: string;
  node_name: string;
  platform: "windows" | "linux" | "macos" | "unknown";
  architecture: "x86_64" | "aarch64" | "unknown";
  public_key: string;
  created_at_ms: number;
};

type ControlTrust = {
  control_url: string;
  control_id: string;
  control_public_key: string;
  control_fingerprint: string;
  policy_revision: number;
  enrolled_at_ms: number;
};

type EnrollmentStatus = {
  state: "unenrolled" | "enrolled";
  identity: NodeIdentity;
  trust: ControlTrust | null;
};

type JobOffer = {
  job_id: string;
  workload_kind: "ai" | "rendering" | "media" | "mining" | "research" | "generic";
  runtime: string;
  runtime_version: string;
  artifact_id: string;
  artifact_version: string;
  limits: ResourceLimits;
  parameters: Record<string, string>;
  expires_at_ms: number;
};

type JobLease = {
  lease_id: string;
  node_id: string;
  offer: JobOffer;
  issued_at_ms: number;
  decision_deadline_ms: number;
  expires_at_ms: number;
};

type JobStatusEvent = {
  event_id: string;
  lease_id: string;
  job_id: string;
  state: "accepted" | "preparing" | "running" | "stopping" | "completed" | "failed";
  sequence: number;
  detail: string | null;
  exit_code: number | null;
  issued_at_ms: number;
};

type JobLeaseStatus = {
  lease: JobLease;
  state: "queued" | "offered" | "accepted" | "preparing" | "running" | "stopping" | "completed" | "failed" | "rejected" | "expired";
  reason: string | null;
  events: JobStatusEvent[];
  pending_event: JobStatusEvent | null;
};

type CpuInfo = {
  model: string;
  logical_cores: number;
  physical_cores: number | null;
  usage_percent: number;
};

type MemoryInfo = {
  total_mb: number;
  used_mb: number;
  available_mb: number;
};

type GpuInfo = {
  name: string;
  memory_total_mb: number | null;
  utilization_percent: number | null;
};

type HardwareSnapshot = {
  os: string;
  kernel: string;
  architecture: string;
  uptime_seconds: number;
  cpu: CpuInfo;
  memory: MemoryInfo;
  gpus: GpuInfo[];
};

type ArtifactCacheSummary = {
  manifests: number;
  content_verified: number;
  pending: number;
  verified_bytes: number;
};

type NodeStatus = {
  node_id: string;
  node_name: string;
  runtime_state: "idle" | "running" | "paused" | "degraded";
  control_url: string | null;
  control_connected: boolean;
  hardware: HardwareSnapshot;
  policy: NodePolicy;
  remote_policy: PolicySnapshot | null;
  effective_policy: NodePolicy;
  active_lease: JobLeaseStatus | null;
  artifact_cache: ArtifactCacheSummary;
  enrollment: EnrollmentStatus;
};

const defaultConfig: NodeConfig = {
  control_url: null,
  policy: {
    enabled: true,
    allow_ai: true,
    allow_rendering: true,
    allow_media: true,
    allow_mining: false,
    allow_research: true,
    allow_generic: false,
    limits: {
      cpu_percent: 70,
      memory_mb: 8192,
      gpu_percent: 80,
      gpu_memory_mb: null
    }
  }
};

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function formatMemory(value: number) {
  if (value >= 1024) {
    return `${(value / 1024).toFixed(1)} GB`;
  }
  return `${value} MB`;
}

function formatBytes(value: number) {
  if (value >= 1024 * 1024 * 1024) return `${(value / 1024 / 1024 / 1024).toFixed(1)} GB`;
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value} B`;
}

function allowedWorkloadCount(policy: NodePolicy | null | undefined) {
  if (!policy) return 0;
  return [
    policy.allow_ai,
    policy.allow_rendering,
    policy.allow_media,
    policy.allow_mining,
    policy.allow_research,
    policy.allow_generic
  ].filter(Boolean).length;
}

function formatUptime(seconds: number) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function App() {
  const [status, setStatus] = useState<NodeStatus | null>(null);
  const [config, setConfig] = useState<NodeConfig>(defaultConfig);
  const [nodeOnline, setNodeOnline] = useState(false);
  const [saving, setSaving] = useState(false);
  const [enrolling, setEnrolling] = useState(false);
  const [enrollmentToken, setEnrollmentToken] = useState("");
  const [message, setMessage] = useState("Connecting to lattice-node");
  const [activePage, setActivePage] = useState<"overview" | "resources" | "jobs" | "settings">("overview");

  const refresh = useCallback(async () => {
    try {
      const [nextStatus, nextConfig] = await Promise.all([
        invoke<NodeStatus>("get_node_status"),
        invoke<NodeConfig>("get_node_config")
      ]);
      setStatus(nextStatus);
      setConfig(nextConfig);
      setNodeOnline(true);
      setMessage(
        nextStatus.control_connected
          ? "Connected to control plane"
          : nextStatus.enrollment.state === "enrolled"
            ? "Node identity is enrolled and trusted"
            : "Node is running locally"
      );
    } catch (error) {
      setNodeOnline(false);
      setMessage(typeof error === "string" ? error : "lattice-node is not reachable");
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = window.setInterval(refresh, 2500);
    return () => window.clearInterval(interval);
  }, [refresh]);

  const memoryMax = useMemo(() => {
    if (!status) return Math.max(8192, config.policy.limits.memory_mb);
    return Math.max(1024, status.hardware.memory.total_mb);
  }, [status, config.policy.limits.memory_mb]);

  async function saveConfig() {
    setSaving(true);
    try {
      const saved = await invoke<NodeConfig>("set_node_config", { config });
      setConfig(saved);
      setMessage("Configuration saved");
      await refresh();
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Unable to save configuration");
    } finally {
      setSaving(false);
    }
  }

  async function enrollNode() {
    if (!config.control_url) {
      setMessage("Control server URL is required");
      return;
    }

    setEnrolling(true);
    try {
      const enrollment = await invoke<EnrollmentStatus>("enroll_node", {
        controlUrl: config.control_url,
        enrollmentToken
      });
      setEnrollmentToken("");
      setMessage(`Enrolled with ${enrollment.trust?.control_id ?? "control plane"}`);
      await refresh();
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Enrollment failed");
    } finally {
      setEnrolling(false);
    }
  }

  async function resetEnrollment() {
    setEnrolling(true);
    try {
      await invoke<EnrollmentStatus>("reset_enrollment");
      setEnrollmentToken("");
      setMessage("Control-plane trust reset");
      await refresh();
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Unable to reset enrollment");
    } finally {
      setEnrolling(false);
    }
  }

  function setPolicy<K extends keyof NodePolicy>(key: K, value: NodePolicy[K]) {
    setConfig((current) => ({
      ...current,
      policy: {
        ...current.policy,
        [key]: value
      }
    }));
  }

  function setLimit<K extends keyof ResourceLimits>(key: K, value: ResourceLimits[K]) {
    setConfig((current) => ({
      ...current,
      policy: {
        ...current.policy,
        limits: {
          ...current.policy.limits,
          [key]: value
        }
      }
    }));
  }

  const workloadItems = [
    ["AI", "allow_ai"],
    ["Rendering", "allow_rendering"],
    ["Media", "allow_media"],
    ["Research", "allow_research"],
    ["Mining", "allow_mining"],
    ["Generic", "allow_generic"]
  ] as const;

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <span />
            <span />
            <span />
          </div>
          <div>
            <strong>Lattice</strong>
            <small>Node</small>
          </div>
        </div>

        <nav>
          <button className={activePage === "overview" ? "active" : ""} onClick={() => setActivePage("overview")}>
            <span className="nav-icon">◫</span>
            Overview
          </button>
          <button className={activePage === "resources" ? "active" : ""} onClick={() => setActivePage("resources")}>
            <span className="nav-icon">⌁</span>
            Resources
          </button>
          <button className={activePage === "jobs" ? "active" : ""} onClick={() => setActivePage("jobs")}>
            <span className="nav-icon">▣</span>
            Jobs
          </button>
          <button className={activePage === "settings" ? "active" : ""} onClick={() => setActivePage("settings")}>
            <span className="nav-icon">⚙</span>
            Settings
          </button>
        </nav>

        <div className="sidebar-status">
          <div className={nodeOnline ? "status-dot online" : "status-dot"} />
          <div>
            <strong>{nodeOnline ? "Node online" : "Node offline"}</strong>
            <small>{nodeOnline ? status?.node_name ?? "Local node" : "Service unavailable"}</small>
          </div>
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">{activePage}</p>
            <h1>{activePage === "overview" ? "Node overview" : activePage === "resources" ? "Resource policy" : activePage === "jobs" ? "Job leases" : "Node settings"}</h1>
          </div>
          <label className="master-switch">
            <span>{config.policy.enabled ? "Resource sharing enabled" : "Resource sharing paused"}</span>
            <input
              type="checkbox"
              checked={config.policy.enabled}
              onChange={(event) => setPolicy("enabled", event.target.checked)}
            />
            <i />
          </label>
        </header>

        <div className="notice">
          <div className={nodeOnline ? "status-dot online" : "status-dot"} />
          <span>{message}</span>
          <button onClick={refresh}>Refresh</button>
        </div>

        {activePage === "overview" && (
          <>
            <section className="metric-grid">
              <article className="metric-card">
                <div className="metric-head">
                  <span>CPU</span>
                  <b>{status ? `${status.hardware.cpu.usage_percent.toFixed(0)}%` : "—"}</b>
                </div>
                <div className="meter">
                  <span style={{ width: `${clamp(status?.hardware.cpu.usage_percent ?? 0, 0, 100)}%` }} />
                </div>
                <strong>{status?.hardware.cpu.model ?? "Waiting for node"}</strong>
                <small>
                  {status
                    ? `${status.hardware.cpu.physical_cores ?? "?"} cores · ${status.hardware.cpu.logical_cores} threads`
                    : "Hardware information unavailable"}
                </small>
              </article>

              <article className="metric-card">
                <div className="metric-head">
                  <span>Memory</span>
                  <b>{status ? formatMemory(status.hardware.memory.used_mb) : "—"}</b>
                </div>
                <div className="meter">
                  <span
                    style={{
                      width: `${clamp(
                        status ? (status.hardware.memory.used_mb / status.hardware.memory.total_mb) * 100 : 0,
                        0,
                        100
                      )}%`
                    }}
                  />
                </div>
                <strong>{status ? `${formatMemory(status.hardware.memory.total_mb)} installed` : "Waiting for node"}</strong>
                <small>{status ? `${formatMemory(status.hardware.memory.available_mb)} available` : "Hardware information unavailable"}</small>
              </article>

              <article className="metric-card">
                <div className="metric-head">
                  <span>GPU</span>
                  <b>{status?.hardware.gpus[0]?.utilization_percent != null ? `${status.hardware.gpus[0].utilization_percent}%` : "—"}</b>
                </div>
                <div className="meter">
                  <span style={{ width: `${clamp(status?.hardware.gpus[0]?.utilization_percent ?? 0, 0, 100)}%` }} />
                </div>
                <strong>{status?.hardware.gpus[0]?.name ?? "No NVIDIA GPU detected"}</strong>
                <small>
                  {status?.hardware.gpus[0]?.memory_total_mb
                    ? `${formatMemory(status.hardware.gpus[0].memory_total_mb)} VRAM`
                    : "GPU telemetry will appear when available"}
                </small>
              </article>
            </section>

            <section className="split-grid">
              <article className="panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">Workloads</p>
                    <h2>Allowed categories</h2>
                  </div>
                  <span className="pill">{workloadItems.filter(([, key]) => config.policy[key]).length} enabled</span>
                </div>
                <div className="workload-grid">
                  {workloadItems.map(([label, key]) => (
                    <label className="workload-item" key={key}>
                      <div>
                        <strong>{label}</strong>
                        <small>{key === "allow_mining" ? "Requires explicit local permission" : "Available to the scheduler"}</small>
                      </div>
                      <input
                        type="checkbox"
                        checked={config.policy[key]}
                        onChange={(event) => setPolicy(key, event.target.checked)}
                      />
                      <i />
                    </label>
                  ))}
                </div>
              </article>

              <article className="panel node-panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">System</p>
                    <h2>Node details</h2>
                  </div>
                  <span className={nodeOnline ? "pill good" : "pill"}>{status?.runtime_state ?? "offline"}</span>
                </div>
                <dl>
                  <div><dt>Node name</dt><dd>{status?.node_name ?? "—"}</dd></div>
                  <div><dt>Node ID</dt><dd>{status?.node_id ?? "—"}</dd></div>
                  <div><dt>Operating system</dt><dd>{status?.hardware.os ?? "—"}</dd></div>
                  <div><dt>Architecture</dt><dd>{status?.hardware.architecture ?? "—"}</dd></div>
                  <div><dt>Uptime</dt><dd>{status ? formatUptime(status.hardware.uptime_seconds) : "—"}</dd></div>
                  <div><dt>Artifact cache</dt><dd>{status ? `${status.artifact_cache.content_verified}/${status.artifact_cache.manifests} verified` : "—"}</dd></div>
                </dl>
              </article>
            </section>
          </>
        )}

        {activePage === "resources" && (
          <section className="panel settings-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Local authority</p>
                <h2>Resource allocation</h2>
              </div>
              <span className="pill">Server cannot exceed these limits</span>
            </div>

            <div className="policy-layer-grid">
              <article>
                <span>Local policy</span>
                <strong>{config.policy.limits.cpu_percent}% CPU</strong>
                <small>{formatMemory(config.policy.limits.memory_mb)} RAM · {config.policy.limits.gpu_percent ?? 0}% GPU</small>
                <small>{allowedWorkloadCount(config.policy)} workload categories allowed locally</small>
              </article>
              <article>
                <span>Remote policy</span>
                <strong>{status?.remote_policy ? `Revision ${status.remote_policy.revision}` : "Not synchronized"}</strong>
                <small>
                  {status?.remote_policy
                    ? `${status.remote_policy.constraints.max_cpu_percent}% CPU max · ${status.remote_policy.constraints.max_memory_mb ? formatMemory(status.remote_policy.constraints.max_memory_mb) : "No RAM cap"}`
                    : "Waiting for an authenticated heartbeat"}
                </small>
                <small>Remote policy can only restrict local permissions.</small>
              </article>
              <article>
                <span>Effective policy</span>
                <strong>{status?.effective_policy ? `${status.effective_policy.limits.cpu_percent}% CPU` : "Unavailable"}</strong>
                <small>
                  {status?.effective_policy
                    ? `${formatMemory(status.effective_policy.limits.memory_mb)} RAM · ${status.effective_policy.limits.gpu_percent ?? 0}% GPU`
                    : "No effective policy available"}
                </small>
                <small>{allowedWorkloadCount(status?.effective_policy)} workload categories currently allowed</small>
              </article>
            </div>

            <div className="slider-setting">
              <div>
                <strong>CPU allocation</strong>
                <small>Maximum CPU capacity available to Lattice workloads</small>
              </div>
              <div className="slider-control">
                <input
                  type="range"
                  min="5"
                  max="100"
                  step="5"
                  value={config.policy.limits.cpu_percent}
                  onChange={(event) => setLimit("cpu_percent", Number(event.target.value))}
                />
                <b>{config.policy.limits.cpu_percent}%</b>
              </div>
            </div>

            <div className="slider-setting">
              <div>
                <strong>Memory allocation</strong>
                <small>Maximum memory available across active workloads</small>
              </div>
              <div className="slider-control">
                <input
                  type="range"
                  min="1024"
                  max={memoryMax}
                  step="512"
                  value={clamp(config.policy.limits.memory_mb, 1024, memoryMax)}
                  onChange={(event) => setLimit("memory_mb", Number(event.target.value))}
                />
                <b>{formatMemory(config.policy.limits.memory_mb)}</b>
              </div>
            </div>

            <div className="slider-setting">
              <div>
                <strong>GPU allocation</strong>
                <small>Maximum GPU compute utilization exposed to workloads</small>
              </div>
              <div className="slider-control">
                <input
                  type="range"
                  min="5"
                  max="100"
                  step="5"
                  value={config.policy.limits.gpu_percent ?? 80}
                  onChange={(event) => setLimit("gpu_percent", Number(event.target.value))}
                />
                <b>{config.policy.limits.gpu_percent ?? 80}%</b>
              </div>
            </div>

            <div className="save-row">
              <span>Changes are enforced by lattice-node on this machine.</span>
              <button className="primary" disabled={!nodeOnline || saving} onClick={saveConfig}>
                {saving ? "Saving…" : "Save resource policy"}
              </button>
            </div>
          </section>
        )}

        {activePage === "jobs" && (
          <section className="panel settings-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Lease protocol</p>
                <h2>Current job lease</h2>
              </div>
              <span className={status?.active_lease?.state === "accepted" ? "pill good" : "pill"}>
                {status?.active_lease?.state ?? "idle"}
              </span>
            </div>

            <div className="artifact-cache-grid">
              <div><span>Manifests</span><strong>{status?.artifact_cache.manifests ?? 0}</strong></div>
              <div><span>Content verified</span><strong>{status?.artifact_cache.content_verified ?? 0}</strong></div>
              <div><span>Pending</span><strong>{status?.artifact_cache.pending ?? 0}</strong></div>
              <div><span>Verified size</span><strong>{formatBytes(status?.artifact_cache.verified_bytes ?? 0)}</strong></div>
            </div>

            {status?.active_lease ? (
              <>
                <div className="job-detail-grid">
                  <div><span>Job ID</span><strong>{status.active_lease.lease.offer.job_id}</strong></div>
                  <div><span>Lease ID</span><strong>{status.active_lease.lease.lease_id}</strong></div>
                  <div><span>Workload</span><strong>{status.active_lease.lease.offer.workload_kind}</strong></div>
                  <div><span>Runtime</span><strong>{status.active_lease.lease.offer.runtime} {status.active_lease.lease.offer.runtime_version}</strong></div>
                  <div><span>Artifact</span><strong>{status.active_lease.lease.offer.artifact_id}@{status.active_lease.lease.offer.artifact_version}</strong></div>
                  <div><span>Lease expires</span><strong>{new Date(status.active_lease.lease.expires_at_ms).toLocaleString()}</strong></div>
                </div>

                <div className="lease-resource-row">
                  <div><span>CPU</span><strong>{status.active_lease.lease.offer.limits.cpu_percent}%</strong></div>
                  <div><span>Memory</span><strong>{formatMemory(status.active_lease.lease.offer.limits.memory_mb)}</strong></div>
                  <div><span>GPU</span><strong>{status.active_lease.lease.offer.limits.gpu_percent != null ? `${status.active_lease.lease.offer.limits.gpu_percent}%` : "Not required"}</strong></div>
                  <div><span>VRAM</span><strong>{status.active_lease.lease.offer.limits.gpu_memory_mb != null ? formatMemory(status.active_lease.lease.offer.limits.gpu_memory_mb) : "Not required"}</strong></div>
                </div>

                {status.active_lease.reason && (
                  <div className="security-note">
                    <strong>Decision reason</strong>
                    <p>{status.active_lease.reason}</p>
                  </div>
                )}

                {(status.active_lease.events.length > 0 || status.active_lease.pending_event) && (
                  <div className="event-history">
                    <div className="event-history-head">
                      <div>
                        <p className="eyebrow">Status events</p>
                        <h2>Authenticated history</h2>
                      </div>
                      <span className="pill">{status.active_lease.events.length} confirmed</span>
                    </div>
                    {status.active_lease.events.map((event) => (
                      <div className="event-row" key={event.event_id}>
                        <div className="event-marker" />
                        <div className="event-main">
                          <strong>{event.state}</strong>
                          <small>{new Date(event.issued_at_ms).toLocaleString()}</small>
                          {event.detail && <p>{event.detail}</p>}
                        </div>
                        <div className="event-meta">
                          <span>#{event.sequence}</span>
                          {event.exit_code != null && <span>exit {event.exit_code}</span>}
                        </div>
                      </div>
                    ))}
                    {status.active_lease.pending_event && (
                      <div className="event-row pending">
                        <div className="event-marker" />
                        <div className="event-main">
                          <strong>{status.active_lease.pending_event.state}</strong>
                          <small>Pending authenticated delivery</small>
                        </div>
                        <div className="event-meta"><span>retrying</span></div>
                      </div>
                    )}
                  </div>
                )}

                <div className="security-note">
                  <strong>Lease execution boundary</strong>
                  <p>An accepted lease reserves a structured workload only. Process execution and runtime adapters are implemented in the later runtime phase.</p>
                </div>
              </>
            ) : (
              <div className="empty-state">
                <strong>No active lease</strong>
                <p>The node will validate and explicitly accept or reject eligible offers received through authenticated heartbeats.</p>
              </div>
            )}
          </section>
        )}

        {activePage === "settings" && (
          <section className="panel settings-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Control plane</p>
                <h2>Identity and enrollment</h2>
              </div>
              <span className={status?.enrollment.state === "enrolled" ? "pill good" : "pill"}>
                {status?.enrollment.state ?? "unavailable"}
              </span>
            </div>

            <div className="identity-grid">
              <div>
                <span>Node ID</span>
                <strong>{status?.enrollment.identity.node_id ?? "—"}</strong>
              </div>
              <div>
                <span>Public key</span>
                <strong className="mono-value">{status?.enrollment.identity.public_key ?? "—"}</strong>
              </div>
            </div>

            <label className="field">
              <span>Control server URL</span>
              <input
                value={config.control_url ?? ""}
                placeholder="https://control.example.com"
                disabled={status?.enrollment.state === "enrolled"}
                onChange={(event) => setConfig((current) => ({ ...current, control_url: event.target.value || null }))}
              />
              <small>HTTPS is required outside localhost. Changing a trusted server requires resetting enrollment first.</small>
            </label>

            {status?.enrollment.state !== "enrolled" ? (
              <label className="field">
                <span>Enrollment token</span>
                <input
                  type="password"
                  value={enrollmentToken}
                  placeholder="Enrollment token"
                  autoComplete="off"
                  onChange={(event) => setEnrollmentToken(event.target.value)}
                />
                <small>The token is sent only during enrollment and is never stored by the node.</small>
              </label>
            ) : (
              <div className="trust-card">
                <div>
                  <span>Control ID</span>
                  <strong>{status.enrollment.trust?.control_id}</strong>
                </div>
                <div>
                  <span>Control fingerprint</span>
                  <strong className="mono-value">{status.enrollment.trust?.control_fingerprint}</strong>
                </div>
                <div>
                  <span>Policy revision</span>
                  <strong>{status.enrollment.trust?.policy_revision ?? 0}</strong>
                </div>
              </div>
            )}

            <div className="security-note">
              <strong>Local policy remains authoritative</strong>
              <p>The control plane can offer jobs and policies, but it cannot enable a workload category or raise resource limits that are disabled locally.</p>
            </div>

            <div className="save-row">
              <span>Node identity is persistent. Resetting enrollment removes control-plane trust but keeps the same node keypair.</span>
              {status?.enrollment.state === "enrolled" ? (
                <button className="danger-button" disabled={!nodeOnline || enrolling} onClick={resetEnrollment}>
                  {enrolling ? "Resetting…" : "Reset enrollment"}
                </button>
              ) : (
                <button
                  className="primary"
                  disabled={!nodeOnline || enrolling || !config.control_url || !enrollmentToken.trim()}
                  onClick={enrollNode}
                >
                  {enrolling ? "Enrolling…" : "Enroll node"}
                </button>
              )}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
