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

type NodeStatus = {
  node_id: string;
  node_name: string;
  runtime_state: "idle" | "running" | "paused" | "degraded";
  control_url: string | null;
  control_connected: boolean;
  hardware: HardwareSnapshot;
  policy: NodePolicy;
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
  const [message, setMessage] = useState("Connecting to lattice-node");
  const [activePage, setActivePage] = useState<"overview" | "resources" | "settings">("overview");

  const refresh = useCallback(async () => {
    try {
      const [nextStatus, nextConfig] = await Promise.all([
        invoke<NodeStatus>("get_node_status"),
        invoke<NodeConfig>("get_node_config")
      ]);
      setStatus(nextStatus);
      setConfig(nextConfig);
      setNodeOnline(true);
      setMessage(nextStatus.control_connected ? "Connected to control plane" : "Node is running locally");
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
            <h1>{activePage === "overview" ? "Node overview" : activePage === "resources" ? "Resource policy" : "Node settings"}</h1>
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

        {activePage === "settings" && (
          <section className="panel settings-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Control plane</p>
                <h2>Server configuration</h2>
              </div>
              <span className="pill">{status?.control_connected ? "connected" : "not connected"}</span>
            </div>

            <label className="field">
              <span>Control server URL</span>
              <input
                value={config.control_url ?? ""}
                placeholder="https://control.example.com"
                onChange={(event) => setConfig((current) => ({ ...current, control_url: event.target.value || null }))}
              />
              <small>HTTPS is required for non-local control servers.</small>
            </label>

            <div className="security-note">
              <strong>Local policy remains authoritative</strong>
              <p>The control plane can offer jobs and policies, but it cannot enable a workload category or raise resource limits that are disabled locally.</p>
            </div>

            <div className="save-row">
              <span>Enrollment and authenticated control-plane transport are the next protocol milestone.</span>
              <button className="primary" disabled={!nodeOnline || saving} onClick={saveConfig}>
                {saving ? "Saving…" : "Save node settings"}
              </button>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
