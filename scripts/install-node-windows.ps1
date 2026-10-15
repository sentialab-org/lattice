# Install lattice-node on Windows (x86_64).
# Run in an elevated PowerShell:
#   $env:LATTICE_ENROLLMENT_TOKEN = 'secret'
#   $env:LATTICE_MASTER_URL = 'http://<master>:7443'
#   $env:LATTICE_BOOTSTRAP_URL = 'http://<bootstrapper>:7443'
#   $env:LATTICE_ALLOW_INSECURE_HTTP = '1'
#   .\scripts\install-node-windows.ps1 -ArtifactDir .\dist
param([string]$ArtifactDir = ".\dist")

$ErrorActionPreference = "Stop"

foreach ($binary in @("lattice-node.exe", "lattice-worker.exe")) {
  if (-not (Test-Path (Join-Path $ArtifactDir $binary))) {
    Write-Error "Missing artifact: $binary"
  }
}

if (-not (Test-Path 'C:\Program Files\WireGuard\wireguard.exe')) {
  Write-Error "WireGuard for Windows is required. Install it, then rerun."
}

$OverlayCidr = if ($env:LATTICE_NETWORK_CIDR) { $env:LATTICE_NETWORK_CIDR } else { "10.77.0.0/16" }
$Iface = if ($env:LATTICE_NETWORK_INTERFACE) { $env:LATTICE_NETWORK_INTERFACE } else { "wg-lattice" }
$RuleName = "Lattice Overlay ($Iface)"
netsh advfirewall firewall delete rule name="$RuleName" | Out-Null
netsh advfirewall firewall add rule name="$RuleName" dir=in action=allow remoteip=$OverlayCidr description="Lattice overlay peer traffic"
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to add overlay firewall exception (run elevated)." }

$InstallDir = "C:\Program Files\Lattice"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item (Join-Path $ArtifactDir "lattice-node.exe") (Join-Path $InstallDir "lattice-node.exe") -Force
Copy-Item (Join-Path $ArtifactDir "lattice-worker.exe") (Join-Path $InstallDir "lattice-worker.exe") -Force

function Send-NodeIpc([string]$Body) {
  $pipe = New-Object IO.Pipes.NamedPipeClientStream(".", "lattice-node", [IO.Pipes.PipeDirection]::InOut)
  $pipe.Connect(15000)
  try {
    $writer = New-Object IO.StreamWriter($pipe)
    $writer.AutoFlush = $true
    $writer.WriteLine($Body)
    $reader = New-Object IO.StreamReader($pipe)
    return $reader.ReadLine()
  } finally {
    $pipe.Close()
  }
}

& (Join-Path $InstallDir "lattice-node.exe") --install-service
Start-Service LatticeNode
Start-Sleep -Seconds 4

$Token = $env:LATTICE_ENROLLMENT_TOKEN
if ($env:LATTICE_BOOTSTRAP_URL -and $Token) {
  Write-Output "Joining bootstrapper $env:LATTICE_BOOTSTRAP_URL"
  $body = @{ method = "enroll_bootstrap"; params = @{ bootstrap_url = $env:LATTICE_BOOTSTRAP_URL; enrollment_token = $Token } } | ConvertTo-Json -Compress -Depth 5
  Send-NodeIpc $body
  $enable = @{ method = "set_network_enabled"; params = @{ enabled = $true } } | ConvertTo-Json -Compress -Depth 5
  Send-NodeIpc $enable
}

if ($env:LATTICE_MASTER_URL -and $Token) {
  Write-Output "Enrolling with master $env:LATTICE_MASTER_URL"
  $body = @{ method = "enroll"; params = @{ control_url = $env:LATTICE_MASTER_URL; enrollment_token = $Token } } | ConvertTo-Json -Compress -Depth 5
  Send-NodeIpc $body
}

Write-Output "Node status:"
Send-NodeIpc (@{ method = "get_status" } | ConvertTo-Json -Compress)
