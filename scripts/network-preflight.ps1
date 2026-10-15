# Lattice overlay network preflight check for Windows (read-only).
# Usage: powershell -ExecutionPolicy Bypass -File scripts\network-preflight.ps1 [-GatewayEndpoint host:port]
param([string]$GatewayEndpoint = $env:LATTICE_NETWORK_GATEWAY_ENDPOINT)

$Iface = if ($env:LATTICE_NETWORK_INTERFACE) { $env:LATTICE_NETWORK_INTERFACE } else { "lattice0" }
$Fail = 0
$Warn = 0

function Pass($m) { Write-Output "PASS: $m" }
function Fail($m) { Write-Output "FAIL: $m"; $script:Fail++ }
function Warn($m) { Write-Output "WARN: $m"; $script:Warn++ }

Write-Output "INFO: Lattice network preflight (Windows)"
Write-Output "INFO: interface=$Iface gateway_endpoint=$GatewayEndpoint"

$wg = "C:\Program Files\WireGuard\wireguard.exe"
if (Test-Path $wg) { Pass "wireguard.exe present" } else { Fail "wireguard.exe missing at $wg" }

try {
  $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Name -like "*$Iface*" -or $_.InterfaceDescription -like "*WireGuard*" }
  if ($adapters) { Warn "existing WireGuard adapter detected"; $adapters | Format-Table Name, Status | Out-String | Write-Output }
  else { Pass "no conflicting WireGuard adapter" }
} catch { Warn "Get-NetAdapter unavailable: $_" }

try {
  $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.DestinationPrefix -like "10.77.0.0*" }
  if ($routes) { Fail "conflicting 10.77.0.0/16 route present"; $routes | Format-Table DestinationPrefix, NextHop | Out-String | Write-Output }
  else { Pass "no conflicting 10.77.0.0/16 route" }
} catch { Warn "Get-NetRoute unavailable: $_" }

if ([string]::IsNullOrWhiteSpace($GatewayEndpoint)) {
  Warn "gateway endpoint unset, skipping UDP probe"
} else {
  $parts = $GatewayEndpoint.Split(":")
  if ($parts.Length -eq 2) {
    $udp = New-Object Net.Sockets.UdpClient
    try {
      $udp.Client.ReceiveTimeout = 3000
      $bytes = [Text.Encoding]::ASCII.GetBytes("lattice-preflight")
      $udp.Send($bytes, $bytes.Length, $parts[0], [int]$parts[1]) | Out-Null
      Pass "UDP send succeeded to $GatewayEndpoint (reachability requires gateway response, send-only is not proof)"
    } catch { Fail "UDP send failed to ${GatewayEndpoint}: $_" }
    finally { $udp.Close() }
  } else {
    Warn "gateway endpoint format invalid: $GatewayEndpoint"
  }
}

Write-Output "---"
Write-Output "failures=$Fail warnings=$Warn"
if ($Fail -gt 0) { Write-Output "RESULT: BLOCKED"; exit 1 }
Write-Output "RESULT: READY (warnings advisory)"
