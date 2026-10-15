# Lattice one-line Windows installer.
#   irm https://lattice.sentialab.org/installer/windows.ps1 | iex
# Security note: prefer HTTPS. The installer verifies SHA-256 checksums of
# every downloaded file, but checksums alone cannot replace TLS against an
# active network attacker. Serve this host over HTTPS in production.
$ErrorActionPreference = "Stop"

$Base = if ($env:LATTICE_RELEASE_BASE) { $env:LATTICE_RELEASE_BASE } else { "https://lattice.sentialab.org/releases" }
$Version = if ($env:LATTICE_VERSION) { $env:LATTICE_VERSION } else { "0.1.0" }
$NonInteractive = $env:LATTICE_NONINTERACTIVE -eq "1"

function Ask-Value([string]$Prompt, [string]$Default) {
    if ($NonInteractive) { return $Default }
    $answer = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    return $answer
}

function Ask-YesNo([string]$Prompt, [string]$Default) {
    while ($true) {
        if ($NonInteractive) { return $Default }
        $answer = Read-Host "$Prompt (y/n) [$Default]"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
        if ($answer -match '^(y|Y|yes|YES)$') { return "y" }
        if ($answer -match '^(n|N|no|NO)$') { return "n" }
        Write-Output "Please answer y or n."
    }
}

function Get-FileHashVerified([string]$Url, [string]$Dest) {
    Invoke-WebRequest -Uri $Url -OutFile $Dest
    Invoke-WebRequest -Uri "$Url.sha256" -OutFile "$Dest.sha256"
    $expected = ((Get-Content "$Dest.sha256" -TotalCount 1) -split '\s+')[0]
    $actual = (Get-FileHash $Dest -Algorithm SHA256).Hash.ToLower()
    if ($expected.ToLower() -ne $actual) {
        throw "Checksum mismatch for $(Split-Path $Dest -Leaf). Aborting."
    }
}

Write-Output "Lattice Windows installer (release $Version)"
Write-Output "Server: $Base"
Write-Output ""

$EnrollmentToken = $env:LATTICE_ENROLLMENT_TOKEN
if (-not $EnrollmentToken) {
    $secure = Read-Host "Enrollment token" -AsSecureString
    $EnrollmentToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
$MasterUrl = Ask-Value "Master URL (empty to skip workload enrollment)" ($env:LATTICE_MASTER_URL | ForEach-Object { $_ })
if (-not $MasterUrl) { $MasterUrl = "" }
$BootstrapUrl = Ask-Value "Bootstrapper URL (empty to skip overlay join)" ($env:LATTICE_BOOTSTRAP_URL | ForEach-Object { $_ })
if (-not $BootstrapUrl) { $BootstrapUrl = "" }
$Insecure = Ask-YesNo "Allow plain HTTP outside localhost (test deployments only)" "n"

$Work = Join-Path $env:TEMP ("lattice-install-" + [Guid]::NewGuid().ToString("N"))
$Dist = Join-Path $Work "dist"
New-Item -ItemType Directory -Force -Path $Dist | Out-Null
try {
    foreach ($binary in @("lattice-node.exe", "lattice-worker.exe")) {
        Get-FileHashVerified "$Base/$Version/windows-x86_64/$binary" (Join-Path $Dist $binary)
    }
    Get-FileHashVerified "$Base/scripts/install-node-windows.ps1" (Join-Path $Work "install-node-windows.ps1")

    Write-Output ""
    Write-Output "Installing node service."
    $env:LATTICE_ENROLLMENT_TOKEN = $EnrollmentToken
    $env:LATTICE_MASTER_URL = $MasterUrl
    $env:LATTICE_BOOTSTRAP_URL = $BootstrapUrl
    if ($Insecure -eq "y") {
        [Environment]::SetEnvironmentVariable("LATTICE_ALLOW_INSECURE_HTTP", "1", "Machine")
    }
    & (Join-Path $Work "install-node-windows.ps1") -ArtifactDir $Dist
} finally {
    Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}

Write-Output ""
Write-Output "Done. Verify with: Get-Service LatticeNode"
