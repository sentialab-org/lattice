$ErrorActionPreference = "Stop"

if (-not $env:RUNNER_TEMP) {
    throw "RUNNER_TEMP is required"
}

if (Get-Service -Name "LatticeNode" -ErrorAction SilentlyContinue) {
    throw "LatticeNode already exists on this runner"
}

$dataDir = Join-Path $env:ProgramData "Lattice"
if (Test-Path $dataDir) {
    throw "Lattice data directory already exists on this runner"
}

$root = Join-Path $env:RUNNER_TEMP "lattice-update-e2e"
$nodeManifest = Join-Path $PWD "crates\lattice-node\Cargo.toml"
$originalManifest = Get-Content -Raw $nodeManifest
$targetNode = Join-Path $root "lattice-node.exe"
$helper = Join-Path $root "lattice-update-helper.exe"
$updateRoot = Join-Path $dataDir "updates"
$statePath = Join-Path $updateRoot "state.json"

function Write-UpdateState {
    param(
        [string]$InstalledVersion,
        [string]$AvailableVersion,
        [string]$StagedVersion,
        [string]$StagedPath,
        [long]$Size
    )

    $state = @{
        installed_version = $InstalledVersion
        release_channel = "stable"
        available_version = $AvailableVersion
        minimum_supported_version = "0.1.0"
        state = "staged"
        downloaded_bytes = $Size
        total_bytes = $Size
        staged_version = $StagedVersion
        staged_path = $StagedPath
        previous_version = $null
        backup_path = $null
        last_error = $null
        retry_count = 0
        checked_at_ms = $null
    }

    New-Item -ItemType Directory -Force -Path (Split-Path $statePath) | Out-Null
    $state | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 $statePath
}

function Write-ApplyPlan {
    param(
        [string]$Path,
        [string]$StagedPath,
        [string]$BackupPath,
        [string]$ExpectedVersion,
        [string]$PreviousVersion,
        [string]$Sha256,
        [long]$Size
    )

    $plan = @{
        staged_path = $StagedPath
        target_path = $targetNode
        backup_path = $BackupPath
        state_path = $statePath
        expected_version = $ExpectedVersion
        previous_version = $PreviousVersion
        sha256 = $Sha256
        size_bytes = $Size
    }

    $plan | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 $Path
}

try {
    New-Item -ItemType Directory -Force -Path $root | Out-Null

    cargo build -p lattice-node -p lattice-update-helper --release
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build baseline updater binaries"
    }

    Copy-Item "target\release\lattice-node.exe" $targetNode
    Copy-Item "target\release\lattice-update-helper.exe" $helper

    & $targetNode --install-service
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install baseline LatticeNode service"
    }

    $updatedManifest = $originalManifest -replace '(?m)^version = "0\.1\.0"$', 'version = "0.1.1"'
    if ($updatedManifest -eq $originalManifest) {
        throw "Failed to prepare updated lattice-node package version"
    }
    Set-Content -Encoding utf8 $nodeManifest $updatedManifest

    cargo build -p lattice-node --release
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build updated lattice-node"
    }

    $stagedSuccessTemp = Join-Path $root "lattice-node-0.1.1.exe"
    Copy-Item "target\release\lattice-node.exe" $stagedSuccessTemp
    Set-Content -Encoding utf8 $nodeManifest $originalManifest

    $successHash = (Get-FileHash -Algorithm SHA256 $stagedSuccessTemp).Hash.ToLowerInvariant()
    $successSize = (Get-Item $stagedSuccessTemp).Length
    $stagedSuccess = Join-Path (Join-Path $updateRoot "staging\objects") $successHash
    $successBackup = Join-Path (Join-Path $updateRoot "backup") "lattice-node-0.1.0.exe"
    $successPlan = Join-Path $root "success-plan.json"
    New-Item -ItemType Directory -Force -Path (Split-Path $stagedSuccess) | Out-Null
    Copy-Item $stagedSuccessTemp $stagedSuccess

    Write-UpdateState "0.1.0" "0.1.1" "0.1.1" $stagedSuccess $successSize
    Write-ApplyPlan $successPlan $stagedSuccess $successBackup "0.1.1" "0.1.0" $successHash $successSize

    $successProcess = Start-Process -FilePath $helper -ArgumentList @("--apply-plan", $successPlan) -Wait -PassThru -NoNewWindow
    if ($successProcess.ExitCode -ne 0) {
        throw "Successful update scenario failed"
    }

    $successState = Get-Content -Raw $statePath | ConvertFrom-Json
    if ($successState.installed_version -ne "0.1.1" -or $successState.state -ne "idle") {
        throw "Updated node did not pass the expected health gate"
    }
    if (-not (Test-Path $successBackup)) {
        throw "Previous executable backup was not preserved"
    }

    $stagedFailureTemp = Join-Path $root "lattice-node-forced-failure.exe"
    Copy-Item $targetNode $stagedFailureTemp
    $failureHash = (Get-FileHash -Algorithm SHA256 $stagedFailureTemp).Hash.ToLowerInvariant()
    $failureSize = (Get-Item $stagedFailureTemp).Length
    $stagedFailure = Join-Path (Join-Path $updateRoot "staging\objects") $failureHash
    $failureBackup = Join-Path (Join-Path $updateRoot "backup") "lattice-node-0.1.1.exe"
    $failurePlan = Join-Path $root "failure-plan.json"
    New-Item -ItemType Directory -Force -Path (Split-Path $stagedFailure) | Out-Null
    Copy-Item $stagedFailureTemp $stagedFailure -Force

    Write-UpdateState "0.1.1" "0.1.2" "0.1.2" $stagedFailure $failureSize
    Write-ApplyPlan $failurePlan $stagedFailure $failureBackup "0.1.2" "0.1.1" $failureHash $failureSize

    $failureProcess = Start-Process -FilePath $helper -ArgumentList @("--apply-plan", $failurePlan) -Wait -PassThru -NoNewWindow
    if ($failureProcess.ExitCode -eq 0) {
        throw "Forced update failure unexpectedly succeeded"
    }

    $failureState = Get-Content -Raw $statePath | ConvertFrom-Json
    if ($failureState.installed_version -ne "0.1.1" -or $failureState.state -ne "failed") {
        throw "Rollback did not restore the previous node version"
    }
    if (-not ($failureState.last_error -like "*rollback succeeded*")) {
        throw "Rollback success was not persisted"
    }

    Write-Host "Windows updater lifecycle validation passed"
}
finally {
    Set-Content -Encoding utf8 $nodeManifest $originalManifest

    if (Test-Path $targetNode) {
        & $targetNode --uninstall-service | Out-Null
    }

    if (Get-Service -Name "LatticeNode" -ErrorAction SilentlyContinue) {
        sc.exe stop LatticeNode | Out-Null
        Start-Sleep -Seconds 1
        sc.exe delete LatticeNode | Out-Null
    }

    if (Test-Path $dataDir) {
        Remove-Item -Recurse -Force $dataDir
    }

    if (Test-Path $root) {
        Remove-Item -Recurse -Force $root
    }
}
