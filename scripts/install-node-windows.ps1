param([Parameter(Mandatory)][string]$ArtifactDir,[ValidateSet('node','master')][string]$Role='node',[string]$BootstrapUrl='https://lattice.sentialab.org',[switch]$AcceptTerms)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator privileges are required' }
function Invoke-Native([string]$Exe, [string[]]$Arguments, [int[]]$Accept=@(0)) { & $Exe @Arguments; if ($LASTEXITCODE -notin $Accept) { throw "Native operation failed (exit $LASTEXITCODE)" } }
$Node = Join-Path $ArtifactDir 'lattice-node.exe'
Invoke-Native $Node @('verify-bundle','--artifact-dir',$ArtifactDir,'--role',$Role)
foreach ($Name in @('lattice.exe','lattice-node.exe','lattice-worker.exe','lattice-update-helper.exe','wireguard.msi')) { if (-not (Test-Path (Join-Path $ArtifactDir $Name) -PathType Leaf)) { throw 'Incomplete bundle' } }
$Signature = Get-AuthenticodeSignature (Join-Path $ArtifactDir 'wireguard.msi')
if ($Signature.Status -ne 'Valid' -or $Signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=WireGuard LLC(,|$)') { throw 'WireGuard publisher signature rejected' }
$WireGuard = Join-Path $env:ProgramFiles 'WireGuard'
if (-not (Test-Path (Join-Path $WireGuard 'wireguard.exe'))) {
    $Msi = Start-Process msiexec.exe -ArgumentList @('/i', ('"' + (Join-Path $ArtifactDir 'wireguard.msi') + '"'),'/qn','/norestart') -Wait -PassThru
    if ($Msi.ExitCode -notin @(0,3010)) { throw 'WireGuard dependency installation failed' }
}
$Base = Join-Path $env:ProgramFiles 'Lattice'; $State = Join-Path $env:ProgramData 'Lattice'; $Current = Join-Path $Base 'current'; $Backup = Join-Path $Base ('rollback-' + [guid]::NewGuid().ToString('N'))
New-Item $Base,$State,$Backup -ItemType Directory -Force | Out-Null
Invoke-Native icacls.exe @($State,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
$OldNode = Get-Service LatticeNode -ErrorAction SilentlyContinue; $OldMaster = Get-Service LatticeMaster -ErrorAction SilentlyContinue
$OldEnv = @{}
foreach ($Name in @('LatticeNode','LatticeMaster')) { $OldEnv[$Name] = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Environment -ErrorAction SilentlyContinue).Environment }
try {
    if ($OldMaster) { Stop-Service LatticeMaster -ErrorAction Stop; Set-Service LatticeMaster -StartupType Disabled }; if ($OldNode) { Stop-Service LatticeNode -ErrorAction Stop }
    if (Test-Path $Current) { Move-Item $Current (Join-Path $Backup 'current') }
    New-Item $Current -ItemType Directory | Out-Null; Copy-Item (Join-Path $ArtifactDir '*') $Current -Recurse -Force
    Invoke-Native icacls.exe @($Current,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-5-32-545:(OI)(CI)RX')
    $Node = Join-Path $Current 'lattice-node.exe'; $Master = Join-Path $Current 'lattice-master.exe'; $MasterData = Join-Path $State 'master'
    Invoke-Native $Node @('--install-service')
    $ServiceEnv = @("LATTICE_CONFIG=$(Join-Path $State 'node.json')", "LATTICE_MASTER_DATA=$MasterData", "PATH=$Current;$WireGuard;$env:SystemRoot\System32;$env:SystemRoot")
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LatticeNode' -Name Environment -Type MultiString -Value $ServiceEnv
    # Only the installed node service owns compute execution and automatic setup.
    Start-Service LatticeNode
    $env:LATTICE_CONFIG = Join-Path $State 'node.json'; $env:LATTICE_MASTER_DATA=$MasterData; $env:PATH="$Current;$WireGuard;$env:PATH"
    $SetupArgs = @('setup','--role',$Role,'--bootstrap-url',$BootstrapUrl,'--timeout-secs','120','--json')
    if ($AcceptTerms) { $SetupArgs += '--accept-terms' }
    & $Node @SetupArgs
    $SetupExit = $LASTEXITCODE
    if ($SetupExit -notin @(0,2)) { throw 'Overlay setup or master activation failed' }
    if ($SetupExit -eq 2) { Write-Host 'Network ready; workload attachment pending. Services will retry.' }
    Write-Host "Base Node service installed; optional modules are supervised by the node. Recovery snapshot: $Backup"
} catch {
    Stop-Service LatticeMaster,LatticeNode -ErrorAction SilentlyContinue
    if (Test-Path $Current) { Move-Item $Current (Join-Path $Backup 'failed') }
    if (Test-Path (Join-Path $Backup 'current')) { Move-Item (Join-Path $Backup 'current') $Current }
    foreach ($Name in @('LatticeNode','LatticeMaster')) { if ($OldEnv[$Name]) { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Environment -Type MultiString -Value $OldEnv[$Name] } }
    if ($OldNode) { & (Join-Path $Current 'lattice-node.exe') --install-service; Start-Service LatticeNode }
    if ($OldMaster) { & (Join-Path $Current 'lattice-master.exe') --install-service; Set-Service LatticeMaster -StartupType $OldMaster.StartType; Start-Service LatticeMaster }
    throw
}
