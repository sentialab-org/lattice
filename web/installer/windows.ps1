$ErrorActionPreference = 'Stop'
$Site = if ($env:LATTICE_SITE_BASE) { $env:LATTICE_SITE_BASE } else { 'https://lattice.sentialab.org' }
$Role = if ($env:LATTICE_ROLE) { $env:LATTICE_ROLE } else { 'node' }
if ($Role -notin @('node','master') -or $Site -notmatch '^https://[A-Za-z0-9.-]+(:[0-9]+)?$') { throw 'Invalid role or HTTPS site origin' }
$Version = if ($env:LATTICE_VERSION) { $env:LATTICE_VERSION } else { (Invoke-RestMethod "$Site/releases/stable").Trim() }
if ($Version -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.-]+)?$') { throw 'Invalid release version' }
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') { throw 'Only Windows x86_64 is currently supported' }
$Stage = Join-Path ([IO.Path]::GetTempPath()) ('lattice-' + [guid]::NewGuid().ToString('N'))
New-Item $Stage -ItemType Directory | Out-Null
function Expand-VerifiedArchive($Archive, $Destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $Names = @{}
        foreach ($Entry in $Zip.Entries) {
            if ($Entry.FullName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or (($Entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000 -or $Entry.Length -gt 268435456 -or $Names.ContainsKey($Entry.FullName)) { throw 'Unsafe archive entry' }
            $Names[$Entry.FullName] = $true
        }
    } finally { $Zip.Dispose() }
    [IO.Compression.ZipFile]::ExtractToDirectory($Archive, $Destination)
}
function Quote-Literal($Value) { "'" + $Value.Replace("'", "''") + "'" }
try {
    $Bundle = "$Site/releases/$Version/windows-x86_64/$Role.zip"
    $Archive = Join-Path $Stage 'bundle.zip'
    Invoke-WebRequest $Bundle -OutFile $Archive -UseBasicParsing
    $Expected = (Invoke-RestMethod "$Bundle.sha256").Trim()
    if ($Expected -notmatch '^[a-f0-9]{64}$' -or (Get-FileHash $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) { throw 'Bundle checksum mismatch' }
    $Artifacts = Join-Path $Stage 'artifacts'
    Expand-VerifiedArchive $Archive $Artifacts
    $Bootstrap = if ($env:LATTICE_BOOTSTRAP_URL) { $env:LATTICE_BOOTSTRAP_URL } else { $Site }
    if ($Bootstrap -notmatch '^https://[A-Za-z0-9.-]+(:[0-9]+)?$') { throw 'Invalid coordinator origin' }
    $DiskScript = Join-Path $Artifacts 'install.ps1'
    $Command = '& ' + (Quote-Literal $DiskScript) + ' -ArtifactDir ' + (Quote-Literal $Artifacts) + ' -Role ' + (Quote-Literal $Role) + ' -BootstrapUrl ' + (Quote-Literal $Bootstrap)
    if ($env:LATTICE_ACCEPT_TERMS -eq '1') { $Command += ' -AcceptTerms' }
    $Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    $Admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($Admin) { & $DiskScript -ArtifactDir $Artifacts -Role $Role -BootstrapUrl $Bootstrap -AcceptTerms:($env:LATTICE_ACCEPT_TERMS -eq '1') }
    else {
        try { $Process = Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$Encoded) -Wait -PassThru }
        catch { if ($_.Exception.NativeErrorCode -eq 1223) { throw 'Administrator elevation cancelled; existing installation retained' }; throw }
        if ($Process.ExitCode -ne 0) { throw 'Elevated installation failed; review its diagnostics' }
    }
} finally { Remove-Item $Stage -Recurse -Force -ErrorAction SilentlyContinue }
