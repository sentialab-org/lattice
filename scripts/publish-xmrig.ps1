param(
    [Parameter(Mandatory = $true)]
    [string]$ControlUrl,

    [Parameter(Mandatory = $true)]
    [string]$OperatorToken,

    [string]$Version = "6.26.0",

    [ValidateSet("windows", "linux")]
    [string]$Platform = "windows",

    [ValidateSet("x86_64")]
    [string]$Architecture = "x86_64",

    [string]$ArchiveSha256 = ""
)

$ErrorActionPreference = "Stop"

$knownHashes = @{
    "6.26.0|windows|x86_64" = "bba8097cb37d9b458a1cb1137876b27cde6740d17fe4ccbc086ba07d87d9e147"
    "6.26.0|linux|x86_64" = "fc6f8ae5f64e4f17481f7e3be29a1c56949f216a998414188003eae1db20c9e5"
}

$key = "$Version|$Platform|$Architecture"
if ([string]::IsNullOrWhiteSpace($ArchiveSha256)) {
    if (-not $knownHashes.ContainsKey($key)) {
        throw "No pinned upstream SHA-256 is known for $key. Supply -ArchiveSha256 explicitly."
    }
    $ArchiveSha256 = $knownHashes[$key]
}

if ($Platform -eq "windows") {
    $asset = "xmrig-$Version-windows-x64.zip"
    $executableName = "xmrig.exe"
} else {
    $asset = "xmrig-$Version-linux-static-x64.tar.gz"
    $executableName = "xmrig"
}

$releaseUrl = "https://github.com/xmrig/xmrig/releases/download/v$Version/$asset"
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("lattice-xmrig-" + [Guid]::NewGuid().ToString("N"))

try {
    New-Item -ItemType Directory -Path $temp | Out-Null
    $archive = Join-Path $temp $asset
    Invoke-WebRequest -Uri $releaseUrl -OutFile $archive

    $actualArchiveSha256 = (Get-FileHash -Algorithm SHA256 -Path $archive).Hash.ToLowerInvariant()
    if ($actualArchiveSha256 -ne $ArchiveSha256.ToLowerInvariant()) {
        throw "Upstream archive SHA-256 mismatch. Expected $ArchiveSha256, got $actualArchiveSha256."
    }

    $extract = Join-Path $temp "extract"
    New-Item -ItemType Directory -Path $extract | Out-Null

    if ($Platform -eq "windows") {
        Expand-Archive -Path $archive -DestinationPath $extract
    } else {
        tar -xzf $archive -C $extract
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to extract XMRig archive."
        }
    }

    $executable = Get-ChildItem -Path $extract -Recurse -File -Filter $executableName | Select-Object -First 1
    if ($null -eq $executable) {
        throw "Could not find $executableName in the verified XMRig archive."
    }

    $runtimeSha256 = (Get-FileHash -Algorithm SHA256 -Path $executable.FullName).Hash.ToLowerInvariant()
    $runtimeSize = $executable.Length
    $base = $ControlUrl.TrimEnd("/")
    $uri = "$base/api/v1/operator/xmrig/runtimes/$Version/$Platform/$Architecture"
    $headers = @{ Authorization = "Bearer $OperatorToken" }

    $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/octet-stream" -InFile $executable.FullName

    Write-Host "Published XMRig $Version for $Platform/$Architecture"
    Write-Host "Executable SHA-256: $runtimeSha256"
    Write-Host "Executable size: $runtimeSize"
    $response | ConvertTo-Json -Depth 8
} finally {
    Remove-Item -Path $temp -Recurse -Force -ErrorAction SilentlyContinue
}
