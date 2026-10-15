param([Parameter(Mandatory)][string]$ArtifactDir,[string]$BootstrapUrl='https://lattice.sentialab.org')
& (Join-Path $PSScriptRoot 'install-node-windows.ps1') -ArtifactDir $ArtifactDir -Role master -BootstrapUrl $BootstrapUrl
