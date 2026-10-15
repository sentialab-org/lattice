param([Parameter(Mandatory)][string]$ExpectedRevision,[string]$TcpPeer)
$ErrorActionPreference='Stop'
if(-not $env:LATTICE_CONFIG){$env:LATTICE_CONFIG=Join-Path $env:ProgramData 'Lattice/node.json'}
$env:PATH="$(Join-Path $env:ProgramFiles 'WireGuard');$env:PATH"
$Node=Join-Path $env:ProgramFiles 'Lattice/current/lattice-node.exe'
$Arguments=@('verify-installation','--expected-revision',$ExpectedRevision)
if($TcpPeer){$Arguments+=@('--tcp-peer',$TcpPeer)}
& $Node @Arguments
exit $LASTEXITCODE
