BeforeAll { $Repo = Split-Path (Split-Path $PSScriptRoot); $Public = Get-Content "$Repo/web/installer/windows.ps1" -Raw; $Installer = Get-Content "$Repo/scripts/install-node-windows.ps1" -Raw }
Describe 'Windows installer contract' {
 It 'UacCancellationLeavesExistingInstallation' { $Public | Should -Match '1223'; $Public | Should -Match 'RunAs' }
 It 'PipelineInvocationRelaunchesProtectedDiskScript' { $Public | Should -Match 'EncodedCommand'; $Public | Should -Match 'Expand-VerifiedArchive' }
 It 'WireGuardDependencyInstalledAndVerified' { $Installer | Should -Match 'Get-AuthenticodeSignature'; $Installer | Should -Match 'WireGuard'; $Installer | Should -Match 'msiexec' }
 It 'NodeBundleIncludesUpdateHelper' { $Installer | Should -Match 'lattice-update-helper.exe' }
 It 'TokenNotInRelaunchArgumentsOrTranscript' { $Public | Should -Not -Match 'activation_token|master_token|Start-Transcript'; $Installer | Should -Not -Match 'Start-Transcript' }
 It 'ScmFailureRestoresPreviousArtifacts' { $Installer | Should -Match 'catch'; $Installer | Should -Match 'rollback' }
 It 'MasterDoesNotStartBeforeOverlayAuthorization' { $Installer.IndexOf('setup --role') | Should -BeLessThan $Installer.IndexOf("'--start-service'") }
}
Describe 'Controlled native Windows acceptance' -Skip:($env:LATTICE_WINDOWS_ACCEPTANCE -ne '1') {
 It 'requires an administrator and a disposable native Windows machine' { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) | Should -BeTrue }
}
