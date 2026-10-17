"""Portable source gates; these do not establish native Windows acceptance."""
import pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
class WindowsSourceTests(unittest.TestCase):
 def test_service_registration_never_starts_before_environment(self):
  for path in ['crates/lattice-node/src/windows_service.rs','crates/lattice-control/src/windows_service.rs']:
   source=(ROOT/path).read_text();install=source.split('pub fn install()',1)[1].split('pub fn uninstall()',1)[0]
   self.assertNotIn('service.start',install)
  source=(ROOT/'scripts/install-node-windows.ps1').read_text()
  self.assertLess(source.index('Services\\LatticeNode\' -Name Environment'),source.index('Start-Service LatticeNode'))
  self.assertNotIn("Invoke-Native $Master @('--install-service')",source)
  self.assertNotIn("Invoke-Native $Master @('--start-service')",source)
