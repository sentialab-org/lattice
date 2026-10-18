import os,pathlib,tempfile,subprocess,unittest,plistlib,socket
ROOT=pathlib.Path(__file__).resolve().parents[2]
class MacInstallTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='lattice & test ');self.dir=pathlib.Path(self.tmp.name);self.host=self.dir/'host';self.host.mkdir();self.art=self.dir/'artifacts';self.art.mkdir();self.shims=self.dir/'shims';self.shims.mkdir();self.log=self.dir/'commands'
  for n in ['launchctl','chown','id']:
   p=self.shims/n;p.write_text('#!/bin/sh\necho "$0 $*" >> "$HARNESS_LOG"\necho 0\nexit 0\n');p.chmod(0o755)
  for n in ['lattice-node','lattice-worker','lattice-master','wg','wg-quick','wireguard-go','bash']:
   p=self.art/n;p.write_text('#!/bin/sh\ncase "$1" in verify-bundle) exit 0;; setup) echo \'{"stage":"waiting_for_master","network_ready":true}\'; exit 2;; esac\n');p.chmod(0o755)
  self.env={**os.environ,'PATH':str(self.shims)+':'+os.environ['PATH'],'LATTICE_INSTALL_TEST_MODE':'1','LATTICE_INSTALL_TEST_ROOT':str(self.host),'HARNESS_LOG':str(self.log),'LATTICE_TEST_SHIMS':str(self.shims)}
 def tearDown(self):self.tmp.cleanup()
 def install(self,role='node',**env):
  r=subprocess.run(['bash',str(ROOT/'scripts/install-node-macos.sh'),'--artifact-dir',str(self.art),'--role',role],env={**self.env,**env},capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
 def plist(self,name='node'):return plistlib.loads((self.host/f'Library/LaunchDaemons/com.lattice.{name}.plist').read_bytes())
 def test_launchdaemon_starts_before_login(self):self.install();p=self.plist();self.assertTrue(p['RunAtLoad']);self.assertTrue(p['KeepAlive']);self.assertEqual(p['UserName'],'root');self.assertIn('bootstrap system',self.log.read_text())
 def test_stale_socket_is_removed_before_starting_new_daemon(self):
  endpoint=self.host/'var/run/lattice/node.sock';endpoint.parent.mkdir(parents=True)
  previous=os.getcwd()
  try:
   os.chdir(endpoint.parent);listener=socket.socket(socket.AF_UNIX);listener.bind('node.sock');listener.close()
  finally:os.chdir(previous)
  self.assertTrue(endpoint.exists());self.install();self.assertFalse(endpoint.exists())
 def test_space_containing_application_support_path_is_valid_xml(self):self.install();self.assertIn('Application Support',self.plist()['EnvironmentVariables']['LATTICE_CONFIG']);r=subprocess.run(['plutil','-lint',str(self.host/'Library/LaunchDaemons/com.lattice.node.plist')],capture_output=True);self.assertEqual(r.returncode,0)
 def test_root_installer_never_runs_brew_as_root(self):self.assertNotIn('brew ',(ROOT/'scripts/install-node-macos.sh').read_text());self.install()
 def test_legacy_user_identity_moves_with_original_retained(self):
  legacy=self.dir/'legacy';legacy.mkdir();(legacy/'identity.json').write_bytes(b'old identity');self.install(LATTICE_LEGACY_USER_STATE=str(legacy));self.assertEqual((legacy/'identity.json').read_bytes(),(self.host/'Library/Application Support/Lattice/identity.json').read_bytes())
 def test_root_service_can_query_and_restore_wireguard(self):self.install();p=self.plist();self.assertIn('current',p['EnvironmentVariables']['PATH']);self.assertTrue(p['EnvironmentVariables']['LATTICE_WG_QUICK'].endswith('/wg-quick'))
 def test_master_repair_does_not_duplicate_node_or_executor(self):self.install('master');self.install('master');self.assertEqual(len(list((self.host/'Library/LaunchDaemons').glob('com.lattice.node.plist'))),1);self.assertFalse((self.host/'Library/LaunchDaemons/com.lattice.master.plist').exists());self.assertNotIn('bootstrap system '+str(self.host/'Library/LaunchDaemons/com.lattice.master.plist'),self.log.read_text())
 def test_failed_upgrade_keeps_previously_unloaded_root_daemons_unloaded(self):
  plists=self.host/'Library/LaunchDaemons';plists.mkdir(parents=True)
  for role in ['node','master']:(plists/f'com.lattice.{role}.plist').write_bytes(plistlib.dumps({'Label':f'com.lattice.{role}'}))
  shim=self.shims/'launchctl';shim.write_text('#!/bin/sh\necho "$0 $*" >> "$HARNESS_LOG"\nif [ "$1" = print ]; then exit 1; fi\nexit 0\n');shim.chmod(0o755)
  node=self.art/'lattice-node';node.write_text('#!/bin/sh\ncase "$1" in verify-bundle) exit 0;; setup) exit 1;; esac\n');node.chmod(0o755)
  result=subprocess.run(['bash',str(ROOT/'scripts/install-node-macos.sh'),'--artifact-dir',str(self.art)],env=self.env,capture_output=True,text=True)
  self.assertNotEqual(result.returncode,0)
  commands=self.log.read_text()
  self.assertNotIn('bootstrap system '+str(plists/'com.lattice.master.plist'),commands)
  self.assertEqual(commands.count('bootstrap system '+str(plists/'com.lattice.node.plist')),1,'only the candidate starts; rollback must keep the old daemon unloaded')
