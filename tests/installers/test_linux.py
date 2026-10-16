import os,pathlib,tempfile,subprocess,unittest,json,shutil,socket
ROOT=pathlib.Path(__file__).resolve().parents[2]
class LinuxInstallTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='lattice test ');self.dir=pathlib.Path(self.tmp.name);self.art=self.dir/'artifacts';self.art.mkdir();self.host=self.dir/'host';self.host.mkdir();self.shims=self.dir/'shims';self.shims.mkdir();self.log=self.dir/'commands'
  for name in ['systemctl','apt-get','wg','ip','id']:
   p=self.shims/name;p.write_text('#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$HARNESS_LOG"\nexit 0\n');p.chmod(0o755)
  (self.shims/'id').write_text('#!/bin/sh\necho 0\n')
  node=self.art/'lattice-node';node.write_text('#!/bin/sh\ncase "$1" in verify-bundle) exit 0;; setup) printf \'{"network_ready":true,"stage":"waiting_for_master"}\\n\'; exit "${HARNESS_SETUP_EXIT:-2}";; esac\n');node.chmod(0o755)
  for name in ['lattice-worker','lattice-master']:(self.art/name).write_text('fixture')
  self.env={**os.environ,'PATH':str(self.shims)+':'+os.environ['PATH'],'LATTICE_INSTALL_TEST_MODE':'1','LATTICE_INSTALL_TEST_ROOT':str(self.host),'HARNESS_LOG':str(self.log)}
 def tearDown(self):self.tmp.cleanup()
 def run_install(self,role='node',**env):return subprocess.run(['bash',str(ROOT/'scripts/install-node-linux.sh'),'--artifact-dir',str(self.art),'--role',role,'--bootstrap-url','https://fixture.test'],env={**self.env,**env},capture_output=True,text=True)
 def test_curl_pipe_reads_prompts_from_tty(self):
  source=(ROOT/'web/installer/linux.sh').read_text();self.assertIn('/dev/tty',source);self.assertNotIn('read -r ',source.split('/dev/tty')[0])
 def test_noninteractive_missing_input_fails_without_loop(self):
  r=subprocess.run(['bash',str(ROOT/'web/installer/linux.sh')],input='',env={**self.env,'LATTICE_ROLE':'invalid','LATTICE_NONINTERACTIVE':'1'},text=True,capture_output=True,timeout=3);self.assertNotEqual(r.returncode,0)
 def test_sudo_cancelled_does_not_replace_binaries(self):
  p=self.shims/'id';p.write_text('#!/bin/sh\necho 501\n');p.chmod(0o755);p=self.shims/'sudo';p.write_text('#!/bin/sh\nexit 1\n');p.chmod(0o755)
  self.assertNotEqual(self.run_install().returncode,0);self.assertFalse((self.host/'usr/local/lib/lattice/current/lattice-node').exists())
 def test_downloaded_helper_paths_are_self_contained(self):self.assertNotIn('lattice-ipc.py',(ROOT/'scripts/install-node-linux.sh').read_text());self.assertEqual(self.run_install().returncode,0)
 def test_paths_with_spaces_are_preserved(self):self.assertEqual(self.run_install().returncode,0);self.assertTrue((self.host/'etc/systemd/system/lattice-node.service').exists())
 def test_stale_socket_does_not_count_as_new_daemon_readiness(self):
  endpoint=self.host/'run/lattice/node.sock';endpoint.parent.mkdir(parents=True)
  listener=socket.socket(socket.AF_UNIX);listener.bind(str(endpoint));listener.close()
  self.assertTrue(endpoint.exists());installed=self.run_install()
  self.assertEqual(installed.returncode,0,installed.stderr);self.assertFalse(endpoint.exists())
 @unittest.skipUnless(shutil.which('systemd-analyze'), 'A native systemd parser is required')
 def test_native_systemd_accepts_node_and_master_environment_files(self):
  installed=self.run_install('master');self.assertEqual(installed.returncode,0,installed.stderr)
  for role in ['node','master']:
   unit=self.host/f'etc/systemd/system/lattice-{role}.service'
   parsed=subprocess.run(['systemd-analyze','verify','--man=no',str(unit)],capture_output=True,text=True)
   self.assertEqual(parsed.returncode,0,parsed.stderr)
   self.assertNotIn('EnvironmentFile= path is not absolute',parsed.stderr)
 def test_owner_can_traverse_program_directories_while_state_stays_private(self):
  result=self.run_install();self.assertEqual(result.returncode,0,result.stderr)
  for name in ['usr/local/lib/lattice','usr/local/lib/lattice/current']:
   self.assertEqual((self.host/name).stat().st_mode&0o055,0o055,name)
  for name in ['var/lib/lattice','etc/lattice']:
   self.assertEqual((self.host/name).stat().st_mode&0o077,0,name)
 def test_node_installs_without_token(self):r=self.run_install();self.assertEqual(r.returncode,0,r.stderr);self.assertNotIn('ENROLLMENT_TOKEN',(self.host/'etc/lattice/node.env').read_text())
 def test_explicit_participation_acceptance_reaches_native_setup(self):
  node=self.art/'lattice-node';node.write_text('#!/bin/sh\ncase "$1" in setup) printf "%s\\n" "$*" >> "$HARNESS_LOG";; esac\nexit 0\n');node.chmod(0o755)
  result=subprocess.run(['bash',str(ROOT/'scripts/install-node-linux.sh'),'--artifact-dir',str(self.art),'--accept-terms'],env=self.env,capture_output=True,text=True)
  self.assertEqual(result.returncode,0,result.stderr);self.assertIn('--accept-terms',self.log.read_text())
 def test_later_master_install_preserves_existing_node_state(self):
  state=self.host/'var/lib/lattice';state.mkdir(parents=True)
  originals={'identity.json':'private identity fixture','node.json':'owner policy fixture','setup.json':'owner choice fixture'}
  for name,value in originals.items():(state/name).write_text(value)
  result=self.run_install('master');self.assertEqual(result.returncode,0,result.stderr)
  for name,value in originals.items():self.assertEqual((state/name).read_text(),value)
  self.assertTrue((self.host/'usr/local/lib/lattice/current/lattice-master').exists());self.assertIn('start lattice-master',self.log.read_text())
 def test_master_requires_activation(self):r=self.run_install('master',HARNESS_SETUP_EXIT='1');self.assertNotEqual(r.returncode,0);self.assertNotIn('start lattice-master',self.log.read_text())
 def test_failed_health_restores_old_service_and_files(self):
  dest=self.host/'usr/local/lib/lattice/current';dest.mkdir(parents=True);(dest/'lattice-node').write_text('old');r=self.run_install(HARNESS_SETUP_EXIT='1');self.assertNotEqual(r.returncode,0);self.assertEqual((dest/'lattice-node').read_text(),'old')
