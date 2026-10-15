import unittest,subprocess,pathlib,json,tempfile,os
import test_linux
ROOT=pathlib.Path(__file__).resolve().parents[2]
class VerificationTests(unittest.TestCase):
 def check(self,report):
  with tempfile.NamedTemporaryFile('w',suffix='.json') as f:
   json.dump(report,f);f.flush();return subprocess.run([str(ROOT/'target/debug/lattice-node'),'verify-report',f.name],capture_output=True,timeout=3).returncode
 def sample(self):return dict(source_revision='a'*40,artifact_sha256='b'*64,artifact_verified=True,os='linux',role='node',service_state='running',master_service_state=None,node_id='node-fixture',virtual_ipv4='10.77.0.2/32',handshake_age_ms=1000,overlay_probe=True,route_verified=True,workload_ready=True,peer_tcp=True)
 def test_verification_rejects_service_only_success(self):self.assertNotEqual(self.check(dict(service_state='running')),0)
 def test_verification_rejects_stale_handshake_or_wrong_route(self):
  for patch in [dict(handshake_age_ms=190000),dict(route_verified=False),dict(overlay_probe=False),dict(artifact_sha256=None),dict(artifact_verified=False)]:self.assertNotEqual(self.check({**self.sample(),**patch}),0)
 def test_reinstall_keeps_identity_ip_and_policy(self):
  f=test_linux.LinuxInstallTests();f.setUp()
  try:
   state=f.host/'var/lib/lattice';state.mkdir(parents=True);identity=b'fixture identity';policy=b'{"policy":{"allow_mining":false,"limits":{"cpu_percent":17,"memory_mb":777}},"virtual_ipv4":"10.77.0.7/32"}'
   (state/'identity.json').write_bytes(identity);(state/'node.json').write_bytes(policy)
   for _ in range(2):self.assertEqual(f.run_install().returncode,0)
   self.assertEqual((state/'identity.json').read_bytes(),identity);self.assertEqual((state/'node.json').read_bytes(),policy)
   self.assertEqual(self.check(self.sample()),0)
  finally:f.tearDown()
 def test_rollback_restores_prior_release_after_gateway_or_service_failure(self):self.assertNotEqual(self.check({**self.sample(),'service_state':'stopped'}),0);self.assertNotEqual(self.check({**self.sample(),'peer_tcp':None}),0)
 def test_wrapper_selects_installed_state(self):
  with tempfile.TemporaryDirectory() as tmp:
   node=pathlib.Path(tmp)/'node';node.write_text('#!/bin/sh\nprintf "%s" "$LATTICE_CONFIG"\n');node.chmod(0o755)
   env={**os.environ,'LATTICE_NODE_BINARY':str(node)};env.pop('LATTICE_CONFIG',None)
   r=subprocess.run(['bash',str(ROOT/'scripts/verify-installation.sh')],env=env,capture_output=True,text=True,check=True)
   self.assertEqual(r.stdout,'/Library/Application Support/Lattice/node.json' if os.uname().sysname=='Darwin' else '/var/lib/lattice/node.json')
