import importlib.util, pathlib, tempfile, unittest, json, hashlib, tarfile, io
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('release',ROOT/'scripts/release_manifest.py');release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
class ReleaseTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.art=self.root/'artifacts';self.source=self.root/'source';self.out=self.root/'staged'
 def tearDown(self): self.tmp.cleanup()
 def fixture(self,target='linux-x86_64'):
  d=self.art/target;d.mkdir(parents=True);files={}
  names=['lattice','lattice-node','lattice-worker','lattice-master','lattice-bootstrapper','lattice-control','lattice-admin']
  if target.startswith('windows'): names=[n+'.exe' for n in names]+['lattice-update-helper.exe','wireguard.msi','THIRD_PARTY_NOTICES.txt','provenance.json']
  if target.startswith('macos'):names+=['wg','wg-quick','wireguard-go','bash','THIRD_PARTY_NOTICES.txt','provenance.json']
  for n in names:
   p=d/n;p.write_bytes(('fixture '+n).encode());p.chmod(0o755);files[n]=hashlib.sha256(p.read_bytes()).hexdigest()
  (d/'build-record.json').write_text(json.dumps({'source_revision':'a'*40,'files':files}))
  suffix='ps1' if target.startswith('windows') else 'sh';osname=target.split('-')[0]
  p=self.source/'scripts'/f'install-node-{osname}.{suffix}';p.parent.mkdir(parents=True);p.write_text('fixture installer')
 def assemble(self,target='linux-x86_64'):release.assemble('0.2.0',self.out,[target],self.art,self.source)
 def test_each_bundle_contains_the_same_verified_optional_components(self):
  self.fixture();self.assemble()
  for role in ['node','master']:
   path=self.out/f'releases/0.2.0/linux-x86_64/{role}.tar.gz'
   contents=release.archive_files(path)
   for name in ['lattice-node','lattice-worker','lattice-master','lattice-control','lattice-admin']:
    self.assertIn(name,contents)
 def test_missing_worker_or_update_helper_blocks_publish(self):
  self.fixture('windows-x86_64');(self.art/'windows-x86_64/lattice-update-helper.exe').unlink()
  with self.assertRaises(ValueError):self.assemble('windows-x86_64')
 def test_corrupt_bundle_blocks_promotion(self):
  self.fixture();self.assemble();p=self.out/'releases/0.2.0/linux-x86_64/node.tar.gz';p.write_bytes(b'corrupt')
  with self.assertRaises(ValueError):release.promote(self.out,self.root/'live')
 def test_archive_rejects_absolute_parent_or_link_entries(self):
  for name,kind in [('/etc/passwd',tarfile.REGTYPE),('../escape',tarfile.REGTYPE),('link',tarfile.SYMTYPE)]:
   p=self.root/'bad.tar.gz'
   with tarfile.open(p,'w:gz') as t:
    entry=tarfile.TarInfo(name);entry.type=kind;t.addfile(entry,io.BytesIO(b''))
   with self.assertRaises(ValueError):release.validate_archive(p)
 def test_missing_target_is_not_advertised(self):
  self.fixture();self.assemble();j=json.loads((self.out/'releases/0.2.0/catalog.json').read_text());self.assertEqual(j['targets'],['linux-x86_64'])
 def test_legacy_binary_paths_remain_available(self):
  self.fixture();self.assemble();self.assertTrue((self.out/'releases/0.2.0/linux-x86_64/lattice-bootstrapper').is_file());release.validate(self.out)
 def test_failed_assembly_keeps_existing_release(self):
  self.fixture();self.assemble();live=self.root/'live';release.promote(self.out,live);old=(live/'releases/stable').read_bytes();(self.art/'linux-x86_64/lattice-worker').unlink()
  with self.assertRaises(ValueError):self.assemble()
  self.assertEqual((live/'releases/stable').read_bytes(),old)
 def test_entry_copy_failure_does_not_advance_stable(self):
  self.fixture();self.assemble();live=self.root/'live';(live/'releases').mkdir(parents=True);(live/'releases/stable').write_text('0.1.0\n');(self.out/'installer').mkdir();(self.out/'installer/linux.sh').write_text('new entry')
  copytree=release.shutil.copytree
  def copying(src,dest,*args,**kwargs):
   if pathlib.Path(src)==self.out/'installer':raise OSError('entry staging failed')
   return copytree(src,dest,*args,**kwargs)
  with patch.object(release.shutil,'copytree',side_effect=copying):
   with self.assertRaises(OSError):release.promote(self.out,live)
  self.assertEqual((live/'releases/stable').read_text(),'0.1.0\n')
