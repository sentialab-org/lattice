#!/usr/bin/env python3
"""Assemble immutable, allowlisted releases. Never execute an input artifact."""
import argparse, hashlib, io, json, os, pathlib, re, shutil, stat, tarfile, tempfile, uuid, zipfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = ['macos-arm64','macos-x86_64','linux-x86_64','linux-aarch64','windows-x86_64']
def sha(data): return hashlib.sha256(data).hexdigest()
def version_ok(v): return bool(re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?', v))
def required(target, role):
 suffix = '.exe' if target.startswith('windows-') else ''
 names = ['lattice-node'+suffix, 'lattice-worker'+suffix, 'install.'+('ps1' if suffix else 'sh')]
 if role == 'master': names.append('lattice-master'+suffix)
 if suffix: names += ['lattice-update-helper.exe','wireguard.msi','THIRD_PARTY_NOTICES.txt','provenance.json']
 if target.startswith('macos-'): names += ['wg','wg-quick','wireguard-go','bash','THIRD_PARTY_NOTICES.txt','provenance.json']
 return set(names)
def safe_name(name): return bool(name and '/' not in name and '\\' not in name and ':' not in name and name not in ('.','..') and not name.startswith('.'))
def archive_files(path):
 result={}
 if path.name.endswith('.zip'):
  with zipfile.ZipFile(path) as z:
   for e in z.infolist():
    if not safe_name(e.filename) or stat.S_ISLNK(e.external_attr>>16) or e.file_size>256*1024*1024 or e.filename in result: raise ValueError('unsafe archive entry')
    result[e.filename]=(z.read(e), bool((e.external_attr>>16)&0o111))
 else:
  with tarfile.open(path,'r:gz') as t:
   for e in t:
    if not safe_name(e.name) or not e.isfile() or e.size>256*1024*1024 or e.name in result: raise ValueError('unsafe archive entry')
    result[e.name]=(t.extractfile(e).read(), bool(e.mode&0o111))
 if sum(len(v[0]) for v in result.values())>1024*1024*1024: raise ValueError('bundle too large')
 return result
def validate_archive(path):
 try:
  contents=archive_files(path);manifest=json.loads(contents['manifest.json'][0]);target=manifest['target'];role=manifest['role']
  if manifest['schema_version']!=1 or target not in TARGETS or role not in ['node','master'] or not version_ok(manifest['version']):raise ValueError('invalid bundle metadata')
  files=manifest['files'];names=[e['path'] for e in files]
  if len(set(names))!=len(names) or set(names)!=required(target,role) or set(contents)!=set(names)|{'manifest.json'}:raise ValueError('incomplete or unexpected bundle contents')
  for e in files:
   data,executable=contents[e['path']]
   if len(data)!=e['size_bytes'] or sha(data)!=e['sha256'] or executable!=e['executable']:raise ValueError('bundle content mismatch')
  return manifest
 except (KeyError, OSError, json.JSONDecodeError, tarfile.TarError, zipfile.BadZipFile) as e: raise ValueError('invalid bundle') from e
def checked_out(path):
 raw=pathlib.Path(path).absolute()
 if raw.is_symlink():raise ValueError('symlink output root')
 p=raw.parent.resolve()/raw.name
 if p==pathlib.Path('/') or p==pathlib.Path.home().resolve() or p==ROOT or ROOT.is_relative_to(p):raise ValueError('unsafe output root')
 return p
def assemble(version,out,targets,artifacts=None,source=None):
 if not version_ok(version) or not targets or len(set(targets))!=len(targets) or any(t not in TARGETS for t in targets):raise ValueError('invalid release target/version')
 out=checked_out(out);artifacts=pathlib.Path(artifacts or ROOT/'target/distribution');source=pathlib.Path(source or ROOT)
 # Preflight every artifact and its build provenance before creating output.
 selected={};revision=None
 for target in targets:
  d=artifacts/target
  try: record=json.loads((d/'build-record.json').read_text())
  except (OSError,ValueError) as e:raise ValueError(f'missing build record: {target}') from e
  rev=record.get('source_revision','')
  if not re.fullmatch('[a-f0-9]{40}',rev) or (revision and revision!=rev):raise ValueError('mixed or invalid source revisions')
  revision=rev;suffix='.exe' if target.startswith('windows-') else '';osname=target.split('-')[0]
  installer=source/'scripts'/f'install-node-{osname}.{ "ps1" if suffix else "sh" }'
  if not installer.is_file() or installer.is_symlink():raise ValueError('missing installer')
  selected[target]={}
  names=required(target,'master')-{'install.ps1','install.sh'}
  if osname=='linux':names|={'lattice-bootstrapper','lattice-control'}
  for name in names:
   p=d/name
   if not p.is_file() or p.is_symlink() or sha(p.read_bytes())!=record.get('files',{}).get(name):raise ValueError(f'missing, stale, or corrupt artifact: {target}/{name}')
   selected[target][name]=p.read_bytes()
  selected[target]['install.ps1' if suffix else 'install.sh']=installer.read_bytes()
 if out.exists():raise ValueError('assembly output already exists; choose a new staging directory')
 out.parent.mkdir(parents=True,exist_ok=True)
 stage=pathlib.Path(tempfile.mkdtemp(prefix='.lattice-release-',dir=out.parent))
 try:
  release=stage/'releases'/version;release.mkdir(parents=True)
  catalog={'schema_version':1,'version':version,'source_revision':revision,'targets':targets,'bundles':[]}
  for target in targets:
   d=release/target;d.mkdir();ext='zip' if target.startswith('windows-') else 'tar.gz'
   for role in ['node','master']:
    entries=selected[target];names=sorted(required(target,role));files=[{'path':n,'sha256':sha(entries[n]),'size_bytes':len(entries[n]),'executable':not n.endswith(('.txt','.json','.msi','.ps1'))} for n in names]
    manifest={'schema_version':1,'version':version,'target':target,'role':role,'files':files};archive=d/f'{role}.{ext}';data={n:entries[n] for n in names};data['manifest.json']=json.dumps(manifest,sort_keys=True).encode();modes={e['path']:0o755 if e['executable'] else 0o644 for e in files};modes['manifest.json']=0o644
    if ext=='zip':
     with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
      for n,b in data.items():i=zipfile.ZipInfo(n);i.external_attr=(stat.S_IFREG|modes[n])<<16;z.writestr(i,b)
    else:
     with tarfile.open(archive,'w:gz') as t:
      for n,b in data.items():i=tarfile.TarInfo(n);i.size=len(b);i.mode=modes[n];t.addfile(i,io.BytesIO(b))
    digest=sha(archive.read_bytes());archive.with_name(archive.name+'.sha256').write_text(digest+'\n');catalog['bundles'].append({'path':f'{target}/{archive.name}','sha256':digest})
   for n,b in selected[target].items():
    if n.startswith('lattice-'):(d/n).write_bytes(b);(d/(n+'.sha256')).write_text(sha(b)+'\n')
  (release/'catalog.json').write_text(json.dumps(catalog,indent=2));(stage/'release-version').write_text(version+'\n')
  for name in ['linux.sh','macos.sh','windows.ps1','index.html']:
   p=source/'web/installer'/name
   if p.is_file():(stage/'installer').mkdir(exist_ok=True);shutil.copy2(p,stage/'installer'/name)
  validate(stage);os.rename(stage,out)
 finally:
  if stage.exists():shutil.rmtree(stage)
def validate(root):
 root=pathlib.Path(root)
 try:
  version=(root/'release-version').read_text().strip()
  if not version_ok(version):raise ValueError('invalid version')
  d=root/'releases'/version;catalog=json.loads((d/'catalog.json').read_text())
  if catalog['version']!=version or catalog['targets']!=sorted(set(catalog['targets']),key=catalog['targets'].index):raise ValueError('invalid catalog')
  expected={f'{t}/{r}.{ "zip" if t.startswith("windows-") else "tar.gz" }' for t in catalog['targets'] for r in ['node','master']}
  if {b['path'] for b in catalog['bundles']}!=expected:raise ValueError('incomplete catalog')
  for b in catalog['bundles']:
   p=d/b['path'];digest=sha(p.read_bytes())
   if digest!=b['sha256'] or p.with_name(p.name+'.sha256').read_text().strip()!=digest:raise ValueError('corrupt archive')
   m=validate_archive(p)
   if m['version']!=version or m['target']!=p.parent.name or m['role']!=p.name.split('.')[0]:raise ValueError('bundle metadata mismatch')
  return version
 except (OSError,KeyError,json.JSONDecodeError) as e:raise ValueError('invalid staged release') from e
def atomic_text(path,text):
 p=path.with_name('.'+path.name+'.'+uuid.uuid4().hex);p.write_text(text);os.replace(p,path)
def promote(staged,out):
 staged=pathlib.Path(staged);out=checked_out(out);version=validate(staged);dest=out/'releases'/version
 if dest.exists():raise ValueError('immutable release already exists')
 dest.parent.mkdir(parents=True,exist_ok=True);temp=dest.with_name('.'+version+'.'+uuid.uuid4().hex)
 shutil.copytree(staged/'releases'/version,temp);os.rename(temp,dest)
 # Existing versions and previous pointer are retained for rollback. Pointer is the final commit point.
 if (out/'releases/stable').exists():shutil.copy2(out/'releases/stable',out/'releases/stable.previous')
 atomic_text(out/'releases/stable',version+'\n')
 for folder in ['installer']:
  if (staged/folder).exists():shutil.copytree(staged/folder,out/folder,dirs_exist_ok=True)
 atomic_text(out/'release-version',version+'\n')
def main():
 p=argparse.ArgumentParser();s=p.add_subparsers(dest='command',required=True)
 a=s.add_parser('assemble');a.add_argument('--version',required=True);a.add_argument('--out',type=pathlib.Path,required=True);a.add_argument('--targets',default=','.join(TARGETS));a.add_argument('--artifacts',type=pathlib.Path);a.add_argument('--source',type=pathlib.Path)
 a=s.add_parser('validate');a.add_argument('--root',type=pathlib.Path,required=True)
 a=s.add_parser('promote');a.add_argument('--staged',type=pathlib.Path,required=True);a.add_argument('--out',type=pathlib.Path,required=True)
 args=p.parse_args()
 try:
  if args.command=='assemble':assemble(args.version,args.out,args.targets.split(','),args.artifacts,args.source)
  elif args.command=='validate':validate(args.root)
  else:promote(args.staged,args.out)
 except ValueError as e:p.exit(1,str(e)+'\n')
if __name__=='__main__':main()
