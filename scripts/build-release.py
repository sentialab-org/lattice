#!/usr/bin/env python3
"""Build fresh Rust artifacts at one clean revision; record every distributable hash."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
TARGETS={'macos-arm64':'aarch64-apple-darwin','macos-x86_64':'x86_64-apple-darwin','linux-x86_64':'x86_64-unknown-linux-gnu','linux-aarch64':'aarch64-unknown-linux-gnu','windows-x86_64':'x86_64-pc-windows-gnu'}
def main():
 p=argparse.ArgumentParser();p.add_argument('--targets',default=','.join(TARGETS));p.add_argument('--dependencies',type=pathlib.Path,default=ROOT/'target/network-dependencies');a=p.parse_args();targets=a.targets.split(',')
 if any(t not in TARGETS for t in targets):p.error('unsupported target')
 if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT).strip():p.error('commit reviewed source changes before building a release')
 revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip();env={**os.environ,'LATTICE_BUILD_REVISION':revision,'CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER':'x86_64-w64-mingw32-gcc'}
 for target in targets:
  triple=TARGETS[target];command=['cargo','zigbuild' if target.startswith('linux-') else 'build','--workspace','--bins','--release','--locked','--target',triple+('.2.28' if target.startswith('linux-') else '')]
  subprocess.run(command,cwd=ROOT,env=env,check=True)
  source=ROOT/'target'/triple/'release';dest=ROOT/'target/distribution'/target;dest.mkdir(parents=True,exist_ok=True);names=['lattice','lattice-node','lattice-worker','lattice-master','lattice-bootstrapper','lattice-control','lattice-admin']
  if target.startswith('windows-'):names=[n+'.exe' for n in names]+['lattice-update-helper.exe']
  files={}
  for name in names:
   shutil.copy2(source/name,dest/name);files[name]=hashlib.sha256((dest/name).read_bytes()).hexdigest()
  if target.startswith(('macos-','windows-')):
   deps=['wg','wg-quick','wireguard-go','bash','THIRD_PARTY_NOTICES.txt','provenance.json'] if target.startswith('macos-') else ['wireguard.msi','THIRD_PARTY_NOTICES.txt','provenance.json']
   for name in deps:
    path=a.dependencies/target/name
    if not path.is_file() or path.is_symlink():raise SystemExit(f'Network dependency is not prepared: {target}/{name}')
    shutil.copy2(path,dest/name);files[name]=hashlib.sha256(path.read_bytes()).hexdigest()
  (dest/'build-record.json').write_text(json.dumps({'source_revision':revision,'files':files},indent=2)+'\n')
  print(f'{target}: fresh artifacts recorded for {revision}')
if __name__=='__main__':main()
