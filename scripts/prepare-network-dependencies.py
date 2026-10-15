#!/usr/bin/env python3
"""Prepare pinned, portable network dependencies without administrator installation."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tarfile,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1];LOCK=json.loads((ROOT/'scripts/network-dependencies.lock.json').read_text());WORK=ROOT/'target/network-dependency-sources';OUT=ROOT/'target/network-dependencies'
def run(args,cwd=None,env=None):subprocess.run(args,cwd=cwd,env=env,check=True)
def download(url,dest,expected):
 if not dest.exists() or hashlib.sha256(dest.read_bytes()).hexdigest()!=expected:
  if not url.startswith('https://'):raise ValueError('HTTPS dependency URL required')
  urllib.request.urlretrieve(url,dest)
 if hashlib.sha256(dest.read_bytes()).hexdigest()!=expected:raise ValueError('dependency checksum mismatch')
def checkout(name):
 pin=LOCK[name]['source'];d=WORK/name
 if not (d/'.git').exists():run(['git','clone','--no-checkout',pin['url'],str(d)])
 run(['git','checkout','--detach',pin['revision']],cwd=d)
 if subprocess.check_output(['git','rev-parse','HEAD'],cwd=d,text=True).strip()!=pin['revision']:raise ValueError('dependency revision mismatch')
 return d
def main():
 p=argparse.ArgumentParser();p.add_argument('--targets',default='macos-arm64,macos-x86_64,windows-x86_64');a=p.parse_args();targets=a.targets.split(',');WORK.mkdir(parents=True,exist_ok=True);OUT.mkdir(parents=True,exist_ok=True)
 if any(t.startswith('macos-') for t in targets):
  tools=checkout('wireguard-tools');go=checkout('wireguard-go');bash=LOCK['bash'];archive=WORK/'bash-5.3.tar.gz';download(bash['source']['url'].replace('https://ftpmirror.gnu.org/','https://ftp.gnu.org/gnu/'),archive,bash['source']['checksum']);base=WORK/'bash-5.3'
  if not (base/'.lattice-patches-applied').exists():
   if base.exists():raise ValueError('incomplete Bash source; inspect or choose a fresh build directory')
   with tarfile.open(archive) as t:t.extractall(WORK,filter='data')
   for patch in bash['patches']:
    file=WORK/pathlib.Path(patch['url']).name;download(patch['url'].replace('https://ftpmirror.gnu.org/','https://ftp.gnu.org/gnu/'),file,patch['sha256']);run(['patch','-p0','-i',str(file)],cwd=base)
   (base/'.lattice-patches-applied').write_text(bash['version'])
  for target in targets:
   if not target.startswith('macos-'):continue
   arch='arm64' if target=='macos-arm64' else 'x86_64';goarch='arm64' if arch=='arm64' else 'amd64';host='aarch64-apple-darwin' if arch=='arm64' else 'x86_64-apple-darwin';dest=OUT/target;dest.mkdir(exist_ok=True)
   run(['make','clean'],cwd=tools/'src');run(['make','-j4',f'CC=clang -arch {arch}','wg'],cwd=tools/'src');shutil.copy2(tools/'src/wg',dest/'wg');shutil.copy2(tools/'src/wg-quick/darwin.bash',dest/'wg-quick')
   run(['go','build','-trimpath','-ldflags=-s -w','-o',str(dest/'wireguard-go'),'.'],cwd=go,env={**os.environ,'GOOS':'darwin','GOARCH':goarch,'CGO_ENABLED':'0'})
   build=WORK/f'bash-build-{arch}';build.mkdir(exist_ok=True);env={**os.environ,'CC':f'clang -arch {arch}','bash_cv_func_strchrnul_works':'no'}
   run([str(base/'configure'),'--disable-nls','--disable-readline','--without-bash-malloc',f'--host={host}','--build=aarch64-apple-darwin'],cwd=build,env=env);run(['make','-j4'],cwd=build,env=env);shutil.copy2(build/'bash',dest/'bash')
   for name in ['wg','wg-quick','wireguard-go','bash']: (dest/name).chmod(0o755)
   for name in ['wg','bash']:
    linked=subprocess.check_output(['otool','-L',str(dest/name)],text=True)
    if '/opt/homebrew/' in linked or '/usr/local/' in linked:raise ValueError('nonportable private dependency')
   notice='Lattice managed network dependencies\n\n'+(tools/'COPYING').read_text()+'\n\n'+(go/'LICENSE').read_text()+'\n\n'+(base/'COPYING').read_text();(dest/'THIRD_PARTY_NOTICES.txt').write_text(notice);(dest/'provenance.json').write_text(json.dumps({'sources':{k:LOCK[k] for k in ['bash','wireguard-tools','wireguard-go']},'build_target':target,'commands':'scripts/prepare-network-dependencies.py; portable Bash disables NLS/readline; WireGuard tools clang -arch; wireguard-go CGO_ENABLED=0'},indent=2))
  sources=OUT/'sources';sources.mkdir(exist_ok=True)
  with tarfile.open(sources/'lattice-network-corresponding-sources.tar.gz','w:gz') as t:
   def allow(info):return None if '/.git/' in '/'+info.name+'/' else info
   for d in [base,tools,go]:t.add(d,arcname=d.name,filter=allow)
   for name in ['prepare-network-dependencies.py','network-dependencies.lock.json']:t.add(ROOT/'scripts'/name,arcname='lattice-build/'+name)
 if 'windows-x86_64' in targets:
  pin=LOCK['wireguard-windows'];dest=OUT/'windows-x86_64';dest.mkdir(exist_ok=True);download(pin['url'],dest/'wireguard.msi',pin['sha256']);(dest/'THIRD_PARTY_NOTICES.txt').write_text('Original WireGuard for Windows MSI package.\nPublisher: WireGuard LLC.\nVersion: '+pin['version']+'\nLicense and source: https://git.zx2c4.com/wireguard-windows/\nUpstream installer and package license notices are retained inside the unmodified MSI.\nNative Authenticode verification is mandatory during installation.\n');(dest/'provenance.json').write_text(json.dumps(pin,indent=2))
if __name__=='__main__':main()
