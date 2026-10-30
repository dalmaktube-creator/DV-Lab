#!/bin/bash
# DV Lab: local source install OR public GitHub bootstrap. No secrets in URLs.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Use sudo bash'; exit 1; }
if [[ -n ${BASH_SOURCE[0]:-} && -f "$(dirname -- "${BASH_SOURCE[0]}")/dvlab/setup.py" ]]; then
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
else
  command -v python3 >/dev/null || { apt-get update; apt-get install -y python3 ca-certificates; }
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  python3 - "$tmp" <<'PY'
import hashlib,io,json,pathlib,re,ssl,sys,tarfile,urllib.request
root=pathlib.Path(sys.argv[1]);repo='dalmaktube-creator/DV-Lab'
def fetch(url,bound):
    request=urllib.request.Request(url,headers={'User-Agent':'DV-Lab-Installer'})
    with urllib.request.urlopen(request,timeout=45,context=ssl.create_default_context()) as r:
        if not r.url.startswith(('https://api.github.com/','https://codeload.github.com/')):raise ValueError('Unexpected HTTPS origin')
        data=r.read(bound+1)
    if len(data)>bound:raise ValueError('Download too large')
    return data
sha=json.loads(fetch('https://api.github.com/repos/'+repo+'/commits/main',65536))['sha']
if not re.fullmatch('[0-9a-f]{40}',sha):raise ValueError('Bad commit identity')
checks=json.loads(fetch('https://api.github.com/repos/'+repo+'/commits/'+sha+'/check-runs?per_page=100',2000000)).get('check_runs',[])
for name in ('unit-and-protocol','ubuntu-isolation','ubuntu-22-isolation','ubuntu-22-hub'):
    matching=[c for c in checks if c.get('name')==name and c.get('head_sha')==sha and c.get('app',{}).get('slug')=='github-actions']
    c=max(matching,key=lambda c:c.get('id',0)) if matching else {}
    if c.get('conclusion')!='success' or c.get('status')!='completed':raise SystemExit('CI for main has not passed; wait for all required green checks before installing')
tree_response=json.loads(fetch('https://api.github.com/repos/'+repo+'/git/trees/'+sha+'?recursive=1',2000000))
if tree_response.get('truncated'):raise ValueError('Git tree truncated')
tree={x['path']:x['sha'] for x in tree_response['tree'] if x['type']=='blob'}
data=fetch('https://codeload.github.com/'+repo+'/tar.gz/'+sha,2000000)
total=0;seen=set()
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as ar:
    for count,m in enumerate(ar):
        if count>=512:raise ValueError('Too many archive entries')
        p=pathlib.PurePosixPath(m.name)
        if p.is_absolute() or '..' in p.parts or '\\' in m.name or p.parts[0] not in ('DV-Lab-'+sha,'dv-lab-'+sha):raise ValueError('Unsafe archive')
        if m.isdir():continue
        if not m.isfile() or m.size>262144:raise ValueError('Unsafe member')
        total+=m.size
        if total>4000000:raise ValueError('Expanded archive too large')
        rel=pathlib.Path(*p.parts[1:])
        if str(rel) in seen:raise ValueError('Duplicate member')
        seen.add(str(rel));dst=root/rel;dst.parent.mkdir(parents=True,exist_ok=True)
        content=ar.extractfile(m).read(m.size)
        if hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()!=tree.get(str(rel)):raise ValueError('Source blob differs from commit tree')
        dst.write_bytes(content);dst.chmod(0o644)
(root/'.source-commit').write_text(sha+'\n')
print('Verified HTTPS source pinned to commit '+sha+' (GitHub CI passed).')
PY
  cd -- "$tmp"
fi
if [[ $# == 0 && -f /etc/dv-lab/update-policy.json ]]; then
  /usr/local/bin/dv-lab
else
  python3 -m dvlab.setup "$@"
fi
