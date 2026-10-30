#!/usr/bin/python3
"""Pinned root-owned update broker. NEVER imports or executes downloaded Python.
The operator trusts successful GitHub Actions commits on fixed repo/main.
Only service-account application code is replaced; root helpers/units/config stay pinned.
"""
import ast
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

REPO='dalmaktube-creator/DV-Lab'
POLICY=Path('/etc/dv-lab/update-policy.json')
STATE=Path('/var/lib/dv-lab-updater')
ROOT=Path('/opt/dv-lab')
MAX_ARCHIVE=2_000_000
ALLOW_ROOT={'Containerfile','install.sh','README.md','README.fa.md','SECURITY.md','UPDATE.md','release.json','.source-commit'}
APP_REQUIRED={'updating.py','__init__.py','common.py','hub.py','agent.py','runner.py','sampling.py','menu.py','setup.py'}
CAPSULE=('__init__.py','common.py','runner.py','sampling.py')
SHA=re.compile(r'[0-9a-f]{40}')


def validate_commit(value):
    if not isinstance(value,str) or not SHA.fullmatch(value):raise ValueError('Use a full lowercase 40-character commit SHA')
    return value


def save(path,data):
    path=Path(path);tmp=path.with_name('.'+path.name+'.tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:json.dump(data,f);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        u=urlsplit(newurl)
        if u.scheme!='https' or u.hostname not in ('api.github.com','codeload.github.com') or u.username or u.password or (u.port not in (None,443)):
            raise ValueError('Unexpected download redirect')
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def fetch(url,limit=MAX_ARCHIVE):
    u=urlsplit(url)
    if u.scheme!='https' or u.hostname not in ('api.github.com','codeload.github.com') or u.username or u.password or u.port not in (None,443):raise ValueError('Unexpected download URL')
    req=urllib.request.Request(url,headers={'User-Agent':'DV-Lab-Update/0.2','Accept':'application/vnd.github+json'})
    opener=urllib.request.build_opener(Redirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(req,timeout=25) as response:data=response.read(limit+1)
    if len(data)>limit:raise ValueError('Download bound exceeded')
    return data


def api(path):return json.loads(fetch('https://api.github.com/repos/'+REPO+path))


def candidate(commit=None):
    latest=validate_commit(api('/commits/main')['sha'])
    commit=validate_commit(commit or latest)
    if commit!=latest:
        comparison=api('/compare/'+commit+'...'+latest)
        if comparison.get('status') not in ('ahead','identical'):raise ValueError('Candidate is not an ancestor of main')
    checks=api('/commits/'+commit+'/check-runs?per_page=100').get('check_runs',[])
    # CI job name is an installed trust policy, not caller input.
    required=('unit-and-protocol','ubuntu-isolation')
    passed=True
    for name in required:
        matching=[c for c in checks if c.get('name')==name and c.get('head_sha')==commit and c.get('app',{}).get('slug')=='github-actions']
        c=max(matching,key=lambda c:c.get('id',0)) if matching else {}
        passed=passed and c.get('status')=='completed' and c.get('conclusion')=='success'

    return dict(commit=commit,latest=latest,ci_passed=passed,repository=REPO)


def unpack(data,target,commit,tree=None):
    """No extractall, links, devices, traversal, executable hooks or uncontrolled trees."""
    validate_commit(commit);target=Path(target)
    kept={};seen=set();expanded=0
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
        for count,member in enumerate(archive):
            if count>=512:raise ValueError('Archive entry bound exceeded')
            p=PurePosixPath(member.name)
            if p.is_absolute() or '..' in p.parts or not p.parts or '\\' in member.name:raise ValueError('Unsafe archive path')
            if p.parts[0] not in ('DV-Lab-'+commit,'dv-lab-'+commit):raise ValueError('Unexpected archive root')
            if member.isdir():continue
            if not member.isfile():raise ValueError('Links/devices are not allowed')
            if member.size>262144:raise ValueError('Archive file bound exceeded')
            expanded+=member.size
            if expanded>4_000_000:raise ValueError('Expanded archive bound exceeded')
            rel=PurePosixPath(*p.parts[1:])
            if str(rel) in seen:raise ValueError('Duplicate archive member')
            seen.add(str(rel))
            allowed=(len(rel.parts)==1 and str(rel) in ALLOW_ROOT) or (len(rel.parts)==2 and rel.parts[0]=='dvlab' and re.fullmatch('[a-z_]+\\.py',rel.parts[1]))
            if not allowed:continue
            content=archive.extractfile(member).read(member.size+1)
            if len(content)!=member.size:raise ValueError('Archive size mismatch')
            if tree is not None and hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()!=tree.get(str(rel)):
                raise ValueError('Archive content does not match pinned Git tree')
            if str(rel).endswith('.py'):ast.parse(content.decode('utf-8'),filename=str(rel))
            kept[str(rel)]=content
    if not all('dvlab/'+x in kept for x in APP_REQUIRED):raise ValueError('Incomplete application')
    manifest=json.loads(kept.get('release.json',b'{}'))
    if manifest.get('update_schema')!=1 or manifest.get('database_schema')!=1 or manifest.get('requires_guard')!=1:raise ValueError('Root policy/schema migration needs operator approval')
    if not isinstance(manifest.get('version'),str) or not re.fullmatch(r'[0-9A-Za-z.+_-]{1,64}',manifest['version']):raise ValueError('Invalid release version')
    target.mkdir(mode=0o755)
    for rel,content in kept.items():
        dst=target/rel;dst.parent.mkdir(mode=0o755,parents=True,exist_ok=True);dst.write_bytes(content);dst.chmod(0o644)
    (target/'.source-commit').write_text(commit+'\n')
    cap=target/'capsule/dvlab';cap.mkdir(parents=True,mode=0o755)
    for name in CAPSULE:shutil.copyfile(target/'dvlab'/name,cap/name)
    for p in target.rglob('*'):
        if p.is_dir():p.chmod(0o755)
    target.chmod(0o755)
    # Bootstrap bundle of this exact candidate; no credentials or mutable files.
    with tarfile.open(target/'dv-lab.tar.gz','w:gz') as out:
        for rel in sorted(kept):out.add(target/rel,arcname='dv-lab/'+rel,recursive=False)
        out.add(target/'.source-commit',arcname='dv-lab/.source-commit',recursive=False)
    (target/'dv-lab.tar.gz').chmod(0o644)
    return manifest


def command(args,check=True):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=45)


def node_command(verb):
    import pwd
    who=pwd.getpwnam('dvlab-node');runtime='/run/user/'+str(who.pw_uid)
    return ['runuser','-u','dvlab-node','--','env','-i','HOME='+who.pw_dir,'USER=dvlab-node','LOGNAME=dvlab-node','PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','XDG_CONFIG_HOME='+who.pw_dir+'/.config','XDG_DATA_HOME='+who.pw_dir+'/.local/share','XDG_RUNTIME_DIR='+runtime,'DBUS_SESSION_BUS_ADDRESS=unix:path='+runtime+'/bus','/usr/bin/systemctl','--user',verb,'dv-lab-agent.service']


def services():
    result=[]
    if Path('/etc/dv-lab/hub.json').exists():result.append(('hub',lambda verb:['systemctl',verb,'dv-lab-hub.service']))
    if Path('/etc/dv-lab/agent.json').exists():result.append(('agent',node_command))
    return result


def switch(path):
    path=Path(path)
    if path.parent!=ROOT/'releases' or not SHA.fullmatch(path.name):raise ValueError('Unexpected release directory')
    tmp=ROOT/'.next';tmp.unlink(missing_ok=True);tmp.symlink_to(path);os.replace(tmp,ROOT/'current')


def backup_db():
    cfg=Path('/etc/dv-lab/hub.json')
    if not cfg.exists():return None
    # Never follow a caller-provided database path.
    db=Path('/var/lib/dv-lab-hub/hub.sqlite3');dest=STATE/'database-backup.sqlite3'
    if db.is_symlink():raise ValueError('Unexpected database symlink')
    if not db.exists():return None
    dest.unlink(missing_ok=True)
    with sqlite3.connect(db) as src,sqlite3.connect(dest) as dst:src.backup(dst)
    dest.chmod(0o600)
    return db,dest


def restore_db(backup):
    if not backup:return
    db,src=backup;stat=db.stat()
    for suffix in ('-wal','-shm'):Path(str(db)+suffix).unlink(missing_ok=True)
    shutil.copyfile(src,db);os.chown(db,stat.st_uid,stat.st_gid);db.chmod(0o600)


def healthy(expected,active):
    for _ in range(25):
        good=True
        for name,argv in active:
            if command(argv('is-active'),check=False).returncode:good=False;continue
            if name=='hub':
                cfg=json.loads(Path('/etc/dv-lab/hub.json').read_text())
                try:
                    # Verify a live local HTTP response, TLS chain configured by operator.
                    req=urllib.request.Request(cfg['public_url']+'/health')
                    with urllib.request.urlopen(req,timeout=3) as r:body=json.load(r)
                    if body.get('commit')!=expected:good=False
                except Exception:good=False
            else:
                try:
                    body=json.loads(Path('/var/lib/dv-lab-node/heartbeat.json').read_text())
                    if body.get('commit')!=expected or time.time()-body.get('at',0)>40:good=False
                except Exception:good=False
        if good:return True
        time.sleep(2)
    return False


def status():
    path=STATE/'status.json'
    value=json.loads(path.read_text()) if path.exists() else {'state':'idle'}
    value['current']=str((ROOT/'current').resolve().name) if (ROOT/'current').exists() else None
    return value


def worker():
    with open(STATE/'worker.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        req=json.loads((STATE/'request.json').read_text());commit=validate_commit(req['commit'])
        old=(ROOT/'current').resolve();target=ROOT/'releases'/commit
        active=[];backup=None;switched=False
        try:
            save(STATE/'status.json',dict(state='verifying',target=commit,at=time.time()))
            if req['action']=='apply':
                info=candidate(commit)
                if not info['ci_passed']:raise ValueError('Required GitHub Actions CI has not passed')
                if target==old:raise ValueError('Already running this commit')
                if not target.exists():
                    data=fetch('https://codeload.github.com/'+REPO+'/tar.gz/'+commit)
                    stage=ROOT/'releases'/('.stage-'+commit)
                    if stage.exists():shutil.rmtree(stage)
                    tree_response=api('/git/trees/'+commit+'?recursive=1')
                    if tree_response.get('truncated'):raise ValueError('Git tree truncated')
                    tree={x['path']:x['sha'] for x in tree_response['tree'] if x['type']=='blob'}
                    unpack(data,stage,commit,tree);os.rename(stage,target)
            elif req['action']=='rollback':
                if not target.is_dir() or target==old:raise ValueError('No retained previous release')
            else:raise ValueError('Unknown update request')
            active=[(name,argv) for name,argv in services() if command(argv('is-active'),check=False).returncode==0]
            if not active:raise ValueError('No running lab services; start them before updating')
            # Stop first: node service cleanup destroys its own ephemeral capsule.
            save(STATE/'status.json',dict(state='stopping_labs',target=commit,at=time.time()))
            for _,argv in active:command(argv('stop'))
            backup=backup_db();switch(target);switched=True
            for _,argv in active:command(argv('start'))
            if not healthy(commit,active):raise RuntimeError('New application failed live health verification')
            save(STATE/'previous.json',dict(commit=old.name))
            save(STATE/'status.json',dict(state='updated' if req['action']=='apply' else 'rolled_back',target=commit,previous=old.name,at=time.time()))
            # Keep current + previous; bound release disk growth.
            for p in (ROOT/'releases').iterdir():
                if p.is_dir() and p not in (target,old):shutil.rmtree(p)
        except Exception as exc:
            if switched:
                for _,argv in active:command(argv('stop'),check=False)
                restore_db(backup);switch(old)
            for _,argv in active:command(argv('start'),check=False)
            old_ok=healthy(old.name,active) if active else False
            save(STATE/'status.json',dict(state='failed_restored' if switched and old_ok else 'failed_needs_inspection',target=commit,error=type(exc).__name__+': '+str(exc)[:180],at=time.time()))
        finally:
            if backup:backup[1].unlink(missing_ok=True)


def request(data):
    if not isinstance(data,dict) or set(data)-{'action','commit'}:raise ValueError('Unknown update fields')
    action=data.get('action')
    if action=='status':return status()
    if action=='check':return candidate(data.get('commit'))
    if action not in ('apply','rollback'):raise ValueError('Use check, status, apply or rollback')
    if action=='rollback':commit=validate_commit(json.loads((STATE/'previous.json').read_text())['commit'])
    else:commit=validate_commit(data.get('commit'))
    # systemd serializes one fixed unit; the mutex also protects request replacement.
    with open(STATE/'request.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if command(['systemctl','show','--property=ActiveState','--value','dv-lab-update.service'],check=False).stdout.strip() in ('active','activating','reloading'):raise ValueError('Update already running')
        save(STATE/'request.json',dict(action=action,commit=commit))
        save(STATE/'status.json',dict(state='queued',target=commit,at=time.time()))
        command(['systemctl','start','--no-block','dv-lab-update.service'])
    return dict(state='queued',commit=commit,next='status; control connection may reconnect during update')


def main():
    if os.geteuid()!=0:raise SystemExit('Root broker required')
    os.umask(0o077)
    st=POLICY.stat()
    if st.st_uid!=0 or st.st_mode&0o022:raise SystemExit('Unsafe update policy')
    policy=json.loads(POLICY.read_text())
    if policy.get('repository')!=REPO or policy.get('guard_schema')!=1:raise SystemExit('Unknown update trust policy')
    if sys.argv[1:]==['--worker']:worker();return
    if sys.argv[1:]:raise SystemExit('No command-line arguments allowed')
    raw=sys.stdin.buffer.read(4097)
    if len(raw)>4096:raise ValueError('Request too large')
    print(json.dumps(request(json.loads(raw))))

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'error':type(exc).__name__+': '+str(exc)[:180]}));sys.exit(1)
