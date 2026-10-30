"""Pinned root resource broker. Fixed node account/cgroup/files only; no shell.

The initial operator-approved ceiling cannot be expanded through this socket.
Changing limits destroys the lab capsule first (controller responsibility), and
shrinks are refused unless the account has actual memory headroom.
"""
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import sys

CONFIG=Path('/etc/dv-lab/agent.json')
POLICY=Path('/etc/dv-lab/resource-policy.json')
STATE=Path('/var/lib/dv-lab-resource')
DROP_ROOT=Path('/etc/systemd/system')
FIELDS=('account_cpus','account_memory_mib','capsule_cpus','capsule_memory_mib')


def ceilings(cpus,memory_mib):
    return dict(max_account_cpus=round(max(.5,min(4,cpus*.75)),2),
                max_account_memory_mib=max(192,min(2048,int(memory_mib*.25))))


def validate(data):
    if not isinstance(data,dict) or set(data)-{'op','action','revision',*FIELDS}:raise ValueError('Unknown resource fields')
    if 'op' in data and data['op']!='resources':raise ValueError('Invalid resource operation')
    if data.get('action') not in ('status','set'):raise ValueError('Use resource status or set')
    if data['action']=='status':
        if set(data)-{'op','action'}:raise ValueError('Status accepts no resource changes')
        return dict(data)
    if not isinstance(data.get('revision'),str) or len(data['revision'])!=64 or any(c not in '0123456789abcdef' for c in data['revision']):raise ValueError('Current resource revision required')
    for name in FIELDS:
        value=data.get(name)
        if type(value) not in (int,float) or not math.isfinite(value):raise ValueError('Finite numeric resources required')
        if 'memory' in name and type(value) is not int:raise ValueError('Memory must be integer MiB')
    if not .25<=data['account_cpus']<=4 or not .1<=data['capsule_cpus']<=data['account_cpus']-.099:
        raise ValueError('Reserve at least 0.1 CPU outside capsule; total must be 0.25–4 CPU')
    if not 192<=data['account_memory_mib']<=2048 or not 64<=data['capsule_memory_mib']<=data['account_memory_mib']-64:
        raise ValueError('Reserve at least 64 MiB outside capsule; account must be 192–2048 MiB')
    return dict(data)


def revision(cfg):
    return hashlib.sha256(json.dumps({k:cfg[k] for k in FIELDS},sort_keys=True).encode()).hexdigest()


def root_json(path):
    st=path.stat()
    if st.st_uid!=0 or st.st_mode&0o022 or path.is_symlink():raise ValueError('Unsafe resource file permissions')
    return json.loads(path.read_text())


def command(args):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=15,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})


def group_path(uid,run=command):
    text=run(['systemctl','show','--property=ControlGroup','--value',f'user-{uid}.slice']).stdout.strip()
    if text!=f'/user.slice/user-{uid}.slice':raise ValueError('Unexpected lab account cgroup')
    return Path('/sys/fs/cgroup')/text.lstrip('/')


def properties(uid,values,run=command):
    run(['systemctl','set-property','--runtime',f'user-{uid}.slice',
         'CPUQuota='+str(values['account_cpus']*100)+'%',
         'MemoryMax='+str(values['account_memory_mib'])+'M','MemorySwapMax=0','TasksMax=128'])


def verify(path,values):
    quota,period=(path/'cpu.max').read_text().split()
    if quota=='max' or abs(int(quota)/int(period)-values['account_cpus'])>.011:raise RuntimeError('CPU quota not applied')
    if (path/'memory.max').read_text().strip()!=str(values['account_memory_mib']*1048576):raise RuntimeError('Memory quota not applied')
    if (path/'memory.swap.max').read_text().strip()!='0' or (path/'pids.max').read_text().strip()!='128':raise RuntimeError('Swap/PID limits changed')


def save(path,data,gid=0,mode=0o600):
    path=Path(path);temporary=path.with_name('.'+path.name+'.resource-next')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(fd,'w') as f:
            f.write(data);f.flush();os.fsync(f.fileno());os.fchown(f.fileno(),0,gid);os.fchmod(f.fileno(),mode)
        os.replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)


def request(data,run=command):
    data=validate(data);who=pwd.getpwnam('dvlab-node')
    policy=root_json(POLICY);cfg=root_json(CONFIG)
    if policy.get('uid')!=who.pw_uid or policy.get('schema')!=1:raise ValueError('Wrong resource policy identity')
    current={k:cfg[k] for k in FIELDS}
    def status():return dict(current={k:cfg[k] for k in FIELDS},ceilings={k:policy[k] for k in ('max_account_cpus','max_account_memory_mib')},revision=revision(cfg),pid_limit=128,swap=0)
    if data['action']=='status':return status()
    if data['revision']!=revision(cfg):raise ValueError('Stale resource revision; fetch status again')
    values={k:data[k] for k in FIELDS}
    if values['account_cpus']>policy['max_account_cpus'] or values['account_memory_mib']>policy['max_account_memory_mib']:raise ValueError('Requested limits exceed the initial operator-approved ceiling')
    path=group_path(who.pw_uid,run)
    # Even a compromised controller cannot lower memory below actual usage.
    if int((path/'memory.current').read_text())+32*1048576>values['account_memory_mib']*1048576:raise ValueError('Insufficient memory headroom; stop lab work before shrinking')
    drop=DROP_ROOT/f'user-{who.pw_uid}.slice.d/dv-lab.conf'
    if not drop.is_file() or drop.is_symlink():raise ValueError('Missing fixed lab quota drop-in')
    previous=drop.read_text();old_cfg=dict(cfg)
    try:
        properties(who.pw_uid,values,run);verify(path,values)
        text='[Slice]\nCPUQuota='+str(values['account_cpus']*100)+'%\nMemoryMax='+str(values['account_memory_mib'])+'M\nMemorySwapMax=0\nTasksMax=128\n'
        save(drop,text,mode=0o644)
        cfg.update(values);save(CONFIG,json.dumps(cfg)+'\n',gid=who.pw_gid,mode=0o640)
        run(['systemctl','daemon-reload'])
        return status()
    except Exception as exc:
        cfg=old_cfg
        try:
            properties(who.pw_uid,current,run);save(drop,previous,mode=0o644)
            save(CONFIG,json.dumps(old_cfg)+'\n',gid=who.pw_gid,mode=0o640)
            run(['systemctl','daemon-reload']);verify(path,current)
        except Exception:raise RuntimeError('Resource change failed; rollback needs operator inspection') from None
        raise RuntimeError('Resource change failed; previous limits restored') from None


def authorize(connection):
    uid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))[1]
    if uid not in (0,pwd.getpwnam('dvlab-node').pw_uid):raise ValueError('Unapproved resource peer')


def main():
    if os.geteuid()!=0:raise ValueError('Root resource broker required')
    os.umask(0o077)
    with socket.fromfd(0,socket.AF_UNIX,socket.SOCK_STREAM) as connection:authorize(connection)
    raw=sys.stdin.buffer.read(4097)
    if len(raw)>4096:raise ValueError('Resource request too large')
    with open(STATE/'lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(request(json.loads(raw))))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'error':type(exc).__name__+': '+str(exc)[:180]}));sys.exit(1)
