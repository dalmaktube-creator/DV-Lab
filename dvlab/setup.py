"""Explicit, one-time operator installation. Not exposed through MCP."""
import getpass
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tarfile
from urllib.parse import urlsplit

from .common import atomic_json, identifier, origin, token
from .agent import Client

ROOT=Path('/opt/dv-lab')
ETC=Path('/etc/dv-lab')
SOURCE=Path(__file__).resolve().parent.parent
USER='dvlab-node'


def run(args, **kw):
    kw.setdefault("check",True)
    return subprocess.run(args, **kw)


def prompt(label, default=''):
    # Bootstrap may have stdin connected to a pipe: prompts always use tty.
    with open('/dev/tty','r+') as tty:
        tty.write(label+(f' [{default}]' if default else '')+': ');tty.flush()
        return tty.readline().strip() or default


def secret(label):
    with open('/dev/tty','r+') as tty:
        return getpass.getpass(label+': ',stream=tty)


def confirm(text):
    print('\033[33m'+text+'\033[0m')
    if prompt('Type INSTALL to continue')!='INSTALL':raise SystemExit('Cancelled; no installation performed')


def preflight(role):
    if os.geteuid()!=0:raise SystemExit('Run as root')
    release=Path('/etc/os-release').read_text()
    if not re.search(r'^ID=ubuntu$',release,re.M) or not re.search(r'^VERSION_ID="24\.04"$',release,re.M):
        raise SystemExit('Preview supports Ubuntu 24.04 only; no unsafe fallback')
    if not Path('/run/systemd/system').is_dir() or not Path('/sys/fs/cgroup/cgroup.controllers').is_file():
        raise SystemExit('systemd + cgroup v2 required')
    marker=ETC/(role+'.json')
    if marker.exists():raise SystemExit('Already installed; use dv-lab menu. No automatic destructive reinstall.')
    name='dvlab-hub' if role=='hub' else USER
    try:pwd.getpwnam(name)
    except KeyError:pass
    else:raise SystemExit('Reserved account already exists; operator must inspect before installation')
    if shutil.disk_usage('/var').free<1024**3:raise SystemExit('At least 1GiB free installation space required')


def files():
    """Install root policy once; versioned service code is separate from operator code."""
    from . import update_guard
    ETC.mkdir(mode=0o755,exist_ok=True);ETC.chmod(0o755)
    ROOT.mkdir(mode=0o755,exist_ok=True);ROOT.chmod(0o755)
    releases=ROOT/'releases';releases.mkdir(mode=0o755,exist_ok=True);releases.chmod(0o755)
    current=ROOT/'current'
    if not current.exists():
        marker=SOURCE/'.source-commit'
        if not marker.exists():raise SystemExit('Source commit missing; use public installer or a pinned checkout')
        sha=update_guard.validate_commit(marker.read_text().strip());dst=releases/sha
        shutil.copytree(SOURCE,dst,ignore=shutil.ignore_patterns('__pycache__','.git','*.zip','*.gz'))
        cap=dst/'capsule/dvlab';cap.mkdir(parents=True,exist_ok=True)
        for name in update_guard.CAPSULE:shutil.copyfile(dst/'dvlab'/name,cap/name)
        for p in dst.rglob('*'):
            p.chmod(0o755 if p.is_dir() else 0o644)
        dst.chmod(0o755);current.symlink_to(dst)
    marker=SOURCE/'.source-commit'
    installed=(current.resolve()/'.source-commit').read_text().strip()
    if marker.exists() and marker.read_text().strip()!=installed:
        raise SystemExit('Existing role is on another commit. Update it first before adding this role.')
    # Root console/guard are pinned at first install. Auto-update NEVER replaces them.
    pinned=Path('/usr/local/lib/dv-lab');pinned.mkdir(mode=0o755,parents=True,exist_ok=True)
    operator=pinned/'operator'
    if not operator.exists():
        operator.mkdir(mode=0o755);shutil.copytree(SOURCE/'dvlab',operator/'dvlab',ignore=shutil.ignore_patterns('__pycache__'))
        for p in operator.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o644)
    guard=pinned/'update_guard.py'
    if not guard.exists():shutil.copyfile(SOURCE/'dvlab/update_guard.py',guard);guard.chmod(0o644)
    wrapper=Path('/usr/local/bin/dv-lab')
    if wrapper.exists() and 'python3 -m dvlab.menu' not in wrapper.read_text():raise SystemExit('Unmanaged launcher')
    wrapper.write_text('#!/bin/sh\ncd /usr/local/lib/dv-lab/operator\nexec /usr/bin/python3 -m dvlab.menu "$@"\n');wrapper.chmod(0o755)
    entry=Path('/usr/local/sbin/dv-lab-update')
    if not entry.exists():
        entry.write_text('#!/bin/sh\nexec /usr/bin/python3 -I /usr/local/lib/dv-lab/update_guard.py "$@"\n');entry.chmod(0o755)
    state=Path('/var/lib/dv-lab-updater');state.mkdir(mode=0o700,exist_ok=True);state.chmod(0o700)
    policy=ETC/'update-policy.json'
    if not policy.exists():config(policy,dict(repository='dalmaktube-creator/DV-Lab',guard_schema=1))
    unit=Path('/etc/systemd/system/dv-lab-update.service')
    if not unit.exists():unit.write_text("""[Unit]
Description=DV Lab pinned application update worker
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I /usr/local/lib/dv-lab/update_guard.py --worker
UMask=0077
CPUQuota=20%
MemoryMax=128M
MemorySwapMax=0
TasksMax=64
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/opt/dv-lab /var/lib/dv-lab-updater -/var/lib/dv-lab-hub
TimeoutStartSec=600
""")


def grant_update(who):
    sudo=Path('/etc/sudoers.d/dv-lab-update-'+who.pw_name)
    sudo.write_text(who.pw_name+' ALL=(root) NOPASSWD: /usr/local/sbin/dv-lab-update ""\n');sudo.chmod(0o440)
    run(['visudo','-cf',str(sudo)])


def account(name):
    run(['useradd','--create-home','--shell','/usr/sbin/nologin',name])
    return pwd.getpwnam(name)


def config(path,value,who=None):
    atomic_json(path,value)
    if who:
        os.chown(path,0,who.pw_gid);path.chmod(0o640)


def bundle(path):
    with tarfile.open(path,'w:gz') as archive:
        for p in sorted((ROOT/'current').resolve().rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.gz','.zip'):
                archive.add(p,arcname='dv-lab/'+str(p.relative_to((ROOT/'current').resolve())),recursive=False)
    path.chmod(0o644)


def portcheck(start,count):
    sockets=[]
    try:
        for port in range(start,start+count):
            for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
                s=socket.socket(socket.AF_INET,kind);sockets.append(s);s.bind(('0.0.0.0',port))
    finally:
        for s in sockets:s.close()


def hub():
    preflight('hub')
    url=origin(prompt('Public HTTPS origin (direct TLS, e.g. https://lab.example.com:8443)'))
    parsed=urlsplit(url);port=parsed.port or 443
    if port<1024:raise SystemExit('Use unprivileged direct TLS port >=1024, e.g. 8443')
    portcheck(port,1)
    cert=Path(prompt('Existing fullchain PEM path')).resolve()
    key=Path(prompt('Existing private key PEM path')).resolve()
    import ssl
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
    confirm('Installs dedicated hub account, TLS service, /opt/dv-lab and menu. No nginx/firewall changes. Updates trust CI-passed main commits from dalmaktube-creator/DV-Lab; only unprivileged app code changes. Root helpers/config/quotas remain pinned. Make the chosen TCP port reachable separately.')
    run(['apt-get','update']);run(['apt-get','install','-y','--no-install-recommends','sudo','ca-certificates'])
    files();who=account('dvlab-hub');grant_update(who)
    state=Path('/var/lib/dv-lab-hub');state.mkdir(mode=0o700);os.chown(state,who.pw_uid,who.pw_gid)
    tls=ETC/'tls';tls.mkdir(mode=0o750);os.chown(tls,0,who.pw_gid)
    for src,name in ((cert,'fullchain.pem'),(key,'privkey.pem')):
        dst=tls/name;shutil.copyfile(src,dst);os.chown(dst,0,who.pw_gid);dst.chmod(0o640)
    package=ROOT/'current/dv-lab.tar.gz';bundle(package)
    cfg=dict(public_url=url,port=port,database=str(state/'hub.sqlite3'),bundle=str(package),
             cert=str(tls/'fullchain.pem'),key=str(tls/'privkey.pem'),admin_token=token(),mcp_token=token())
    config(ETC/'hub.json',cfg,who)
    Path('/etc/systemd/system/dv-lab-hub.service').write_text('''[Unit]
Description=DV Lab MCP mother
After=network-online.target
Wants=network-online.target
[Service]
User=dvlab-hub
Group=dvlab-hub
WorkingDirectory=/opt/dv-lab/current
ExecStart=/usr/bin/python3 -m dvlab.hub
Restart=on-failure
RestartSec=5
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/dv-lab-hub /var/lib/dv-lab-updater
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
CPUQuota=25%
MemoryMax=256M
MemorySwapMax=0
TasksMax=80
[Install]
WantedBy=multi-user.target
''')
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','dv-lab-hub.service'])
    print('Hub installed. Run: sudo dv-lab . Renewed TLS files must be copied to /etc/dv-lab/tls and hub restarted.')


def userrun(who,args,**kw):
    env=['-i','HOME='+who.pw_dir,'USER='+who.pw_name,'LOGNAME='+who.pw_name,'PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','XDG_CONFIG_HOME='+who.pw_dir+'/.config','XDG_DATA_HOME='+who.pw_dir+'/.local/share','XDG_RUNTIME_DIR=/run/user/'+str(who.pw_uid),'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(who.pw_uid)+'/bus']
    return run(['runuser','-u',who.pw_name,'--','env',*env,*args],**kw)


def subids(name):
    files=[Path('/etc/subuid'),Path('/etc/subgid')]
    if all(any(x.startswith(name+':') and int(x.split(':')[2])>=65536 for x in p.read_text().splitlines()) for p in files):return
    ranges=[]
    for p in files:
        for line in p.read_text().splitlines():
            _,start,count=line.split(':');ranges.append((int(start),int(start)+int(count)))
    start=100000
    while any(start<b and start+65536>a for a,b in ranges):start+=65536
    run(['usermod','--add-subuids',f'{start}-{start+65535}','--add-subgids',f'{start}-{start+65535}',name])


def agent(url=None):
    preflight('agent')
    url=origin(url or prompt('Mother HTTPS origin'))
    parsed=urlsplit(url)
    hub_ips=sorted({x[4][0] for x in socket.getaddrinfo(parsed.hostname,parsed.port or 443,socket.AF_INET,socket.SOCK_STREAM)})
    if not hub_ips or not all(ipaddress.IPv4Address(x).is_global for x in hub_ips):raise SystemExit('Mother must resolve to public IPv4')
    portcheck(45100,8)
    if not Path('/dev/net/tun').exists():raise SystemExit('/dev/net/tun required; no host network fallback')
    name=identifier(prompt('Node name',re.sub('[^a-zA-Z0-9_-]','-',socket.gethostname())[:48]))
    code=secret('One-use invitation (hidden)')
    confirm('One-time host changes: dedicated unprivileged account; Podman packages/image; bounded user slice; own nft table on ports 45100-45107; exact sudo peer-set helper. Lab account: <=0.5 CPU,192MiB incl networking; capsule <=0.4 CPU,128MiB. Existing firewall rules are NOT removed. App updates trust CI-passed main commits from dalmaktube-creator/DV-Lab; no root helper, quota or system-package updates. Not production-certified.')
    # No invitation is written to disk, argv or URLs.
    enrollment=Client(url).post('/agent/enroll',dict(code=code,name=name));code=''
    run(['apt-get','update'])
    run(['apt-get','install','-y','--no-install-recommends','podman','slirp4netns','uidmap','dbus-user-session','nftables','sudo','fuse-overlayfs','ca-certificates','iproute2'])
    check=run(['nft','list','tables'],capture_output=True,text=True)
    if 'table inet dv_lab_agent' in check.stdout:raise SystemExit('Reserved nft table exists; refusing takeover')
    files();who=account(USER);subids(USER);grant_update(who)
    state=Path("/var/lib/dv-lab-node");state.mkdir(mode=0o700);os.chown(state,who.pw_uid,who.pw_gid)
    run(['loginctl','enable-linger',USER]);run(['systemctl','start',f'user@{who.pw_uid}.service'])
    # Build before UID-specific egress restriction and quotas; one-time cost, NOT benchmark overhead.
    userrun(who,['test','-r','/dev/net/tun']);userrun(who,['test','-w','/dev/net/tun'])
    userrun(who,['podman','build','--pull=always','-t','localhost/dv-lab:preview','-f',str(ROOT/'current/Containerfile'),str(ROOT/'current')])
    image=userrun(who,['podman','image','inspect','--format','{{.Id}}','localhost/dv-lab:preview'],capture_output=True,text=True).stdout.strip()
    if not image.startswith('sha256:'):image='sha256:'+image
    cfg=dict(hub=url,**enrollment,image=image,port_start=45100,port_count=8,
             capsule_memory_mib=128,capsule_cpus=.4,account_memory_mib=192,account_cpus=.5)
    config(ETC/'agent.json',cfg,who)
    dns=[]
    for line in Path('/etc/resolv.conf').read_text().splitlines():
        if line.startswith('nameserver '):
            try:dns.append(str(ipaddress.IPv4Address(line.split()[1])))
            except ipaddress.AddressValueError:pass
    hosts=json.loads(run(['ip','-j','-4','addr','show'],capture_output=True,text=True).stdout)
    ips=[a['local'] for link in hosts for a in link.get('addr_info',[]) if a.get('family')=='inet']
    config(ETC/'network.json',dict(uid=who.pw_uid,hub_ips=hub_ips,hub_port=parsed.port or 443,dns_ips=dns,host_ips=ips,port_start=45100,port_count=8))
    helper=Path('/usr/local/sbin/dv-lab-netpolicy');shutil.copyfile(ROOT/'current/dvlab/netpolicy.py',helper);helper.chmod(0o755)
    sudo=Path('/etc/sudoers.d/dv-lab-node')
    sudo.write_text(f'{USER} ALL=(root) NOPASSWD: /usr/local/sbin/dv-lab-netpolicy ""\n');sudo.chmod(0o440)
    run(['visudo','-cf',str(sudo)])
    policy=Path('/etc/systemd/system/dv-lab-network.service')
    policy.write_text('''[Unit]
Description=DV Lab own-table network guard
After=network-online.target nftables.service
Wants=network-online.target
Before=user@'''+str(who.pw_uid)+'''.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dv-lab-netpolicy --boot
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''')
    # The user manager cannot start at boot unless our guard succeeded.
    dep=Path(f'/etc/systemd/system/user@{who.pw_uid}.service.d');dep.mkdir(parents=True,exist_ok=True)
    (dep/'dv-lab.conf').write_text('[Unit]\nRequires=dv-lab-network.service\nAfter=dv-lab-network.service\n')
    drop=Path(f'/etc/systemd/system/user-{who.pw_uid}.slice.d');drop.mkdir(parents=True,exist_ok=True)
    (drop/'dv-lab.conf').write_text('[Slice]\nCPUQuota=50%\nMemoryMax=192M\nMemorySwapMax=0\nTasksMax=128\n')
    unitdir=Path(who.pw_dir)/'.config/systemd/user';unitdir.mkdir(parents=True,exist_ok=True)
    unit=unitdir/'dv-lab-agent.service'
    unit.write_text('''[Unit]
Description=DV Lab isolated node controller
[Service]
WorkingDirectory=/opt/dv-lab/current
ExecStart=/usr/bin/python3 -m dvlab.agent
ExecStopPost=/usr/bin/python3 -m dvlab.agent --stop
Restart=on-failure
RestartSec=5
Delegate=yes
UMask=0077
TimeoutStopSec=25
KillMode=control-group
[Install]
WantedBy=default.target
''')
    # Unit is root-owned, read-only to the dedicated user. Parent home isn't mounted in capsule.
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now','dv-lab-network.service'])
    run(['systemctl','set-property',f'user-{who.pw_uid}.slice','CPUQuota=50%','MemoryMax=192M','MemorySwapMax=0','TasksMax=128'])
    userrun(who,['systemctl','--user','daemon-reload']);userrun(who,['systemctl','--user','enable','--now','dv-lab-agent.service'])
    print('Node installed. First capsule creation validates cgroups, namespaces and TUN; failure stops capsule. Run sudo dv-lab for status.')


def main():
    if len(sys.argv)<2:
        print('DV LAB — Mother / Node installer')
        role=prompt('Role: hub or agent','hub')
    else:role=sys.argv[1]
    if role not in ('hub','agent'):raise SystemExit('Usage: sudo bash install.sh hub|agent [https://mother:8443]')
    if role=='hub':hub()
    else:agent(sys.argv[2] if len(sys.argv)>2 else None)

if __name__=='__main__':main()
