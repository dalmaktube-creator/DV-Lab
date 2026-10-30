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
import ssl
from urllib.parse import urlsplit

from .common import atomic_json, identifier, origin, token
from .agent import Client
from . import __version__
from .install_ui import Console, color
from .tls_manager import Manager as TLSManager, install as install_tls

ROOT=Path('/opt/dv-lab')
ETC=Path('/etc/dv-lab')
SOURCE=Path(__file__).resolve().parent.parent
USER='dvlab-node'
CONSOLE=Console()


def run(args, **kw):
    kw.setdefault('check',True)
    if CONSOLE.active and not any(k in kw for k in ('capture_output','stdout','stderr')):
        with CONSOLE.logstream() as log:
            try:return subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,**kw)
            finally:CONSOLE.trimlog()
    return subprocess.run(args, **kw)


def prompt(label, default=''):
    # A tty is non-seekable: buffered r+ opens fail on Python 3.10+.
    # Keep separate read/write streams; stdin may be the consumed curl pipe.
    try:
        with open('/dev/tty','w') as out, open('/dev/tty','r') as inp:
            out.write(color('  › '+label+(f' [{default}]' if default else '')+': ','blue',out));out.flush()
            answer=inp.readline()
            if not answer:raise SystemExit('Terminal closed; rerun in an interactive SSH session.')
            return answer.strip() or default
    except OSError as exc:
        raise SystemExit('Interactive terminal unavailable; run from an interactive SSH session, not a background task.') from None


def secret(label):
    try:
        with open('/dev/tty','w') as out:
            return getpass.getpass(color('  › '+label+': ','blue',out),stream=out)
    except (OSError,EOFError):
        raise SystemExit('Interactive terminal unavailable for hidden input; rerun in an interactive SSH session.') from None


def ask(label,validator,default='',hint=''):
    if hint:CONSOLE.hint(hint)
    while True:
        answer=prompt(label,default)
        try:return validator(answer)
        except ValueError as exc:CONSOLE.error(str(exc))


def confirm(text):
    for line in text.splitlines():CONSOLE.hint(line)
    CONSOLE.hint('INSTALL = continue  ·  CANCEL = exit')
    while True:
        answer=prompt('Confirm').strip().upper()
        if answer=='INSTALL':return
        if answer in ('CANCEL','N','NO','Q','QUIT'):raise SystemExit('Cancelled. No installation changes were started.')
        CONSOLE.error('Enter INSTALL or CANCEL.')


def validate_hub_url(value):
    try:url=origin(value);port=urlsplit(url).port or 443
    except ValueError:raise ValueError('Use https://DOMAIN:PORT, without /mcp or another path.') from None
    if port<1024:raise ValueError('Direct TLS needs port 1024–65535; try 8443 or 9443.')
    try:portcheck(port,1,tcp_only=True)
    except OSError as exc:
        if exc.errno==98:raise ValueError(f'TCP port {port} is in use. Choose another port; no service will be stopped.') from None
        raise ValueError('Cannot bind this TCP port. Check local permissions and choose another.') from None
    return url


def domain_name(value):
    value=value.strip()
    if not value or any(c in value for c in '/:@?#\\') or any(c.isspace() for c in value):
        raise ValueError('Enter only the domain, e.g. lab.example.com; no https://, port or path.')
    try:host=value.encode('idna').decode('ascii').lower()
    except UnicodeError:raise ValueError('Invalid domain. Example: lab.example.com') from None
    if len(host)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in host.split('.')):
        raise ValueError('Invalid domain. Example: lab.example.com')
    try:ipaddress.ip_address(host)
    except ValueError:return host
    raise ValueError('Enter a domain, not an IP address; the TLS certificate must match it.')


def hub_port(value):
    if not re.fullmatch(r'[0-9]{1,5}',value) or not 1024<=int(value)<=65535:
        raise ValueError('Enter a port number from 1024 to 65535, e.g. 9443.')
    port=int(value)
    # Reuse the same direct-TLS and local TCP availability checks.
    validate_hub_url(f'https://port-check.invalid:{port}')
    return port


def hub_address():
    domain=ask('Domain',domain_name,hint='Example: lab.example.com — no https:// or port; www is not required.')
    port=ask('HTTPS port',hub_port,default='9443',hint='Local TCP check only; firewall/public access is not checked.')
    url=f'https://{domain}:{port}'
    CONSOLE.ok('HTTPS address: '+url)
    return url


def pem_path(value):
    try:
        p=Path(value).expanduser()
        if not p.is_absolute():raise ValueError('Enter a full file path starting with /.')
        p=p.resolve(strict=True)
        if not p.is_file():raise ValueError('Choose an existing PEM file, not a directory.')
        with p.open('rb') as f:f.read(1)
        return p
    except (OSError,RuntimeError):raise ValueError('PEM file not found or unreadable. Check the full path.') from None


def tls_files():
    CONSOLE.hint('Existing certificate required; no automatic TLS issuance.')
    while True:
        cert=ask('Certificate PEM',pem_path,hint='Example: /etc/letsencrypt/live/YOUR-DOMAIN/fullchain.pem')
        key=ask('Private-key PEM',pem_path,hint='Enter the local file path only; never paste key contents.')
        try:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key,password='')
            return cert,key
        except (ssl.SSLError,OSError):
            CONSOLE.error('Certificate/key could not be loaded. Use matching PEM files and an unencrypted service key.')


def validate_role(value):
    role={'1':'hub','2':'agent','mother':'hub','node':'agent'}.get(value.strip().lower(),value.strip().lower())
    if role not in ('hub','agent'):raise ValueError('Choose hub (mother) or agent (test node).')
    return role


def mother_url(value):
    try:
        url=origin(value);parsed=urlsplit(url)
        ips=sorted({x[4][0] for x in socket.getaddrinfo(parsed.hostname,parsed.port or 443,socket.AF_INET,socket.SOCK_STREAM)})
        if not ips or not all(ipaddress.IPv4Address(x).is_global for x in ips):raise ValueError('Mother must resolve to public IPv4.')
        return url
    except socket.gaierror:raise ValueError('DNS lookup failed. Check the domain and its DNS record.') from None
    except ValueError:raise ValueError('Use an HTTPS mother address that resolves to public IPv4.') from None


def node_name(value):
    try:return identifier(value)
    except ValueError:raise ValueError('Use 1–64 letters, digits, hyphens or underscores for the node name.') from None


def validate_platform(release,role):
    values={}
    for line in release.splitlines():
        if '=' in line:
            key,value=line.split('=',1);values[key]=value.strip().strip('"').strip("'")
    if role not in ('hub','agent'):raise SystemExit('Role must be hub or agent')
    version=values.get('VERSION_ID','unknown')
    if values.get('ID')!='ubuntu':raise SystemExit('Only Ubuntu is supported; no unsafe fallback')
    if version in ('22.04','24.04'):return
    raise SystemExit('Unsupported Ubuntu '+version+'. Hub and agent: 22.04/24.04.')


def preflight(role):
    if os.geteuid()!=0:raise SystemExit('Run as root')
    if sys.version_info<(3,10):raise SystemExit('Python 3.10 or newer is required')
    validate_platform(Path('/etc/os-release').read_text(),role)
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
    if not policy.exists():config(policy,dict(repository='dalmaktube-creator/DV-Lab',guard_schema=2))
    unit=Path('/etc/systemd/system/dv-lab-update.service')
    if not unit.exists():unit.write_text("""[Unit]
Description=DV Lab pinned application update worker
After=network-online.target
[Service]
Type=oneshot
Slice=dv-lab-maintenance.slice
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
    # Socket activation has no idle Python daemon. All maintenance jobs share a
    # root-owned 0.2 CPU / 128MiB slice, independently of lab-account workloads.
    group='dv-lab-update'
    try:entry=grp.getgrnam(group)
    except KeyError:
        run(['groupadd','--system',group]);entry=grp.getgrnam(group)
    if set(entry.gr_mem)-{'dvlab-hub','dvlab-node'}:
        raise SystemExit('Reserved update group has unexpected members; inspect before installation')
    run(['usermod','--append','--groups',group,who.pw_name])
    units={
      'dv-lab-maintenance.slice':"""[Unit]
Description=DV Lab bounded maintenance budget
[Slice]
CPUQuota=20%
MemoryMax=128M
MemorySwapMax=0
TasksMax=64
""",
      'dv-lab-update-broker.socket':"""[Unit]
Description=DV Lab local authenticated update request socket
[Socket]
ListenStream=/run/dv-lab/update.sock
SocketUser=root
SocketGroup=dv-lab-update
SocketMode=0660
DirectoryMode=0755
Accept=yes
MaxConnections=4
RemoveOnStop=yes
[Install]
WantedBy=sockets.target
""",
      'dv-lab-update-broker@.service':"""[Unit]
Description=DV Lab narrow update request broker
[Service]
Type=exec
Slice=dv-lab-maintenance.slice
ExecStart=/usr/bin/python3 -I /usr/local/lib/dv-lab/update_guard.py
StandardInput=socket
StandardOutput=inherit
StandardError=journal
RuntimeMaxSec=90
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/dv-lab-updater
CPUQuota=20%
MemoryMax=64M
MemorySwapMax=0
TasksMax=16
UMask=0077
"""}
    for name,content in units.items():
        p=Path('/etc/systemd/system')/name
        if not p.exists():p.write_text(content)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now','dv-lab-update-broker.socket'])


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


def portcheck(start,count,tcp_only=False):
    sockets=[]
    try:
        for port in range(start,start+count):
            for kind in ((socket.SOCK_STREAM,) if tcp_only else (socket.SOCK_STREAM,socket.SOCK_DGRAM)):
                s=socket.socket(socket.AF_INET,kind);sockets.append(s);s.bind(('0.0.0.0',port))
    finally:
        for s in sockets:s.close()


def hub():
    CONSOLE.banner('Mother / Hub',__version__)
    CONSOLE.stage(1,5,'System checks')
    preflight('hub');CONSOLE.ok('System and reserved account checked.')
    CONSOLE.stage(2,5,'Connection & TLS')
    url=hub_address()
    parsed=urlsplit(url);port=parsed.port or 443
    tls_manager=TLSManager(run,CONSOLE)
    tls_plan=tls_manager.inspect(parsed.hostname)
    CONSOLE.stage(3,5,'Review & approve')
    CONSOLE.summary([('Role','Mother'),('Address',url),('Service budget','0.25 CPU / 256 MiB')])
    confirm('Creates a dedicated hub account and bounded services.\nTLS: reuse + renewal test, or automatic Let’s Encrypt issuance.\nINSTALL also accepts Let’s Encrypt terms: letsencrypt.org/repository/\nACME account has no email; a twice-daily renewal timer is installed.\nExisting SSH, proxy and firewall rules are not changed.')
    CONSOLE.installing=True;CONSOLE.stage(4,5,'Install & configure')
    CONSOLE.hint('Installing dependencies. Details go to a private local log.')
    run(['apt-get','update']);run(['apt-get','install','-y','--no-install-recommends','sudo','ca-certificates','openssl','certbot'])
    CONSOLE.ok('Dependencies ready.')
    cert,key=tls_manager.ensure(tls_plan)
    files();who=account('dvlab-hub');grant_update(who)
    state=Path('/var/lib/dv-lab-hub');state.mkdir(mode=0o700);os.chown(state,who.pw_uid,who.pw_gid)
    install_tls(tls_plan,run)
    tls=ETC/'tls/current'
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
SupplementaryGroups=dv-lab-update
NoNewPrivileges=yes
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
    CONSOLE.ok('Account, TLS files and bounded services configured.')
    CONSOLE.stage(5,5,'Start service')
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','dv-lab-hub.service'])
    run(['systemctl','enable','--now','dv-lab-tls-renew.timer'])
    run(['systemctl','is-enabled','--quiet','dv-lab-tls-renew.timer'])
    run(['systemctl','is-active','--quiet','dv-lab-tls-renew.timer'])
    run(['systemctl','is-active','--quiet','dv-lab-hub.service'])
    CONSOLE.ok('Mother service started.')
    CONSOLE.line('Next: sudo dv-lab','title')
    CONSOLE.ok('Automatic TLS renewal timer is enabled and active.')
    CONSOLE.hint('Public MCP-port access is not verified; keep challenge access available.')


def userrun(who,args,**kw):
    env=['-i','HOME='+who.pw_dir,'USER='+who.pw_name,'LOGNAME='+who.pw_name,'PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','XDG_CONFIG_HOME='+who.pw_dir+'/.config','XDG_DATA_HOME='+who.pw_dir+'/.local/share','XDG_RUNTIME_DIR=/run/user/'+str(who.pw_uid),'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(who.pw_uid)+'/bus']
    kw.setdefault('cwd',str(ROOT/'current'))
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


def resource_ceilings():
    from .resource_guard import ceilings
    memory=next(int(line.split()[1])//1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:'))
    return ceilings(os.cpu_count() or 1,memory)


def install_resources(who,run_command=run):
    limits=resource_ceilings()
    config(ETC/'resource-policy.json',dict(schema=1,uid=who.pw_uid,**limits))
    helper=Path('/usr/local/lib/dv-lab/resource_guard.py')
    if helper.exists():raise SystemExit('Reserved resource helper exists; inspect before installing')
    helper.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    shutil.copyfile(SOURCE/'dvlab/resource_guard.py',helper);helper.chmod(0o644)
    state=Path('/var/lib/dv-lab-resource');state.mkdir(mode=0o700);state.chmod(0o700)
    Path('/etc/systemd/system/dv-lab-resources.socket').write_text('''[Unit]
Description=DV Lab bounded resource control socket
[Socket]
ListenStream=/run/dv-lab/resources.sock
SocketMode=0660
SocketUser=root
SocketGroup=dvlab-node
DirectoryMode=0755
Accept=yes
MaxConnections=2
[Install]
WantedBy=sockets.target
''')
    Path('/etc/systemd/system/dv-lab-resources@.service').write_text('''[Unit]
Description=DV Lab fixed resource broker
[Service]
ExecStart=/usr/bin/python3 -I /usr/local/lib/dv-lab/resource_guard.py
StandardInput=socket
StandardOutput=inherit
User=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
CPUQuota=10%
MemoryMax=64M
MemorySwapMax=0
TasksMax=16
RuntimeMaxSec=60
UMask=0077
''')
    return limits


def agent(url=None):
    CONSOLE.banner('Isolated test node',__version__)
    CONSOLE.stage(1,6,'System checks')
    preflight('agent')
    try:portcheck(45100,8)
    except OSError:raise SystemExit('Lab ports 45100–45107 must be free. No existing service will be stopped.') from None
    if not Path('/dev/net/tun').exists():raise SystemExit('/dev/net/tun is required; host-network fallback is disabled.')
    CONSOLE.ok('System and reserved test ports checked.')
    CONSOLE.stage(2,6,'Mother & node identity')
    if url:
        try:url=mother_url(url)
        except ValueError as exc:
            CONSOLE.error(str(exc));url=ask('Mother HTTPS address',mother_url)
    else:url=ask('Mother HTTPS address',mother_url)
    parsed=urlsplit(url)
    hub_ips=sorted({x[4][0] for x in socket.getaddrinfo(parsed.hostname,parsed.port or 443,socket.AF_INET,socket.SOCK_STREAM)})
    default=re.sub('[^a-zA-Z0-9_-]','-',socket.gethostname())[:48]
    name=ask('Node name',node_name,default)
    CONSOLE.hint('One-use invitation from the mother; input is hidden.')
    code=secret('Join code')
    CONSOLE.stage(3,6,'Review & approve')
    limits=resource_ceilings()
    CONSOLE.summary([('Node',name),('Mother',url),('Lab ports','45100–45107 TCP + UDP'),('Starting budget','0.5 CPU / 192 MiB'),('MCP resource ceiling',str(limits['max_account_cpus'])+' CPU / '+str(limits['max_account_memory_mib'])+' MiB')])
    confirm('Adds a rootless capsule, own account, fixed helpers and own firewall table.\nStarts at 0.4 CPU / 128 MiB inside a 0.5 CPU / 192 MiB account.\nMCP can adjust lab resources within the displayed ceiling; no unlimited mode.\nResource changes stop lab jobs and clear temporary /work.\nUpdates trust this repo. Existing services are not rewritten.')
    CONSOLE.stage(4,6,'Enroll & install dependencies')
    while True:
        try:enrollment=Client(url).post('/agent/enroll',dict(code=code,name=name));code='';break
        except (OSError,RuntimeError,ValueError):
            code='';CONSOLE.error('Enrollment failed. Check mother TLS/reachability, a unique node name and a fresh invite.')
            if prompt('Retry enrollment? y/n','n').lower() not in ('y','yes'):raise SystemExit('Cancelled before local installation changes.')
            name=ask('Node name',node_name,name);code=secret('New join code')
    CONSOLE.installing=True
    run(['apt-get','update'])
    run(['apt-get','install','-y','--no-install-recommends','podman','slirp4netns','uidmap','dbus-user-session','nftables','sudo','fuse-overlayfs','ca-certificates','iproute2'])
    check=run(['nft','list','tables'],capture_output=True,text=True)
    if 'table inet dv_lab_agent' in check.stdout:raise SystemExit('Reserved nft table exists; refusing takeover. Inspect it before retrying.')
    CONSOLE.ok('Enrolled; dependencies ready.')
    CONSOLE.stage(5,6,'Build isolated environment')
    CONSOLE.hint('One-time image build; detailed output is kept in the private log.')
    files();who=account(USER);subids(USER);grant_update(who)
    state=Path("/var/lib/dv-lab-node");state.mkdir(mode=0o700);os.chown(state,who.pw_uid,who.pw_gid)
    delegation=Path(f'/etc/systemd/system/user@{who.pw_uid}.service.d');delegation.mkdir(parents=True,exist_ok=True)
    (delegation/'dv-lab-delegation.conf').write_text('[Service]\nDelegate=cpu memory pids\n')
    run(['systemctl','daemon-reload'])
    run(['loginctl','enable-linger',USER]);run(['systemctl','start',f'user@{who.pw_uid}.service'])
    # Build before UID-specific egress restriction and quotas; one-time cost, NOT benchmark overhead.
    userrun(who,['test','-r','/dev/net/tun']);userrun(who,['test','-w','/dev/net/tun'])
    userrun(who,['podman','build','--pull=always','-t','localhost/dv-lab:preview','-f',str(ROOT/'current/Containerfile'),str(ROOT/'current')])
    image=userrun(who,['podman','image','inspect','--format','{{.Id}}','localhost/dv-lab:preview'],capture_output=True,text=True).stdout.strip()
    if not image.startswith('sha256:'):image='sha256:'+image
    cfg=dict(hub=url,**enrollment,image=image,port_start=45100,port_count=8,
             capsule_memory_mib=128,capsule_cpus=.4,account_memory_mib=192,account_cpus=.5)
    config(ETC/'agent.json',cfg,who)
    install_resources(who)
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
    CONSOLE.ok('Image, quotas and dedicated network guard configured.')
    CONSOLE.stage(6,6,'Start node')
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now','dv-lab-network.service'])
    run(['systemctl','set-property',f'user-{who.pw_uid}.slice','CPUQuota=50%','MemoryMax=192M','MemorySwapMax=0','TasksMax=128'])
    run(['systemctl','enable','--now','dv-lab-resources.socket'])
    userrun(who,['systemctl','--user','daemon-reload']);userrun(who,['systemctl','--user','enable','--now','dv-lab-agent.service'])
    CONSOLE.ok('Node service started.')
    CONSOLE.line('Next: sudo dv-lab','title')
    CONSOLE.hint('First capsule creation verifies namespaces, cgroups and TUN; failures stop the capsule.')


def main():
    if len(sys.argv)<2:
        CONSOLE.banner('Choose role',__version__)
        role=ask('Role',validate_role,'hub',hint='hub = mother  ·  agent = isolated test node')
    else:
        try:role=validate_role(sys.argv[1])
        except ValueError as exc:raise SystemExit(str(exc))
    if role=='hub':hub()
    else:agent(sys.argv[2] if len(sys.argv)>2 else None)


def entrypoint():
    try:
        main();return 0
    except KeyboardInterrupt:
        CONSOLE.warn('Cancelled.')
        if CONSOLE.installing:CONSOLE.hint('Installation may be partial; inspect the local log before retrying.')
        return 130
    except SystemExit as exc:
        if exc.code in (None,0):return 0
        CONSOLE.error(str(exc.code));return 1
    except subprocess.CalledProcessError as exc:
        CONSOLE.error('Command failed: '+str(exc.cmd[0])+'. No automatic destructive retry was attempted.')
    except (ValueError,OSError,RuntimeError) as exc:
        CONSOLE.error(str(exc)[:600])
    if CONSOLE.log_path:CONSOLE.hint('Private log: '+str(CONSOLE.log_path))
    if CONSOLE.installing:CONSOLE.hint('Installation may be partial; inspect before retrying.')
    return 1


if __name__=='__main__':raise SystemExit(entrypoint())
