"""Operator-only TLS lifecycle. Pinned at installation; never imported by MCP.

No webserver installer, host-service stop, firewall change, forced daily issuance,
or idle ACME daemon. Renewal is one bounded, scheduled oneshot for one lineage.
"""
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

LE=Path('/etc/letsencrypt')
OWN=Path('/etc/dv-lab/acme')
POLICY=Path('/etc/dv-lab/tls-policy.json')
DEST=Path('/etc/dv-lab/tls')
PINNED=Path('/usr/local/lib/dv-lab/tls_manager.py')
NAME=re.compile(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}')
PRODUCTION='https://acme-v02.api.letsencrypt.org/directory'
STAGING='https://acme-staging-v02.api.letsencrypt.org/directory'


def command(args,**kw):
    kw.setdefault('check',True)
    kw.setdefault('timeout',600)
    return subprocess.run(args,**kw)


def valid_pair(domain,cert,key,run=command,minimum=86400):
    """Check key match, SAN/hostname, expiry, and local system trust chain."""
    try:
        cert,key=Path(cert),Path(key)
        if not all(p.is_file() and p.stat().st_size<=512*1024 for p in (cert,key)):return False
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert,key,password='')
        for args in (
            ['openssl','x509','-in',str(cert),'-noout','-checkend',str(minimum)],
            ['openssl','verify','-purpose','sslserver','-verify_hostname',domain,
             '-CApath','/etc/ssl/certs','-untrusted',str(cert),str(cert)],
        ):
            if run(args,check=False,capture_output=True,text=True,timeout=20).returncode:return False
        return True
    except (OSError,ValueError,ssl.SSLError,subprocess.SubprocessError):return False


def renewal_options(path):
    # Certbot uses nested [[webroot_map]], which standard ConfigParser cannot
    # read. Only inspect simple, single-line renewalparams; never rewrite it.
    options={};section=''
    for line in path.read_text().splitlines():
        text=line.strip()
        if text.startswith('['):section=text;continue
        if section=='[renewalparams]' and '=' in text and not text.startswith(('#',';')):
            key,value=text.split('=',1);options[key.strip().lower().replace('-','_')]=value.strip()
    return options


def safe_renewal(path):
    try:
        opts=renewal_options(path)
        auth=opts.get('authenticator','')
        # Do not invoke another application's webserver installer or stop hooks.
        return (auth in ('standalone','webroot') or auth.startswith('dns-')) and not any(
            opts.get(k,'').lower() not in ('','none') for k in
            ('installer','pre_hook','post_hook','renew_hook','deploy_hook'))
    except OSError:return False


def roots(config):
    config=Path(config)
    if config==LE:return ['--config-dir',str(LE)]
    if config==OWN:return ['--config-dir',str(OWN),'--work-dir','/var/lib/dv-lab-acme','--logs-dir','/var/log/dv-lab-acme']
    raise ValueError('Unapproved ACME configuration directory')


def certbot_args(config):
    # Ignore global cli.ini hooks/options and directory hooks. Stored lineage
    # hooks are refused separately. Never renew every certificate on the host.
    return ['certbot','--config','/dev/null',*roots(config),'--non-interactive','--no-directory-hooks']


def candidates(domain,run=command):
    result=[]
    for config in (LE,OWN):
        live=config/'live'
        if not live.is_dir():continue
        for lineage in sorted(live.iterdir())[:256]:
            if not NAME.fullmatch(lineage.name):continue
            cert,key=lineage/'fullchain.pem',lineage/'privkey.pem'
            renewal=config/'renewal'/(lineage.name+'.conf')
            if safe_renewal(renewal) and valid_pair(domain,cert,key,run,minimum=0):
                result.append(dict(domain=domain,config=str(config),name=lineage.name))
    # Prefer DV Lab's isolated lineage on subsequent setup attempts.
    return sorted(result,key=lambda item:item['config']!=str(OWN))


def paths(plan):
    config=Path(plan['config']);roots(config)
    if not NAME.fullmatch(plan['name']):raise ValueError('Invalid certificate lineage')
    lineage=config/'live'/plan['name']
    return lineage/'fullchain.pem',lineage/'privkey.pem'


def public_dns(domain):
    try:
        addresses={x[4][0] for x in socket.getaddrinfo(domain,80,0,socket.SOCK_STREAM)}
        if not addresses or not all(ipaddress.ip_address(x).is_global for x in addresses):raise ValueError()
    except (OSError,ValueError):
        raise ValueError('TLS issuance needs public DNS. Point A/AAAA to this server; use DNS only (no proxy).') from None


def http_port_free():
    sockets=[]
    try:
        for family,host in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
            if family==socket.AF_INET6 and not socket.has_ipv6:continue
            try:
                sock=socket.socket(family,socket.SOCK_STREAM);sockets.append(sock)
                if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                sock.bind((host,80))
            except OSError as exc:
                if family==socket.AF_INET6 and exc.errno in (97,99):continue
                raise ValueError('Automatic HTTP-01 needs free TCP port 80. Another service will NOT be stopped; use an existing safe Certbot lineage or configure a DNS/webroot challenge.') from None
    finally:
        for sock in sockets:sock.close()


class Manager:
    def __init__(self,run=command,console=None):self.run=run;self.console=console
    def say(self,text):
        if self.console:self.console.hint(text)
    def inspect(self,domain):
        options=candidates(domain,self.run)
        if options:
            self.say('Existing matching certificate found; renewal will be tested.')
            return options[0]
        self.say('TLS: automatic Let’s Encrypt issuance + scheduled renewal.')
        self.say('Needs DNS pointing here and public TCP 80; no service is stopped.')
        name='dv-lab-'+domain if len(domain)<=246 else 'dv-lab-'+hashlib.sha256(domain.encode()).hexdigest()
        return dict(domain=domain,config=str(OWN),name=name)
    def acme(self,args,message):
        try:self.run(args,timeout=600)
        except subprocess.SubprocessError:
            raise RuntimeError(message+' Check DNS A/AAAA, public TCP 80 (for HTTP-01), CA reachability and the private install log. No firewall rule or webserver was changed.') from None
    def ensure(self,plan):
        """Called after explicit INSTALL approval and dependency installation."""
        domain=plan['domain']
        # Dependencies may have been absent during the read-only preview.
        if not (Path(plan['config'])/'renewal'/(plan['name']+'.conf')).is_file():
            found=candidates(domain,self.run)
            if found:plan.clear();plan.update(found[0])
        cert,key=paths(plan);config=Path(plan['config'])
        existing=(config/'renewal'/(plan['name']+'.conf')).is_file()
        base=certbot_args(config)
        if existing and safe_renewal(config/'renewal'/(plan['name']+'.conf')):
            opts=renewal_options(config/'renewal'/(plan['name']+'.conf'))
            if opts['authenticator']=='standalone':public_dns(domain);http_port_free()
            self.say('Testing existing certificate renewal (staging; no replacement).')
            self.acme([*base,'renew','--cert-name',plan['name'],'--dry-run','--server',STAGING,'--agree-tos','--register-unsafely-without-email'],
                      'Existing renewal test failed; refusing unnecessary duplicate issuance.')
            # Only renew when Certbot considers this lineage due. No force flag.
            self.acme([*base,'renew','--cert-name',plan['name']], 'Certificate renewal failed.')
        else:
            if existing:raise RuntimeError('DV Lab certificate name already has an unsafe renewal configuration; inspect it before continuing.')
            public_dns(domain);http_port_free()
            self.say('Checking domain validation with Let’s Encrypt staging first.')
            issue=[*base,'certonly','--standalone','--preferred-challenges','http','--cert-name',plan['name'],
                   '-d',domain,'--agree-tos','--register-unsafely-without-email','--keep-until-expiring']
            self.acme([*issue,'--dry-run','--server',STAGING], 'Domain validation test failed; no production certificate requested.')
            self.say('Obtaining the production TLS certificate.')
            self.acme([*issue,'--server',PRODUCTION], 'Certificate issuance failed.')
        if not valid_pair(domain,cert,key,self.run,minimum=86400):
            raise RuntimeError('Certificate is not trusted, does not match this domain/key, or expires within 24 hours.')
        if self.console:self.console.ok('TLS certificate validated; renewal challenge passed.')
        return cert,key


def healthy(domain):
    cfg=json.loads(Path('/etc/dv-lab/hub.json').read_text())
    context=ssl.create_default_context()
    for attempt in range(20):
        try:
            with socket.create_connection(('127.0.0.1',cfg['port']),timeout=2) as raw:
                with context.wrap_socket(raw,server_hostname=domain) as conn:
                    conn.sendall(('GET /health HTTP/1.1\r\nHost: '+domain+'\r\nConnection: close\r\n\r\n').encode('ascii'))
                    if conn.recv(128).split(b'\r\n',1)[0].split()[1:2]==[b'200']:return
        except OSError:pass
        time.sleep(.25)
    raise RuntimeError('TLS service health check failed')


def deploy(plan,run=command,restart=True):
    """Copy a complete keypair into a versioned root-owned directory, then
    atomically switch ONE symlink. No mixed pair on reload or failed writes."""
    cert,key=paths(plan);domain=plan['domain']
    if not valid_pair(domain,cert,key,run):raise RuntimeError('Renewed certificate validation failed; current TLS left unchanged')
    data=cert.read_bytes();private=key.read_bytes()
    fingerprint=hashlib.sha256(data+private).hexdigest()
    group=grp.getgrnam('dvlab-hub').gr_gid
    DEST.mkdir(mode=0o750,parents=True,exist_ok=True);os.chown(DEST,0,group);DEST.chmod(0o750)
    generation=DEST/fingerprint
    if not generation.exists():
        temporary=Path(tempfile.mkdtemp(prefix='.new-',dir=DEST))
        try:
            os.chown(temporary,0,group);temporary.chmod(0o750)
            for filename,content in (('fullchain.pem',data),('privkey.pem',private)):
                p=temporary/filename
                fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                with os.fdopen(fd,'wb') as f:
                    f.write(content);f.flush();os.fsync(f.fileno());os.fchown(f.fileno(),0,group);os.fchmod(f.fileno(),0o640)
            if not valid_pair(domain,temporary/'fullchain.pem',temporary/'privkey.pem',run):
                raise RuntimeError('TLS source changed during copying; current pair left unchanged')
            temporary.rename(generation)
        finally:
            if temporary.exists():shutil.rmtree(temporary)
    link=DEST/'current'
    previous=os.readlink(link) if link.is_symlink() else None
    if previous==fingerprint:return False
    pending=DEST/'.current-next';pending.unlink(missing_ok=True);pending.symlink_to(fingerprint);os.replace(pending,link)
    try:
        if restart:run(['systemctl','restart','dv-lab-hub.service'],timeout=60)
        if restart:run(['systemctl','is-active','--quiet','dv-lab-hub.service'],timeout=20)
        if restart:healthy(domain)
    except (subprocess.SubprocessError,RuntimeError,OSError,ValueError):
        if previous:
            pending.symlink_to(previous);os.replace(pending,link)
            try:run(['systemctl','restart','dv-lab-hub.service'],check=False,timeout=60)
            except subprocess.SubprocessError:pass
        raise RuntimeError('TLS restart failed; previous keypair restored') from None
    # Bound retained private key generations; retain current and previous.
    for p in DEST.iterdir():
        if p.is_dir() and not p.is_symlink() and re.fullmatch('[0-9a-f]{64}',p.name) and p.name not in (fingerprint,previous):shutil.rmtree(p)
    return True


def install(plan,run=command):
    POLICY.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    data=json.dumps(plan)+'\n';fd=os.open(POLICY,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:f.write(data)
    PINNED.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    if PINNED.exists():raise RuntimeError('Reserved pinned TLS helper exists; inspect before continuing')
    shutil.copyfile(Path(__file__),PINNED);PINNED.chmod(0o644)
    deploy(plan,run,restart=False)
    unit=Path('/etc/systemd/system/dv-lab-tls-renew.service')
    timer=Path('/etc/systemd/system/dv-lab-tls-renew.timer')
    for p in (unit,timer):
        if p.exists():raise RuntimeError('Reserved TLS renewal unit exists; inspect before continuing')
    unit.write_text('''[Unit]
Description=DV Lab single-lineage TLS renewal and atomic deployment
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I /usr/local/lib/dv-lab/tls_manager.py
UMask=0077
PrivateTmp=yes
NoNewPrivileges=yes
CPUQuota=20%
MemoryMax=256M
MemorySwapMax=0
TasksMax=64
TimeoutStartSec=15min
''')
    timer.write_text('''[Unit]
Description=DV Lab TLS renewal schedule (no idle daemon)
[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1h
Persistent=yes
[Install]
WantedBy=timers.target
''')


def renew():
    if os.geteuid()!=0:raise RuntimeError('Root operator context required')
    info=POLICY.stat()
    if info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('Unsafe TLS policy permissions')
    plan=json.loads(POLICY.read_text());cert,key=paths(plan)
    renewal=Path(plan['config'])/'renewal'/(plan['name']+'.conf')
    if not safe_renewal(renewal):raise RuntimeError('Renewal configuration changed; refusing unsafe hooks or installer')
    command([*certbot_args(plan['config']),'renew','--cert-name',plan['name']],timeout=600)
    deploy(plan)


if __name__=='__main__':
    try:renew()
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        raise SystemExit('DV Lab TLS renewal failed: '+str(exc)) from None
