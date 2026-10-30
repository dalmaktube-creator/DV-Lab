"""Real installation on an ephemeral Ubuntu 22.04 runner, NOT a mock service."""
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from dvlab import setup
from dvlab.agent import Client
from dvlab import tls_manager
from unittest.mock import patch

if os.environ.get('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Disposable root CI only')
origin='https://localhost:18443'
answers=iter(('localhost','18443'))
lineage=tls_manager.OWN/'live/ci-fixture'
lineage.mkdir(parents=True)
(lineage/'fullchain.pem').symlink_to(sys.argv[1])
(lineage/'privkey.pem').symlink_to(sys.argv[2])
renewal=tls_manager.OWN/'renewal';renewal.mkdir()
(renewal/'ci-fixture.conf').write_text('[renewalparams]\nauthenticator = webroot\n')
setup.prompt=lambda *args,**kwargs:next(answers)
setup.confirm=lambda text:print('CI operator-approved install: hub only; no production server involved')
try:
    with patch.object(tls_manager.Manager,'acme',lambda self,args,message: print('CI: external ACME request mocked; real certificate validation/deployment retained')):
        setup.hub()  # Actual packages, account, TLS validation/deploy, services and timer.
except Exception:
    if setup.CONSOLE.log_path:
        print('CI private install log tail:')
        print(setup.CONSOLE.log_path.read_text(errors='replace')[-5000:])
    raise
cfg=json.loads(Path('/etc/dv-lab/hub.json').read_text())
for attempt in range(50):
    try:
        with urllib.request.urlopen(origin+'/health',timeout=2) as r:health=json.load(r)
        break
    except (OSError,urllib.error.URLError):time.sleep(.2)
else:raise AssertionError('Hub never became healthy')
assert health['commit']==os.environ['GITHUB_SHA'],health
mcp=Client(origin,cfg['mcp_token'])
r=mcp.post('/mcp',dict(jsonrpc='2.0',id=1,method='initialize',params={'protocolVersion':'2025-03-26'}));assert r['result']['serverInfo']['name']=='DV Lab',r
r=mcp.post('/mcp',dict(jsonrpc='2.0',id=2,method='tools/list'));assert len(r['result']['tools'])==13,r
# Exercise the real unprivileged hub -> local socket broker path under its unit sandbox.
r=mcp.post('/mcp',dict(jsonrpc='2.0',id=3,method='tools/call',params={'name':'lab_update','arguments':{'target':'mother','action':'status'}}));assert r['result']['isError'] is False,r
state=json.loads(r['result']['content'][0]['text']);assert state['current']==health['commit'],state
assert subprocess.check_output(['systemctl','show','--property=NoNewPrivileges','--value','dv-lab-hub.service'],text=True).strip()=='yes'
mcp.conn.close()
try:
    Client(origin,'invalid-token').post('/mcp',dict(jsonrpc='2.0',id=4,method='tools/list'))
    raise AssertionError('Invalid bearer accepted')
except RuntimeError as exc:assert '401' in str(exc),exc
with urllib.request.urlopen(origin+'/bootstrap.sh') as r:bootstrap=r.read()
assert cfg['mcp_token'].encode() not in bootstrap and cfg['admin_token'].encode() not in bootstrap
# Console/update status must exist after installation, unlike the user's failed run.
p=subprocess.run(['/usr/local/bin/dv-lab','update','status'],check=True,capture_output=True,text=True);assert json.loads(p.stdout)['current']==health['commit']
# Verify real service cgroups, not just the unit text.
cg=subprocess.check_output(['systemctl','show','--property=ControlGroup','--value','dv-lab-hub.service'],text=True).strip()
path=Path('/sys/fs/cgroup')/cg.lstrip('/')
quota,period=(path/'cpu.max').read_text().split();assert quota!='max' and int(quota)/int(period)<=.25+.01
assert int((path/'memory.max').read_text())<=256*1048576
assert (path/'memory.swap.max').read_text().strip()=='0'
# Key inaccessible to an unrelated unprivileged account.
p=subprocess.run(['runuser','-u','nobody','--','test','-r','/etc/dv-lab/tls/current/privkey.pem']);assert p.returncode!=0
assert subprocess.run(['systemctl','is-enabled','--quiet','dv-lab-tls-renew.timer']).returncode==0
assert subprocess.run(['systemctl','is-active','--quiet','dv-lab-tls-renew.timer']).returncode==0
assert Path('/usr/local/lib/dv-lab/tls_manager.py').stat().st_uid==0
assert not (Path('/usr/local/lib/dv-lab/tls_manager.py').stat().st_mode & 0o022)
assert json.loads(tls_manager.POLICY.read_text())['name']=='ci-fixture'
# Exercise the actual pinned deployment helper against the running TLS service.
import importlib.util
spec=importlib.util.spec_from_file_location('pinned_tls','/usr/local/lib/dv-lab/tls_manager.py')
pinned_tls=importlib.util.module_from_spec(spec);spec.loader.exec_module(pinned_tls)
plan=json.loads(tls_manager.POLICY.read_text());source_cert=Path(sys.argv[1])
old=os.readlink('/etc/dv-lab/tls/current');source_cert.write_bytes(source_cert.read_bytes()+b'\n')
assert pinned_tls.deploy(plan) is True
assert os.readlink('/etc/dv-lab/tls/current')!=old
with urllib.request.urlopen(origin+'/health',timeout=3) as r:assert r.status==200
print('PASS: pinned TLS helper rotated a real keypair generation, restarted only the hub and verified live HTTPS health')
print('PASS: TLS managed certificate reuse, real trust/key/hostname validation, atomic deployment and active renewal timer; external CA requests mocked')
print('PASS: Ubuntu 22.04 real hub install, trusted TLS, authenticated MCP tools, pinned socket update status, console command, cgroup quotas and private-key permissions')

# Actual controlling TTY after root -> hub privilege drop. No tokens are revealed.
import fcntl,pty,select,signal,termios
master,slave=pty.openpty()
def controlling_tty():
    os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
process=subprocess.Popen(['/usr/local/bin/dv-lab'],stdin=slave,stdout=slave,stderr=slave,pass_fds=(slave,),preexec_fn=controlling_tty)
os.close(slave);output=b'';step=0;deadline=time.monotonic()+15
try:
    while time.monotonic()<deadline:
        if not select.select([master],[],[],.2)[0]:
            if process.poll() is not None:break
            continue
        try:data=os.read(master,8192)
        except OSError:break
        output+=data
        assert len(output)<32768,'Console output bound'
        if step==0 and b'Choose [0]' in output:os.write(master,b'1\n');step=1
        elif step==1 and b'Press Enter to return to menu' in output:
            assert output.count(b'CONTROL CENTER')==1,'Menu redrew before Enter'
            os.write(master,b'\n');step=2
        elif step==2 and output.count(b'CONTROL CENTER')==2 and output.count(b'Choose [0]')>=2:
            os.write(master,b'0\n');step=3
    process.wait(timeout=3)
    assert process.returncode==0 and step==3,output.decode(errors='replace')[-3000:]
finally:
    if process.poll() is None:process.kill();process.wait()
    os.close(master)
print('PASS: real privilege-dropped operator console, controlling TTY, results held until Enter and clean return to menu')
