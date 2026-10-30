"""Operator-only colorful terminal console. Not a host-shell MCP tool."""
import json
import os
from pathlib import Path
import pwd
import shlex
import subprocess
import sys

from .agent import Client
from .setup import prompt, userrun
from .updating import broker

C='\033[36m';G='\033[32m';Y='\033[33m';D='\033[2m';R='\033[0m'
ETC=Path('/etc/dv-lab')


def load(role):return json.loads((ETC/(role+'.json')).read_text())

def api(path,data=None):
    c=load('hub');return Client(c['public_url'],c['admin_token']).post(path,data or {})

def nodes():
    rows=api('/admin/nodes')
    print(f'{C}{"NODE":18} {"PUBLIC IPv4":16} {"STATUS":10} LAST SEEN / QUOTAS{R}')
    for n in rows:
        info=n['info'];state='PAUSED' if n['paused'] else ('ONLINE' if n['seconds_since_seen']<60 else 'OFFLINE')
        print(f"{n['name'][:18]:18} {n['public_ipv4']:16} {state:10} {n['seconds_since_seen']:5.1f}s / {info.get('account_cpus','?')} CPU · {info.get('account_memory_mib','?')} MiB")
        print(D+f"  id={n['id']}  {info.get('status','enrolled; waiting for heartbeat')}"+R)
    if not rows:print(Y+'No nodes yet. Create an invitation.'+R)
    return rows


def invite():
    result=api('/admin/invite');cfg=load('hub')
    url=cfg['public_url']+'/bootstrap.sh'
    print(G+'One-use join code — valid 10 minutes, enter only in node installer:'+R)
    print(result['code'])
    print('\nRun on the target server (script downloaded for inspection; no secret in URL):')
    print('curl -fL --proto "=https" --proto-redir "=https" '+shlex.quote(url)+' -o /tmp/dv-lab-bootstrap.sh')
    print('less /tmp/dv-lab-bootstrap.sh')
    print('sudo bash /tmp/dv-lab-bootstrap.sh')
    print(Y+'Bootstrap trusts the mother HTTPS endpoint. Never paste join/MCP tokens into chat.'+R)


def set_pause(all_nodes=False,paused=True):
    rows=nodes()
    if not rows:return
    if all_nodes:
        if prompt('Type PAUSE-ALL to stop all lab capsules')!='PAUSE-ALL':return
        targets=rows
    else:
        target=prompt('Exact node name or ID')
        targets=[x for x in rows if target in (x['id'],x['name'])]
        if len(targets)!=1:raise ValueError('Select exactly one enrolled node')
    for n in targets:api('/admin/pause',dict(node=n['id'],paused=paused))
    print(Y+'Requested. Applied on agent heartbeat, not a synchronous stop confirmation.'+R)


def local_status():
    cfg=load('agent');who=pwd.getpwnam('dvlab-node')
    print(json.dumps({k:v for k,v in cfg.items() if k not in ('token','image')},indent=2))
    userrun(who,['systemctl','--user','status','dv-lab-agent.service','--no-pager'],check=False)


def local_stop():
    if prompt('Type STOP to stop only the local DV Lab node')!='STOP':return
    who=pwd.getpwnam('dvlab-node')
    userrun(who,['systemctl','--user','stop','dv-lab-agent.service'])
    userrun(who,['python3','-m','dvlab.agent','--stop'])
    print(G+'Local node service stopped and owned capsule removed. No production service touched.'+R)


def main():
    if os.geteuid()!=0:raise SystemExit('Use sudo dv-lab (operator console; secrets are local only)')
    if len(sys.argv)>1 and sys.argv[1]=='--emergency-stop':local_stop();return
    if len(sys.argv)>1 and sys.argv[1]=='update':
        action=sys.argv[2] if len(sys.argv)>2 else 'check'
        args=dict(action=action)
        if len(sys.argv)>3:args['commit']=sys.argv[3]
        print(json.dumps(broker(args),indent=2));return
    while True:
        hub=(ETC/'hub.json').exists();node=(ETC/'agent.json').exists()
        print('\n'+C+'╭──────────────────────────────────────────────────╮')
        print('│  DV LAB   /   CONTROL CENTER             preview │')
        print('╰──────────────────────────────────────────────────╯'+R)
        print(D+'  REAL NETWORK · BOUNDED RESOURCES · NO HOST SHELL'+R)
        if hub:print('  1  Nodes & health\n  2  Bootstrap / one-use invite\n  3  MCP connection\n  4  Pause node\n  5  Resume node\n  6  Emergency pause ALL labs')
        if node:print('  7  Local node status\n  8  Stop local lab NOW\n  9  Restart local node service')
        print('  U  Update this machine\n  S  Update status\n  R  Roll back application\n  0  Exit')
        choice=prompt('Choose','0')
        try:
            if choice=='0':return
            elif choice.upper()=='S':print(json.dumps(broker(dict(action='status')),indent=2))
            elif choice.upper()=='U':
                candidate=broker(dict(action='check'));print(json.dumps(candidate,indent=2))
                print(Y+'Update stops local lab workloads and clears the temporary workspace. Download artifacts first.'+R)
                if candidate['ci_passed'] and prompt('Type UPDATE to apply this exact commit')=='UPDATE':
                    print(json.dumps(broker(dict(action='apply',commit=candidate['commit'])),indent=2))
            elif choice.upper()=='R':
                if prompt('Type ROLLBACK to stop local labs and restore previous app')=='ROLLBACK':
                    print(json.dumps(broker(dict(action='rollback')),indent=2))
            elif choice=='1' and hub:nodes()
            elif choice=='2' and hub:invite()
            elif choice=='3' and hub:
                cfg=load('hub');print('Streamable HTTP endpoint: '+cfg['public_url']+'/mcp')
                print('Authorization: Bearer token. Enter in your MCP client secure connection form.')
                if prompt('Reveal MCP token locally? type SHOW')=='SHOW':print(cfg['mcp_token'])
            elif choice=='4' and hub:set_pause()
            elif choice=='5' and hub:set_pause(paused=False)
            elif choice=='6' and hub:set_pause(all_nodes=True)
            elif choice=='7' and node:local_status()
            elif choice=='8' and node:local_stop()
            elif choice=='9' and node:userrun(pwd.getpwnam('dvlab-node'),['systemctl','--user','restart','dv-lab-agent.service'])
            else:print('Unknown option')
        except Exception as exc:print(Y+type(exc).__name__+': '+str(exc)[:200]+R)

if __name__=='__main__':main()
