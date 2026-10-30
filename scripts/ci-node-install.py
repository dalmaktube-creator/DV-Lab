"""Real production node installer + outbound TLS enrollment + MCP operations.
Only terminal answers are supplied by CI. No network, cgroup or Podman mock.
"""
import json,os,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from dvlab import setup
from dvlab.agent import Client
if os.environ.get('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Disposable root CI only')
folder=Path(sys.argv[1]);connection=folder/'connection.json'
for _ in range(50):
    if connection.is_file():break
    time.sleep(.1)
else:raise AssertionError('CI mother did not start: '+(folder/'mother.log').read_text()[-2000:])
private=json.loads(connection.read_text());url='https://dv-lab-ci.test:18443'
setup.prompt=lambda label,default='':'ci-node'
setup.secret=lambda label:private['code']
setup.confirm=lambda text:print('CI: initial node installation and resource ceilings approved on disposable VM')
try:setup.agent(url)
except Exception:
    if setup.CONSOLE.log_path:print(setup.CONSOLE.log_path.read_text(errors='replace')[-6000:])
    raise
client=Client(url,private['mcp_token']);sequence=0

def call(name,args):
    global sequence
    sequence+=1
    reply=client.post('/mcp',dict(jsonrpc='2.0',id=sequence,method='tools/call',params=dict(name=name,arguments=args)))['result']
    assert not reply['isError'],reply
    return json.loads(reply['content'][0]['text'])

def action(name,args):
    queued=call(name,args)
    for _ in range(120):
        result=call('lab_action',dict(action=queued['action']))
        if result['state']=='done':
            assert result['result']['ok'],result
            return result['result']['result']
        assert result['state'] not in ('expired','cancelled'),result
        time.sleep(.25)
    raise AssertionError('Node action timed out')

for _ in range(120):
    nodes=call('lab_nodes',{})
    if nodes and nodes[0]['info'].get('version'):break
    time.sleep(.25)
else:raise AssertionError('No real node heartbeat')
node=nodes[0]['id'];assert nodes[0]['public_ipv4']=='192.0.0.10',nodes
process=action('lab_exec',dict(node=node,command='echo dv-lab-e2e; test ! -e /etc/dv-lab/agent.json',seconds=5))['process']
time.sleep(.5)
logs=action('lab_logs',dict(node=node,process=process));assert 'dv-lab-e2e' in logs['output'],logs
state=action('lab_resources',dict(node=node,action='status'))
changed=action('lab_resources',dict(node=node,action='set',revision=state['revision'],account_cpus=.75,account_memory_mib=320,capsule_cpus=.65,capsule_memory_mib=256))
metrics=action('lab_metrics',dict(node=node));assert metrics['cgroup']['memory.max'].strip()==str(256*1048576),metrics
assert metrics['lab_account']['memory.max'].strip()==str(320*1048576),metrics
state=action('lab_resources',dict(node=node,action='set',revision=changed['revision'],account_cpus=.5,account_memory_mib=192,capsule_cpus=.4,capsule_memory_mib=128))
assert state['current']['account_memory_mib']==192,state
client.conn.close()
print('PASS: full node installation, real outbound TLS enrollment, authenticated heartbeat, MCP shell only in capsule, logs, remote resource changes and enforced account/capsule cgroups')
