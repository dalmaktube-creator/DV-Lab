"""Disposable CI kernel smoke, not a substitute for multi-server acceptance."""
from pathlib import Path
import sys,time,subprocess
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from dvlab.agent import Capsule,verify_account_limits,host_environment
root=Path(__file__).resolve().parent.parent
cfg=dict(node='ci',image=(root/'image-id').read_text().strip(),port_start=45100,port_count=8,capsule_cpus=.4,capsule_memory_mib=128,account_cpus=.5,account_memory_mib=192)
def diagnostic_run(argv,data=None,timeout=20):
    p=subprocess.run(argv,input=data,capture_output=True,timeout=timeout,env=host_environment())
    if p.returncode:
        print('CI fixed-helper failure:',argv[0:2], 'exit',p.returncode, file=sys.stderr)
        print(p.stderr.decode(errors='replace')[-6000:],file=sys.stderr)
        raise RuntimeError('CI host helper failed')
    if len(p.stdout)>300000 or len(p.stderr)>65536:raise RuntimeError('Helper output bound')
    return p.stdout
c=Capsule(cfg,run=diagnostic_run)
try:
    verify_account_limits(cfg);c.ensure()
    out=c.operate(dict(op='write',path='hello',data_b64='aGVsbG8='));assert out['ok'],out
    out=c.operate(dict(op='read',path='hello'));assert out['result']['data_b64']=='aGVsbG8=',out
    task=c.operate(dict(op='start',command='test ! -e /etc/dv-lab/agent.json && test ! -w /etc && echo isolated',seconds=5))
    pid=task['result']['process'];time.sleep(1)
    result=c.operate(dict(op='logs',process=pid));assert 'isolated' in result['result']['output'],result
    metrics=c.operate(dict(op='metrics'));assert metrics['ok'],metrics
    print('PASS: rootless namespaces, TUN create/delete, actual cgroups, workspace, readonly root, no agent-secret mount; nft syntax/apply')
finally:c.stop()
