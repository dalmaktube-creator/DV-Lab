"""Disposable CI kernel smoke, not a substitute for multi-server acceptance."""
from pathlib import Path
import sys,time
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from dvlab.agent import Capsule,verify_account_limits
root=Path(__file__).resolve().parent.parent
cfg=dict(node='ci',image=(root/'image-id').read_text().strip(),port_start=45100,port_count=8,capsule_cpus=.4,capsule_memory_mib=128,account_cpus=.5,account_memory_mib=192)
c=Capsule(cfg)
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
