"""Unprivileged fixed-command client for the pinned root update broker."""
import json
from pathlib import Path
import re
import subprocess
from . import __version__

def identity():
    p=Path(__file__).resolve().parent.parent/'.source-commit'
    commit=p.read_text().strip() if p.exists() else 'development'
    return dict(version=__version__,commit=commit)

def validate_update(a):
    if not isinstance(a,dict) or set(a)-{'op','action','commit'}:raise ValueError('Unknown update argument')
    if a.get('action') not in ('check','status','apply','rollback'):raise ValueError('Invalid update action')
    if a['action']=='apply' or 'commit' in a:
        if not isinstance(a.get('commit'),str) or not re.fullmatch('[0-9a-f]{40}',a['commit']):raise ValueError('Full commit SHA required')
    return a

def broker(a):
    validate_update(a)
    data={k:v for k,v in a.items() if k!='op'}
    p=subprocess.run(['sudo','-n','/usr/local/sbin/dv-lab-update'],input=json.dumps(data).encode(),capture_output=True,timeout=90)
    if len(p.stdout)>16384 or len(p.stderr)>4096:raise RuntimeError('Broker response bound exceeded')
    try:value=json.loads(p.stdout)
    except ValueError:raise RuntimeError('Update broker unavailable; inspect local installation')
    if p.returncode:raise RuntimeError(value.get('error','Update refused'))
    return value
