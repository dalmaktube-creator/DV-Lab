"""Unprivileged fixed-command client for the pinned root update broker."""
import json
from pathlib import Path
import re
import socket
from . import __version__

BROKER_SOCKET="/run/dv-lab/update.sock"

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
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(90)
            connection.connect(BROKER_SOCKET)
            connection.sendall(json.dumps(data).encode())
            connection.shutdown(socket.SHUT_WR)
            with connection.makefile('rb') as response:raw=response.read(16385)
    except OSError:
        raise RuntimeError('Local update socket unavailable; inspect dv-lab-update-broker.socket') from None
    if len(raw)>16384:raise RuntimeError('Broker response bound exceeded')
    try:value=json.loads(raw)
    except ValueError:raise RuntimeError('Invalid local update response') from None
    if 'error' in value:raise RuntimeError(value['error'])
    return value
