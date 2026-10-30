"""Unprivileged client for an initial-installation, bounded resource socket."""
import json
import socket
from .resource_guard import validate

SOCKET='/run/dv-lab/resources.sock'

def broker(data):
    data={k:v for k,v in validate(data).items() if k!='op'}
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(60);connection.connect(SOCKET)
            connection.sendall(json.dumps(data).encode());connection.shutdown(socket.SHUT_WR)
            with connection.makefile('rb') as f:raw=f.read(16385)
    except OSError:raise RuntimeError('Resource socket unavailable; this node needs the initial resource-capable installer') from None
    if len(raw)>16384:raise RuntimeError('Resource response exceeded bound')
    result=json.loads(raw)
    if 'error' in result:raise RuntimeError(result['error'])
    return result
