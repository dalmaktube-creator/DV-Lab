"""Disposable CI only: genuine TLS/MCP mother inside a separate network namespace."""
import json,os,ssl,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from dvlab.hub import Hub,Server
from dvlab.common import token,atomic_json
if os.environ.get('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Disposable root CI only')
folder=Path(sys.argv[1]);cfg=dict(public_url='https://dv-lab-ci.test:18443',database=str(folder/'mother.db'),admin_token=token(),mcp_token=token(),bundle=str(folder/'bundle'))
(folder/'bundle').write_bytes(b'CI fixture: no secrets')
hub=Hub(cfg);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(folder/'cert.pem',folder/'key.pem')
server=Server(('192.0.0.9',18443),hub,context)
atomic_json(folder/'connection.json',dict(code=hub.invite()['code'],mcp_token=cfg['mcp_token']))
server.serve_forever()
