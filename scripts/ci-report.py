"""Stream disposable isolation logs and publish a bounded failure annotation."""
from collections import deque
import os
import subprocess
import sys

if os.environ.get('GITHUB_ACTIONS')!='true':raise SystemExit('GitHub Actions only')
args=['sudo','env','GITHUB_ACTIONS=true','GITHUB_SHA='+os.environ['GITHUB_SHA'],'bash','scripts/ci-isolation.sh']
tail=deque(maxlen=50)
with subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True) as p:
    for line in p.stdout:
        print(line,end='',flush=True);tail.append(line)
    code=p.wait()
if code:
    message=''.join(tail)[-10000:].replace('%','%25').replace('\r','%0D').replace('\n','%0A')
    print('::error title=Rootless isolation failure::'+message,flush=True)
sys.exit(code)
