"""Local enrollment helper, executed only as the dedicated hub account by setup.
No MCP command, root shell, shared hub credentials or privileged fallback.
"""
import json
import os
from pathlib import Path
import pwd
import sys
from .common import public_ip
from .hub import Hub

NAME='mother-local'
CONFIG=Path('/etc/dv-lab/hub.json')


def enroll(ip):
    who=pwd.getpwnam('dvlab-hub')
    if who.pw_uid==0 or os.geteuid()!=who.pw_uid:
        raise ValueError('Local enrollment must run as the dedicated hub account')
    ip=public_ip(ip)
    hub=Hub(json.loads(CONFIG.read_text()))
    with hub.db() as db:
        if db.execute('SELECT 1 FROM nodes WHERE name=?',(NAME,)).fetchone():
            raise ValueError('mother-local already enrolled; refusing duplicate or credential replacement')
    invitation=hub.invite()
    return hub.enroll(invitation['code'],NAME,ip)


def main():
    if len(sys.argv)!=2:raise SystemExit('Expected mother public IPv4 only')
    try:result=enroll(sys.argv[1])
    except (ValueError,OSError,KeyError):raise SystemExit('Local enrollment failed; inspect existing mother-local registration') from None
    print(json.dumps(result))


if __name__=='__main__':main()
