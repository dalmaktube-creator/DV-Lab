"""Fixed, root-pinned launcher. Drop privileges BEFORE loading mutable UI code."""
import os
from pathlib import Path
import pwd
import sys


def launch(args):
    if os.geteuid()!=0:raise SystemExit('Use sudo dv-lab')
    args=list(args)
    node=bool(args and args[0]=='--node')
    if node:args.pop(0)
    account='dvlab-hub' if not node and Path('/etc/dv-lab/hub.json').is_file() else 'dvlab-node'
    if not Path('/etc/dv-lab/'+('hub' if account=='dvlab-hub' else 'agent')+'.json').is_file():raise SystemExit('Requested DV Lab role is not installed')
    who=pwd.getpwnam(account)
    if who.pw_uid==0 or who.pw_gid==0:raise SystemExit('Unsafe dedicated account identity')
    env=dict(HOME=who.pw_dir,USER=account,LOGNAME=account,PATH='/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
        LANG='C.UTF-8',TERM=os.environ.get('TERM','dumb'),PYTHONDONTWRITEBYTECODE='1',
        XDG_RUNTIME_DIR='/run/user/'+str(who.pw_uid),DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/'+str(who.pw_uid)+'/bus')
    if 'NO_COLOR' in os.environ:env['NO_COLOR']='1'
    os.chdir('/opt/dv-lab/current')
    os.initgroups(account,who.pw_gid);os.setgid(who.pw_gid);os.setuid(who.pw_uid)
    if os.getuid()!=who.pw_uid or os.geteuid()!=who.pw_uid:raise SystemExit('Could not drop console privileges')
    os.execve('/usr/bin/python3',['/usr/bin/python3','-m','dvlab.menu',*args],env)


if __name__=='__main__':launch(sys.argv[1:])
