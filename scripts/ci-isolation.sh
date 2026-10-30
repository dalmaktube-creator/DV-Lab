#!/bin/bash
# Only for a fresh, disposable GitHub-hosted VM. NEVER run on production.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true ]] || { echo 'Disposable GitHub runner only'; exit 1; }
apt-get update -qq
apt-get install -y --no-install-recommends podman slirp4netns uidmap dbus-user-session nftables sudo fuse-overlayfs iproute2
useradd -m -s /bin/bash dvlab-node
uid=$(id -u dvlab-node)
runtime=/run/user/$uid
mkdir -p "/etc/systemd/system/user@$uid.service.d"
printf '[Service]\nDelegate=cpu memory pids\n' > "/etc/systemd/system/user@$uid.service.d/dv-lab-delegation.conf"
systemctl daemon-reload
loginctl enable-linger dvlab-node
systemctl start "user@$uid.service"
root=/opt/dv-lab-ci
mkdir -p "$root"
cp -r dvlab Containerfile scripts "$root/"
printf '%s\n' "$GITHUB_SHA" > "$root/.source-commit"
mkdir -p "$root/capsule/dvlab"
cp dvlab/{__init__,common,runner,sampling}.py "$root/capsule/dvlab/"
chmod -R a+rX "$root"
cd "$root"
# Ubuntu 24.04 AppArmor may restrict unprivileged user namespaces. Use the
# packaged podman profile; do NOT disable AppArmor/sysctls globally to pass.
runuser -u dvlab-node -- env -i HOME=/home/dvlab-node USER=dvlab-node LOGNAME=dvlab-node PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin XDG_CONFIG_HOME=/home/dvlab-node/.config XDG_DATA_HOME=/home/dvlab-node/.local/share XDG_RUNTIME_DIR="$runtime" DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" podman build -t localhost/dv-lab:ci "$root"
image=$(runuser -u dvlab-node -- env -i HOME=/home/dvlab-node USER=dvlab-node LOGNAME=dvlab-node PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin XDG_CONFIG_HOME=/home/dvlab-node/.config XDG_DATA_HOME=/home/dvlab-node/.local/share XDG_RUNTIME_DIR="$runtime" DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" podman image inspect --format '{{.Id}}' localhost/dv-lab:ci)
[[ $image == sha256:* ]] || image=sha256:$image
printf '%s' "$image" > "$root/image-id"
systemctl set-property "user-$uid.slice" CPUQuota=50% MemoryMax=192M MemorySwapMax=0 TasksMax=128
mkdir -p /etc/dv-lab
python3 - "$uid" <<'PY'
import json,sys,pwd
from pathlib import Path
from dvlab import setup
from dvlab.resource_guard import FIELDS
from dvlab.netpolicy import initial_policy
cfg=dict(uid=int(sys.argv[1]),hub_ips=['8.8.8.8'],hub_port=8443,dns_ips=[],host_ips=['127.0.0.1'],port_start=45100,port_count=8)
p=Path('/etc/dv-lab/network.json');p.write_text(json.dumps(cfg));p.chmod(0o600)
Path('/tmp/dv-lab-ci.nft').write_text(initial_policy(cfg))
who=pwd.getpwnam('dvlab-node')
agent=dict(node='ci',image=Path('/opt/dv-lab-ci/image-id').read_text(),port_start=45100,port_count=8,capsule_cpus=.4,capsule_memory_mib=128,account_cpus=.5,account_memory_mib=192)
setup.config(Path('/etc/dv-lab/agent.json'),agent,who)
drop=Path(f'/etc/systemd/system/user-{who.pw_uid}.slice.d');drop.mkdir(parents=True,exist_ok=True)
(drop/'dv-lab.conf').write_text('[Slice]\nCPUQuota=50%\nMemoryMax=192M\nMemorySwapMax=0\nTasksMax=128\n')
setup.install_resources(who)
PY
systemctl daemon-reload
systemctl enable --now dv-lab-resources.socket
nft -c -f /tmp/dv-lab-ci.nft
nft -f /tmp/dv-lab-ci.nft
# The entire test + rootless helpers belong to the bounded user slice.
runuser -u dvlab-node -- env -i HOME=/home/dvlab-node USER=dvlab-node LOGNAME=dvlab-node PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin XDG_CONFIG_HOME=/home/dvlab-node/.config XDG_DATA_HOME=/home/dvlab-node/.local/share XDG_RUNTIME_DIR="$runtime" DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemd-run --user --wait --pipe --collect --unit=dv-lab-ci-test --property=Delegate=yes --setenv=HOME=/home/dvlab-node --setenv=XDG_RUNTIME_DIR="$runtime" --setenv=DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" --working-directory="$root" /usr/bin/python3 "$root/scripts/smoke.py"
