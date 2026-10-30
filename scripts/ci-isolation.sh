#!/bin/bash
# Only for a fresh, disposable GitHub-hosted VM. NEVER run on production.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true ]] || { echo 'Disposable GitHub runner only'; exit 1; }
apt-get update -qq
apt-get install -y --no-install-recommends podman slirp4netns uidmap dbus-user-session nftables sudo fuse-overlayfs iproute2
useradd -m -s /bin/bash dvlab-ci
uid=$(id -u dvlab-ci)
runtime=/run/user/$uid
loginctl enable-linger dvlab-ci
systemctl start "user@$uid.service"
root=/opt/dv-lab-ci
mkdir -p "$root"
cp -r dvlab Containerfile scripts "$root/"
printf '%s\n' "$GITHUB_SHA" > "$root/.source-commit"
mkdir -p "$root/capsule/dvlab"
cp dvlab/{__init__,common,runner,sampling}.py "$root/capsule/dvlab/"
chmod -R a+rX "$root"
# Ubuntu 24.04 AppArmor may restrict unprivileged user namespaces. Use the
# packaged podman profile; do NOT disable AppArmor/sysctls globally to pass.
runuser -u dvlab-ci -- env XDG_RUNTIME_DIR="$runtime" DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" podman build -t localhost/dv-lab:ci "$root"
image=$(runuser -u dvlab-ci -- env XDG_RUNTIME_DIR="$runtime" DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" podman image inspect --format '{{.Id}}' localhost/dv-lab:ci)
[[ $image == sha256:* ]] || image=sha256:$image
printf '%s' "$image" > "$root/image-id"
systemctl set-property "user-$uid.slice" CPUQuota=50% MemoryMax=192M MemorySwapMax=0 TasksMax=128
mkdir -p /etc/dv-lab
python3 - "$uid" <<'PY'
import json,sys
from pathlib import Path
from dvlab.netpolicy import initial_policy
cfg=dict(uid=int(sys.argv[1]),hub_ips=['8.8.8.8'],hub_port=8443,dns_ips=[],host_ips=['127.0.0.1'],port_start=45100,port_count=8)
p=Path('/etc/dv-lab/network.json');p.write_text(json.dumps(cfg));p.chmod(0o600)
Path('/tmp/dv-lab-ci.nft').write_text(initial_policy(cfg))
PY
nft -c -f /tmp/dv-lab-ci.nft
nft -f /tmp/dv-lab-ci.nft
# The entire test + rootless helpers belong to the bounded user slice.
runuser -u dvlab-ci -- env XDG_RUNTIME_DIR="$runtime" DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemd-run --user --wait --pipe --collect --unit=dv-lab-ci-test --property=Delegate=yes --working-directory="$root" /usr/bin/python3 "$root/scripts/smoke.py"
