#!/bin/bash
# A fresh disposable GitHub VM only. Synthetic special-purpose addresses are
# routed solely to a local network namespace; no public server is contacted.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && -n ${GITHUB_SHA:-} ]] || exit 1
. /etc/os-release
[[ $ID == ubuntu && ( $VERSION_ID == 22.04 || $VERSION_ID == 24.04 ) ]] || exit 1
apt-get update -qq
apt-get install -y --no-install-recommends iproute2 openssl ca-certificates
folder=$(mktemp -d /var/tmp/dv-lab-node-ci.XXXXXX)
chmod 700 "$folder"
openssl req -x509 -newkey rsa:2048 -nodes -days 90 -keyout "$folder/key.pem" -out "$folder/cert.pem" -subj /CN=dv-lab-ci.test -addext subjectAltName=DNS:dv-lab-ci.test -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
cp "$folder/cert.pem" /usr/local/share/ca-certificates/dv-lab-node-ci.crt
update-ca-certificates >/dev/null
ip netns add dv-lab-ci-mother
ip link add dvl-ci-host type veth peer name dvl-ci-peer
ip link set dvl-ci-peer netns dv-lab-ci-mother
ip addr add 10.200.0.1/30 dev dvl-ci-host
ip link set dvl-ci-host up
ip addr add 192.0.0.10/32 dev lo
ip netns exec dv-lab-ci-mother ip link set lo up
ip netns exec dv-lab-ci-mother ip addr add 10.200.0.2/30 dev dvl-ci-peer
ip netns exec dv-lab-ci-mother ip link set dvl-ci-peer up
ip netns exec dv-lab-ci-mother ip addr add 192.0.0.9/32 dev lo
ip route add 192.0.0.9/32 via 10.200.0.2 dev dvl-ci-host src 192.0.0.10
ip netns exec dv-lab-ci-mother ip route add 192.0.0.10/32 via 10.200.0.1 dev dvl-ci-peer
printf '\n192.0.0.9 dv-lab-ci.test\n' >> /etc/hosts
printf '%s\n' "$GITHUB_SHA" > .source-commit
ip netns exec dv-lab-ci-mother /usr/bin/python3 scripts/ci-node-mother.py "$folder" > "$folder/mother.log" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true; ip netns del dv-lab-ci-mother 2>/dev/null || true' EXIT
/usr/bin/python3 scripts/ci-node-install.py "$folder"
