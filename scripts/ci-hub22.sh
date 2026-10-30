#!/bin/bash
# Destructive to our reserved paths/account only; disposable CI VM ONLY.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true ]] || { echo 'Disposable GitHub runner only'; exit 1; }
[[ -n ${GITHUB_SHA:-} ]] || exit 1
. /etc/os-release
[[ $ID == ubuntu && ( $VERSION_ID == 22.04 || $VERSION_ID == 24.04 ) ]] || { echo 'Ubuntu 22.04 or 24.04 runner required'; exit 1; }
certdir=$(mktemp -d /var/tmp/dv-lab-hub-ci.XXXXXX)
# The key lives outside the repository: it must NEVER enter the bootstrap archive.
openssl req -x509 -newkey rsa:2048 -nodes -days 90 -keyout "$certdir/key.pem" -out "$certdir/cert.pem" -subj /CN=dv-lab-hub-ci.test -addext subjectAltName=DNS:dv-lab-hub-ci.test -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
cp "$certdir/cert.pem" /usr/local/share/ca-certificates/dv-lab-disposable-ci.crt
update-ca-certificates >/dev/null
# RFC6890 globally-reachable fixture address, routed only to this disposable VM.
ip addr add 192.0.0.9/32 dev lo
printf '\n192.0.0.9 dv-lab-hub-ci.test\n' >> /etc/hosts
printf '%s\n' "$GITHUB_SHA" > .source-commit
/usr/bin/python3 scripts/hub22-smoke.py "$certdir/cert.pem" "$certdir/key.pem"
