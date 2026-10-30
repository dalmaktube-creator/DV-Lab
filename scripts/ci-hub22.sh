#!/bin/bash
# Destructive to our reserved paths/account only; disposable CI VM ONLY.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true ]] || { echo 'Disposable GitHub runner only'; exit 1; }
[[ -n ${GITHUB_SHA:-} ]] || exit 1
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 22.04 ]] || { echo 'Jammy runner required'; exit 1; }
certdir=$(mktemp -d /var/tmp/dv-lab-hub-ci.XXXXXX)
# The key lives outside the repository: it must NEVER enter the bootstrap archive.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$certdir/key.pem" -out "$certdir/cert.pem" -subj /CN=localhost -addext subjectAltName=DNS:localhost -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
cp "$certdir/cert.pem" /usr/local/share/ca-certificates/dv-lab-disposable-ci.crt
update-ca-certificates >/dev/null
printf '%s\n' "$GITHUB_SHA" > .source-commit
/usr/bin/python3 scripts/hub22-smoke.py "$certdir/cert.pem" "$certdir/key.pem"
