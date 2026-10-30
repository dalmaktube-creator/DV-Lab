# DV Lab

**0.2.0-preview.1 — isolated multi-server test lab with an MCP controller.**

[راهنمای فارسی](README.fa.md) · [Updates](UPDATE.md) · [Security boundaries](SECURITY.md) · [Acceptance checklist](CHECKLIST.md)

## One-command installation

Once this repository is public **and both CI jobs on main are green**:

```bash
curl -fsSL https://raw.githubusercontent.com/dalmaktube-creator/DV-Lab/main/install.sh | sudo bash
```

The installer asks for **hub** or **agent**, reads prompts through `/dev/tty`, pins an exact main commit, requires passing GitHub CI, verifies downloaded files against that commit's Git tree, and asks for explicit confirmation before host changes. For a private repository, unauthenticated raw downloads do not work. No GitHub token is collected by this installer.

**Preview, not production-certified.** Ubuntu 24.04 + systemd + cgroup v2 only. Hub needs an existing valid TLS certificate and public DNS; no automatic certificate issuance, nginx edits or host firewall overrides. There has been no deployment on the owner's Iran/Turkey servers.

## Control center

```bash
sudo dv-lab
sudo dv-lab update check
sudo dv-lab update status
sudo dv-lab update apply FULL_40_CHARACTER_COMMIT_SHA
sudo dv-lab update rollback
```

The mother creates one-use node invitations and public bootstrap links. Agents call the mother over outbound HTTPS, without sharing SSH keys. Nodes exchange real TCP/UDP traffic only on the operator-reserved lab port pool.

MCP endpoint: `https://YOUR-MOTHER:8443/mcp`, Streamable HTTP, bearer authentication. Get the token locally from the console, never from chat.

## Agent autonomy

`lab_nodes`, `lab_exec`, `lab_action`, `lab_logs`, `lab_kill`, `lab_read`, `lab_write`, `lab_list`, `lab_metrics`, `lab_pause`, `lab_resume`, `lab_update`.

Commands run **inside** an ephemeral rootless Podman capsule. Readonly root; fixed TUN/net capabilities; no host secrets; no Docker socket; no host network/PID namespace. The only host bind mount contains a small immutable, non-secret capsule code directory, readonly. Workspace and logs are bounded. Capsules are destroyed on pause/stop; download artifacts first.

The enclosing lab account, including the controller and rootless networking, defaults to **0.5 CPU / 192MiB**, with the capsule limited to **0.4 CPU / 128MiB**. These are ceilings, not measured idle usage. A one-second bounded CPU/RAM sampler reports account vs capsule usage and throttling. Rootless packet processing has overhead; quota-limited throughput is not a bare-metal tunnel maximum.

## Self-update without an arbitrary root shell

After code changes through Moory **or GitHub MCP**:

1. Push to main; wait for `unit-and-protocol` and `ubuntu-isolation` to succeed.
2. Call `lab_update` with `action=check`, `target=<node ID>`.
3. Apply the explicit full commit SHA to a canary node, inspect status/version/health; update other nodes sequentially.
4. Update `target=mother` last and reconnect if necessary.

A pinned root broker stages only application files from this fixed repo/main, verifies Git blob identities, stops local lab workloads, atomically switches the active code directory, restarts only DV Lab services, verifies live health, and restores the previous code on failure. Failed-health recovery also restores a pre-update mother database snapshot. Manual later rollback is application-only. It never runs downloaded install scripts as root or changes quotas, services, firewall policy or host packages. Root helper/operator console and base image upgrades require an operator-reviewed migration. [Read the trust model](UPDATE.md).

## Validation

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q dvlab scripts
bash -n install.sh scripts/ci-isolation.sh
```

31 local regression tests passed at publication preparation. GitHub CI is configured to repeat those tests and run rootless Podman/TUN/cgroup/nft smoke on a disposable Ubuntu runner. **A configured workflow is not evidence it passed**; consult the actual Actions run. Multi-server throughput, target-host overhead, reboot/fault acceptance and deployment remain separate validation tasks. The CI helper refuses execution outside GitHub Actions and must never be run on production.
