# DV Lab

**0.2.0-preview.8 — isolated multi-server test lab with an MCP controller.**

[راهنمای فارسی](README.fa.md) · [Updates](UPDATE.md) · [Security boundaries](SECURITY.md) · [Acceptance checklist](CHECKLIST.md)

## One-command installation

Once this repository is public **and all required CI jobs on main are green**:

```bash
curl -fsSL https://raw.githubusercontent.com/dalmaktube-creator/DV-Lab/main/install.sh | sudo bash
```

The installer asks for **hub** or **agent**, reads prompts through `/dev/tty`, pins an exact main commit, requires passing GitHub CI, verifies downloaded files against that commit's Git tree, and asks for explicit confirmation before host changes. For a private repository, unauthenticated raw downloads do not work. No GitHub token is collected by this installer.

**Preview, not production-certified.** Hub: Ubuntu 22.04 or 24.04. Isolated agent: Ubuntu 22.04 or 24.04. Both require systemd + cgroup v2. Hub needs public DNS; TLS is discovered or obtained automatically as documented below. No webserver shutdown or host firewall override. Target-server throughput remains a separate validation task.

## Mother includes a test node by default

Fresh **hub** installation now provisions `mother-local` automatically, using the
**same** rootless agent installer as remote servers. It appears in `lab_nodes`
with `info.location="mother"`; use its returned ID with the existing exec, file,
log, metrics and resource tools. No new host-shell tool or privileged fallback.
The hub and lab agent have different Unix accounts, credentials and cgroups.
Starting local-agent limits: account0.5CPU/192MiB, capsule0.4CPU/128MiB, lab ports
45100–45107 TCP/UDP. Hub budget remains0.25CPU/256MiB. A direct mother domain
with one public IPv4, free test ports and TUN are checked before install changes.
The capsule is created lazily by the normal agent and removed on idle/offline;
it is not an always-running workload. Remote nodes can still be added later.

### Existing mother (preview.7 or earlier)

An application-only MCP update **cannot** add Unix users, packages, root helpers,
network policy or systemd units. Keep that installed privilege boundary intact.
After this exact release has been merged, CI-passed and applied normally, an
operator must run this **one-time root migration on the mother**:

```bash
sudo sh -c 'cd /opt/dv-lab/current && /usr/bin/python3 -m dvlab.setup mother-node-upgrade'
```

Review the displayed changes and confirm `INSTALL`. This uses the shared agent
installer without rewriting the hub configuration, TLS, tokens or remote-node
registrations. Existing agent accounts/configs, occupied ports, mismatched source
commit or duplicate `mother-local` enrollment are refused, never taken over.
Partial installation is reported for inspection, not automatically retried.
Updating only the Python application is **not** reported as a completed migration.
Confirm an authenticated `mother-local` heartbeat and a real capsule command via
MCP before starting tunnel tests. A merge alone does not deploy to existing hosts.

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

1. Push to main; wait for `unit-and-protocol`, `ubuntu-isolation` and `ubuntu-22-hub` to succeed.
2. Call `lab_update` with `action=check`, `target=<node ID>`.
3. Apply the explicit full commit SHA to a canary node, inspect status/version/health; update other nodes sequentially.
4. Update `target=mother` last and reconnect if necessary.

A pinned root broker stages only application files from this fixed repo/main, verifies Git blob identities, stops local lab workloads, atomically switches the active code directory, restarts only DV Lab services, verifies live health, and restores the previous code on failure. Failed-health recovery also restores a pre-update mother database snapshot. Manual later rollback is application-only. It never runs downloaded install scripts as root or changes quotas, services, firewall policy or host packages. Pinned root helpers, the fixed privilege-dropping console launcher and base-image upgrades require an operator-reviewed migration; the unprivileged menu UI follows application updates. [Read the trust model](UPDATE.md).

## Validation

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q dvlab scripts
bash -n install.sh scripts/ci-isolation.sh
```

95 local regression tests passed at publication preparation. GitHub CI is configured to repeat those tests and run rootless Podman/TUN/cgroup/nft smoke on a disposable Ubuntu runner. **A configured workflow is not evidence it passed**; consult the actual Actions run. Multi-server throughput, target-host overhead, reboot/fault acceptance and deployment remain separate validation tasks. The CI helper refuses execution outside GitHub Actions and must never be run on production.

Both supported Ubuntu releases have real rootless isolation CI (namespace separation, TUN, CPU/RAM/PID/swap enforcement and nft), plus full hub installation CI. Jammy requires explicit CPU/memory/PID delegation to its dedicated user manager; no global AppArmor/sysctl bypass or unsupported Podman CLI flags are used. VPS kernels must still expose cgroup v2 controllers, user namespaces and TUN; unsupported hosts fail closed.

### Installer interface

Separate bare-domain and HTTPS-port questions automatically build the secure URL (no scheme or www prefix to type). Compact color-coded stages, short examples, a review before changes, and recoverable domain/port/TLS setup errors. Occupied ports never trigger stopping another service. Detailed command output goes to a private root-owned install log instead of flooding the terminal; a failure shows its log path. NO_COLOR and non-TTY output remain plain. Stages are real milestones, not fabricated percentage progress. Public/firewall reachability is explicitly not inferred from a local port check.

### Automatic TLS lifecycle

The installer discovers matching managed Certbot lineages in `/etc/letsencrypt/live` or DV Lab’s isolated `/etc/dv-lab/acme`, checks trusted chain/hostname/key/expiry, and proves renewal with a staging dry run before reuse. It never force-renews a healthy certificate daily, invokes existing stop hooks/webserver installers, or rewrites another application's renewal configuration. Unsafe or non-Certbot-managed certificates are not adopted blindly.

If no suitable managed lineage exists, standalone HTTP-01 is tested against staging before production issuance. **Public DNS must point here and inbound TCP 80 must be free and reachable, independently of the MCP HTTPS port.** No service is stopped and no firewall is changed. A busy port is an explicit blocker; new DNS-provider challenge setup is not implemented. Existing safe webroot/DNS renewal configurations can be reused. INSTALL confirms Let’s Encrypt terms; the ACME account is registered without email.

A root-pinned single-lineage renewal helper runs twice daily via `dv-lab-tls-renew.timer` (random delay, no idle daemon). A renewed pair is validated and copied root:hub 640 into an atomic generation; only a changed pair restarts the hub, followed by local HTTPS/SNI health verification and rollback on failure. The current and previous generations are retained. Scheduling and a successful staging test are checked, not a promise that future DNS/firewall/credentials cannot break. Inspect failures with `journalctl -u dv-lab-tls-renew.service`.

CI uses a real locally trusted certificate, real atomic deployment/service restart/live HTTPS checks, and an explicitly mocked external ACME request. It does not issue a live public certificate for a domain we do not control.

### Remote resource control

`lab_resources(node, action="status")` queues a read of current lab quotas, immutable initial ceilings and a revision. To set, use that revision and all four `account_cpus`, `account_memory_mib`, `capsule_cpus`, `capsule_memory_mib` values. Fetch completion through `lab_action`. A set stops ONLY the capsule and destroys temporary `/work`; export artifacts first. No controller or host shell is exposed.

New node installs include a separate root-pinned, socket-activated resource broker. Initial account/capsule limits remain 0.5 CPU/192MiB and 0.4 CPU/128MiB. The initial installer displays and approves hard maxima derived from the host: up to 75% of logical CPUs (absolute maximum 4 CPU, minimum 0.5), and up to 25% of host RAM (absolute maximum 2048MiB, minimum 192MiB). At least 0.1 CPU and 64MiB remain outside the capsule. Actual usage plus 32MiB headroom is required before shrinking memory; swap and PID bounds remain fixed. These are limits, not reservations or guarantees of zero production impact.

Only the dedicated lab user slice and fixed agent config/drop-in may change; no caller-supplied path, executable or host-wide quota is accepted. Changes are verified against real cgroups and persisted for reboot, with rollback on ordinary failure. A capsule and the enclosing account are revalidated after changes. The helper is a 10% CPU/64MiB bounded socket oneshot, not an idle daemon. Application self-update remains independent: an existing mother can receive this release without a privileged helper migration. Older nodes without the resource socket need an operator-reviewed initial migration; changing immutable root ceilings is never smuggled through an application update.

### Console usability and legacy migration

Interactive results remain on screen until `Press Enter to return to menu`. Bootstrap URL and one-use invite have separate colored cards; the URL itself is a single undecorated copyable line, with a separate one-line node install command. No token is embedded in that URL. A node needs no inbound management listener, domain or certificate: it authenticates with its dedicated bearer over outbound HTTPS and validates the mother's certificate. The tunneled test data plane is separate; its encryption is whatever the tested tunnel provides, so use synthetic test traffic.

New installations pin a tiny root launcher that drops supplementary identity to the dedicated service account before executing the versioned menu. Mutable UI code is never loaded as root. Future UI fixes then follow `lab_update`. Existing installations with the old frozen root menu need exactly one explicit operator migration **after** the application update:

```bash
curl -fsSL https://raw.githubusercontent.com/dalmaktube-creator/DV-Lab/main/install.sh | sudo bash -s -- console-upgrade
```

This requires the downloaded and installed commit to match, preserves the previous launcher and changes no tokens, TLS, service units, firewall or budgets. It is not a reinstall. Afterwards use `sudo dv-lab` (or `sudo dv-lab --node` when both roles are on one machine). Root policy/helper upgrades still cannot be smuggled through application updates.

In addition to isolated kernel checks, separate full-node CI jobs run the actual installer, a real TLS mother in a private network namespace, outbound enrollment/heartbeat, MCP capsule execution/logs and remote resource changes on both Ubuntu versions. Only terminal answers are supplied by CI; networking, quota enforcement and Podman are not mocked. Test-only special-purpose addresses are routed inside the disposable VM, not to public servers.
