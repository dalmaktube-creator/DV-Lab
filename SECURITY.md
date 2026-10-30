# DV Lab security model / preview

## Trust

The operator and OS root are trusted. The hub and its MCP bearer have broad authority **within the lab**, not on the production host. All lab shell code, process output, files and node metadata are untrusted. Treat logs as data, never instructions. A leaked MCP bearer can operate every enrolled lab; keep it out of chat, URLs and shared recordings. The hub stores node token hashes; each node keeps its own plaintext token outside the capsule. Hub admin and MCP credentials are separate.

## Boundaries

Dedicated non-login user; no SSH keys or secret-bearing host filesystem mounts; the only bind is the readonly non-secret capsule code directory. Rootless daemonless Podman, private user/network/PID/mount namespaces, readonly root, no extra image volumes, no privilege escalation, only namespace-local NET_ADMIN/NET_RAW and TUN device. A local immutable image ID is used after installation. The first build trusts the upstream Python image tag and apt repository; it is not a reproducible/signed supply-chain attestation.

Capsule cgroups plus the enclosing dedicated user slice bound CPU, memory, swap and processes. The enclosing slice includes user-mode networking and helper processes. `/work`, `/tmp`, `/run` and shared memory are bounded temporary storage. Container logs are disabled; runner logs/history and hub queues/history are bounded. Payloads/results and commands are temporarily stored in the hub database; this is not a secret store. No production file or service access is exposed as an MCP operation.

The network root helper only updates the dedicated table's public IPv4 peer set. Its no-argument invocation is the only sudoers allowance; root/systemd also has a fixed `--boot` initialization. No client-controlled executable, nft expression, UID or port policy is accepted. All operator paths/config/helper code must remain root-owned and not group/world writable. The package installer changes its own reserved account/paths/ports only; it deliberately refuses unattended reinstall over an existing account/table.

UID-specific output ACL: exact mother IP/TLS port, exact DNS servers, enrolled public peer IPs on reserved lab ports, established replies to peers; other output including IPv6 denied. Inbound lab ports are limited to peers; unrelated host ports and rules are not flushed. Existing restrictive host firewalls can still block the lab. DNS/coordinator endpoints are trusted exceptions, not completely separated management NICs. Do not change host firewall policy blindly to make a test pass.

## Limits / residual risk

Containers share the host kernel. Kernel/Podman vulnerabilities, root modifications or incorrect operator deployment can break assumptions. This is not a VM/hardware trust boundary or a security certification. Use dedicated disposable test servers for hostile workloads.

No hard network bandwidth cap, whole-host load guard or guarantee of no production latency impact. Traffic and memory contention, even within quotas, may affect production services or the remote peer. CPU ceilings can invalidate maximum-throughput comparisons. Rootless packet processing consumes CPU. Idle RSS, packet-rate overhead and throughput are not yet measured on target servers.

Shell code can kill its own runner, create detached descendants or interfere with other jobs in the **same** capsule. Per-job group kill is best-effort for inherited groups; it is not protection against intentionally escaped process groups. Destroying the owned capsule is the stronger cleanup. The whole account remains resource bounded. Workspaces are disposable, not a durable artifact archive.

Watchdog/stop are best-effort under resource starvation. All node operations are asynchronous; receiving a pause acknowledgment is not proof of a stopped remote process. A lost leased action is never automatically replayed. Local service stop invokes additional cleanup, and startup destroys the prior owned capsule.

External root firewall reloads can remove our table; the helper checks/recreates it each heartbeat, but **cannot guarantee uninterrupted policy against external root changing kernel rules**. Coordinate firewall management; stop lab nodes before reloading/rewriting firewall rules. Reboot order requires the network guard before the dedicated user manager.

Default TLS listener is direct, no reverse proxy. A proxy is not automatically configured; trusting forwarded IP headers would require a separately reviewed design. Enrollment observes the TCP source IPv4. Shared NAT or non-public IPv4 is unsupported. IP/DNS changes require an operator review of fixed network.json.

Public source downloads include no credentials. Bootstrap is verified by SHA256 delivered from the same HTTPS mother; this detects corruption but is not an independent signature or protection against a compromised mother. Inspect the script/source before root installation.

Credentials have no automatic scheduled rotation/revocation UI in this preview. For an incident: pause nodes, stop node services locally, stop the hub, rotate hub tokens and re-enroll agents through an operator-reviewed procedure. Do not merely change one token and assume every previously leased job vanished. No automated uninstall is supplied: removing the wrong user slice/firewall table or workspace can destroy data; inspect ownership before removal.

## Validation still required

Unit/protocol tests do not validate the running Linux isolation boundary. Verify on disposable Ubuntu 24.04 machines: namespace differences, TUN, rootless cgroups, account quotas including slirp, deny host/private/IPv6 egress, peer port allowlist, no host data/secret mounts, pause/offline/agent crash cleanup, reboot ordering, bounded memory/disk/logs and actual client tool discovery. Do not deploy on a production host as though these tests have already passed.

## Update boundary

See UPDATE.md. Application self-update trusts the fixed repository/main and successful latest CI checks, not an independent signing key. It can change dedicated-user controller code; it cannot replace the pinned root broker, root console, netpolicy helper, systemd units, host image/packages or quotas. A malicious authorized release can abuse its service account and management privileges, so protect repository publishing authority. The update transaction stops local lab workloads and deletes temporary workspaces. Update requests use a root-owned socket-activated broker with kernel peer-UID checks; only root and the dedicated lab service accounts are accepted. The hub retains NoNewPrivileges. Broker and update worker share a bounded maintenance slice, and no unrestricted sudo update allowance is installed. Root broker/console code is not imported from the mutable application path. No unattended periodic auto-upgrade is enabled.

## Operator TLS automation

Initial INSTALL approval authorizes root Certbot package installation and CA requests under Let’s Encrypt terms (no email), plus a pinned renewal helper and timer. This operator-only root capability is not an MCP tool and is not updated from a mutable release. It selects exactly one lineage, rejects renewal stop hooks/webserver installers, ignores global CLI config and directory hooks, checks key/hostname/system trust/expiry and swaps a complete root:hub pair atomically. Only the DV Lab hub is restarted, with local trusted HTTPS health verification and pair rollback. No webserver shutdown or firewall bypass is performed. Initial standalone issuance needs public TCP 80; safe existing webroot/DNS lineages retain their operator-configured challenge mechanism and credentials. The timer is a bounded periodic root job (20% CPU, 256MiB ceiling, 15-minute timeout), not a daemon. Existing distro/client renewal schedules are not deleted or rewritten. Public CA issuance and future renewal availability are not proven by mocked ACME tests.
