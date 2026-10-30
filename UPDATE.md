# Application updates / operator trust policy

## Interfaces

- Local root operator: `sudo dv-lab`, options U/S/R, or `sudo dv-lab update check|status|apply COMMIT|rollback`.
- MCP: `lab_update(target="mother" or node ID, action="check"|"status"|"apply"|"rollback", commit=full SHA for apply)`.
- Node operations are queued. Use `lab_action` for the queued request. During a restart its completion may be lost: reconnect and request update status; **never blindly replay a potentially executed update**.
- Hub updates interrupt MCP. Reconnect and confirm the live commit/version and `lab_update status`.

## Authority and authenticity

At initial installation the operator approves a root-owned update policy: **dalmaktube-creator/DV-Lab**, branch **main**, successful latest check results from GitHub Actions jobs **unit-and-protocol**, **ubuntu-isolation**, **ubuntu-22-isolation**, **ubuntu-22-hub** and **ubuntu-24-hub**, fixed request schema version 1 and guard generation 2. Private unauthenticated API access fails closed. No GitHub personal token is kept on the server.

The broker checks the full commit is main or an ancestor of main. Downloads use validated HTTPS to api.github.com/codeload.github.com. Every selected file is checked using its Git blob identity against the pinned commit tree. No unsigned arbitrary URL or arbitrary branch/string is accepted. This is a **GitHub/repository trust model**, not a separate offline release-signing key. A malicious maintainer, compromised GitHub account/Actions configuration or hostile main commit can change unprivileged application behavior; CI is not a security review. Protect main and GitHub access. The initial `curl | sudo bash` itself trusts the raw main installer; inspect/download it first if that trust is unacceptable.

## What updates may change

Versioned, root-owned Python application files, docs, installer source for future bootstrap use, metadata, and readonly non-secret capsule runner code. The small capsule-code mount is intentionally updated with the application while the pinned base image remains unchanged. Workloads are stopped before switching.

**Not changed through MCP:** pinned root broker, nft helper, operator root console snapshot, sudoers, systemd unit files, `/etc/dv-lab` configuration, cgroup ceilings, host packages, TLS keys or the Podman base image. Neither `install.sh` nor `setup.py` from a download is run by the root worker. Application code is only executed under dvlab-hub/dvlab-node services. The root console uses an independent pinned initial snapshot so an app update does not replace the next root menu command.

The fixed root broker is socket-activated through `/run/dv-lab/update.sock`; no idle Python daemon is required. Socket mode/group and kernel SO_PEERCRED checks restrict callers to root and the dedicated lab service UIDs. It accepts bounded JSON with check/status/apply/rollback; no executable/path/URL argument. No update sudoers allowance is installed. The hub retains explicit NoNewPrivileges=yes. Broker instances and the separate fixed root worker share a root-owned maintenance slice capped at 0.2 CPU / 128MiB. Never replace this boundary with unrestricted sudo or mount the broker socket into a capsule.

Root helper/schema/host-image upgrades need a separately reviewed operator installation step. A future package must explicitly bump the required guard/schema; the old broker rejects it instead of silently obtaining wider authority.

## Transaction / rollback

1. Verify candidate/main ancestry and all required latest CI checks.
2. Download bounded source, reject links/devices/traversal/duplicates, verify selected Git blobs, parse Python without executing it, and check declared schema compatibility.
3. Stage in `/opt/dv-lab/releases/<commit>` with readonly public code permissions. Keep a separate capsule-code directory and bootstrap archive, never include secrets.
4. Detect which local DV Lab services are active. Stop those services; agent cleanup removes its own capsule. **All local `/work` files and active tests are lost; retrieve artifacts first.**
5. Snapshot the mother database, switch `/opt/dv-lab/current` atomically, start the previously active services.
6. Check mother live HTTPS `/health` commit and node authenticated-heartbeat commit, not merely process liveness.
7. On failed health, stop the new services, restore the snapshot/code and restart the old services. Report failure rather than claiming success. On success retain the prior release; prune older code directories.

Failed-health snapshot recovery can discard operations accepted during the short trial interval. Avoid running other tests/enrollment during maintenance. Later explicit rollback restores the previous **code**, not an old database; schema-changing application migrations are outside this policy. Service health does not prove a new version preserved isolation or performance; use canary + read the code/CI.

A machine power loss or forced termination during activation is not a fully crash-journaled transactional package manager. Inspect current symlink, service and status on recovery. Never advertise guaranteed rollback under kernel/OOM/disk failure. The two-phase queued root service serializes updates on each machine; do not issue simultaneous fleet-wide updates.

## Fleet order

Download test artifacts → check candidate → one canary node → status and real smoke → remaining nodes one by one → mother last → reconnect and inspect all reported commits. Do not automatically resume a benchmark that was interrupted. A lost action may have executed and must not be replayed by assumption.

No periodic unattended upgrade is enabled. The operator or authenticated MCP caller explicitly requests every rollout; the agent can do this without new SSH sessions or a repeated manual installer.

The extra Jammy hub check is part of the new-install guard policy from 0.2.0-preview.3. Existing installations retain their pinned root guard and its prior check set until an operator-reviewed helper migration; an ordinary application update does not replace it. From preview.7, Jammy agents have a separate real isolation job and explicit dedicated-manager CPU delegation. Guard generation 2 also introduces the local socket broker and its pinned units; older guards reject release manifests requiring generation 2, so application-only self-update cannot silently install privileged units.


Resource changes use a separate initial-installation pinned broker, not the update worker. Application-only deployment cannot widen its immutable root policy. Fresh nodes receive this broker in preview.7; a previously installed mother can update its application and route resource operations without a root migration. The authenticated MCP caller can explicitly apply CI-passed releases; it does not require the human to operate U in the console. Existing pinned guards retain the checks they originally approved; before each rollout also inspect all current release CI checks, especially the added Jammy isolation and Noble hub jobs.
