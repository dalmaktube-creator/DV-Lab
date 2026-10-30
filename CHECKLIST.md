# One-time release acceptance (not yet performed)

Use two disposable Ubuntu 24.04 VMs, not production tunnel endpoints.

- [ ] Install hub with valid TLS and verify `/mcp` unauthorized=401, authenticated GET=405, initialize/tools discovery from actual client.
- [ ] Install both agents; compare `lab_nodes` heartbeat and advertised pool. Confirm no production units, nginx, SSH or unrelated firewall rules were modified.
- [ ] Verify rootless `podman info`, namespaces, readonly root, no host mounts, no new privileges; verify /dev/net/tun works inside only.
- [ ] Verify actual container and user-UID.slice cgroup CPU/memory/swap/PID values; place helpers and rootless network inside the account budget. If any limit is absent, capsule must fail closed.
- [ ] Check real nft syntax/application and rule ordering with existing firewall. Do NOT flush the host ruleset. Verify only the lab UID is egress restricted and only reserved inbound ports are affected.
- [ ] From capsule, test permitted peer TCP + UDP, especially inbound connections and replies to ephemeral ports; test blocked localhost/private/own public IP, unrelated peer ports, arbitrary internet and IPv6. Exact controller/DNS exceptions are intentional.
- [ ] Read/write chunks, transfer a binary, compare SHA256, run two-way iperf and TUN traffic, collect account+capsule CPU samples over the exact same interval. Report quota throttling and generator overhead.
- [ ] Test 300-second deadline, inherited background child cleanup, escaped-session job bounded by capsule destruction, ring logs, 4-job and action-queue bounds.
- [ ] Pause, unplug control link, stop/kill agent and reboot; verify owned capsule cleanup and network guard before user service. Never infer a remote stop solely from the hub acknowledgment.
- [ ] Check actual idle RSS/CPU and active network helper overhead. Record versions/hardware. No claimed overhead percentage until measured.
- [ ] Review TLS renewal, token incident response, firewall reload ownership, root-owned configs and immutable image ID.


## Mother-local default (preview.8)

- [ ] Fresh mother exposes mother-local with authenticated heartbeat through lab_nodes.
- [ ] Ordinary MCP executes only inside its real isolated capsule, with TUN and no hub credentials.
- [ ] Explicit existing-mother migration preserves hub config/TLS/tokens and remote enrollment.
- [ ] Both dedicated accounts/cgroups retain independent limits and host services remain untouched.
- [ ] Later remote-node enrollment and existing full-node CI continue to pass.
- [ ] Existing live mother migrated by operator; real capsule probe verified before WAN benchmark.
