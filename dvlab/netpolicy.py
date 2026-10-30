#!/usr/bin/python3
"""Narrow root helper: only the DV-Lab-owned nftables IPv4 peer set."""
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys

TABLE="dv_lab_agent"


def peer_transaction(peers):
    if not isinstance(peers,list) or len(peers)>32:
        raise ValueError("At most 32 peer addresses")
    values=[]
    for raw in peers:
        ip=ipaddress.IPv4Address(raw)
        if not ip.is_global:raise ValueError("Public IPv4 peers only")
        values.append(str(ip))
    text=f"flush set inet {TABLE} peers4\n"
    if values:text+=f"add element inet {TABLE} peers4 {{ "+", ".join(sorted(set(values)))+" }\n"
    return text


def initial_policy(cfg):
    uid=int(cfg["uid"]);start=int(cfg["port_start"]);count=int(cfg["port_count"])
    if uid<1000 or not 1024<=start<=65000 or not 1<=count<=8 or start+count>65535:
        raise ValueError("Invalid fixed operator network policy")
    ips=[str(ipaddress.IPv4Address(x)) for x in cfg["hub_ips"]]
    dns=[str(ipaddress.IPv4Address(x)) for x in cfg["dns_ips"]]
    hosts=[str(ipaddress.IPv4Address(x)) for x in cfg["host_ips"]]
    hubport=int(cfg["hub_port"])
    if not 1<=hubport<=65535:raise ValueError("Invalid mother port")
    ports=f"{start}-{start+count-1}"
    rules=[
        f"add table inet {TABLE}",
        f"add set inet {TABLE} peers4 {{ type ipv4_addr; }}",
        f"add chain inet {TABLE} output {{ type filter hook output priority -20; policy accept; }}",
        f"add chain inet {TABLE} input {{ type filter hook input priority -20; policy accept; }}",
    ]
    # Control-plane exception is exact-IP + exact-port; no general host access.
    for ip in ips:
        rules.append(f"add rule inet {TABLE} output meta skuid {uid} ip daddr {ip} tcp dport {hubport} accept")
    for ip in dns:
        for proto in ("tcp","udp"):
            rules.append(f"add rule inet {TABLE} output meta skuid {uid} ip daddr {ip} {proto} dport 53 accept")
    rules.append(f"add rule inet {TABLE} output meta skuid {uid} ip daddr @peers4 ct state established,related accept")
    for ip in hosts:
        rules.append(f"add rule inet {TABLE} output meta skuid {uid} ip daddr {ip} drop")
    rules.append(f"add rule inet {TABLE} output meta skuid {uid} ip daddr {{ 0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4,240.0.0.0/4 }} drop")
    for proto in ("tcp","udp"):
        rules.append(f"add rule inet {TABLE} output meta skuid {uid} ip daddr @peers4 {proto} dport {ports} accept")
    # This also denies IPv6 for the dedicated account, not other host users.
    rules.append(f"add rule inet {TABLE} output meta skuid {uid} drop")
    # Never touch any port outside the operator-reserved lab pool.
    for proto in ("tcp","udp"):
        rules.append(f"add rule inet {TABLE} input meta nfproto ipv4 ip saddr @peers4 {proto} dport {ports} accept")
        rules.append(f"add rule inet {TABLE} input {proto} dport {ports} drop")
    return "\n".join(rules)+"\n"


def main():
    if os.geteuid()!=0 or sys.argv[1:] not in ([],["--boot"]):raise SystemExit("Root helper takes no arguments (root-only --boot for systemd)")
    marker=Path("/etc/dv-lab/network.json")
    if marker.stat().st_uid!=0 or marker.stat().st_mode&0o022:raise SystemExit("Unsafe network policy owner")
    raw=b'{"peers":[]}' if sys.argv[1:]==["--boot"] else sys.stdin.buffer.read(8193)
    if len(raw)>8192:raise SystemExit("Peer update too large")
    data=json.loads(raw)
    if set(data)!={"peers"}:raise SystemExit("Only peers may be updated")
    cfg=json.loads(marker.read_text())
    peer_transaction(data["peers"])  # Validate before taking root action.
    # Re-create ONLY our owned table if the host firewall was reloaded.
    check=subprocess.run(["nft","list","table","inet",TABLE],capture_output=True)
    if check.returncode:
        text=initial_policy(cfg)+peer_transaction(data["peers"])
    else:
        text=peer_transaction(data["peers"])
    subprocess.run(["nft","-c","-f","-"],input=text.encode(),check=True,capture_output=True)
    subprocess.run(["nft","-f","-"],input=text.encode(),check=True,capture_output=True)


if __name__=="__main__":
    main()
