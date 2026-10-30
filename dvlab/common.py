import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit

MAX_BODY = 300_000
MAX_CHUNK = 65536
OPS = {"start", "logs", "kill", "read", "write", "list", "metrics", "update"}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def token():
    return secrets.token_urlsafe(32)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", value):
        raise ValueError("Invalid identifier")
    return value


def public_ip(value):
    address = ipaddress.IPv4Address(value)
    if not address.is_global:
        raise ValueError("A globally routable IPv4 address is required")
    return str(address)


def origin(value):
    if not isinstance(value,str) or any(c.isspace() for c in value):
        raise ValueError("HTTPS origin cannot contain whitespace")
    u = urlsplit(value)
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        raise ValueError("Use an HTTPS origin without a path, credentials or query")
    if not re.fullmatch(r"[A-Za-z0-9.-]+",u.hostname) or not (1 <= (u.port or 443) <= 65535):
        raise ValueError("Valid DNS name or IPv4 and port required")
    return value.rstrip("/")


def atomic_json(path, data):
    path = Path(path)
    tmp = path.with_name("." + path.name + "." + secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def validate_operation(args):
    if not isinstance(args, dict) or args.get("op") not in OPS:
        raise ValueError("Unsupported sandbox operation")
    if args.get("op")=="update":
        from .updating import validate_update
        return dict(validate_update(args))
    a = dict(args)
    op = a["op"]
    allowed = {
        "start": {"op", "command", "seconds"},
        "logs": {"op", "process", "offset"},
        "kill": {"op", "process"},
        "read": {"op", "path", "offset", "length"},
        "write": {"op", "path", "data_b64"},
        "list": {"op", "path"},
        "metrics": {"op"},
    }
    if set(a) - allowed[op]:
        raise ValueError("Unknown operation field")
    if op == "start":
        command = a.get("command")
        if not isinstance(command, str) or not command or len(command.encode()) > 8192 or "\0" in command:
            raise ValueError("Command must be 1..8192 bytes")
        seconds = a.setdefault("seconds", 60)
        if type(seconds) is not int or not 1 <= seconds <= 300:
            raise ValueError("Process lifetime must be 1..300 seconds")
    if op in ("logs", "kill"):
        identifier(a.get("process"))
    if op in ("read", "write", "list"):
        p = a.get("path", "")
        if not isinstance(p, str) or len(p.encode()) > 1024 or "\0" in p or p.startswith("/") or ".." in p.split("/"):
            raise ValueError("Use a relative /work path without parent traversal")
        if op != "list" and not p:
            raise ValueError("A file path is required")
    for k in ("offset", "length"):
        if k in a and (type(a[k]) is not int or not 0 <= a[k] <= (MAX_CHUNK if k == "length" else 1_000_000_000)):
            raise ValueError("Invalid file/log range")
    if op == "write":
        try:
            raw = base64.b64decode(a.get("data_b64", ""), validate=True)
        except Exception as exc:
            raise ValueError("Invalid base64") from exc
        if len(raw) > MAX_CHUNK:
            raise ValueError("Maximum file write is 64 KiB; use separate files or shell assembly")
    return a
