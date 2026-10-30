#!/usr/bin/env python3
"""Runs INSIDE the read-only capsule; no host access or credentials."""
import base64
import collections
import hashlib
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import time

# Installed as a single read-only file; include the same validation module in
# the image and put its parent on sys.path, never load code from /work.
sys.path.insert(0, "/opt/dv-lab")
from dvlab.sampling import Sampler
from dvlab.common import MAX_BODY, MAX_CHUNK, validate_operation

WORK = Path("/work")
SOCKET = "/run/dv-lab.sock"
PROCESSES = {}
LOCK = threading.Lock()
LOG_LIMIT = 65536
SAMPLES = Sampler("/sys/fs/cgroup")


def parent_fd(path):
    """Walk each component with O_NOFOLLOW, including during concurrent jobs."""
    parts = [x for x in path.split("/") if x not in ("", ".")]
    if not parts or any(x == ".." for x in parts):
        raise ValueError("Invalid workspace path")
    fd = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


class Task:
    def __init__(self, command, seconds):
        self.id = secrets.token_hex(16)
        self.command = command
        self.seconds = seconds
        self.output = bytearray()
        self.dropped = 0
        self.exit_code = None
        self.reason = None
        self.process = None
        self.ready = threading.Event()
        self.done = threading.Event()
        self.cancel = threading.Event()
        self.lock = threading.Lock()

    def run(self):
        p = None
        try:
            p = self.process = subprocess.Popen(
                ["/bin/sh", "-lc", self.command], cwd=WORK,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                     "HOME": "/work", "TMPDIR": "/tmp", "LANG": "C.UTF-8"},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, start_new_session=True)
            self.ready.set()
            deadline = time.monotonic() + self.seconds
            with selectors.DefaultSelector() as sel:
                os.set_blocking(p.stdout.fileno(), False)
                sel.register(p.stdout, selectors.EVENT_READ)
                while True:
                    if self.cancel.is_set() or time.monotonic() >= deadline:
                        self.reason = "cancelled" if self.cancel.is_set() else "deadline"
                        break
                    for key, _ in sel.select(.1):
                        chunk = os.read(key.fileobj.fileno(), 16384)
                        if chunk:
                            with self.lock:
                                self.output.extend(chunk)
                                if len(self.output) > LOG_LIMIT:
                                    n = len(self.output) - LOG_LIMIT
                                    del self.output[:n]
                                    self.dropped += n
                        else:
                            sel.unregister(key.fileobj)
                    if p.poll() is not None and not sel.get_map():
                        break
        except BaseException as exc:
            self.reason = type(exc).__name__
        finally:
            self.ready.set()
            if p is not None:
                # Kill inherited background children even if their shell exited.
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.exit_code = p.wait()
            if p is not None and p.stdout is not None:p.stdout.close()
            self.done.set()

    def snapshot(self, offset=0):
        with self.lock:
            start = max(offset, self.dropped)
            data = bytes(self.output[max(0, start - self.dropped):])
            return dict(process=self.id, running=not self.done.is_set(),
                        exit_code=self.exit_code, stop_reason=self.reason,
                        dropped_log_bytes=self.dropped, offset=start,
                        next_offset=self.dropped + len(self.output),
                        output=data.decode("utf-8", errors="replace"))


def dispatch(a):
    a = validate_operation(a)
    op = a["op"]
    if op == "start":
        with LOCK:
            if sum(not p.done.is_set() for p in PROCESSES.values()) >= 4:
                raise ValueError("Four active processes maximum")
            for key in list(PROCESSES):
                if len(PROCESSES) >= 64 and PROCESSES[key].done.is_set():
                    del PROCESSES[key]
            if len(PROCESSES) >= 64:
                raise ValueError("Process history full; reset capsule")
            task = Task(a["command"], a["seconds"])
            PROCESSES[task.id] = task
            threading.Thread(target=task.run, daemon=True).start()
        task.ready.wait(2)
        return task.snapshot()
    if op in ("logs", "kill"):
        with LOCK:
            task = PROCESSES[a["process"]]
        if op == "kill":
            task.cancel.set()
            task.done.wait(2)
        return task.snapshot(a.get("offset", 0))
    if op == "list":
        path = a.get("path", "")
        if path in ("", "."):
            fd = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            parent, name = parent_fd(path)
            try:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            finally:
                os.close(parent)
        try:
            names = sorted(os.listdir(fd))
            return dict(names=names[:200], truncated=len(names) > 200)
        finally:
            os.close(fd)
    if op in ("read", "write"):
        parent, name = parent_fd(a["path"])
        try:
            if op == "write":
                data = base64.b64decode(a["data_b64"], validate=True)
                tmp = ".dv-" + secrets.token_hex(8)
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(data)
                    os.rename(tmp, name, src_dir_fd=parent, dst_dir_fd=parent)
                finally:
                    try:
                        os.unlink(tmp, dir_fd=parent)
                    except FileNotFoundError:
                        pass
                return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    raise ValueError("Only regular files may be read")
                offset = a.get("offset", 0)
                f.seek(offset)
                data = f.read(a.get("length", MAX_CHUNK))
                return dict(data_b64=base64.b64encode(data).decode(), bytes=len(data),
                            next_offset=offset+len(data), sha256=hashlib.sha256(data).hexdigest())
        finally:
            os.close(parent)
    if op == "metrics":
        cg = Path("/sys/fs/cgroup")
        result = {}
        for file in ("cpu.stat", "cpu.max", "memory.current", "memory.max", "memory.events", "pids.current", "pids.max"):
            result[file] = (cg/file).read_text()[:4096]
        return dict(cgroup=result, samples=SAMPLES.snapshot(), active_processes=sum(not x.done.is_set() for x in PROCESSES.values()))


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            raw = self.rfile.readline(MAX_BODY+1)
            if len(raw) > MAX_BODY or not raw.endswith(b"\n"):
                raise ValueError("Invalid request frame")
            result = {"ok": True, "result": dispatch(json.loads(raw))}
        except Exception as exc:
            result = {"ok": False, "error": type(exc).__name__ + ": " + str(exc)[:150]}
        self.wfile.write(json.dumps(result).encode()+b"\n")


def main():
    os.umask(0o077)
    if sys.argv[1:] == ["serve"]:
        SAMPLES.start()
        if os.path.exists(SOCKET):
            os.unlink(SOCKET)
        with socketserver.ThreadingUnixStreamServer(SOCKET, Handler) as server:
            server.daemon_threads = True
            server.serve_forever(poll_interval=.5)
    elif sys.argv[1:] == ["client"]:
        data = sys.stdin.buffer.read(MAX_BODY+1)
        if len(data) > MAX_BODY:
            raise ValueError("Request too large")
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(8)
            s.connect(SOCKET)
            s.sendall(data.rstrip(b"\n")+b"\n")
            with s.makefile("rb") as f:
                response = f.readline(MAX_BODY+1)
                if len(response) > MAX_BODY:
                    raise ValueError("Response too large")
                sys.stdout.buffer.write(response)
    else:
        raise SystemExit("Use serve or client")


if __name__ == "__main__":
    main()
