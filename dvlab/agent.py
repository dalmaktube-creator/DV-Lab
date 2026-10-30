"""Outbound-only node controller. Host execution is fixed Podman/helper argv."""
import argparse
import http.client
import json
import os
import pwd
from pathlib import Path
import signal
import ssl
import subprocess
import threading
import time
from urllib.parse import urlsplit
import urllib.request

from .sampling import Sampler
from .updating import broker, identity
from .resources import broker as resource_broker
from .resource_guard import FIELDS as RESOURCE_FIELDS

from .common import MAX_BODY, atomic_json, origin, public_ip, validate_operation

NAME="dv-lab-box"
LABEL="io.dv-lab.owner"


def host_environment():
    who=pwd.getpwuid(os.getuid());runtime='/run/user/'+str(who.pw_uid)
    return dict(PATH='/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',HOME=who.pw_dir,
        USER=who.pw_name,LOGNAME=who.pw_name,LANG='C.UTF-8',
        XDG_CONFIG_HOME=who.pw_dir+'/.config',XDG_DATA_HOME=who.pw_dir+'/.local/share',
        XDG_RUNTIME_DIR=runtime,DBUS_SESSION_BUS_ADDRESS='unix:path='+runtime+'/bus')


def fixed_run(argv, data=None, timeout=20):
    # Never pass a remote command to a host shell.
    p=subprocess.run(argv,input=data,capture_output=True,timeout=timeout,check=False,env=host_environment())
    if len(p.stdout)>MAX_BODY or len(p.stderr)>65536:
        raise RuntimeError("Host helper output exceeded its fixed bound")
    if p.returncode:
        raise RuntimeError("Fixed host helper failed: "+argv[0])
    return p.stdout


class Capsule:
    def __init__(self, config, run=fixed_run):
        self.cfg=config
        self.run=run
        self.lock=threading.RLock()
        self.validated=False
        self.last_use=time.monotonic()
        self.peer_cache=None
        self.samples=Sampler(f"/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice",os.cpu_count())

    def inspect(self):
        try:
            data=json.loads(self.run(["podman","inspect",NAME],timeout=8))
        except RuntimeError:
            return None
        if not isinstance(data,list) or len(data)!=1:
            raise RuntimeError("Unexpected capsule identity")
        item=data[0]
        if item.get("Config",{}).get("Labels",{}).get(LABEL)!=self.cfg["node"]:
            raise RuntimeError("Name occupied by a non-DV-Lab container; refusing access")
        return item

    def stop(self):
        with self.lock:
            item=self.inspect()
            if item is not None:
                self.run(["podman","rm","--force",item["Id"]],timeout=15)
            self.validated=False

    def sync_peers(self, peers):
        peers=sorted(set(public_ip(x) for x in peers))
        if len(peers)>32:raise ValueError("Too many peers")
        # Check/restore our table on every heartbeat, not just roster changes.
        self.run(["sudo","-n","/usr/local/sbin/dv-lab-netpolicy"],
                 json.dumps({"peers":peers}).encode(),timeout=8)
        self.peer_cache=peers

    def create_argv(self):
        cfg=self.cfg
        image=cfg["image"]
        if not image.startswith("sha256:") or len(image)!=71:
            raise ValueError("Operator-pinned image ID required")
        memory=int(cfg["capsule_memory_mib"])
        if not 64<=memory<=4096 or not .1<=float(cfg["capsule_cpus"])<=8:
            raise ValueError("Invalid operator quota")
        argv=["podman","run","--detach","--name",NAME,"--label",LABEL+"="+cfg["node"],
              "--pull=never","--read-only","--read-only-tmpfs=false",
              "--cap-drop=ALL","--cap-add=NET_ADMIN","--cap-add=NET_RAW",
              "--security-opt=no-new-privileges","--pids-limit=64",
              "--cpus="+str(cfg["capsule_cpus"]),"--memory="+str(memory)+"m",
              "--memory-swap="+str(memory)+"m","--log-driver=none",
              "--network=slirp4netns:allow_host_loopback=false,enable_ipv6=false",
              "--device=/dev/net/tun","--image-volume=ignore",
              "--volume="+str(Path(__file__).resolve().parent.parent/"capsule/dvlab")+":/opt/dv-lab/dvlab:ro,nodev,nosuid",
              "--tmpfs=/work:rw,exec,nosuid,nodev,size="+str(min(128,memory//2))+"m",
              "--tmpfs=/tmp:rw,nosuid,nodev,size=8m",
              "--tmpfs=/run:rw,nosuid,nodev,size=8m",
              "--shm-size=4m","--env=PYTHONDONTWRITEBYTECODE=1","--workdir=/work"]
        # Image includes only the immutable runner and validation module.
        for port in range(cfg["port_start"],cfg["port_start"]+cfg["port_count"]):
            argv += ["--publish",f"0.0.0.0:{port}:{port}/tcp",
                     "--publish",f"0.0.0.0:{port}:{port}/udp"]
        return argv+[image,"python3","-m","dvlab.runner","serve"]

    def exec_json(self, operation):
        raw=self.run(["podman","exec","-i",NAME,"python3","-m","dvlab.runner","client"],
                     json.dumps(operation).encode(),timeout=10)
        result=json.loads(raw)
        if not isinstance(result,dict):raise RuntimeError("Invalid capsule response")
        return result

    def ensure(self):
        with self.lock:
            item=self.inspect()
            if item is None:
                self.run(self.create_argv(),timeout=25)
                self.validated=False
                item=self.inspect()
            if not item or not item.get("State",{}).get("Running"):
                raise RuntimeError("Capsule not running; operator reset may be required")
            if not self.validated:
                try:
                    # Verify enforced bounds, not just a successful CLI exit.
                    for attempt in range(20):
                        try:
                            result=self.exec_json({"op":"metrics"})
                            if not result.get("ok"):raise RuntimeError("Runner not ready")
                            break
                        except (RuntimeError,KeyError,ValueError):
                            if attempt==19:raise
                            time.sleep(.1)
                    cg=result["result"]["cgroup"]
                    if cg["memory.max"].strip()=="max" or int(cg["memory.max"])>self.cfg["capsule_memory_mib"]*1048576:
                        raise RuntimeError("Capsule memory cgroup limit not enforced")
                    quota,period=cg["cpu.max"].split()
                    if quota=="max" or int(quota)/int(period)>float(self.cfg["capsule_cpus"])+.01:
                        raise RuntimeError("Capsule CPU cgroup limit not enforced")
                    if cg["pids.max"].strip()=="max" or int(cg["pids.max"])>64:
                        raise RuntimeError("Capsule PID cgroup limit not enforced")
                    inside=json.loads(self.run(["podman","exec",NAME,"python3","-c",
                        "import os,json;print(json.dumps({k:os.readlink('/proc/self/ns/'+k) for k in ('net','user','pid','mnt')}))"],timeout=8))
                    if any(inside[k]==os.readlink("/proc/self/ns/"+k) for k in inside):
                        raise RuntimeError("Required namespace separation missing")
                    self.run(["podman","exec",NAME,"ip","tuntap","add","dev","dvlcheck","mode","tun"],timeout=8)
                    self.run(["podman","exec",NAME,"ip","link","delete","dvlcheck"],timeout=8)
                    self.validated=True
                except BaseException:
                    self.stop()
                    raise
            self.last_use=time.monotonic()

    def operate(self, operation):
        validate_operation(operation)
        self.ensure()
        with self.lock:
            result=self.exec_json(operation)
            if operation["op"]=="metrics":
                result["lab_account"]=account_metrics()
                result["lab_account"]["logical_cpus"]=os.cpu_count()
                result["lab_account"]["samples"]=self.samples.snapshot()
            return result


def account_metrics():
    uid=os.getuid()
    path=Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice")
    result={}
    for name in ("cpu.stat","cpu.max","memory.current","memory.max","memory.swap.max","pids.current","pids.max"):
        result[name]=(path/name).read_text()[:4096]
    result["agent_rss_kib"]=next(int(x.split()[1]) for x in Path("/proc/self/status").read_text().splitlines() if x.startswith("VmRSS:"))
    result["note"]="Lab account includes controller, rootless networking and capsule. Capsule CPU is only one subset; compare deltas over the same interval."
    return result


def verify_account_limits(cfg):
    metrics=account_metrics()
    quota,period=metrics["cpu.max"].split()
    if quota=="max" or int(quota)/int(period)>float(cfg["account_cpus"])+.01:
        raise RuntimeError("Whole lab-account CPU limit missing")
    if metrics["memory.max"].strip()=="max" or int(metrics["memory.max"])>cfg["account_memory_mib"]*1048576:
        raise RuntimeError("Whole lab-account memory limit missing")
    if metrics["memory.swap.max"].strip()!="0":
        raise RuntimeError("Lab account swap must be disabled")
    if metrics["pids.max"].strip()=="max" or int(metrics["pids.max"])>128:
        raise RuntimeError("Lab account PID limit missing")
    return metrics


class Client:
    def __init__(self,url,credential=None):
        self.url=origin(url)
        self.credential=credential
        u=urlsplit(self.url)
        self.conn=http.client.HTTPSConnection(u.hostname,u.port or 443,timeout=30,
                                              context=ssl.create_default_context())
    def post(self,path,data):
        headers={"Content-Type":"application/json","Accept":"application/json"}
        if self.credential:headers["Authorization"]="Bearer "+self.credential
        try:
            self.conn.request("POST",path,json.dumps(data),headers)
            response=self.conn.getresponse()
            raw=response.read(MAX_BODY+1)
            if len(raw)>MAX_BODY:raise ValueError("Mother response too large")
            if response.status!=200:raise RuntimeError("Mother refused request: "+str(response.status))
            return json.loads(raw)
        except BaseException:
            self.conn.close()
            raise


class Agent:
    def __init__(self,cfg):
        self.cfg=cfg
        self.client=Client(cfg["hub"],cfg["token"])
        self.capsule=Capsule(cfg)
        self.quit=threading.Event()
        self.contact=time.monotonic()
        self.paused=False
        self.status="starting"
    def resources(self,op):
        if op['action']=='set':self.capsule.stop()
        try:return {'ok':True,'result':resource_broker(op)}
        finally:
            cfg=json.loads(Path('/etc/dv-lab/agent.json').read_text())
            self.cfg.update({k:cfg[k] for k in RESOURCE_FIELDS})
            self.capsule.cfg=self.cfg
            verify_account_limits(self.cfg)

    def watchdog(self):
        while not self.quit.wait(2):
            if time.monotonic()-self.contact>60 or time.monotonic()-self.capsule.last_use>600:
                try:self.capsule.stop()
                except Exception:pass
                self.status="offline_or_idle_capsule_stopped"
    def run(self):
        verify_account_limits(self.cfg)
        self.capsule.samples.start()
        # No capsule automatically restored across agent restarts.
        self.capsule.stop()
        threading.Thread(target=self.watchdog,daemon=True).start()
        try:
            while not self.quit.is_set():
                try:
                    response=self.client.post("/agent/poll",{"info":{
                        **identity(),"status":self.status,"port_start":self.cfg["port_start"],
                        "port_count":self.cfg["port_count"],"account_cpus":self.cfg["account_cpus"],
                        "account_memory_mib":self.cfg["account_memory_mib"],
                        "capsule_memory_mib":self.cfg["capsule_memory_mib"],
                        "capsule_cpus":self.cfg["capsule_cpus"],"resource_control":True,
                        "isolation":"rootless-readonly-ephemeral"}})
                    self.contact=time.monotonic()
                    atomic_json("/var/lib/dv-lab-node/heartbeat.json",dict(at=time.time(),**identity()))
                    self.capsule.sync_peers(response["peers"])
                    self.paused=bool(response["paused"])
                    if self.paused:
                        self.capsule.stop()
                        self.status="paused"
                        self.quit.wait(3)
                        continue
                    action=response.get("action")
                    self.status="ready"
                    if not action:continue
                    try:
                        op=validate_operation(action["operation"])
                        if op["op"]=="update":result={"ok":True,"result":broker(op)}
                        elif op["op"]=="resources":result=self.resources(op)
                        else:result=self.capsule.operate(op)
                    except Exception as exc:
                        result={"ok":False,"error":type(exc).__name__+": "+str(exc)[:160]}
                    # Retry only the same completion, NEVER replay its operation.
                    for attempt in range(3):
                        try:
                            self.client.post("/agent/result",dict(action=action["id"],lease=action["lease"],result=result))
                            self.contact=time.monotonic()
                            break
                        except Exception:
                            if attempt==2:self.status="result_delivery_uncertain_no_replay"
                            self.quit.wait(1)
                except Exception as exc:
                    self.status=type(exc).__name__  # No tokens/command/results logged.
                    try:self.capsule.stop()
                    except Exception:pass
                    self.quit.wait(5)
        finally:
            self.capsule.stop()


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--config",default="/etc/dv-lab/agent.json")
    ap.add_argument("--stop",action="store_true")
    args=ap.parse_args()
    cfg=json.loads(Path(args.config).read_text())
    if args.stop:
        Capsule(cfg).stop()
        return
    agent=Agent(cfg)
    for sig in (signal.SIGINT,signal.SIGTERM):
        signal.signal(sig,lambda *_:agent.quit.set())
    agent.run()


if __name__=="__main__":
    main()
