"""One file-read sample/second; bounded history, no subprocesses or busy loops."""
from collections import deque
from pathlib import Path
import os
import threading
import time

class Sampler:
    def __init__(self,path,cpus=None):
        self.path=Path(path);self.cpus=cpus;self.rows=deque(maxlen=180);self.lock=threading.Lock()
    def sample(self):
        stats={k:int(v) for k,v in (line.split() for line in (self.path/'cpu.stat').read_text().splitlines())}
        now=time.monotonic();row=dict(unix_time=time.time(),monotonic=now,cpu_usage_usec=stats['usage_usec'],
            memory_bytes=int((self.path/'memory.current').read_text()),nr_throttled=stats.get('nr_throttled'),throttled_usec=stats.get('throttled_usec'))
        with self.lock:
            if self.rows:
                old=self.rows[-1];seconds=now-old['monotonic']
                if seconds>0:
                    row['cpu_percent_one_core']=round((row['cpu_usage_usec']-old['cpu_usage_usec'])/seconds/10000,3)
                    if self.cpus:row['cpu_percent_host_capacity']=round(row['cpu_percent_one_core']/self.cpus,3)
            self.rows.append(row)
    def start(self):
        def loop():
            while True:
                try:self.sample()
                except (OSError,ValueError,KeyError):pass
                time.sleep(1)
        threading.Thread(target=loop,daemon=True,name='dvlab-metrics').start()
    def snapshot(self):
        with self.lock:return list(self.rows)
