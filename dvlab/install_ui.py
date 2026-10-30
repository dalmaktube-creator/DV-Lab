"""Small ANSI installer console; no animation, daemon or third-party dependency."""
import os
import shutil
import sys
import tempfile
import textwrap
from pathlib import Path

COLORS={'blue':'\033[96m','ok':'\033[92m','warn':'\033[93m','error':'\033[91m','muted':'\033[90m','title':'\033[1m'}
RESET='\033[0m'

def color(text,tone,stream):
    if stream.isatty() and 'NO_COLOR' not in os.environ and os.environ.get('TERM')!='dumb':
        return COLORS.get(tone,'')+text+RESET
    return text

class Console:
    def __init__(self,stream=None):
        self.stream=stream;self.active=False;self.log_path=None;self.installing=False
    def out(self):return self.stream if self.stream is not None else sys.stdout
    def width(self):
        try:columns=os.get_terminal_size(self.out().fileno()).columns
        except (OSError,AttributeError,ValueError):columns=80
        return max(32,min(72,columns-4))
    def line(self,text='',tone=None):
        out=self.out()
        lines=textwrap.wrap(str(text),width=self.width()-2,break_long_words=True,break_on_hyphens=False) if text else ['']
        for line in lines:print('  '+color(line,tone,out) if tone else '  '+line,file=out,flush=True)
    def banner(self,role,version):
        if not self.active:
            self.line();self.line('DV LAB  /  INSTALLER','blue');self.line(version+'  |  '+role,'muted');self.line('─'*(self.width()-2),'muted')
        else:self.line(role,'title')
        self.active=True
    def stage(self,number,total,title):
        self.line();self.line(f'[{number}/{total}] {title}','blue')
    def hint(self,text):self.line(text,'muted')
    def ok(self,text):self.line('+ '+text,'ok')
    def error(self,text):self.line('! '+text,'error')
    def warn(self,text):self.line('! '+text,'warn')
    def summary(self,items):
        for label,value in items:self.line(f'{label}: {value}')
    def logfile(self):
        if self.log_path is None:
            fd,path=tempfile.mkstemp(prefix='dv-lab-install-',suffix='.log',dir='/var/log');os.close(fd)
            self.log_path=Path(path)
        return self.log_path
    def logstream(self):
        fd=os.open(self.logfile(),os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
        return os.fdopen(fd,'ab')
    def trimlog(self):
        if self.log_path and self.log_path.stat().st_size>2*1024*1024:
            with self.log_path.open('rb') as f:f.seek(-512*1024,2);tail=f.read()
            with self.log_path.open('wb') as f:f.write(b'[earlier install output trimmed]\n'+tail)
