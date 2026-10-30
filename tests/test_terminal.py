"""Actual controlling pseudo-terminal, while stdin is a closed pipe (curl mode)."""
import errno
import fcntl
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import termios
import time
import unittest

ROOT=Path(__file__).resolve().parent.parent

class TerminalPrompts(unittest.TestCase):
    def interact(self,code,label,answer):
        master,slave=pty.openpty()
        def session():
            os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
        p=None;output=b''
        try:
            p=subprocess.Popen([sys.executable,'-c',code],cwd=ROOT,stdin=subprocess.PIPE,stdout=slave,stderr=slave,pass_fds=(slave,),preexec_fn=session)
            os.close(slave);slave=-1;p.stdin.close()
            deadline=time.monotonic()+6;sent=False
            while time.monotonic()<deadline:
                if select.select([master],[],[],.1)[0]:
                    try:chunk=os.read(master,4096)
                    except OSError as exc:
                        if exc.errno==errno.EIO:break
                        raise
                    if not chunk:break
                    output+=chunk
                    if not sent and label in output:
                        # getpass disables ECHO before writing its prompt.
                        os.write(master,answer);sent=True
                elif p.poll() is not None:break
            p.wait(timeout=2)
            self.assertTrue(sent,output.decode(errors='replace'));self.assertEqual(p.returncode,0,output.decode(errors='replace'))
            return output.decode(errors='replace')
        finally:
            if p is not None and p.poll() is None:p.kill();p.wait()
            if slave!=-1:os.close(slave)
            os.close(master)
    def test_typed_role_with_pipe_stdin(self):
        output=self.interact("from dvlab.setup import prompt;print('RESULT:'+prompt('Role','hub'),flush=True)",b'Role [hub]: ',b'agent\n')
        self.assertIn('RESULT:agent',output)
    def test_default_role_with_pipe_stdin(self):
        output=self.interact("from dvlab.setup import prompt;print('RESULT:'+prompt('Role','hub'),flush=True)",b'Role [hub]: ',b'\n')
        self.assertIn('RESULT:hub',output)
    def test_hidden_input_is_not_echoed(self):
        output=self.interact("from dvlab.setup import secret;print('LENGTH:'+str(len(secret('Code'))),flush=True)",b'Code: ',b'fixture-only-code\n')
        self.assertIn('LENGTH:17',output);self.assertNotIn('fixture-only-code',output)
    def test_no_controlling_terminal_has_friendly_error(self):
        p=subprocess.run([sys.executable,'-c',"from dvlab.setup import prompt;prompt('Role','hub')"],cwd=ROOT,stdin=subprocess.DEVNULL,capture_output=True,text=True,start_new_session=True,timeout=4)
        self.assertNotEqual(p.returncode,0);self.assertIn('Interactive terminal unavailable',p.stderr);self.assertNotIn('Traceback',p.stderr)
