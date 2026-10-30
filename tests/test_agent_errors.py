import subprocess
import unittest
from unittest.mock import patch
from dvlab.agent import fixed_run

class AgentErrors(unittest.TestCase):
    def failed(self,argv,stderr,data=None):
        result=subprocess.CompletedProcess(argv,125,b'',stderr)
        with patch('dvlab.agent.subprocess.run',return_value=result):
            with self.assertRaises(RuntimeError) as exc:fixed_run(argv,data)
        return str(exc.exception)
    def test_podman_reason_without_argv_or_input(self):
        text=self.failed(['podman','run','private-argv'],b'Error: memory cgroup permission denied',b'private-input')
        self.assertIn('podman run (exit 125)',text)
        self.assertIn('memory cgroup permission denied',text)
        self.assertNotIn('private-argv',text);self.assertNotIn('private-input',text)
    def test_details_are_bounded_and_controls_removed(self):
        text=self.failed(['podman','exec'],b'\x1b[31mError:\x1b[0m bad\n'+b'x'*1000)
        self.assertLess(len(text),480);self.assertNotIn('\x1b',text);self.assertNotIn('\n',text)
    def test_non_podman_helper_output_stays_private(self):
        text=self.failed(['sudo','helper'],b'private helper configuration')
        self.assertNotIn('private helper configuration',text)
