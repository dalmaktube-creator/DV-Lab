import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from dvlab.agent import Agent,Capsule

class Watchdog(unittest.TestCase):
    def agent(self,contact,last_use,lock=None):
        a=Agent.__new__(Agent)
        a.contact=contact;a.status='ready'
        a.quit=SimpleNamespace(wait=Mock(side_effect=[False,True]))
        a.capsule=SimpleNamespace(last_use=last_use,lock=lock or threading.RLock(),stop=Mock())
        return a
    def test_stale_expiry_rechecked_after_new_work_gets_lock(self):
        a=self.agent(1000,0)
        class Lock:
            def __enter__(self):a.capsule.last_use=1000
            def __exit__(self,*args):pass
        a.capsule.lock=Lock()
        with patch('dvlab.agent.time.monotonic',return_value=1000):a.watchdog()
        a.capsule.stop.assert_not_called()
        self.assertEqual(a.status,'ready')
    def test_idle_expiry_still_stops_capsule(self):
        a=self.agent(1000,0)
        with patch('dvlab.agent.time.monotonic',return_value=1000):a.watchdog()
        a.capsule.stop.assert_called_once()
    def test_lost_control_plane_still_stops_capsule(self):
        a=self.agent(0,1000)
        with patch('dvlab.agent.time.monotonic',return_value=1000):a.watchdog()
        a.capsule.stop.assert_called_once()
    def test_ensure_and_operation_share_one_critical_section(self):
        c=Capsule({});entered=[]
        class Lock:
            def __enter__(self):entered.append(True)
            def __exit__(self,*args):entered.pop()
        c.lock=Lock()
        c.ensure=lambda:self.assertTrue(entered)
        c.exec_json=lambda op:{'ok':True,'result':{}}
        c.operate({'op':'list'})
