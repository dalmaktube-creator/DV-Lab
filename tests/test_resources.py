import contextlib,json,os,struct,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
from dvlab import resource_guard as g
from dvlab.common import validate_operation
from dvlab.hub import Hub,tools

BASE=dict(account_cpus=.5,account_memory_mib=192,capsule_cpus=.4,capsule_memory_mib=128)
NEW=dict(account_cpus=.75,account_memory_mib=320,capsule_cpus=.65,capsule_memory_mib=256)

class Resources(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.stack=contextlib.ExitStack()
        self.who=SimpleNamespace(pw_uid=12345,pw_gid=os.getgid())
        self.stack.enter_context(patch.object(g.pwd,'getpwnam',return_value=self.who))
        self.stack.enter_context(patch.object(g,'CONFIG',self.root/'agent.json'))
        self.stack.enter_context(patch.object(g,'POLICY',self.root/'policy.json'))
        self.stack.enter_context(patch.object(g,'DROP_ROOT',self.root/'units'))
        self.stack.enter_context(patch.object(g.os,'fchown'))
        self.stack.enter_context(patch.object(g,'root_json',side_effect=lambda p:json.loads(p.read_text())))
        self.cg=self.root/'cgroup';self.cg.mkdir();self.write_cg(BASE)
        (self.cg/'memory.current').write_text(str(50*1048576))
        self.stack.enter_context(patch.object(g,'group_path',return_value=self.cg))
        g.CONFIG.write_text(json.dumps({**BASE,'token':'fixture-secret'}))
        g.POLICY.write_text(json.dumps(dict(schema=1,uid=12345,max_account_cpus=1,max_account_memory_mib=512)))
        self.drop=g.DROP_ROOT/'user-12345.slice.d/dv-lab.conf';self.drop.parent.mkdir(parents=True);self.drop.write_text('[Slice]\nCPUQuota=50%\nMemoryMax=192M\nMemorySwapMax=0\nTasksMax=128\n')
        self.calls=[]
    def tearDown(self):self.stack.close();self.tmp.cleanup()
    def write_cg(self,values):
        for name,value in [('cpu.max',str(round(values['account_cpus']*100000))+' 100000'),('memory.max',str(values['account_memory_mib']*1048576)),('memory.swap.max','0'),('pids.max','128')]:
            (self.cg/name).write_text(value)
    def fake_run(self,args):
        self.calls.append(args)
        if 'set-property' in args:
            cpu=next(float(x.split('=')[1][:-1])/100 for x in args if x.startswith('CPUQuota='))
            mem=next(int(x.split('=')[1][:-1]) for x in args if x.startswith('MemoryMax='))
            self.write_cg(dict(account_cpus=cpu,account_memory_mib=mem))
        return SimpleNamespace(stdout='',returncode=0)
    def req(self,**values):return dict(action='set',revision=g.revision(BASE),**(values or NEW))
    def test_status_returns_only_resources_policy_and_revision(self):
        result=g.request({'action':'status'},self.fake_run)
        self.assertEqual(result['current'],BASE);self.assertEqual(result['ceilings']['max_account_memory_mib'],512)
        self.assertNotIn('fixture-secret',json.dumps(result));self.assertEqual(self.calls,[])
    def test_resource_operation_has_optimistic_revision(self):
        self.assertEqual(validate_operation(dict(op='resources',**self.req()))['account_cpus'],.75)
        with self.assertRaisesRegex(ValueError,'Stale'):g.request({**self.req(),'revision':'0'*64},self.fake_run)
        self.assertEqual(self.calls,[])
    def test_rejects_unknown_fields_and_missing_values(self):
        for request in ({'action':'shell'},dict(self.req(),path='/root'),dict(self.req(),command='id'),{'action':'set'},dict(action='status',account_cpus=2)):
            with self.subTest(request=request),self.assertRaises(ValueError):g.validate(request)
    def test_rejects_nan_bool_negative_fractional_memory_and_unbounded(self):
        for name,value in [('account_cpus',float('nan')),('capsule_cpus',float('inf')),('account_cpus',True),('account_cpus',0),('account_memory_mib',320.5),('capsule_memory_mib',True),('account_memory_mib',4096)]:
            with self.subTest(name=name,value=value),self.assertRaises(ValueError):g.validate({**self.req(),name:value})
    def test_reserves_controller_headroom(self):
        for change in (dict(capsule_cpus=.74),dict(capsule_memory_mib=300)):
            with self.assertRaises(ValueError):g.validate({**self.req(),**change})
    def test_policy_ceiling_cannot_be_raised_by_remote_request(self):
        with self.assertRaisesRegex(ValueError,'operator-approved'):g.request(self.req(account_cpus=2,account_memory_mib=1024,capsule_cpus=1.9,capsule_memory_mib=960),self.fake_run)
        self.assertEqual(self.calls,[])
    def test_actual_memory_usage_prevents_unsafe_shrink(self):
        (self.cg/'memory.current').write_text(str(300*1048576))
        with self.assertRaisesRegex(ValueError,'headroom'):g.request(self.req(),self.fake_run)
        self.assertEqual(self.calls,[])
    def test_set_changes_only_fixed_lab_slice_and_persists_limits(self):
        result=g.request(self.req(),self.fake_run)
        self.assertEqual(result['current'],NEW);self.assertNotEqual(result['revision'],g.revision(BASE))
        self.assertEqual(json.loads(g.CONFIG.read_text())['token'],'fixture-secret')
        self.assertEqual(g.CONFIG.stat().st_mode&0o777,0o640)
        self.assertIn('MemoryMax=320M',self.drop.read_text())
        self.assertTrue(all(call[:2] in (['systemctl','set-property'],['systemctl','daemon-reload']) for call in self.calls))
        self.assertIn('user-12345.slice',self.calls[0]);self.assertNotIn('user.slice',self.calls[0])
    def test_failure_restores_both_cgroup_and_config(self):
        failed=False
        def run(args):
            nonlocal failed
            if args==['systemctl','daemon-reload'] and not failed:
                failed=True;raise subprocess.CalledProcessError(1,args)
            return self.fake_run(args)
        with self.assertRaisesRegex(RuntimeError,'previous limits restored'):g.request(self.req(),run)
        self.assertEqual({k:json.loads(g.CONFIG.read_text())[k] for k in BASE},BASE)
        g.verify(self.cg,BASE);self.assertIn('MemoryMax=192M',self.drop.read_text())
    def test_unapproved_peer_uid_is_rejected(self):
        conn=Mock();conn.getsockopt.return_value=struct.pack('3i',1,9999,9999)
        with self.assertRaisesRegex(ValueError,'Unapproved'):g.authorize(conn)
        conn.getsockopt.return_value=struct.pack('3i',1,12345,12345);g.authorize(conn)
    def test_conservative_host_based_ceilings(self):
        self.assertEqual(g.ceilings(1,1024),dict(max_account_cpus=.75,max_account_memory_mib=256))
        self.assertEqual(g.ceilings(64,64000),dict(max_account_cpus=4,max_account_memory_mib=2048))
    def test_mcp_resources_is_queued_not_a_host_shell(self):
        hub=Hub(dict(public_url='https://lab.example.com:9443',database=str(self.root/'hub.db'),admin_token='a',mcp_token='b',bundle='unused'))
        node=hub.enroll(hub.invite()['code'],'iran','8.8.8.8')
        result=hub.call('lab_resources',{'node':node['node'],'action':'status'})
        self.assertIn('action',result)
        tool=next(t for t in tools() if t['name']=='lab_resources')
        self.assertTrue(tool['annotations']['destructiveHint']);self.assertFalse(tool['annotations']['readOnlyHint'])
        self.assertFalse(tool['inputSchema']['additionalProperties'])
