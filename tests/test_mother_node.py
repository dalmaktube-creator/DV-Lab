"""Mother uses the same node enrollment, action queue and rootless installer."""
import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from dvlab import local_node,setup
from dvlab.hub import Hub
from dvlab.common import digest

class MotherAddress(unittest.TestCase):
    def resolve(self,values):return [(2,1,6,'',(value,9443)) for value in values]
    def test_one_public_address(self):
        with patch.object(setup.socket,'getaddrinfo',return_value=self.resolve(['8.8.8.8','8.8.8.8'])):
            self.assertEqual(setup.mother_node_address('https://lab.example:9443'),'8.8.8.8')
    def test_nonpublic_multi_and_empty_fail(self):
        for values in ([],['127.0.0.1'],['10.0.0.1'],['8.8.8.8','1.1.1.1']):
            with self.subTest(values=values),patch.object(setup.socket,'getaddrinfo',return_value=self.resolve(values)),self.assertRaises(ValueError):
                setup.mother_node_address('https://lab.example:9443')
    def test_https_port_cannot_occupy_test_pool(self):
        with patch.object(setup.socket,'getaddrinfo') as lookup:
            for port in range(45100,45108):
                with self.assertRaisesRegex(ValueError,'overlaps'):setup.mother_node_address(f'https://lab.example:{port}')
            lookup.assert_not_called()

class LocalEnrollment(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        d=Path(self.tmp.name);self.cfg={'public_url':'https://lab.example:9443','database':str(d/'hub.sqlite3'),'admin_token':'fixture-admin','mcp_token':'fixture-mcp'}
        self.path=d/'hub.json';self.path.write_text(json.dumps(self.cfg));self.hub=Hub(self.cfg)
        self.remote=self.hub.enroll(self.hub.invite()['code'],'existing-remote','1.1.1.1')
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(local_node,'CONFIG',self.path))
        self.stack.enter_context(patch.object(local_node.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=1200)))
        self.stack.enter_context(patch.object(local_node.os,'geteuid',return_value=1200))
    def test_is_normal_node_and_preserves_remote(self):
        result=local_node.enroll('8.8.8.8');self.assertEqual(set(result),{'node','token'})
        nodes=self.hub.nodes();self.assertEqual({n['name'] for n in nodes},{'mother-local','existing-remote'})
        self.assertEqual(self.hub.auth(result['token'],'node')['id'],result['node'])
        self.assertIsNotNone(self.hub.auth(self.remote['token'],'node'))
        with self.hub.db() as db:self.assertEqual(db.execute('SELECT secret FROM nodes WHERE id=?',(result['node'],)).fetchone()[0],digest(result['token']))
        queued=self.hub.call('lab_exec',{'node':result['node'],'command':'echo fixture','seconds':5})
        node=self.hub.auth(result['token'],'node');lease=self.hub.poll(node,{'location':'mother'},wait=0)
        self.assertEqual(lease['action']['id'],queued['action']);self.assertEqual(lease['action']['operation']['op'],'start')
        self.assertNotIn('fixture-admin',json.dumps(lease));self.assertNotIn('fixture-mcp',json.dumps(lease))
    def test_no_duplicate_or_credential_rotation(self):
        old=local_node.enroll('8.8.8.8')
        with self.assertRaisesRegex(ValueError,'already enrolled'):local_node.enroll('8.8.8.8')
        self.assertIsNotNone(self.hub.auth(old['token'],'node'));self.assertEqual(len(self.hub.nodes()),2)
    def test_no_root_or_unrelated_uid(self):
        for uid in (0,1201):
            with patch.object(local_node.os,'geteuid',return_value=uid),self.assertRaisesRegex(ValueError,'dedicated hub'):local_node.enroll('8.8.8.8')
        self.assertEqual(len(self.hub.nodes()),1)
    def test_nonpublic_has_no_enrollment_side_effect(self):
        with self.assertRaises(ValueError):local_node.enroll('127.0.0.1')
        self.assertEqual(len(self.hub.nodes()),1)

class InstallerReuse(unittest.TestCase):
    def test_uses_unprivileged_enrollment_and_same_agent(self):
        who=SimpleNamespace(pw_name='dvlab-hub');credential={'node':'local-fixture','token':'fixture-not-to-log'}
        with patch.object(setup.pwd,'getpwnam',return_value=who),patch.object(setup,'userrun',return_value=SimpleNamespace(stdout=json.dumps(credential))) as run,patch.object(setup,'install_agent') as install,contextlib.redirect_stdout(io.StringIO()) as out:
            setup.install_mother_agent('https://lab.example:9443','8.8.8.8',dependencies=False)
        run.assert_called_once_with(who,['/usr/bin/python3','-m','dvlab.local_node','8.8.8.8'],capture_output=True,text=True)
        install.assert_called_once_with('https://lab.example:9443',credential,['8.8.8.8'],mother_local=True,dependencies=False)
        self.assertNotIn(credential['token'],out.getvalue())
    def test_enrollment_failure_does_not_install_runtime(self):
        with patch.object(setup.pwd,'getpwnam'),patch.object(setup,'userrun',side_effect=RuntimeError('fixture')),patch.object(setup,'install_agent') as install,self.assertRaises(RuntimeError):
            setup.install_mother_agent('https://lab.example:9443','8.8.8.8')
        install.assert_not_called()
    def test_migration_requires_root(self):
        with patch.object(setup.os,'geteuid',return_value=1200),patch.object(setup,'install_mother_agent') as install,self.assertRaises(SystemExit):setup.migrate_mother_agent()
        install.assert_not_called()
    def test_migration_exact_release_and_preserved_hub(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);source=p/'source';root=p/'application';etc=p/'etc'
            for path in [source,root/'current',etc]:path.mkdir(parents=True,exist_ok=True)
            sha='a'*40
            (source/'.source-commit').write_text(sha);(root/'current/.source-commit').write_text(sha)
            original=json.dumps({'public_url':'https://lab.example:9443','mcp_token':'keep-this','admin_token':'also-keep'})
            (etc/'hub.json').write_text(original)
            with patch.object(setup,'SOURCE',source),patch.object(setup,'ROOT',root),patch.object(setup,'ETC',etc),patch.object(setup.os,'geteuid',return_value=0),patch.object(setup,'local_agent_preflight') as preflight,patch.object(setup,'mother_node_address',return_value='8.8.8.8'),patch.object(setup,'resource_ceilings',return_value={'max_account_cpus':1,'max_account_memory_mib':256}),patch.object(setup,'run',return_value=SimpleNamespace(returncode=0)),patch.object(setup,'confirm') as confirm,patch.object(setup,'install_mother_agent') as install,contextlib.redirect_stdout(io.StringIO()):
                setup.migrate_mother_agent();preflight.assert_called_once();confirm.assert_called_once();install.assert_called_once_with('https://lab.example:9443','8.8.8.8')
                self.assertEqual((etc/'hub.json').read_text(),original)
                (source/'.source-commit').write_text('b'*40);install.reset_mock()
                with self.assertRaisesRegex(SystemExit,'exact release'):setup.migrate_mother_agent()
                install.assert_not_called()

if __name__=='__main__':unittest.main()
