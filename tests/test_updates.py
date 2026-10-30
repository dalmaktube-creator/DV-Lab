import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from dvlab import update_guard as g
from dvlab.updating import validate_update
from dvlab.common import validate_operation
from dvlab.hub import tools

SHA='a'*40

def archive(extra=None,manifest=None):
    files={'dvlab/'+p:b'# source\n' for p in g.APP_REQUIRED}
    files['release.json']=json.dumps(manifest or dict(update_schema=1,database_schema=1,requires_guard=2,version='0.2.0-preview.1')).encode()
    files.update(extra or {})
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w:gz') as ar:
        for name,body in files.items():
            info=tarfile.TarInfo('DV-Lab-'+SHA+'/'+name)
            if body is None:info.type=tarfile.SYMTYPE;info.linkname='/etc/shadow';ar.addfile(info)
            else:info.size=len(body);ar.addfile(info,io.BytesIO(body))
    return out.getvalue(),files

class Updates(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(validate_operation(dict(op='update',action='apply',commit=SHA))['commit'],SHA)
        for args in (dict(action='apply'),dict(action='apply',commit='main'),dict(action='apply',commit=SHA,command='evil'),dict(action='shell'),dict(action='apply',commit='A'*40)):
            with self.assertRaises(ValueError):validate_update(args)
    def test_safe_unpack_and_permissions(self):
        data,files=archive()
        tree={p:hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest() for p,b in files.items()}
        with tempfile.TemporaryDirectory() as d:
            old=os.umask(0o077)
            try:g.unpack(data,Path(d)/'new',SHA,tree)
            finally:os.umask(old)
            p=Path(d)/'new'
            self.assertEqual((p/'.source-commit').read_text().strip(),SHA)
            self.assertEqual(p.stat().st_mode&0o777,0o755)
            self.assertEqual((p/'.source-commit').stat().st_mode&0o777,0o644)
            self.assertEqual((p/'capsule/dvlab/runner.py').stat().st_mode&0o777,0o644)
            self.assertEqual((p/'capsule/dvlab').stat().st_mode&0o777,0o755)
            self.assertTrue((p/'dv-lab.tar.gz').exists())
    def test_git_blob_integrity(self):
        data,_=archive()
        with tempfile.TemporaryDirectory() as d,self.assertRaisesRegex(ValueError,'Git tree'):g.unpack(data,Path(d)/'x',SHA,{})
    def test_path_link_and_invalid_python(self):
        for extra in ({'../../evil':b'x'},{'dvlab/link.py':None},{'dvlab/hub.py':b'def invalid syntax'}):
            data,_=archive(extra)
            with tempfile.TemporaryDirectory() as d,self.assertRaises((ValueError,SyntaxError)):g.unpack(data,Path(d)/'x',SHA)
    def test_policy_change_is_rejected(self):
        data,_=archive(manifest=dict(update_schema=2,database_schema=1,requires_guard=2,version='2'))
        with tempfile.TemporaryDirectory() as d,self.assertRaises(ValueError):g.unpack(data,Path(d)/'x',SHA)
    def test_no_downloaded_root_hooks(self):
        data,_=archive({'install.sh':b'echo not-executed','etc/sudoers':b'evil','scripts/root.sh':b'evil'})
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x';g.unpack(data,p,SHA)
            self.assertFalse((p/'etc').exists());self.assertFalse((p/'scripts').exists())
            self.assertEqual((p/'install.sh').stat().st_mode&0o777,0o644)
    def test_both_ci_checks_latest_must_pass(self):
        checks=[dict(id=1,name=n,head_sha=SHA,status='completed',conclusion='success',app={'slug':'github-actions'}) for n in ('unit-and-protocol','ubuntu-isolation','ubuntu-22-hub')]
        def api(path):
            return {'sha':SHA} if path=='/commits/main' else {'check_runs':checks}
        with patch.object(g,'api',side_effect=api):self.assertTrue(g.candidate(SHA)['ci_passed'])
        checks.append(dict(id=2,name='ubuntu-isolation',head_sha=SHA,status='completed',conclusion='failure',app={'slug':'github-actions'}))
        with patch.object(g,'api',side_effect=api):self.assertFalse(g.candidate(SHA)['ci_passed'])
    def test_bad_branch_ref_is_not_accepted(self):
        with self.assertRaises(ValueError):g.validate_commit('main; rm -rf /')
    def test_mcp_update_is_explicit_target(self):
        t=next(t for t in tools() if t['name']=='lab_update')
        self.assertEqual(set(t['inputSchema']['required']),{'target','action'})
    def test_worker_rollback_on_failed_health(self):
        # Exercise transaction choreography without systemd/root/network calls.
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'app';state=Path(d)/'state';state.mkdir();(root/'releases').mkdir(parents=True)
            old=root/'releases'/('b'*40);old.mkdir();new=root/'releases'/SHA;new.mkdir();(root/'current').symlink_to(old)
            (state/'request.json').write_text(json.dumps(dict(action='apply',commit=SHA)))
            seen=[]
            class Result:returncode=0;stdout=''
            def cmd(a,check=True):seen.append(a);return Result()
            with patch.object(g,'ROOT',root),patch.object(g,'STATE',state),patch.object(g,'candidate',return_value={'ci_passed':True}),patch.object(g,'services',return_value=[('fake',lambda verb:['fake',verb])]),patch.object(g,'command',side_effect=cmd),patch.object(g,'backup_db',return_value=None),patch.object(g,'healthy',side_effect=[False,True]):g.worker()
            self.assertEqual((root/'current').resolve(),old)
            self.assertEqual(json.loads((state/'status.json').read_text())['state'],'failed_restored')
            self.assertIn(['fake','stop'],seen)

class AccountEnvironment(unittest.TestCase):
    def test_account_helpers_do_not_inherit_operator_configuration(self):
        from types import SimpleNamespace
        from dvlab import setup
        who=SimpleNamespace(pw_uid=1234,pw_name='dvlab-node',pw_dir='/home/dvlab-node')
        with patch.object(setup,'run') as run:
            setup.userrun(who,['podman','info'])
            args=run.call_args.args[0]
            self.assertEqual(args[args.index('env')+1],'-i')
            self.assertIn('HOME=/home/dvlab-node',args)
            self.assertEqual(run.call_args.kwargs['cwd'],str(setup.ROOT/'current'))
            self.assertIn('XDG_CONFIG_HOME=/home/dvlab-node/.config',args)
        with patch('pwd.getpwnam',return_value=who):
            args=g.node_command('restart')
            self.assertEqual(args[args.index('env')+1],'-i')
            self.assertIn('HOME=/home/dvlab-node',args)
    def test_podman_environment_uses_actual_uid_not_manager_environment(self):
        from types import SimpleNamespace
        from dvlab.agent import host_environment
        who=SimpleNamespace(pw_uid=1234,pw_name='lab',pw_dir='/home/lab')
        with patch('pwd.getpwuid',return_value=who),patch.dict(os.environ,{'XDG_RUNTIME_DIR':'/run/user/999','CONTAINERS_STORAGE_CONF':'/private/other','SSH_AUTH_SOCK':'/secret'}):
            env=host_environment()
            self.assertEqual(env['XDG_RUNTIME_DIR'],'/run/user/1234')
            self.assertEqual(env['DBUS_SESSION_BUS_ADDRESS'],'unix:path=/run/user/1234/bus')
            self.assertNotIn('CONTAINERS_STORAGE_CONF',env)
            self.assertNotIn('SSH_AUTH_SOCK',env)

class SocketUpdateTransport(unittest.TestCase):
    def test_unprivileged_client_uses_socket_not_sudo(self):
        import socket,threading
        from dvlab import updating
        with tempfile.TemporaryDirectory() as d:
            path=str(Path(d)/'broker.sock');received=[]
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(path);listener.listen(1)
            def serve():
                c,_=listener.accept()
                with c:
                    with c.makefile('rb') as r:received.append(json.loads(r.read(4097)))
                    c.sendall(b'{"state":"idle"}\n')
            t=threading.Thread(target=serve);t.start()
            try:
                with patch.object(updating,'BROKER_SOCKET',path):self.assertEqual(updating.broker({'action':'status'}),{'state':'idle'})
                t.join(3);self.assertFalse(t.is_alive());self.assertEqual(received,[{'action':'status'}])
            finally:listener.close()
    def test_kernel_peer_uid_must_be_approved(self):
        import struct
        from types import SimpleNamespace
        fake=unittest.mock.MagicMock();fake.getsockopt.return_value=struct.pack('3i',10,999,999)
        with patch.object(g.socket,'fromfd',return_value=fake),patch.object(g.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=1234)):
            with self.assertRaisesRegex(ValueError,'Unapproved'):g.authorize_input()
