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
    files['release.json']=json.dumps(manifest or dict(update_schema=1,database_schema=1,requires_guard=1,version='0.2.0-preview.1')).encode()
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
        data,_=archive(manifest=dict(update_schema=2,database_schema=1,requires_guard=1,version='2'))
        with tempfile.TemporaryDirectory() as d,self.assertRaises(ValueError):g.unpack(data,Path(d)/'x',SHA)
    def test_no_downloaded_root_hooks(self):
        data,_=archive({'install.sh':b'echo not-executed','etc/sudoers':b'evil','scripts/root.sh':b'evil'})
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x';g.unpack(data,p,SHA)
            self.assertFalse((p/'etc').exists());self.assertFalse((p/'scripts').exists())
            self.assertEqual((p/'install.sh').stat().st_mode&0o777,0o644)
    def test_both_ci_checks_latest_must_pass(self):
        checks=[dict(id=1,name=n,head_sha=SHA,status='completed',conclusion='success',app={'slug':'github-actions'}) for n in ('unit-and-protocol','ubuntu-isolation')]
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
