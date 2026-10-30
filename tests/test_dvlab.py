import base64
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from dvlab import common, runner, netpolicy
from dvlab.agent import Capsule, verify_account_limits
from dvlab.hub import Hub, Server, bootstrap_script, tools

class Core(unittest.TestCase):
    def test_operation_validation(self):
        bad=[dict(op='start',command='echo ok',seconds=True),dict(op='start',command='x',seconds=301),dict(op='read',path='../secret'),dict(op='read',path='/etc/passwd'),dict(op='read',path='x',length=65537),dict(op='write',path='x',data_b64='!'),dict(op='metrics',host=True),dict(op='shell',command='x')]
        for op in bad:
            with self.subTest(op=op),self.assertRaises((ValueError,TypeError)):common.validate_operation(op)
        self.assertEqual(common.validate_operation(dict(op='start',command='echo ok'))['seconds'],60)
    def test_origin(self):
        for value in ('http://a.com','https://a.com/x','https://a.com?q=1',"https://a.com';evil",'https://a.com:99999','https://user:pass@a.com'):
            with self.assertRaises(ValueError):common.origin(value)
    def test_capsule_argv(self):
        cfg=dict(node='node1',image='sha256:'+'a'*64,capsule_memory_mib=128,capsule_cpus=.4,port_start=45100,port_count=8)
        argv=Capsule(cfg).create_argv();text=' '.join(argv)
        for flag in ('--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory-swap=128m','--pids-limit=64','allow_host_loopback=false'):
            self.assertIn(flag,text)
        for forbidden in ('--privileged','--network=host','--pid=host','docker.sock'):
            self.assertNotIn(forbidden,text)
        self.assertEqual(argv.count('--publish'),16)
        mounts=[a for a in argv if a.startswith('--volume=')]
        self.assertEqual(len(mounts),1);self.assertTrue(mounts[0].endswith('capsule/dvlab:/opt/dv-lab/dvlab:ro,nodev,nosuid'))
    def test_capsule_identity(self):
        calls=[]
        def fake(argv,**kw):calls.append(argv);return json.dumps([{'Id':'production','Config':{'Labels':{}}}]).encode()
        with self.assertRaises(RuntimeError):Capsule({'node':'ours'},fake).stop()
        self.assertEqual(len(calls),1)
    def test_account_fail_closed(self):
        good={'cpu.max':'50000 100000','memory.max':str(192*1048576),'memory.swap.max':'0','pids.max':'128'}
        cfg=dict(account_cpus=.5,account_memory_mib=192)
        with patch('dvlab.agent.account_metrics',return_value=good):verify_account_limits(cfg)
        for key in good:
            with patch('dvlab.agent.account_metrics',return_value={**good,key:'max'}),self.assertRaises((RuntimeError,ValueError)):verify_account_limits(cfg)
    def test_netpolicy(self):
        cfg=dict(uid=1001,port_start=45100,port_count=8,hub_ips=['8.8.8.8'],hub_port=8443,dns_ips=['127.0.0.53'],host_ips=['1.1.1.1'])
        p=netpolicy.initial_policy(cfg)
        self.assertIn('meta skuid 1001',p);self.assertIn('ct state established,related',p)
        self.assertNotIn('flush ruleset',p);self.assertNotIn('dport 22',p)
        self.assertIn('45100-45107',p)
        for ip in ('127.0.0.1','10.1.2.3','8.8.8.8; flush ruleset','::1'):
            with self.assertRaises(ValueError):netpolicy.peer_transaction([ip])

class HubTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();p=Path(self.tmp.name)
        (p/'bundle').write_bytes(b'public source only')
        self.cfg=dict(public_url='https://lab.example:8443',database=str(p/'db'),admin_token='admin-secret',mcp_token='mcp-secret',bundle=str(p/'bundle'))
        self.h=Hub(self.cfg)
    def tearDown(self):self.tmp.cleanup()
    def enroll(self,name='iran',ip='1.1.1.1'):
        return self.h.enroll(self.h.invite()['code'],name,ip)
    def test_auth_separation(self):
        self.assertTrue(self.h.auth('mcp-secret','mcp'));self.assertFalse(self.h.auth('admin-secret','mcp'));self.assertFalse(self.h.auth('mcp-secret','admin'))
        r=self.enroll();self.assertEqual(self.h.auth(r['token'],'node')['id'],r['node']);self.assertFalse(self.h.auth('bad','node'))
        self.assertNotIn(r['token'],json.dumps(self.h.nodes()))
        with self.h.db() as db:self.assertNotEqual(db.execute('SELECT secret FROM nodes').fetchone()[0],r['token'])
    def test_invitation_once_expiry(self):
        c=self.h.invite()['code'];self.h.enroll(c,'iran','1.1.1.1')
        with self.assertRaises(ValueError):self.h.enroll(c,'turkey','8.8.8.8')
        c=self.h.invite()['code']
        with self.h.db() as db:db.execute('UPDATE invites SET expires=0')
        with self.assertRaises(ValueError):self.h.enroll(c,'turkey','8.8.8.8')
    def test_queue_lease_scoped_and_never_replayed(self):
        a=self.enroll();b=self.enroll('turkey','8.8.8.8');na=self.h.auth(a['token'],'node');nb=self.h.auth(b['token'],'node')
        q=self.h.queue(a['node'],dict(op='start',command='printf ok'))
        self.assertIsNone(self.h.poll(nb,{},wait=0)['action'])
        leased=self.h.poll(na,{},wait=0)['action'];self.assertEqual(leased['id'],q['action'])
        self.assertIsNone(self.h.poll(na,{},wait=0)['action'])
        with self.assertRaises(ValueError):self.h.complete(nb,leased['id'],leased['lease'],{'ok':True})
        with self.assertRaises(ValueError):self.h.complete(na,leased['id'],'wrong',{'ok':True})
        self.h.complete(na,leased['id'],leased['lease'],{'ok':True})
        self.assertEqual(self.h.action(leased['id'])['state'],'done')
        self.assertNotIn('lease',self.h.action(leased['id']))
    def test_pause_and_offline(self):
        a=self.enroll();q=self.h.queue(a['node'],dict(op='metrics'))
        self.h.pause(a['node'],True);self.assertEqual(self.h.action(q['action'])['state'],'cancelled')
        with self.assertRaises(ValueError):self.h.queue(a['node'],dict(op='metrics'))
        self.h.pause(a['node'],False)
        with self.h.db() as db:db.execute('UPDATE nodes SET seen=0')
        with self.assertRaises(ValueError):self.h.queue(a['node'],dict(op='metrics'))
    def test_bootstrap_no_secrets(self):
        b=bootstrap_script(self.cfg).decode()
        self.assertNotIn('admin-secret',b);self.assertNotIn('mcp-secret',b);self.assertIn('sha256sum -c',b)
    def test_rpc_schema_and_bounds(self):
        r=self.h.rpc(dict(jsonrpc='2.0',id=1,method='initialize',params={'protocolVersion':'2025-03-26'}))
        self.assertEqual(r['result']['protocolVersion'],'2025-03-26')
        self.assertEqual(len(tools()),13)
        self.assertIsNone(self.h.rpc(dict(jsonrpc='2.0',method='notifications/initialized')))
        for t in tools():self.assertFalse(t['inputSchema']['additionalProperties'])
        self.assertIn('error',self.h.rpc(dict(jsonrpc='2.0',id=1,method='initialize',params=['bad'])))
    def test_http_protocol(self):
        server=Server(('127.0.0.1',0),self.h)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(method,path,data=None,bearer=None,extra=None):
            c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
            headers={'Content-Type':'application/json'}
            if bearer:headers['Authorization']='Bearer '+bearer
            headers.update(extra or {})
            c.request(method,path,json.dumps(data) if data is not None else None,headers)
            r=c.getresponse();body=r.read();status=r.status;c.close();return status,body
        try:
            self.assertEqual(request('POST','/mcp',{'jsonrpc':'2.0','id':1,'method':'tools/list'})[0],401)
            st,b=request('POST','/mcp',{'jsonrpc':'2.0','id':1,'method':'tools/list'},'mcp-secret');self.assertEqual(st,200);self.assertEqual(len(json.loads(b)['result']['tools']),13)
            self.assertEqual(request('POST','/mcp',{'jsonrpc':'2.0','method':'notifications/initialized'},'mcp-secret'),(202,b''))
            self.assertEqual(request('GET','/mcp',bearer='mcp-secret')[0],405)
            self.assertEqual(request('POST','/mcp',{},'mcp-secret',{'Origin':'https://evil.example'})[0],403)
            self.assertEqual(request('POST','/admin/invite',{},'mcp-secret')[0],401)
        finally:server.shutdown();server.server_close();thread.join(3)

class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.patch=patch.object(runner,'WORK',Path(self.tmp.name));self.patch.start();runner.PROCESSES.clear()
    def tearDown(self):
        for p in runner.PROCESSES.values():p.cancel.set();p.done.wait(3)
        self.patch.stop();self.tmp.cleanup()
    def test_files_and_chunks(self):
        text=b'hello\x00world'
        r=runner.dispatch(dict(op='write',path='x',data_b64=base64.b64encode(text).decode()));self.assertEqual(r['bytes'],len(text))
        r=runner.dispatch(dict(op='read',path='x',offset=6,length=5));self.assertEqual(base64.b64decode(r['data_b64']),b'world')
        self.assertIn('x',runner.dispatch(dict(op='list'))['names'])
    def test_no_symlink_or_fifo_read(self):
        root=Path(self.tmp.name);(root/'link').symlink_to('/etc/passwd');(root/'dir').symlink_to('/etc',target_is_directory=True);os.mkfifo(root/'fifo')
        for path in ('link','dir/passwd','fifo'):
            with self.assertRaises((ValueError,OSError)):runner.dispatch(dict(op='read',path=path))
        # Atomic write replaces a leaf symlink, never follows it.
        runner.dispatch(dict(op='write',path='link',data_b64='eA=='));self.assertFalse((root/'link').is_symlink())
    def test_job_deadline_and_logs(self):
        r=runner.dispatch(dict(op='start',command="printf 'hello'; sleep 10",seconds=1));p=runner.PROCESSES[r['process']]
        self.assertTrue(p.done.wait(3));self.assertEqual(p.reason,'deadline');self.assertIn('hello',p.snapshot()['output'])
    def test_log_ring(self):
        r=runner.dispatch(dict(op='start',command="python3 -c \"print('a'*100000)\"",seconds=5));p=runner.PROCESSES[r['process']]
        self.assertTrue(p.done.wait(5));self.assertLessEqual(len(p.output),65536);self.assertGreater(p.dropped,0)
    def test_kill_and_concurrency_limit(self):
        ids=[runner.dispatch(dict(op='start',command='sleep 10',seconds=20))['process'] for _ in range(4)]
        with self.assertRaises(ValueError):runner.dispatch(dict(op='start',command='echo x'))
        self.assertFalse(runner.dispatch(dict(op='kill',process=ids[0]))['running'])

if __name__=='__main__':unittest.main(verbosity=2)

class AdditionalTests(unittest.TestCase):
    def test_sampling_cpu_normalization(self):
        from dvlab.sampling import Sampler
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'cpu.stat').write_text('usage_usec 1000000\nnr_throttled 2\nthrottled_usec 100\n');(p/'memory.current').write_text('12345')
            s=Sampler(p,2)
            with patch('dvlab.sampling.time.monotonic',return_value=10):s.sample()
            (p/'cpu.stat').write_text('usage_usec 1500000\nnr_throttled 3\nthrottled_usec 200\n')
            with patch('dvlab.sampling.time.monotonic',return_value=11):s.sample()
            self.assertEqual(s.snapshot()[-1]['cpu_percent_one_core'],50)
            self.assertEqual(s.snapshot()[-1]['cpu_percent_host_capacity'],25)
    def test_real_tls_and_verification(self):
        import ssl
        import subprocess
        from dvlab.agent import Client
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);cert=p/'cert.pem';key=p/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,capture_output=True)
            cfg=dict(public_url='https://localhost:8443',database=str(p/'db'),admin_token='admin',mcp_token='mcp',bundle=str(p/'bundle'))
            h=Hub(cfg);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
            server=Server(('127.0.0.1',0),h,ctx);url='https://localhost:'+str(server.server_port);h.origin=url
            t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
            try:
                with self.assertRaises(ssl.SSLError):Client(url,'admin').post('/admin/nodes',{})
                with patch.dict(os.environ,{'SSL_CERT_FILE':str(cert)}):
                    client=Client(url,'admin')
                    self.assertEqual(client.post('/admin/nodes',{}),[])
                    self.assertEqual(client.post('/admin/nodes',{}),[]) # persistent TLS reuse
                    client.conn.close()
            finally:server.shutdown();server.server_close();t.join(3)
    def test_bundle_has_no_self_archive_or_cache(self):
        from dvlab import setup
        import tarfile
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'releases'/('a'*40);root.mkdir(parents=True);(base/'current').symlink_to(root);(root/'dvlab').mkdir();(root/'dvlab/common.py').write_text('# public code')
            (root/'old.zip').write_bytes(b'not bundled');(root/'__pycache__').mkdir();(root/'__pycache__/x.pyc').write_bytes(b'cache')
            with patch.object(setup,'ROOT',base):setup.bundle(root/'dv-lab.tar.gz')
            with tarfile.open(root/'dv-lab.tar.gz') as ar:self.assertEqual(ar.getnames(),['dv-lab/dvlab/common.py'])
