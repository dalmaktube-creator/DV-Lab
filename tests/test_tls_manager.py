import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch,Mock
from dvlab import tls_manager as tls


class TLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.fixture=Path(cls.temp.name)
        for name in ('good','other'):
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','90',
                '-keyout',str(cls.fixture/(name+'.key')),'-out',str(cls.fixture/(name+'.pem')),
                '-subj','/CN=lab.example.com','-addext','subjectAltName=DNS:lab.example.com',
                '-addext','basicConstraints=critical,CA:TRUE'],check=True,capture_output=True)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.stack=contextlib.ExitStack()
        for name,rel in (('LE','letsencrypt'),('OWN','acme'),('DEST','tls'),('POLICY','tls-policy.json'),('PINNED','pinned/tls_manager.py')):
            self.stack.enter_context(patch.object(tls,name,self.root/rel))
        self.plan=dict(domain='lab.example.com',config=str(tls.OWN),name='dv-lab-lab.example.com')
    def tearDown(self):self.stack.close();self.tmp.cleanup()
    def trusted(self,args,**kw):
        args=list(args)
        if args[:2]==['openssl','verify']:
            index=args.index('-CApath');args[index:index+2]=['-CAfile',str(self.fixture/'good.pem')]
        return tls.command(args,**kw)
    def lineage(self,auth='standalone',extra=''):
        cert,key=tls.paths(self.plan);cert.parent.mkdir(parents=True)
        shutil.copyfile(self.fixture/'good.pem',cert);shutil.copyfile(self.fixture/'good.key',key)
        renewal=tls.OWN/'renewal';renewal.mkdir(exist_ok=True)
        (renewal/(self.plan['name']+'.conf')).write_text('[renewalparams]\nauthenticator = '+auth+'\n'+extra)
        return cert,key
    def test_real_certificate_chain_hostname_expiry_and_key_checks(self):
        cert,key=self.fixture/'good.pem',self.fixture/'good.key'
        self.assertTrue(tls.valid_pair('lab.example.com',cert,key,self.trusted))
        self.assertFalse(tls.valid_pair('wrong.example.com',cert,key,self.trusted))
        self.assertFalse(tls.valid_pair('lab.example.com',cert,self.fixture/'other.key',self.trusted))
        self.assertFalse(tls.valid_pair('lab.example.com',cert,key,self.trusted,minimum=100*86400))
        self.assertFalse(tls.valid_pair('lab.example.com',cert,key)) # untrusted self-signed rejected
    def test_existing_managed_matching_certificate_is_discovered(self):
        self.lineage()
        plan=tls.Manager(self.trusted).inspect('lab.example.com')
        self.assertEqual(plan,self.plan)
    def test_discovery_rejects_wrong_hostname(self):
        self.lineage()
        self.assertEqual(tls.candidates('wrong.example.com',self.trusted),[])
    def test_existing_stop_hooks_and_webserver_installers_are_not_run(self):
        for extra in ('pre_hook = systemctl stop nginx\n','post_hook = reboot\n','deploy_hook = /root/hook\n','renew_hook = /root/hook\n','installer = nginx\n'):
            cert,key=self.lineage('standalone',extra) if not (tls.OWN/'live').exists() else tls.paths(self.plan)
            path=tls.OWN/'renewal'/(self.plan['name']+'.conf');path.write_text('[renewalparams]\nauthenticator = standalone\n'+extra)
            self.assertFalse(tls.safe_renewal(path));self.assertEqual(tls.candidates('lab.example.com',self.trusted),[])
    def test_manual_renewal_without_automation_is_not_claimed_safe(self):
        self.lineage('manual')
        self.assertEqual(tls.candidates('lab.example.com',self.trusted),[])
    def test_existing_valid_cert_uses_dryrun_and_due_only_renewal(self):
        self.lineage('webroot');calls=[]
        def run(args,**kw):
            if args[0]=='certbot':calls.append(args);return subprocess.CompletedProcess(args,0)
            return self.trusted(args,**kw)
        self.assertEqual(tls.Manager(run).ensure(self.plan),tls.paths(self.plan))
        self.assertEqual(len(calls),2);self.assertIn('--dry-run',calls[0]);self.assertNotIn('--dry-run',calls[1])
        self.assertTrue(all('renew' in c and '--cert-name' in c and '--no-directory-hooks' in c for c in calls))
        self.assertFalse(any('certonly' in c or '--force-renewal' in c for c in calls))
    def test_failed_existing_renewal_never_requests_duplicate_production_cert(self):
        self.lineage('webroot');calls=[]
        def run(args,**kw):
            calls.append(args);raise subprocess.CalledProcessError(1,args)
        with self.assertRaisesRegex(RuntimeError,'unnecessary duplicate'):tls.Manager(run).ensure(self.plan)
        self.assertEqual(len(calls),1);self.assertNotIn('certonly',calls[0])
    def test_new_issue_staging_then_production_and_validates_pair(self):
        calls=[]
        def run(args,**kw):
            if args[0]=='certbot':
                calls.append(args)
                if '--dry-run' not in args:self.lineage()
                return subprocess.CompletedProcess(args,0)
            return self.trusted(args,**kw)
        with patch.object(tls,'public_dns'),patch.object(tls,'http_port_free'):
            tls.Manager(run).ensure(self.plan)
        self.assertEqual(len(calls),2);self.assertIn('--dry-run',calls[0]);self.assertIn(tls.STAGING,calls[0]);self.assertIn(tls.PRODUCTION,calls[1])
        self.assertIn('--keep-until-expiring',calls[1]);self.assertNotIn('--force-renewal',calls[1])
    def test_staging_failure_prevents_production_issuance(self):
        calls=[]
        def run(args,**kw):calls.append(args);raise subprocess.CalledProcessError(1,args)
        with patch.object(tls,'public_dns'),patch.object(tls,'http_port_free'),self.assertRaisesRegex(RuntimeError,'no production certificate'):
            tls.Manager(run).ensure(self.plan)
        self.assertEqual(len(calls),1);self.assertIn('--dry-run',calls[0])
    def test_occupied_http_port_never_stops_a_service_or_calls_ca(self):
        run=Mock()
        with patch.object(tls,'public_dns'),patch.object(tls,'http_port_free',side_effect=ValueError('TCP 80 busy')),self.assertRaisesRegex(ValueError,'TCP 80'):
            tls.Manager(run).ensure(self.plan)
        run.assert_not_called()
    def test_public_dns_rejects_private_and_missing_records(self):
        for addresses in ([],[(2,1,6,'',('127.0.0.1',80))],[(2,1,6,'',('10.0.0.2',80))]):
            with patch.object(tls.socket,'getaddrinfo',return_value=addresses),self.assertRaises(ValueError):tls.public_dns('lab.example.com')
        with patch.object(tls.socket,'getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',80))]):tls.public_dns('lab.example.com')
    def test_unapproved_paths_and_lineage_names_are_rejected(self):
        with self.assertRaises(ValueError):tls.paths({**self.plan,'config':'/root'})
        with self.assertRaises(ValueError):tls.paths({**self.plan,'name':'../outside'})
    def deploy_context(self):
        stack=contextlib.ExitStack()
        stack.enter_context(patch.object(tls.grp,'getgrnam',return_value=type('G',(),{'gr_gid':os.getgid()})()))
        stack.enter_context(patch.object(tls.os,'chown'));stack.enter_context(patch.object(tls.os,'fchown'))
        return stack
    def test_atomic_deploy_key_permissions_and_no_repeat_restart(self):
        self.lineage();calls=[]
        def run(args,**kw):
            if args[0]=='systemctl':calls.append(args);return subprocess.CompletedProcess(args,0)
            return self.trusted(args,**kw)
        with self.deploy_context():
            self.assertTrue(tls.deploy(self.plan,run,restart=False))
            target=tls.DEST/'current';self.assertTrue(target.is_symlink())
            self.assertEqual((target/'privkey.pem').stat().st_mode&0o777,0o640)
            self.assertFalse(tls.deploy(self.plan,run));self.assertEqual(calls,[])
    def test_failed_restart_rolls_back_atomic_pair(self):
        cert,key=self.lineage()
        with self.deploy_context():
            tls.deploy(self.plan,self.trusted,restart=False);before=os.readlink(tls.DEST/'current')
            # A changed PEM representation of the same valid chain changes hash.
            cert.write_bytes(cert.read_bytes()+b'\n');calls=[]
            def run(args,**kw):
                if args[0]=='systemctl':
                    calls.append(args)
                    if len(calls)==1:raise subprocess.CalledProcessError(1,args)
                    return subprocess.CompletedProcess(args,0)
                return self.trusted(args,**kw)
            with self.assertRaisesRegex(RuntimeError,'previous keypair restored'):tls.deploy(self.plan,run)
            self.assertEqual(os.readlink(tls.DEST/'current'),before);self.assertEqual(len(calls),2)
    def test_bad_pair_never_changes_live_symlink(self):
        cert,key=self.lineage()
        with self.deploy_context():
            tls.deploy(self.plan,self.trusted,restart=False);before=os.readlink(tls.DEST/'current')
            shutil.copyfile(self.fixture/'other.key',key)
            with self.assertRaisesRegex(RuntimeError,'validation failed'):tls.deploy(self.plan,self.trusted)
            self.assertEqual(os.readlink(tls.DEST/'current'),before)

    def test_failed_tls_health_check_restores_previous_pair(self):
        cert,key=self.lineage()
        with self.deploy_context():
            tls.deploy(self.plan,self.trusted,restart=False);before=os.readlink(tls.DEST/'current')
            cert.write_bytes(cert.read_bytes()+b'\n')
            def run(args,**kw):
                if args[0]=='systemctl':return subprocess.CompletedProcess(args,0)
                return self.trusted(args,**kw)
            with patch.object(tls,'healthy',side_effect=RuntimeError('TLS not healthy')),self.assertRaisesRegex(RuntimeError,'previous keypair restored'):
                tls.deploy(self.plan,run)
            self.assertEqual(os.readlink(tls.DEST/'current'),before)

    def test_live_https_health_uses_sni_and_host_with_nondefault_port(self):
        import ssl,threading
        from dvlab.hub import Hub,Server
        cfg=dict(public_url='https://lab.example.com:9443',database=str(self.root/'hub.db'),admin_token='fixture-admin',mcp_token='fixture-mcp',bundle=str(self.root/'bundle'))
        hub=Hub(cfg);server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.fixture/'good.pem',self.fixture/'good.key')
        server=Server(('127.0.0.1',0),hub,server_context)
        hub.origin='https://lab.example.com:'+str(server.server_port)
        config=self.root/'hub.json';config.write_text(json.dumps({'port':server.server_port}))
        context=ssl.create_default_context(cafile=str(self.fixture/'good.pem'))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with patch.object(tls,'HUB_CONFIG',config),patch.object(tls.ssl,'create_default_context',return_value=context):
                tls.healthy('lab.example.com')
        finally:server.shutdown();server.server_close();thread.join(2)
