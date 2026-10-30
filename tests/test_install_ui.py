import contextlib
import io
import socket
import tempfile
from pathlib import Path
import re
import unittest
from unittest.mock import patch
from dvlab import setup
from dvlab.install_ui import Console,color

class Tty(io.StringIO):
    def isatty(self):return True
    def fileno(self):return 1

class InstallUI(unittest.TestCase):
    def test_bad_value_is_explained_and_reprompted(self):
        output=io.StringIO();console=Console(output)
        with patch.object(setup,'CONSOLE',console),patch.object(setup,'prompt',side_effect=['wrong','hub']):
            self.assertEqual(setup.ask('Role',setup.validate_role),'hub')
        self.assertIn('Choose hub',output.getvalue())
    def test_url_rejects_path_http_low_port_and_busy_port(self):
        for value in ('http://lab.example:8443','https://lab.example:9443/mcp','https://lab.example:443'):
            with self.assertRaises(ValueError):setup.validate_hub_url(value)
        with patch.object(setup,'portcheck',side_effect=OSError(98,'busy')):
            with self.assertRaisesRegex(ValueError,'in use'):setup.validate_hub_url('https://lab.example:9443')
    def test_valid_url_only_checks_tcp(self):
        with patch.object(setup,'portcheck') as check:
            self.assertEqual(setup.validate_hub_url('https://lab.example:9443'),'https://lab.example:9443')
            check.assert_called_once_with(9443,1,tcp_only=True)
    def test_tcp_port_check_does_not_reserve_udp(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.bind(('127.0.0.1',0));port=udp.getsockname()[1]
            setup.portcheck(port,1,tcp_only=True)
    def test_pem_path_requires_existing_full_file(self):
        with self.assertRaises(ValueError):setup.pem_path('relative.pem')
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):setup.pem_path(d)
            with self.assertRaises(ValueError):setup.pem_path(str(Path(d)/'missing.pem'))
            p=Path(d)/'cert.pem';p.write_text('fixture')
            self.assertEqual(setup.pem_path(str(p)),p)
    def test_confirm_retries_typo_and_can_cancel(self):
        with patch.object(setup,'CONSOLE',Console(io.StringIO())),patch.object(setup,'prompt',side_effect=['typo','INSTALL']):setup.confirm('Review')
        with patch.object(setup,'CONSOLE',Console(io.StringIO())),patch.object(setup,'prompt',return_value='CANCEL'):
            with self.assertRaises(SystemExit):setup.confirm('Review')
    def test_non_tty_and_no_color_are_plain(self):
        self.assertEqual(color('text','blue',io.StringIO()),'text')
        with patch.dict('os.environ',{'NO_COLOR':'1'}):self.assertEqual(color('text','blue',Tty()),'text')
    def test_small_terminal_wraps_and_color_does_not_hide_labels(self):
        out=Tty();console=Console(out)
        with patch('os.get_terminal_size',return_value=__import__('os').terminal_size((52,30))):
            console.banner('Mother / Hub','preview');console.stage(2,5,'Connection & TLS');console.error('This is a readable error that wraps on a narrow SSH terminal without hiding the next action.')
        text=re.sub(r'\x1b\[[0-9;]*m','',out.getvalue())
        self.assertIn('[2/5] Connection & TLS',text)
        self.assertTrue(all(len(line)<=52 for line in text.splitlines()),text)
    def test_entrypoint_returns_success_and_errors_have_no_traceback(self):
        with patch.object(setup,'main',return_value=None):self.assertEqual(setup.entrypoint(),0)
        out=io.StringIO()
        with patch.object(setup,'CONSOLE',Console(out)),patch.object(setup,'main',side_effect=ValueError('Invalid input')):
            self.assertEqual(setup.entrypoint(),1)
        self.assertIn('Invalid input',out.getvalue());self.assertNotIn('Traceback',out.getvalue())
    def test_bad_pem_pair_is_explained_without_traceback_and_retried(self):
        import ssl
        output=io.StringIO();context=unittest.mock.MagicMock()
        context.load_cert_chain.side_effect=[ssl.SSLError('fixture mismatch'),None]
        with patch.object(setup,'CONSOLE',Console(output)),patch.object(setup,'ask',side_effect=[Path('/cert1'),Path('/key1'),Path('/cert2'),Path('/key2')]),patch.object(setup.ssl,'SSLContext',return_value=context):
            self.assertEqual(setup.tls_files(),(Path('/cert2'),Path('/key2')))
        self.assertIn('matching PEM files',output.getvalue());self.assertNotIn('Traceback',output.getvalue())

    def test_domain_accepts_bare_hostname_without_adding_www(self):
        self.assertEqual(setup.domain_name('DVLAB.DalmakTube.cyou'),'dvlab.dalmaktube.cyou')
        self.assertEqual(setup.domain_name('example.com'),'example.com')
        self.assertEqual(setup.domain_name('www.example.com'),'www.example.com')
        self.assertEqual(setup.domain_name('مثال.com'),'xn--mgbh0fb.com')
    def test_domain_rejects_scheme_port_path_and_malformed_names(self):
        for value in ('','https://example.com','example.com:2086','example.com/mcp','user@example.com','a b.com','-a.com','a-.com','a..com','127.0.0.1','[::1]','a'*64+'.com','example.com?x','example.com#x'):
            with self.subTest(value=value),self.assertRaises(ValueError):setup.domain_name(value)
    def test_port_requires_valid_integer_and_available_tcp(self):
        for value in ('0','443','1023','65536','9443/mcp','abc','1.5','-1',''):
            with self.subTest(value=value),self.assertRaises(ValueError):setup.hub_port(value)
        with patch.object(setup,'portcheck') as check:
            for value in ('1024','2086','9443','65535'):
                self.assertEqual(setup.hub_port(value),int(value))
            check.assert_called_with(65535,1,tcp_only=True)
        with patch.object(setup,'portcheck',side_effect=OSError(98,'busy')):
            with self.assertRaisesRegex(ValueError,'in use'):setup.hub_port('9443')
    def test_separate_questions_retry_only_bad_field_and_build_https(self):
        out=io.StringIO()
        with patch.object(setup,'CONSOLE',Console(out)),patch.object(setup,'portcheck'),patch.object(setup,'prompt',side_effect=['https://example.com','dvlab.dalmaktube.cyou','wrong','2086']) as prompt:
            self.assertEqual(setup.hub_address(),'https://dvlab.dalmaktube.cyou:2086')
        self.assertEqual([call.args[0] for call in prompt.call_args_list],['Domain','Domain','HTTPS port','HTTPS port'])
        self.assertIn('HTTPS address: https://dvlab.dalmaktube.cyou:2086',out.getvalue())
    def test_default_port_is_passed_to_prompt(self):
        with patch.object(setup,'CONSOLE',Console(io.StringIO())),patch.object(setup,'portcheck'),patch.object(setup,'prompt',side_effect=['example.com','9443']) as prompt:
            self.assertEqual(setup.hub_address(),'https://example.com:9443')
        self.assertEqual(prompt.call_args_list[-1].args,('HTTPS port','9443'))
