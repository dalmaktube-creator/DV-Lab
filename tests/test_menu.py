import contextlib,io,os,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
from dvlab import menu,console_launcher

class Menu(unittest.TestCase):
    def test_bootstrap_card_has_exact_copyable_url_and_no_code_in_url(self):
        out=io.StringIO();url='https://lab.example.com:2086/bootstrap.sh'
        with patch.object(menu,'api',return_value={'code':'one-use-fixture'}),patch.object(menu,'load',return_value={'public_url':'https://lab.example.com:2086'}),contextlib.redirect_stdout(out):menu.invite()
        lines=out.getvalue().splitlines()
        self.assertIn(url,lines);self.assertIn('BOOTSTRAP URL',out.getvalue())
        command=next(line for line in lines if line.startswith('curl '))
        self.assertNotIn('one-use-fixture',command);self.assertIn(url,command)
        self.assertIn('one-use-fixture',lines);self.assertIn('no node domain needed',out.getvalue())
    def test_result_is_followed_by_enter_before_menu_redraw(self):
        events=[];out=io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'hub.json').write_text('{}')
            def prompt(label,default=''):
                events.append(('prompt',label))
                return '1' if len(events)==1 else ('' if 'Press Enter' in label else '0')
            with patch.object(menu,'ETC',Path(d)),patch.object(menu.os,'geteuid',return_value=1001),patch.object(menu.pwd,'getpwuid',return_value=SimpleNamespace(pw_name='dvlab-hub')),patch.object(menu.sys,'argv',['dv-lab']),patch.object(menu,'prompt',side_effect=prompt),patch.object(menu,'nodes',side_effect=lambda:events.append(('result','nodes'))),contextlib.redirect_stdout(out):menu.main()
        self.assertEqual(events[:4],[('prompt','Choose'),('result','nodes'),('prompt','Press Enter to return to menu'),('prompt','Choose')])
    def test_errors_are_also_held_until_enter(self):
        labels=[]
        def prompt(label,default=''):
            labels.append(label);return '1' if len(labels)==1 else ('' if 'Press Enter' in label else '0')
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'hub.json').write_text('{}')
            with patch.object(menu,'ETC',Path(d)),patch.object(menu.os,'geteuid',return_value=1001),patch.object(menu.pwd,'getpwuid',return_value=SimpleNamespace(pw_name='dvlab-hub')),patch.object(menu.sys,'argv',['dv-lab']),patch.object(menu,'prompt',side_effect=prompt),patch.object(menu,'nodes',side_effect=RuntimeError('fixture error')),contextlib.redirect_stdout(io.StringIO()):menu.main()
        self.assertIn('Press Enter to return to menu',labels)
    def test_noninteractive_update_command_does_not_pause(self):
        with patch.object(menu.os,'geteuid',return_value=1001),patch.object(menu.pwd,'getpwuid',return_value=SimpleNamespace(pw_name='dvlab-hub')),patch.object(menu.sys,'argv',['dv-lab','update','status']),patch.object(menu,'broker',return_value={'state':'idle'}),patch.object(menu,'wait_return') as wait,contextlib.redirect_stdout(io.StringIO()):menu.main()
        wait.assert_not_called()
    def test_root_launcher_drops_identity_before_exec_and_clears_env(self):
        events=[];who=SimpleNamespace(pw_uid=1001,pw_gid=1001,pw_dir='/home/dvlab-hub');uid=0
        def setuid(value):
            nonlocal uid
            uid=value;events.append('uid')
        with patch.object(console_launcher.os,'geteuid',side_effect=lambda:uid),patch.object(console_launcher.os,'getuid',side_effect=lambda:uid),patch.object(console_launcher.Path,'is_file',return_value=True),patch.object(console_launcher.pwd,'getpwnam',return_value=who),patch.object(console_launcher.os,'chdir',side_effect=lambda x:events.append('cwd')),patch.object(console_launcher.os,'initgroups',side_effect=lambda *x:events.append('groups')),patch.object(console_launcher.os,'setgid',side_effect=lambda x:events.append('gid')),patch.object(console_launcher.os,'setuid',side_effect=setuid),patch.object(console_launcher.os,'execve',side_effect=lambda *x:events.append(('exec',x))) as execute,patch.dict(os.environ,{'PYTHONPATH':'/tmp/evil','LD_PRELOAD':'evil'}):
            console_launcher.launch(['update','status'])
        self.assertEqual(events[:4],['cwd','groups','gid','uid'])
        self.assertEqual(events[4][0],'exec');args=execute.call_args.args
        self.assertEqual(args[0],'/usr/bin/python3');self.assertNotIn('PYTHONPATH',args[2]);self.assertNotIn('LD_PRELOAD',args[2])
        self.assertEqual(args[1],['/usr/bin/python3','-m','dvlab.menu','update','status'])
    def test_mutable_menu_refuses_root_execution(self):
        with patch.object(menu.os,'geteuid',return_value=0),self.assertRaisesRegex(SystemExit,'privilege-dropping'):menu.main()
    def test_legacy_console_migration_requires_exact_installed_release(self):
        from dvlab import setup
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source';source.mkdir();(source/'.source-commit').write_text('a'*40)
            application=root/'app';(application/'current').mkdir(parents=True);marker=application/'current/.source-commit';marker.write_text('b'*40)
            etc=root/'etc';etc.mkdir();(etc/'hub.json').write_text('{}')
            with patch.object(setup,'SOURCE',source),patch.object(setup,'ROOT',application),patch.object(setup,'ETC',etc),patch.object(setup.os,'geteuid',return_value=0),patch.object(setup,'console_launcher') as migrate,contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(SystemExit,'exact release'):setup.migrate_console()
                migrate.assert_not_called();marker.write_text('a'*40);setup.migrate_console();migrate.assert_called_once_with(migration=True)
