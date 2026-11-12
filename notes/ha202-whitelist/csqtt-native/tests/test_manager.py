import importlib.util
import json
import tempfile
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('csqtt_app', Path(__file__).parents[1] / 'manager.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class Tests(TestCase):
    def test_invalid_link_never_stored(self):
        for text in ('https://example.org', 'csqtt://bad\nSECRET', 'csqtt://has whitespace', 'x' * 9000):
            with self.assertRaises(app.AppError):
                app.parse_link(text)

    def test_link_parse_no_args_with_secrets(self):
        class Fake:
            returncode = 0
            stdout = json.dumps({'line':'2.5','host':'example.org','port':443,'hashes':[]})
        with patch.object(app.subprocess, 'run', return_value=Fake()) as runner:
            out = app.parse_link('csqtt://example')
            self.assertEqual(json.loads(out)['line'], '2.5')
            self.assertEqual(runner.call_args.kwargs['input'], 'csqtt://example')
            self.assertEqual(runner.call_args.args[0], ['python3','-I','/opt/csq-socks/link.py','parse'])

    def test_config_private_atomic_backup(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(app, 'STORE', Path(d)), patch.object(app, 'CONFIG', Path(d)/'conn.json'), patch.object(app, 'BACKUP', Path(d)/'previous.json'):
                app.atomic_secret(app.CONFIG, b'{"name":"old"}')
                with patch.object(app, 'parse_link', return_value=b'{"name":"new"}'):
                    app.save_link('csqtt://new')
                self.assertEqual(app.CONFIG.read_bytes(), b'{"name":"new"}')
                self.assertEqual(app.BACKUP.read_bytes(), b'{"name":"old"}')
                self.assertEqual(app.CONFIG.stat().st_mode & 0o777, 0o600)
                with patch.object(app, 'mode', return_value='off'):
                    app.rollback()
                self.assertEqual(app.CONFIG.read_bytes(), b'{"name":"old"}')
                self.assertFalse(app.BACKUP.exists())

    def test_no_tun_modes_callable(self):
        with patch.object(app, 'mode', return_value='tun'):
            with self.assertRaises(app.AppError):
                app.stop_socks()
            with self.assertRaises(app.AppError):
                app.start_socks()


class SecurityTests(TestCase):
    def test_supervisor_token_not_forwarded_to_client(self):
        class Fake:
            returncode = 0
        with patch.dict(app.os.environ, {'SUPERVISOR_TOKEN': 'top_secret_test_value'}):
            with patch.object(app.subprocess, 'run', return_value=Fake()) as mocked:
                app.run_cli('down', timeout=1)
                self.assertNotIn('SUPERVISOR_TOKEN', mocked.call_args.kwargs['env'])

    def test_cannot_run_full_tunnel(self):
        with self.assertRaises(app.AppError):
            app.run_cli('tun')


if __name__ == '__main__':
    main()
