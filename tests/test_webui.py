import json
import sys
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'wdtt_tailscale'))
import controller as c
import webui as ui

class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        opts = Path(self.tmp.name)/'options.json'
        opts.write_text(json.dumps({'connection_mode': 'off', 'peer':'192.0.2.1:2222',
                                    'password':'never-expose', 'vk_hashes':'abc321',
                                    'device_id':'test-haos', 'obfs_mode':'video', 'go_dns':'doh-cloudflare'}))
        self.override=patch.object(c,'OPTIONS_PATH',opts)
        self.override.start();self.addCleanup(self.override.stop)
        self.over2=patch.object(ui,'SETTINGS_PATH',Path(self.tmp.name)/'override.json')
        self.over2.start();self.addCleanup(self.over2.stop)
        self.over3=patch.object(c,'SETTINGS_PATH',Path(self.tmp.name)/'override.json')
        self.over3.start();self.addCleanup(self.over3.stop)
        self.state = ui.PanelState(c.read_settings, [])
        self.server = ui.WebServer(('127.0.0.1',0),self.state,c.Opts.from_raw)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method,path,payload=None):
        conn=HTTPConnection('127.0.0.1',self.server.server_port,timeout=4)
        headers={'X-WDTT-UI':'1','Content-Type':'application/json'}
        conn.request(method,path,body=json.dumps(payload) if payload is not None else None,headers=headers)
        r=conn.getresponse(); output=json.loads(r.read());status=r.status;conn.close()
        return status,output

    def test_settings_exposes_hash_count_but_not_hashes(self):
        p = self.state.settings()
        self.assertNotIn('vk_hashes', p)
        self.assertNotIn('password', p)
        self.assertIn('vk_hash_count', p)

    def test_secrets_not_visible(self):
        status, data=self.request('GET','/api/settings')
        self.assertEqual(status,200)
        self.assertNotIn('password',data)
        self.assertNotIn('vk_hashes',data)
        self.assertEqual(data['obfs_mode'],'video')
        self.assertEqual(data['go_dns'],'doh-cloudflare')
        self.assertTrue(data['password_configured'])
        self.assertTrue(data['vk_hashes_configured'])

    def test_diagnostics_does_not_execute_freeform(self):
        with patch.object(ui.subprocess,'run') as run:
            code,data=self.request('POST','/api/diagnostics',{'command':'rm -rf /'})
            self.assertEqual(code,400)
            run.assert_not_called()

    def test_diagnostics_uses_allowlisted_argv(self):
        from subprocess import CompletedProcess
        with patch.object(ui.subprocess,'run',return_value=CompletedProcess([],0,'ok','')) as run:
            code,data=self.request('POST','/api/diagnostics',{'command':'rules'})
            self.assertEqual(code,200)
            self.assertEqual(data['output'],'ok')
            self.assertFalse(run.call_args.kwargs['shell'])

    def test_settings_writes_video_and_cloudflare(self):
        status,_=self.request('POST','/api/settings',{'obfs_mode':'audio','go_dns':'doh-yandex'})
        self.assertEqual(status,200)
        status,data=self.request('GET','/api/settings')
        self.assertEqual(data['obfs_mode'],'audio')
        self.assertEqual(data['go_dns'],'doh-yandex')
        self.assertEqual(data['peer'],'192.0.2.1:2222')

    def test_invalid_method_rejected(self):
        status,data=self.request('POST','/api/settings',{'obfs_mode':'not-a-method'})
        self.assertEqual(status,400)

if __name__=='__main__':unittest.main()
