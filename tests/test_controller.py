import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1] / 'wdtt_tailscale' / 'controller.py'
spec = importlib.util.spec_from_file_location('wdtt_controller', APP)
import sys
sys.path.insert(0, str(APP.parent))
c = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = c
spec.loader.exec_module(c)


class ValidationTests(unittest.TestCase):
    def test_hash_normalization(self):
        self.assertEqual(c.hashes_clean('https://vk.com/call/join/abc_1, def2'), 'abc_1,def2')
        with self.assertRaises(ValueError):
            c.hashes_clean('')

    def test_uci_injection_rejected(self):
        with self.assertRaises(ValueError):
            c.uci_quote('bad\noption evil 1')
        with self.assertRaises(ValueError):
            c.uci_quote("bad' value")

    def test_off_mode_valid_with_blank_secrets(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / 'options.json'
            p.write_text(json.dumps({'connection_mode':'off'}))
            self.assertEqual(c.Opts.load(p).mode, 'off')

    def test_always_requires_credentials(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / 'options.json'
            p.write_text(json.dumps({'connection_mode':'always', 'peer':'192.0.2.1:56000'}))
            with self.assertRaises(ValueError):
                c.Opts.load(p)

    def test_generates_external_only_and_private_file(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / 'options.json'
            p.write_text(json.dumps({'connection_mode':'always', 'peer':'192.0.2.1:56000',
                                     'password':'secret', 'vk_hashes':'HASH123', 'device_id':'ha-123'}))
            opts = c.Opts.load(p)
            with patch.object(c, 'UCI_PATH', Path(t)/'wdtt'):
                c.write_uci(opts)
                s = (Path(t)/'wdtt').read_text()
                self.assertIn("option routing_mode 'external'", s)
                self.assertNotIn("option routing_mode 'full'", s)
                self.assertEqual((Path(t)/'wdtt').stat().st_mode & 0o777, 0o600)

    def test_never_claim_used_routing_priority(self):
        with patch.object(c, 'own_rule_present', return_value=True), patch.object(c, 'table_routes', return_value=''):
            self.assertIsNotNone(c.Routes(True).conflict())

    def test_no_enable_without_tailscale0(self):
        with patch.object(c, 'existing_link', side_effect=lambda name: name == 'wg-wdtt'):
            with self.assertRaisesRegex(RuntimeError, 'tailscale0'):
                c.Routes(True).enable()

    def test_stale_removal_only_for_exact_rule(self):
        with patch.object(c, 'own_rule_present', side_effect=[True, False]), \
             patch.object(c, 'table_routes', side_effect=['default dev wg-wdtt', '']), \
             patch.object(c, 'matching_owned_rule', return_value=False), \
             patch.object(c.Routes, 'disable') as disable:
            c.recover_stale_rules(True)
            disable.assert_not_called()


if __name__ == '__main__':
    unittest.main()
