import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE/'wdtt_tailscale'))
import controller as c
from patch_upstream import patch as upstream_patch

class HardeningTests(unittest.TestCase):
    def test_boolean_string_cannot_enable_route(self):
        for value in ('true', 'false', 0, 1, None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'must be boolean'):
                c.Opts.from_raw({'connection_mode': 'off', 'route_tailscale': value})

    def test_block_ipv6_mandatory_when_route_enabled(self):
        with self.assertRaisesRegex(ValueError, 'route_ipv6_block'):
            c.Opts.from_raw({'connection_mode': 'off', 'route_tailscale': True, 'route_ipv6_block': False})

    def test_numeric_input_cannot_be_string_or_bool(self):
        for val in ('9', True, 9.5):
            with self.subTest(value=val), self.assertRaisesRegex(ValueError, 'must be an integer'):
                c.Opts.from_raw({'connection_mode': 'off', 'workers': val})

    def test_log_redaction(self):
        with patch.object(c, 'SECRET_VALUES', {'s3cret', 'HASH789'}):
            with patch.object(c, 'print') as printer:
                c.note('Error s3cret and HASH789')
                output = printer.call_args.args[0]
                self.assertNotIn('s3cret', output)
                self.assertNotIn('HASH789', output)
                self.assertIn('[REDACTED]', output)

    def test_reject_unowned_interface_cleanup(self):
        with patch.object(c, 'existing_link', return_value=True), patch.object(c, 'owned_wireguard_link', return_value=False), patch.object(c, 'cmd') as run:
            self.assertFalse(c.remove_owned_link())
            run.assert_not_called()

    def test_owned_stale_interface_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            marker=Path(folder)/'marker.json'
            marker.write_text(json.dumps({'iface':'wg-wdtt','kind':'wireguard'}))
            with patch.object(c, 'OWNED_LINK', marker), patch.object(c, 'existing_link', return_value=True), patch.object(c, 'cmd') as run:
                run.return_value.returncode=0
                run.return_value.stdout='wg-wdtt: <POINTOPOINT> wireguard'
                self.assertTrue(c.remove_owned_link())
                self.assertFalse(marker.exists())
                self.assertTrue(any('del' in args for args in [call.args for call in run.call_args_list]))

    def test_upstream_patch_matches_exact_two_sections(self):
        fixture = ("\tvar routes []string\n\tgw, uplinkDev := gatewayForUplink(uplinkIface)\n"
                   "\tfor _, ip := range turnIPs {\n\t\t_ = ip\n\t}\n"
                   "\t// full — routing\n\tif mode == ModeFull {\n\t}\n"
                   "\tvar routes []string\n\tgw, uplinkDev := gatewayForUplink(uplinkIface)\n"
                   "\tfor _, ip := range turnIPs {\n\t\t_ = ip\n\t}\n"
                   "\tif mode == ModeFull {\n\t}\n")
        with tempfile.TemporaryDirectory() as folder:
            f=Path(folder)/'openwrt.go';f.write_text(fixture)
            upstream_patch(f)
            text=f.read_text()
            self.assertEqual(text.count('if mode != ModeExternal {'), 2)

    def test_upstream_patch_fails_closed_if_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            f=Path(folder)/'openwrt.go';f.write_text('package wg\n')
            with self.assertRaises(SystemExit):
                upstream_patch(f)

    def test_lan_bypass_and_default_marked_in_separate_table(self):
        calls=[]
        def fake_cmd(*args, **kwargs):
            calls.append(args)
            from subprocess import CompletedProcess
            if 'get' in args:
                return CompletedProcess(args,0,'1.1.1.1 dev wg-wdtt table 7477','')
            return CompletedProcess(args,0,'','')
        with patch.object(c,'cmd',side_effect=fake_cmd), patch.object(c,'existing_link',return_value=True), patch.object(c.Routes,'conflict',return_value=None):
            routes=c.Routes(True);routes.enable();routes.disable()
        self.assertTrue(any('throw' in args and '192.168.0.0/16' in args for args in calls))
        self.assertTrue(any('default' in args and '7477' in args for args in calls))
        self.assertFalse(any('route' in args and ('replace' in args) for args in calls))
        for args in calls:
            if 'route' in args and ('add' in args or 'del' in args):
                self.assertIn('table',args)

if __name__=='__main__': unittest.main()
