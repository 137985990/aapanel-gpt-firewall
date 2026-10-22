import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from ban_store import BanStore
from tests.test_panel_performance import load_backend


class UnbanResultsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'ip_black.json'
        self.ip = '192.0.2.10'
        self.exact = [[192, 0, 2, 10], [192, 0, 2, 10], 9999999999]
        self.range = [[198, 51, 100, 0], [198, 51, 100, 255]]
        self.path.write_text(json.dumps([self.exact, self.range]))
        self.store = BanStore(self.path)
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            httpGet=Mock(side_effect=[json.dumps({'status': True}), '[]']),
            serviceReload=Mock(return_value=False),
        )
        self.backend = load_backend(self.public)
        self.backend._free_waf_main__ban_store = lambda: self.store
        self.backend._free_waf_main__write_log = Mock()
        self.backend._free_waf_main__reload_panel_nginx = Mock()

    def call(self, name='remove_waf_drop_ip', ip=None):
        return getattr(self.backend, name)(types.SimpleNamespace(ip=self.ip if ip is None else ip))

    def test_runtime_reject_does_not_report_success(self):
        self.public.httpGet.side_effect = [json.dumps({'status': False}), '[]']
        self.assertFalse(self.call()['status'])

    def test_persistent_write_failure_does_not_report_success(self):
        with patch.object(self.store, 'save_rules', side_effect=OSError('disk full')):
            self.assertFalse(self.call()['status'])

    def test_reload_failure_does_not_report_success(self):
        self.backend._free_waf_main__reload_panel_nginx.side_effect = RuntimeError('reload failed')
        self.assertFalse(self.call()['status'])

    def test_runtime_still_banned_does_not_report_success(self):
        self.public.httpGet.side_effect = [json.dumps({'status': True}), json.dumps([self.ip])]
        self.assertFalse(self.call()['status'])

    def test_legacy_button_uses_same_verified_unban_flow(self):
        self.public.httpGet.side_effect = OSError('runtime unavailable')
        self.assertFalse(self.call('remove_permanent_ban')['status'])

    def test_legacy_button_can_remove_runtime_only_registration_ban(self):
        self.path.write_text(json.dumps([self.range]))
        self.assertTrue(self.call('remove_permanent_ban')['status'])
        self.assertEqual(self.store.load_rules(), [self.range])

    def test_success_removes_exact_rule_preserves_range_and_verifies_runtime(self):
        self.assertTrue(self.call()['status'])
        self.assertEqual(self.store.load_rules(), [self.range])
        self.backend._free_waf_main__reload_panel_nginx.assert_called_once_with()
        self.public.serviceReload.assert_not_called()
        self.assertEqual(self.public.httpGet.call_count, 2)

    def test_invalid_ip_does_not_access_storage_or_runtime(self):
        for ip in ('192.0.2.10&scope=all', '192.0.2.999', '192.0.2.10.4', ''):
            with self.subTest(ip=ip):
                self.assertFalse(self.call(ip=ip)['status'])
        self.assertEqual(self.store.load_rules(), [self.exact, self.range])
        self.public.httpGet.assert_not_called()

    def test_repeat_unban_is_idempotent(self):
        self.public.httpGet.side_effect = [json.dumps({'status': True}), '[]'] * 2
        self.assertTrue(self.call()['status'])
        self.assertTrue(self.call()['status'])
        self.assertEqual(self.backend._free_waf_main__reload_panel_nginx.call_count, 2)

    def test_retry_after_partial_reload_failure_attempts_reload_again(self):
        self.backend._free_waf_main__reload_panel_nginx.side_effect = [RuntimeError('failed'), None]
        self.assertFalse(self.call()['status'])
        self.assertEqual(self.store.load_rules(), [self.range])
        self.assertTrue(self.call()['status'])
        self.assertEqual(self.backend._free_waf_main__reload_panel_nginx.call_count, 2)

    def test_clean_runtime_rejection_does_not_report_success(self):
        self.public.httpGet.side_effect = [json.dumps({'status': False}), '[]']
        self.assertFalse(self.backend.clean_waf_drop_ip(None)['status'])

    def test_clean_reload_failure_does_not_report_success(self):
        self.backend._free_waf_main__reload_panel_nginx.side_effect = RuntimeError('reload failed')
        self.assertFalse(self.backend.clean_waf_drop_ip(None)['status'])

    def test_clean_retry_after_partial_save_reloads_even_when_no_exact_rule_remains(self):
        self.backend._free_waf_main__reload_panel_nginx.side_effect = [RuntimeError('failed'), None]
        self.assertFalse(self.backend.clean_waf_drop_ip(None)['status'])
        self.assertEqual(self.store.load_rules(), [self.range])
        self.assertTrue(self.backend.clean_waf_drop_ip(None)['status'])
        self.assertEqual(self.backend._free_waf_main__reload_panel_nginx.call_count, 2)

    def test_panel_reload_uses_checked_panel_binary(self):
        del self.backend._free_waf_main__reload_panel_nginx
        with patch('subprocess.run', return_value=types.SimpleNamespace(returncode=0)) as run:
            self.backend._free_waf_main__reload_panel_nginx()
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['/www/server/nginx/sbin/nginx', '-t'],
            ['/www/server/nginx/sbin/nginx', '-s', 'reload'],
        ])

    def test_failed_nginx_test_does_not_send_reload_signal(self):
        del self.backend._free_waf_main__reload_panel_nginx
        with patch('subprocess.run', return_value=types.SimpleNamespace(returncode=1)) as run:
            self.assertFalse(self.call()['status'])
        self.assertEqual(run.call_count, 1)
        self.public.httpGet.assert_not_called()

    def test_ipv6_unban_does_not_touch_ipv4_persistent_rules(self):
        self.assertTrue(self.call(ip='2001:db8::1')['status'])
        self.assertEqual(self.store.load_rules(), [self.exact, self.range])
        self.assertTrue(self.public.httpGet.call_args_list[0].args[0].endswith('ip=2001%3Adb8%3A%3A1'))
        self.backend._free_waf_main__reload_panel_nginx.assert_not_called()

    def test_ipv6_mapped_tail_does_not_remove_ipv4_ban(self):
        self.assertTrue(self.call(ip='::ffff:192.0.2.10')['status'])
        self.assertEqual(self.store.load_rules(), [self.exact, self.range])

    def test_ipv6_verification_compares_address_identity(self):
        self.public.httpGet.side_effect = [json.dumps({'status': True}), json.dumps(['2001:0db8:0:0:0:0:0:1'])]
        self.assertFalse(self.call(ip='2001:db8::1')['status'])

    def test_ipv6_zone_is_not_a_valid_client_address_for_unban(self):
        self.assertFalse(self.call(ip='fe80::1%eth0')['status'])
        self.public.httpGet.assert_not_called()


if __name__ == '__main__':
    unittest.main()
