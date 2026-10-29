import copy
import json
import tempfile
import types
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

from tests.test_panel_performance import load_backend


class CdnTrustTest(unittest.TestCase):
    def setUp(self):
        self.public = types.SimpleNamespace(returnMsg=lambda status, msg: dict(status=status, msg=msg))
        self.backend = load_backend(self.public)
        self.sites = {'example.invalid': {'cdn': True, 'cdn_header': ['x-forwarded-for'],
                                        'cdn_trusted_proxy': []},
                      'other.invalid': {'cdn': True}}
        self.backend.get_site_config = lambda get: copy.deepcopy(self.sites)
        self.backend._free_waf_main__endpoint_transaction = lambda **kw: nullcontext()
        self.backend._free_waf_main__update_request_is_post = Mock(return_value=True)
        self.backend._free_waf_main__write_log = Mock()
        self.write = self.backend._free_waf_main__write_site_config = Mock(return_value=True)

    def args(self, **kw):
        return types.SimpleNamespace(siteName='example.invalid', **kw)

    def test_legacy_read_is_honest_and_has_no_write(self):
        result = self.backend.get_site_cdn_trust_mode(self.args())
        self.assertEqual(result['mode'], 'legacy')
        self.assertEqual(result['trusted_proxy_count'], 0)
        self.assertIn('信任', result['notice'])
        self.write.assert_not_called()

    def test_existing_site_projection_does_not_add_strict_mode(self):
        self.public.M = lambda table: types.SimpleNamespace(field=lambda fields: types.SimpleNamespace(
            select=lambda: [dict(name=name) for name in self.sites]))
        self.backend.get_config = lambda get: {'logs_path': '/nonexistent-fixture'}
        projected = self.backend._free_waf_main__check_site(self.sites)
        self.assertTrue(all('cdn_trust_mode' not in conf for conf in projected.values()))
        self.write.assert_not_called()

    def test_strict_migration_needs_confirmation(self):
        result = self.backend.set_site_cdn_trust_mode(self.args(mode='strict'))
        self.assertFalse(result['status'])
        self.write.assert_not_called()

    def test_migration_rejects_get_even_with_confirmation(self):
        self.backend._free_waf_main__update_request_is_post.return_value = False
        result = self.backend.set_site_cdn_trust_mode(self.args(mode='strict', confirmation='CONFIRM_STRICT_CDN'))
        self.assertFalse(result['status'])
        self.write.assert_not_called()

    def test_confirmed_migration_changes_only_selected_mode(self):
        result = self.backend.set_site_cdn_trust_mode(self.args(mode='strict', confirmation='CONFIRM_STRICT_CDN'))
        self.assertTrue(result['status'])
        expected = copy.deepcopy(self.sites)
        expected['example.invalid']['cdn_trust_mode'] = 'strict'
        self.write.assert_called_once_with(expected)

    def test_save_failure_is_not_reported_as_success(self):
        for failure in (False, OSError('internal path')):
            with self.subTest(failure=type(failure).__name__):
                self.write.side_effect = failure if isinstance(failure, Exception) else None
                self.write.return_value = False
                result = self.backend.set_site_cdn_trust_mode(self.args(mode='strict', confirmation='CONFIRM_STRICT_CDN'))
                self.assertFalse(result['status'])
                self.assertNotIn('internal path', result['msg'])

    def test_unknown_site_and_mode_do_not_write(self):
        for args in (types.SimpleNamespace(siteName='missing.invalid', mode='strict', confirmation='CONFIRM_STRICT_CDN'),
                     self.args(mode='legacy', confirmation='CONFIRM_STRICT_CDN')):
            self.assertFalse(self.backend.set_site_cdn_trust_mode(args)['status'])
        self.write.assert_not_called()

    def test_bad_proxy_ranges_do_not_migrate(self):
        for value in (None, 'all', [[[-1, 0, 0, 0], [255, 255, 255, 255]]],
                      [[[192, 0, 2, 9], [192, 0, 2, 1]]]):
            self.sites['example.invalid']['cdn_trusted_proxy'] = value
            self.assertFalse(self.backend.set_site_cdn_trust_mode(self.args(mode='strict', confirmation='CONFIRM_STRICT_CDN'))['status'])
        self.write.assert_not_called()

    def test_newly_enabled_cdn_uses_strict_without_affecting_other_sites(self):
        self.sites['example.invalid']['cdn'] = False
        self.assertTrue(self.backend.set_site_cdn_state(self.args())['status'])
        saved = self.write.call_args[0][0]
        self.assertEqual(saved['example.invalid']['cdn_trust_mode'], 'strict')
        self.assertNotIn('cdn_trust_mode', saved['other.invalid'])

    def test_generic_site_toggle_used_by_ui_also_enables_strict_mode(self):
        self.sites['example.invalid']['cdn'] = False
        self.assertTrue(self.backend.set_site_obj_open(self.args(obj='cdn'))['status'])
        self.assertEqual(self.write.call_args[0][0]['example.invalid'].get('cdn_trust_mode'), 'strict')

    def test_enabling_cdn_rejects_malformed_proxy_ranges(self):
        self.sites['example.invalid'].update(cdn=False, cdn_trusted_proxy=[[[256, 0, 0, 1], [256, 0, 0, 2]]])
        self.assertFalse(self.backend.set_site_cdn_state(self.args())['status'])
        self.write.assert_not_called()


class SampleAndCacheTest(unittest.TestCase):
    def test_unavailable_runtime_does_not_turn_cached_bans_into_unbanned(self):
        public = types.SimpleNamespace(httpGet=Mock(side_effect=OSError('private error')))
        backend = load_backend(public)
        backend._security_reports = types.SimpleNamespace(get=lambda *a, **kw: {
            'cached': True, 'summary': {'active_bans': 1},
            'blocked_ips': [dict(ip='192.0.2.1', active=True, count_24h=1)]})
        result = backend.get_overview_report(types.SimpleNamespace())
        self.assertFalse(result['status'])
        self.assertNotIn('private error', json.dumps(result))
        self.assertNotIn('active_bans', result)

    def test_notification_limit_marks_truncated_drop_records_partial(self):
        import time
        backend = load_backend(types.SimpleNamespace())
        backend._free_waf_main__bounded_waf_files = lambda *args: iter(())
        backend._free_waf_main__bounded_log_rows = lambda *args: iter(
            (i, json.dumps([int(time.time()), '192.0.2.1', 'example.invalid', '/', '', 'cc']))
            for i in range(11))
        with patch('os.path.exists', return_value=True):
            result = backend.get_defense_notifications(types.SimpleNamespace(limit=10))
        self.assertEqual(len(result['items']), 10)
        self.assertTrue(result['coverage']['partial'])

    def test_capability_audit_handles_invalid_config_as_unknown_not_ready(self):
        backend = load_backend(types.SimpleNamespace(readFile=lambda path: 'null'))
        backend._free_waf_main__get_rule = lambda name: []
        result = backend.get_official_feature_audit(None)
        self.assertFalse(result['status'])
        self.assertFalse(result['runtime_verified'])
        self.assertEqual(result['scope'], 'configuration_structure_only')
        self.assertFalse(next(row for row in result['items'] if row['key'] == 'false_positive_safety')['status'])

    def test_security_scan_contention_returns_busy_without_waiting(self):
        import threading
        from report_store import SecurityReports
        with tempfile.TemporaryDirectory() as root:
            store = SecurityReports(root)
            entered, release = threading.Event(), threading.Event()
            def slow():
                entered.set()
                release.wait(2)
                return {'summary': {}}
            worker = threading.Thread(target=lambda: store.get('first', slow))
            worker.start()
            try:
                self.assertTrue(entered.wait(1))
                import time
                start = time.monotonic()
                result = store.get('second', lambda: self.fail('concurrent log scan'))
                self.assertLess(time.monotonic() - start, 0.5)
                self.assertFalse(result['status'])
                self.assertEqual(result['code'], 'report_busy')
            finally:
                release.set()
                worker.join(3)
                store.close()

    def test_cached_overview_refreshes_active_bans_without_reading_history(self):
        backend = load_backend(types.SimpleNamespace())
        backend._security_reports = types.SimpleNamespace(get=lambda *a, **kw: {
            'cached': True, 'summary': {'active_bans': 9}, 'active_bans': 9,
            'blocked_ips': [dict(ip='192.0.2.1', active=True, count_24h=2)]})
        backend._free_waf_main__runtime_ip_snapshot = lambda: ({'192.0.2.2'}, {'192.0.2.2'})
        result = backend.get_overview_report(types.SimpleNamespace())
        self.assertEqual(result['active_bans'], 1)
        by_ip = {row['ip']: row for row in result['blocked_ips']}
        self.assertFalse(by_ip['192.0.2.1']['active'])
        self.assertTrue(by_ip['192.0.2.2']['active'])

    def test_cached_overview_rejoins_full_history_before_truncation(self):
        backend = load_backend(types.SimpleNamespace())
        history = [dict(ip='192.0.2.%d' % index, active=False, count_24h=12-index,
                        total_count=12-index, reason='404_flood') for index in range(1, 12)]
        backend._security_reports = types.SimpleNamespace(get=lambda *a, **kw: {
            'cached': True, 'summary': {}, '_blocked_history': copy.deepcopy(history),
            'blocked_ips': copy.deepcopy(history[:10])})
        backend._free_waf_main__runtime_ip_snapshot = lambda: ({'192.0.2.11'}, {'192.0.2.11'})
        result = backend.get_overview_report(types.SimpleNamespace())
        self.assertEqual(result['blocked_ips'][0]['ip'], '192.0.2.11')
        self.assertEqual(result['blocked_ips'][0]['total_count'], 1)
        self.assertNotIn('_blocked_history', result)

    def test_expired_runtime_only_rows_are_not_retained_in_cached_history(self):
        backend = load_backend(types.SimpleNamespace())
        backend._security_reports = types.SimpleNamespace(get=lambda *a, **kw: {
            'cached': True, 'summary': {}, '_blocked_history': [],
            'blocked_ips': [dict(ip='192.0.2.1', active=True, total_count=0, count_24h=0, reason='运行中')]})
        backend._free_waf_main__runtime_ip_snapshot = lambda: (set(), set())
        self.assertEqual(backend.get_overview_report(types.SimpleNamespace())['blocked_ips'], [])

    def test_dashboard_live_count_is_identical_cold_cached_and_forced(self):
        from report_store import SecurityReports
        backend = load_backend(types.SimpleNamespace())
        backend.get_waf_drop_ip = lambda get: ['2001:db8::1', '2001:0db8::1', 'not-an-ip']
        with tempfile.TemporaryDirectory() as root:
            store = SecurityReports(root)
            self.addCleanup(store.close)
            backend._security_reports = store
            with patch('os.path.exists', return_value=False):
                for force in (0, 0, 1):
                    result = backend.get_report_dashboard_summary(types.SimpleNamespace(force=force))
                    self.assertEqual(result['summary']['active_bans'], 1)

    def test_sample_check_does_not_claim_runtime_decision(self):
        backend = load_backend(types.SimpleNamespace())
        backend._free_waf_main__get_rule = lambda name: []
        result = backend.simulate_attack(types.SimpleNamespace(uri='/.env'))
        self.assertEqual(result['engine'], 'python-re-sample')
        self.assertFalse(result['runtime_evaluated'])
        self.assertIn('样本', result['decision_text'])
        self.assertTrue(any('Lua' in text for text in result['notes']))

    def test_security_snapshot_reuses_data_but_not_callers_mutations(self):
        from report_store import SecurityReports
        with tempfile.TemporaryDirectory() as root:
            store = SecurityReports(root, ttl=30)
            self.addCleanup(store.close)
            build = Mock(return_value={'summary': {'hits': 7}})
            first = store.get('scope-a', build)
            self.assertFalse(first['cached'])
            first['summary']['hits'] = 900
            second = store.get('scope-a', build)
            self.assertTrue(second['cached'])
            self.assertEqual(second['summary']['hits'], 7)
            self.assertEqual(build.call_count, 1)
            store.get('scope-a', build, force=True)
            store.get('scope-b', build)
            self.assertEqual(build.call_count, 3)

    def test_expired_and_failed_reports_are_not_silently_served_fresh(self):
        from report_store import SecurityReports
        with tempfile.TemporaryDirectory() as root:
            store = SecurityReports(root, ttl=30)
            self.addCleanup(store.close)
            build = Mock(return_value={'summary': {'hits': 7}})
            with patch('report_store.time.time', return_value=100):
                store.get('scope', build)
            with patch('report_store.time.time', return_value=131):
                store.get('scope', build)
            self.assertEqual(build.call_count, 2)
            failure = store.get('bad', lambda: dict(status=False, msg='unavailable'))
            self.assertFalse(failure['status'])
            self.assertFalse(store._path('bad').exists())


if __name__ == '__main__':
    unittest.main()
