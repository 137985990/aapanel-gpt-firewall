import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

from tests.test_panel_performance import load_backend


ROOT = Path(__file__).resolve().parents[1]


class RiskAdviceBackendTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'rule').mkdir()
        self.logs = self.root / 'logs'
        self.logs.mkdir()
        self.global_config = dict(open=True)
        self.sites = {'fixture.example': dict(open=True, cdn=False),
                      'other.example': dict(open=True, cdn=False)}
        self.write_config()
        (self.root / 'rule/ip_white.json').write_text('[]')
        self.protected = {'repeat_bans.json': b'not an automatic snapshot',
                          'rule/ip_black.json': b'[]', 'drop_ip.log': b'original history'}
        for name, body in self.protected.items():
            (self.root / name).write_bytes(body)
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            readFile=Mock(side_effect=AssertionError('legacy migration/read')),
            writeFile=Mock(side_effect=AssertionError('unsafe writer')),
            httpGet=Mock(side_effect=AssertionError('unexpected network')),
            serviceReload=Mock(side_effect=AssertionError('unchecked reload')))
        self.backend = load_backend(self.public)
        self.backend._free_waf_main__path = str(self.root) + os.sep
        self.backend._free_waf_main__PATH = str(ROOT) + os.sep
        self.backend._free_waf_main__risk_log_root = lambda: str(self.logs)
        self.backend._free_waf_main__update_request_is_post = Mock(return_value=True)
        self.backend._free_waf_main__checked_nginx_reload = Mock()
        self.backend._free_waf_main__risk_runtime_matches = Mock(return_value=True)

    def write_config(self):
        (self.root / 'config.json').write_text(json.dumps(self.global_config))
        (self.root / 'site.json').write_text(json.dumps(self.sites))

    def call(self, method, **args):
        function = getattr(self.backend, method, None)
        self.assertTrue(callable(function), method + ' API missing')
        return function(types.SimpleNamespace(**args))

    def log(self, paths=None, site='fixture.example', ip='192.0.2.17'):
        now = int(time.time())
        if paths is None:
            paths = ['/app{}/.env.production'.format(i) for i in range(30)]
            paths += ['/app{}/.git/config'.format(i) for i in range(30)]
        rows = [[time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now - len(paths) * 2 + i)),
                 ip, 'GET', path, '', 'user_agent', 'fixture'] for i, path in enumerate(paths * 2)]
        filename = site + '_' + time.strftime('%Y-%m-%d', time.localtime(now)) + '.log'
        (self.logs / filename).write_text('\n'.join(json.dumps(row) for row in rows), encoding='utf-8')
        return rows

    def advice(self):
        result = self.call('get_risk_advice', siteName='fixture.example')
        self.assertIs(result['status'], True, result)
        return result

    def apply(self, advice=None, **kwargs):
        advice = advice or self.advice()
        row = advice['items'][0]
        params = dict(siteName='fixture.example', ip=row['ip'], fingerprint=row['fingerprint'],
                      config_revision=advice['config_revision'], duration='86400')
        params.update(kwargs)
        return self.call('apply_risk_advice', **params)

    def assert_protected(self):
        for name, body in self.protected.items():
            self.assertEqual((self.root / name).read_bytes(), body)
        self.public.readFile.assert_not_called()
        self.public.writeFile.assert_not_called()
        self.public.httpGet.assert_not_called()
        self.public.serviceReload.assert_not_called()

    def test_missing_feature_contract_is_detected(self):
        for method in ('get_risk_advice_sites', 'get_risk_advice', 'apply_risk_advice',
                       'get_risk_site_bans', 'remove_risk_site_ban'):
            self.assertTrue(callable(getattr(self.backend, method, None)), method + ' API missing')

    def test_reads_only_selected_site_and_does_not_initialize_storage(self):
        self.log()
        self.log(site='other.example')
        before = {str(path.relative_to(self.root)): path.read_bytes()
                  for path in self.root.rglob('*') if path.is_file()}
        result = self.advice()
        self.assertEqual(len(result['items']), 1)
        self.assertEqual(result['items'][0]['recommended_seconds'], 86400)
        self.assertIs(result['items'][0]['actionable'], True)
        self.assertEqual(result['coverage']['scanned_files'], 1)
        self.assertEqual(result['coverage']['invalid_lines'], 0)
        self.assertEqual(before, {str(path.relative_to(self.root)): path.read_bytes()
                                 for path in self.root.rglob('*') if path.is_file()})
        self.assert_protected()

    def test_normal_api_and_empty_ua_are_observation_only(self):
        self.log(['/v1/chat/completions'] * 1000)
        result = self.advice()
        self.assertFalse(any(row['actionable'] for row in result['items']))
        self.assertFalse(any(row['recommended_seconds'] for row in result['items']))
        self.assertIs(self.apply(result)['status'], False)
        self.assertFalse((self.root / 'manual_site_bans.json').exists())

    def test_apply_is_site_only_finite_and_does_not_touch_automatic_counts(self):
        self.log()
        result = self.apply()
        self.assertIs(result['status'], True, result)
        self.assertIs(result['saved'], True)
        self.assertIs(result['runtime_verified'], True)
        snapshot = json.loads((self.root / 'manual_site_bans.json').read_text())
        self.assertEqual(len(snapshot['entries']), 1)
        self.assertEqual(snapshot['entries'][0]['site'], 'fixture.example')
        self.assertEqual(snapshot['entries'][0]['duration'], 86400)
        self.backend._free_waf_main__checked_nginx_reload.assert_called_once_with()
        self.assert_protected()

    def test_stale_config_and_changed_evidence_are_rejected_without_saving(self):
        self.log()
        result = self.advice()
        self.sites['other.example']['open'] = False
        self.write_config()
        self.assertIs(self.apply(result)['status'], False)
        result = self.advice()
        self.log(['/ordinary'])
        self.assertIs(self.apply(result)['status'], False)
        self.assertFalse((self.root / 'manual_site_bans.json').exists())

    def test_safety_holds_whitelist_proxy_disabled_and_unknown_site(self):
        self.log()
        cases = [(dict(open=False), dict(open=True), []),
                 (dict(open=True), dict(open=False), []),
                 (dict(open=True), dict(open=True, cdn=True), []),
                 (dict(open=True), dict(open=True), [[[192, 0, 2, 0], [192, 0, 2, 255]]])]
        for global_config, site, white in cases:
            self.global_config = global_config
            self.sites['fixture.example'] = site
            self.write_config()
            (self.root / 'rule/ip_white.json').write_text(json.dumps(white))
            result = self.advice()
            self.assertFalse(result['items'][0]['actionable'])
            self.assertTrue(result['items'][0]['hold_reasons'])
            self.assertIs(self.apply(result)['status'], False)
        self.assertIs(self.call('get_risk_advice', siteName='missing.example')['status'], False)
        self.assertNotIn('missing.example', json.loads((self.root / 'site.json').read_text()))

    def test_post_only_duration_validation_and_explicit_ten_year_confirmation(self):
        self.log()
        advice = self.advice()
        for duration in ('0', '-1', '59', '315360001', 'nan', '1.5', '1e5', True, None):
            self.assertIs(self.apply(advice, duration=duration)['status'], False)
        self.assertIs(self.apply(advice, duration='315360000')['status'], False)
        self.backend._free_waf_main__update_request_is_post.return_value = False
        self.assertIs(self.apply(advice)['status'], False)
        self.backend._free_waf_main__update_request_is_post.return_value = True
        result = self.apply(advice, duration='315360000', confirm_long='1')
        self.assertIs(result['status'], True, result)

    def test_reload_failure_reports_saved_but_unverified_and_allows_removal(self):
        self.log()
        self.backend._free_waf_main__checked_nginx_reload.side_effect = RuntimeError('fixture')
        result = self.apply()
        self.assertIs(result['status'], False)
        self.assertIs(result['saved'], True)
        self.assertIs(result['runtime_verified'], False)
        listed = self.call('get_risk_site_bans', siteName='fixture.example')
        self.assertEqual(len(listed['entries']), 1)
        self.backend._free_waf_main__checked_nginx_reload.side_effect = None
        removed = self.call('remove_risk_site_ban', siteName='fixture.example',
                            ip='192.0.2.17', revision=listed['revision'])
        self.assertIs(removed['status'], True, removed)
        self.assertEqual(json.loads((self.root / 'manual_site_bans.json').read_text())['entries'], [])
        self.assert_protected()

    def fail_after_atomic_commit(self, operation):
        store = self.backend._free_waf_main__risk_store()
        self.backend._free_waf_main__risk_store = lambda: store
        original = store._read_bytes
        reads = []

        def read():
            reads.append(True)
            if len(reads) == 2:
                raise OSError('fixture readback failed after replace')
            return original()

        with patch.object(store, '_read_bytes', side_effect=read):
            result = operation()
        self.assertEqual(len(reads), 2)
        self.assertIs(result['status'], False)
        self.assertIn('saved', result)
        self.assertIsNone(result['saved'])
        self.assertIs(result['save_uncertain'], True)
        self.assertIs(result['runtime_verified'], False)
        self.assertNotIn('\u672a\u6267\u884c\u5c01\u7981', result['msg'])
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()
        self.assert_protected()

    def test_apply_readback_failure_does_not_claim_no_ban_was_saved(self):
        self.log()
        advice = self.advice()
        self.fail_after_atomic_commit(lambda: self.apply(advice))
        snapshot = json.loads((self.root / 'manual_site_bans.json').read_text())
        self.assertEqual(len(snapshot['entries']), 1)

    def test_remove_readback_failure_reports_uncertain_instead_of_unsaved(self):
        self.log()
        self.assertTrue(self.apply()['status'])
        listed = self.call('get_risk_site_bans', siteName='fixture.example')
        self.backend._free_waf_main__checked_nginx_reload.reset_mock()
        self.fail_after_atomic_commit(lambda: self.call('remove_risk_site_ban',
            siteName='fixture.example', ip='192.0.2.17', revision=listed['revision']))
        snapshot = json.loads((self.root / 'manual_site_bans.json').read_text())
        self.assertEqual(snapshot['entries'], [])

    def test_invalid_lines_and_budget_are_explicit(self):
        self.log()
        path = next(self.logs.glob('*.log'))
        with path.open('a') as stream:
            stream.write('\ninvalid\n["2099-01-01 00:00:00","192.0.2.1","GET","/.env","","args"]\n')
        result = self.advice()
        self.assertGreaterEqual(result['coverage']['invalid_lines'], 2)
        self.backend.LEGACY_LOG_MAX_LINES = 2
        result = self.advice()
        self.assertTrue(result['coverage']['partial'])
        self.assertLessEqual(result['coverage']['scanned_lines'], 2)

    def test_manual_list_does_not_scan_or_create_lock(self):
        before = set(self.root.iterdir())
        self.backend._free_waf_main__risk_read_rows = Mock(side_effect=AssertionError('eager scan'))
        result = self.call('get_risk_site_bans', siteName='fixture.example')
        self.assertIs(result['status'], True, result)
        self.assertEqual(result['entries'], [])
        self.assertEqual(set(self.root.iterdir()), before)
        self.assert_protected()

    def test_alias_evidence_is_canonical_and_never_cross_site(self):
        self.global_config.update(compatibility_profile='bt-free-waf-8.4',
                                  site_aliases={'alias.example': 'fixture.example'})
        self.write_config()
        self.log(site='alias.example')
        result = self.advice()
        self.assertEqual(result['items'][0]['site'], 'fixture.example')
        self.assertIs(self.apply(result)['status'], True)
        other = self.call('get_risk_site_bans', siteName='other.example')
        self.assertEqual(other['entries'], [])
        self.assert_protected()

    def test_ipv6_uses_canonical_identity_and_whitelist_changes_invalidate_confirmation(self):
        self.log(ip='2001:db8:0:0:0:0:0:17')
        advice = self.advice()
        self.assertEqual(advice['items'][0]['ip'], '2001:db8::17')
        self.assertIs(self.apply(advice)['status'], True)
        (self.root / 'rule/ip_white.json').write_text('[[[192,0,2,17],[192,0,2,17]]]')
        self.assertIs(self.apply(advice)['status'], False)
        rows = self.call('get_risk_site_bans', siteName='fixture.example')['entries']
        self.assertEqual(rows[0]['ip'], '2001:db8::17')

    def test_unknown_site_and_traversal_inputs_do_not_create_config(self):
        before = (self.root / 'site.json').read_bytes()
        for name in ('missing.example', '../config', '', 'a..b', '/tmp/f', None):
            self.assertIs(self.call('get_risk_advice', siteName=name)['status'], False)
            self.assertIs(self.call('get_risk_site_bans', siteName=name)['status'], False)
        self.assertEqual((self.root / 'site.json').read_bytes(), before)
        self.assertFalse((self.root / 'manual_site_bans.json').exists())

    def test_manual_remove_is_post_only_and_rejects_stale_snapshot(self):
        self.log()
        self.assertTrue(self.apply()['status'])
        before = (self.root / 'manual_site_bans.json').read_bytes()
        result = self.call('remove_risk_site_ban', siteName='fixture.example',
                           ip='192.0.2.17', revision='0' * 32)
        self.assertIs(result['status'], False)
        listing = self.call('get_risk_site_bans', siteName='fixture.example')
        self.backend._free_waf_main__update_request_is_post.return_value = False
        result = self.call('remove_risk_site_ban', siteName='fixture.example',
                           ip='192.0.2.17', revision=listing['revision'])
        self.assertIs(result['status'], False)
        self.assertEqual((self.root / 'manual_site_bans.json').read_bytes(), before)

    def test_invalid_whitelist_disables_shortcut_but_leaves_evidence_visible(self):
        self.log()
        (self.root / 'rule/ip_white.json').write_text('[{"bad":"shape"}]')
        result = self.advice()
        self.assertEqual(result['items'][0]['recommended_seconds'], 86400)
        self.assertFalse(result['items'][0]['actionable'])
        self.assertIs(self.apply(result)['status'], False)

    @unittest.skipUnless(hasattr(os, 'symlink'), 'requires symlinks')
    def test_symlinked_log_is_not_followed(self):
        rows = self.log()
        original = next(self.logs.glob('*.log'))
        target = self.root / 'outside.log'
        original.replace(target)
        try:
            original.symlink_to(target)
        except OSError:
            self.skipTest('symlink permission unavailable')
        result = self.call('get_risk_advice', siteName='fixture.example')
        self.assertIs(result['status'], False)
        self.assertFalse((self.root / 'manual_site_bans.json').exists())

    def test_fresh_worker_proof_requires_exact_snapshot_and_policy_signature(self):
        snapshot = dict(version=1, revision='a' * 32, entries=[])
        self.backend.__dict__.pop('_free_waf_main__risk_runtime_matches')
        expected = dict(status=True, valid=True, revision='a' * 32, entries=[], policy_signature='b' * 32)
        connection = Mock()
        with patch('socket.create_connection', return_value=connection):
            for changed in ({}, {'revision': 'c' * 32}, {'policy_signature': 'd' * 32},
                            {'entries': [{}]}, {'valid': False}, {'status': False}):
                body = json.dumps(dict(expected, **changed)).encode()
                connection.recv.side_effect = [b'HTTP/1.0 200 OK\r\nContent-Length: '
                    + str(len(body)).encode() + b'\r\n\r\n' + body, b'']
                self.assertEqual(self.backend._free_waf_main__risk_runtime_matches(snapshot, 'b' * 32),
                                 not changed)
        self.assertTrue(connection.sendall.call_args[0][0].startswith(b'GET /get_manual_site_bans HTTP/1.0\r\n'))

    def test_worker_proof_has_absolute_deadline_for_headers_and_body(self):
        self.backend.__dict__.pop('_free_waf_main__risk_runtime_matches')
        snapshot = dict(version=1, revision='a' * 32, entries=[])
        value = dict(status=True, valid=True, revision='a' * 32, entries=[], policy_signature='b' * 32)
        body = json.dumps(value).encode()
        header = b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
        for phase in ('headers', 'body'):
            with self.subTest(phase=phase):
                clock = [100.0]
                parts = iter([bytes([byte]) for byte in header] + [body, b''] if phase == 'headers'
                             else [header] + [bytes([byte]) for byte in body] + [b''])
                connection = Mock()
                connection.recv.side_effect = lambda limit: (clock.__setitem__(0, clock[0] + 0.2) or next(parts))
                legacy = Mock()
                legacy.getresponse.return_value.status = 200
                legacy.getresponse.return_value.read.side_effect = lambda limit: (
                    clock.__setitem__(0, clock[0] + 19) or body)
                with patch('socket.create_connection', return_value=connection), \
                        patch('http.client.HTTPConnection', return_value=legacy), \
                        patch('time.monotonic', side_effect=lambda: clock[0]):
                    self.assertFalse(self.backend._free_waf_main__risk_runtime_matches(snapshot, 'b' * 32, wait=True))
                self.assertLessEqual(clock[0], 102.8)

    def test_analysis_limits_ip_checks_and_compiles_whitelist_once(self):
        import ipaddress
        (self.root / 'rule/ip_white.json').write_text('[[[10,0,0,0],[10,0,0,255]],[[10,0,1,0],[10,0,1,255]]]')
        items = [dict(ip=str(ipaddress.IPv4Address(3221225984 + index)),
                      recommended_seconds=0, strong_targets=0) for index in range(2000)]
        self.backend._free_waf_main__risk_read_rows = Mock(return_value=([], {}))
        module = self.backend._free_waf_main__ban_store_module()
        original_holds = self.backend._free_waf_main__risk_holds
        self.backend._free_waf_main__risk_holds = Mock(wraps=original_holds)
        address_type = ipaddress.IPv4Address
        context = self.backend._free_waf_main__risk_context(types.SimpleNamespace(siteName='fixture.example'))
        with patch.object(module.RiskAdviceAnalyzer, 'analyze', return_value=items), \
                patch('ipaddress.IPv4Address', wraps=address_type) as address_calls:
            now, result, coverage = self.backend._free_waf_main__risk_analysis(context)
        self.assertEqual(len(result), 500)
        self.assertTrue(coverage['items_limited'])
        self.assertEqual(self.backend._free_waf_main__risk_holds.call_count, 500)
        self.assertLessEqual(address_calls.call_count, 510)

    def test_compiled_whitelist_preserves_inclusive_merged_ranges_and_invalid_holds(self):
        self.log()
        (self.root / 'rule/ip_white.json').write_text('[[[192,0,2,18],[192,0,2,19]],'
                                                   '[[192,0,2,16],[192,0,2,17]]]')
        context = self.backend._free_waf_main__risk_context(types.SimpleNamespace(siteName='fixture.example'))
        self.assertEqual(len(context['white_intervals'][0]), 1)
        for ip in ('192.0.2.16', '192.0.2.17', '192.0.2.18', '192.0.2.19'):
            self.assertTrue(self.backend._free_waf_main__risk_holds(context, ip), ip)
        for ip in ('192.0.2.15', '192.0.2.20', '2001:db8::17'):
            self.assertEqual(self.backend._free_waf_main__risk_holds(context, ip), [], ip)
        (self.root / 'rule/ip_white.json').write_text('[[[192,0,2,19],[192,0,2,18]]]')
        context = self.backend._free_waf_main__risk_context(types.SimpleNamespace(siteName='fixture.example'))
        self.assertIsNone(context['white_intervals'])
        self.assertTrue(self.backend._free_waf_main__risk_holds(context, '2001:db8::17'))

    def test_oversized_site_configuration_is_rejected_before_log_scan(self):
        (self.root / 'site.json').write_bytes(b' ' * (2 * 1024 * 1024 + 1))
        self.backend._free_waf_main__risk_read_rows = Mock(side_effect=AssertionError('scan after bad config'))
        self.assertIs(self.call('get_risk_advice', siteName='fixture.example')['status'], False)
        self.backend._free_waf_main__risk_read_rows.assert_not_called()

    def test_site_selector_has_a_read_budget_and_no_side_effects(self):
        before = set(self.root.iterdir())
        result = self.call('get_risk_advice_sites')
        self.assertIs(result['status'], True, result)
        self.assertEqual(result['sites'], [dict(siteName=site) for site in sorted(self.sites)])
        self.assertEqual(set(self.root.iterdir()), before)
        path = self.root / 'site.json'
        path.write_bytes(path.read_bytes() + b' ' * (2 * 1024 * 1024))
        self.assertIs(self.call('get_risk_advice_sites')['status'], False)

    def test_pending_policy_recovery_blocks_new_mutations_and_reload(self):
        pending = self.root / '.policy-recovery'
        pending.mkdir()
        (pending / 'pending.json').write_text('{}')
        self.backend._free_waf_main__risk_store = Mock(side_effect=AssertionError('must not access mutable store'))
        context = self.backend._free_waf_main__risk_context(types.SimpleNamespace(siteName='fixture.example'))
        self.backend._free_waf_main__risk_analysis = Mock(return_value=(int(time.time()), [
            dict(ip='192.0.2.17', actionable=True, fingerprint='a' * 64)], {}))
        result = self.call('apply_risk_advice', siteName='fixture.example', ip='192.0.2.17',
                           fingerprint='a' * 64, config_revision=context['revision'], duration='86400')
        self.assertIs(result['status'], False)
        self.call('remove_risk_site_ban', siteName='fixture.example', ip='192.0.2.17', revision='0' * 32)
        self.backend._free_waf_main__risk_store.assert_not_called()
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_analysis_time_external_config_changes_are_rechecked_before_save(self):
        context = self.backend._free_waf_main__risk_context(types.SimpleNamespace(siteName='fixture.example'))
        def concurrent_change(current):
            (self.root / 'rule/ip_white.json').write_text('[[[192,0,2,17],[192,0,2,17]]]')
            return int(time.time()), [dict(ip='192.0.2.17', actionable=True, fingerprint='a' * 64)], {}
        self.backend._free_waf_main__risk_analysis = concurrent_change
        self.backend._free_waf_main__risk_store = Mock(side_effect=AssertionError('must not save stale context'))
        result = self.call('apply_risk_advice', siteName='fixture.example', ip='192.0.2.17',
                           fingerprint='a' * 64, config_revision=context['revision'], duration='86400')
        self.assertIs(result['status'], False)
        self.backend._free_waf_main__risk_store.assert_not_called()
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_missing_alias_candidates_still_obey_deadline(self):
        context = self.backend._free_waf_main__risk_context(types.SimpleNamespace(siteName='fixture.example'))
        context['log_names'] = ['alias{}.example'.format(index) for index in range(1000)]
        self.backend.LEGACY_LOG_MAX_SECONDS = -1
        with patch('os.path.lexists', wraps=os.path.lexists) as checked:
            rows, coverage = self.backend._free_waf_main__risk_read_rows(context, int(time.time()))
        self.assertEqual(rows, [])
        self.assertTrue(coverage['partial'])
        self.assertLess(checked.call_count, 10)

    def test_all_2000_api_records_are_inside_the_actual_analysis_window(self):
        self.log(['/v1/chat/completions'] * 1000)
        context = self.backend._free_waf_main__risk_context(types.SimpleNamespace(siteName='fixture.example'))
        rows, coverage = self.backend._free_waf_main__risk_read_rows(context, int(time.time()))
        self.assertEqual(len(rows), 2000)
        self.assertEqual(coverage['invalid_lines'], 0)

    def test_malformed_scanner_paths_are_counted_invalid_without_hiding_valid_evidence(self):
        self.log()
        path = next(self.logs.glob('*.log'))
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 1))
        with path.open('a') as stream:
            stream.write('\n' + json.dumps([ts, '192.0.2.17', 'GET', '/%xx/.env', '', 'get']))
        result = self.advice()
        self.assertEqual(result['coverage']['invalid_lines'], 1)
        self.assertEqual(result['items'][0]['recommended_seconds'], 86400)


if __name__ == '__main__':
    unittest.main()
