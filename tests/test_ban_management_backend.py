"""Unified ban reads and explicit writes, using only disposable documentation fixtures."""
import json
import os
import time
import types
import unittest
from unittest.mock import Mock, patch

from tests import test_risk_advice_backend as fixtures


class BanManagementBackendTest(unittest.TestCase):
    write_config = fixtures.RiskAdviceBackendTest.write_config
    def call(self, method, **args):
        if method == 'add_quick_ban' and 'config_revision' not in args:
            args['config_revision'] = self.context()['revision']
        return fixtures.RiskAdviceBackendTest.call(self, method, **args)

    def setUp(self):
        fixtures.RiskAdviceBackendTest.setUp(self)
        (self.root / 'repeat_bans.json').unlink()
        (self.root / 'drop_ip.log').write_text('')
        self.now = int(time.time())
        self.runtime = dict(status=True, schema_version=1, rows=[],
                            coverage=dict(partial=False, sources={}),
                            policy_signature=self.context()['signature'])
        self.backend._free_waf_main__ban_runtime_snapshot = Mock(return_value=self.runtime)
        self.backend._free_waf_main__ban_runtime_request = Mock(return_value=dict(status=True))
        self.backend.add_ip_black.__func__.__globals__.update(
            TEMP_BAN_SECONDS=28800, MANUAL_MAX_BAN_SECONDS=315360000)
        self.backend._free_waf_main__write_drop_ip_entry = Mock()
        self.backend._free_waf_main__write_log = Mock()

    def context(self):
        return self.backend._free_waf_main__risk_context(types.SimpleNamespace(siteName='fixture.example'))

    def manual(self, site='fixture.example', ip='192.0.2.17', seconds=3600):
        return self.backend._free_waf_main__risk_store().add(site, ip, seconds, 'a' * 64)

    def runtime_row(self, source='cc', ip='192.0.2.17', site='fixture.example', **kwargs):
        row = dict(source=source, ip=ip, site=site, scope='site' if site else 'global',
                   started_at=None, expires_at=self.now + 3600, enforcement='active',
                   runtime_id='a' * 32, runtime_revision='b' * 32, removable=True)
        row.update(kwargs)
        self.runtime['rows'].append(row)
        return row

    def test_apis_exist(self):
        for name in ('get_active_bans', 'get_ban_history', 'add_quick_ban', 'remove_active_ban'):
            self.assertTrue(callable(getattr(self.backend, name, None)), name + ' API missing')

    def test_merge_all_exact_sources_and_canonical_ip_summary(self):
        snapshot = self.manual(ip='2001:db8::1')
        self.runtime_row(ip='2001:0DB8:0:0:0:0:0:1')
        self.runtime_row(source='legacy', ip='192.0.2.17', site='')
        self.runtime_row(source='registration_abuse', ip='192.0.2.17')
        self.runtime_row(source='manual_site_bans',
                         store_revision=snapshot['revision'], **snapshot['entries'][0])
        (self.root / 'rule/ip_black.json').write_text(json.dumps([
            [[192, 0, 2, 17], [192, 0, 2, 17], self.now + 300],
            [[198, 51, 100, 0], [198, 51, 100, 255]]]))
        self.runtime_row(source='ip_black', ip='192.0.2.17', site='', expires_at=self.now + 300)
        result = self.call('get_active_bans')
        self.assertTrue(result['status'], result)
        self.assertEqual(result['schema_version'], 1)
        self.assertEqual(len(result['rows']), 5)
        self.assertEqual(result['summary']['active_ips'], 2)
        self.assertEqual(result['coverage']['range_entries'], 1)
        self.assertEqual({row['source'] for row in result['rows']},
                         {'cc', 'legacy', 'registration_abuse', 'manual_site_bans', 'ip_black'})

    def test_config_only_record_is_unknown_and_runtime_failure_is_partial(self):
        self.manual()
        self.backend._free_waf_main__ban_runtime_snapshot.side_effect = OSError('fixture')
        result = self.call('get_active_bans')
        self.assertTrue(result['status'], result)
        self.assertTrue(result['coverage']['partial'])
        self.assertEqual(result['summary']['active_ips'], 0)
        self.assertEqual(result['summary']['unknown_entries'], 1)
        self.assertEqual(result['rows'][0]['enforcement'], 'unknown')
        self.assertTrue(result['rows'][0]['removable'])

    def test_disabled_site_record_is_not_active_and_state_summary_precedes_filter(self):
        self.manual()
        self.sites['fixture.example']['open'] = False
        self.write_config()
        result = self.call('get_active_bans', state='active')
        self.assertEqual(result['total'], 0)
        self.assertEqual(result['summary']['inactive_entries'], 1)
        result = self.call('get_active_bans', state='disabled', site='fixture.example')
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['rows'][0]['enforcement'], 'disabled')

    def test_stale_worker_config_is_unknown_not_active(self):
        self.runtime_row()
        self.runtime['policy_signature'] = 'f' * 32
        result = self.call('get_active_bans')
        self.assertEqual(result['rows'][0]['enforcement'], 'unknown')
        self.assertTrue(result['coverage']['partial'])

    def test_expired_and_future_manual_rows_do_not_count_active(self):
        self.manual()
        path = self.root / 'manual_site_bans.json'
        value = json.loads(path.read_text())
        value['entries'][0].update(started_at=self.now - 7200, expires_at=self.now - 3600)
        path.write_text(json.dumps(value))
        self.assertEqual(self.call('get_active_bans')['total'], 0)
        value['entries'][0].update(started_at=self.now + 7200, expires_at=self.now + 10800)
        path.write_text(json.dumps(value))
        self.assertNotEqual(self.call('get_active_bans')['rows'][0]['enforcement'], 'active')

    def test_reads_do_not_create_locks_migrate_prune_or_write(self):
        self.manual()
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.call('get_active_bans')
        self.call('get_ban_history')
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()
        self.public.httpGet.assert_not_called()

    def test_corrupt_store_is_partial_not_silently_empty(self):
        (self.root / 'repeat_bans.json').write_text('{broken')
        result = self.call('get_active_bans')
        self.assertTrue(result['coverage']['partial'])
        self.assertIn('repeat_bans', result['coverage']['unavailable_sources'])

    def history(self, rows):
        (self.root / 'drop_ip.log').write_text('\n'.join(json.dumps(row) for row in rows))

    def test_history_groups_canonical_identity_before_pagination_without_loss(self):
        rows = [[self.now - i, '2001:0DB8::1' if i % 2 else '2001:db8::1',
                 'fixture.example', '/private?token=do-not-return', 60 + i, 'cc'] for i in range(35)]
        rows += [[self.now, '192.0.2.18', 'other.example', '/', 600, 'manual_temp']]
        self.history(rows)
        result = self.call('get_ban_history', limit='1', p='2', days='1')
        self.assertTrue(result['status'], result)
        self.assertEqual(result['total'], 2)
        pages = [self.call('get_ban_history', limit='1', p=str(p))['rows'][0] for p in (1, 2)]
        grouped = next(row for row in pages if row['reason'] == 'cc')
        self.assertEqual(grouped['count'], 35)
        self.assertEqual(grouped['ip'], '2001:db8::1')
        self.assertEqual(grouped['first_time'], self.now - 34)
        self.assertEqual(grouped['last_time'], self.now)
        self.assertNotIn('do-not-return', json.dumps(result))
        raw = self.call('get_ban_history', ip=grouped['ip'], site=grouped['site'], reason='cc',
                        view='raw', limit='200', days='1')
        self.assertEqual(raw['total'], 35)
        self.assertTrue(all(row['count'] == 1 and row['reason'] == 'cc' for row in raw['rows']))
        self.assertEqual(len((self.root / 'drop_ip.log').read_text().splitlines()), 36)

    def test_history_exact_empty_site_and_reason_filters_do_not_leak_scopes(self):
        self.history([[self.now, '192.0.2.17', site, '/', 60, reason]
                      for site in ('', 'fixture.example') for reason in ('cc', 'manual_temp')])
        result = self.call('get_ban_history', site='', reason='cc', view='raw')
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['rows'][0]['site'], '')

    def test_history_limits_and_invalid_records_report_inexact_totals(self):
        self.history([[self.now, '192.0.2.17', 'fixture.example', '/', 60, 'cc']] * 5)
        self.backend.LEGACY_LOG_MAX_LINES = 2
        result = self.call('get_ban_history')
        self.assertTrue(result['coverage']['partial'])
        self.assertIs(result['total_exact'], False)
        self.assertEqual(result['rows'][0]['count'], 2)

    def test_strict_read_parameters(self):
        for method, params in [('get_active_bans', dict(state='invalid')),
                               ('get_active_bans', dict(ip='192.0.2.0/24')),
                               ('get_active_bans', dict(limit=True)),
                               ('get_ban_history', dict(days='31')),
                               ('get_ban_history', dict(view='html')),
                               ('get_ban_history', dict(p='0'))]:
            with self.subTest(method=method, params=params):
                self.assertFalse(self.call(method, **params)['status'])

    def test_quick_ban_site_is_finite_manual_and_preserves_other_sources(self):
        result = self.call('add_quick_ban', ip='::ffff:192.0.2.17', scope='site',
                           siteName='fixture.example', duration_seconds='600')
        self.assertTrue(result['status'], result)
        self.assertTrue(result['saved'])
        self.assertTrue(result['runtime_verified'])
        row = json.loads((self.root / 'manual_site_bans.json').read_text())['entries'][0]
        self.assertEqual(row['ip'], '192.0.2.17')
        self.assertEqual(row['duration'], 600)
        self.assertEqual(row['reason'], 'risk_advice')
        self.assertEqual(len(row['evidence_hash']), 64)
        self.assertEqual((self.root / 'rule/ip_black.json').read_text(), '[]')

    def test_quick_ban_requires_post_explicit_scope_valid_site_and_duration(self):
        good = dict(ip='192.0.2.17', scope='site', siteName='fixture.example', duration_seconds='600')
        for changes in (dict(scope=''), dict(scope='all'), dict(siteName=''), dict(siteName='unknown.example'),
                        dict(ip='192.0.2.0/24'), dict(duration_seconds=True), dict(duration_seconds='59'),
                        dict(duration_seconds='315360001'), dict(duration_seconds='1e3'),
                        dict(duration_seconds='315360000'), dict(config_revision='stale')):
            with self.subTest(changes=changes):
                self.assertFalse(self.call('add_quick_ban', **dict(good, **changes))['status'])
        self.backend._free_waf_main__update_request_is_post.return_value = False
        self.assertFalse(self.call('add_quick_ban', **good)['status'])
        self.assertFalse((self.root / 'manual_site_bans.json').exists())

    def test_quick_ban_whitelist_and_disabled_site_are_fail_closed(self):
        (self.root / 'rule/ip_white.json').write_text(json.dumps([[[192, 0, 2, 0], [192, 0, 2, 255]]]))
        for scope in ('site', 'global'):
            self.assertFalse(self.call('add_quick_ban', ip='192.0.2.17', scope=scope,
                                       siteName='fixture.example', duration_seconds='600')['status'])
        (self.root / 'rule/ip_white.json').write_text('[]')
        self.sites['fixture.example']['open'] = False
        self.write_config()
        self.assertFalse(self.call('add_quick_ban', ip='192.0.2.17', scope='site',
                                   siteName='fixture.example', duration_seconds='600')['status'])

    def test_quick_ban_reload_failure_reports_saved_without_verified(self):
        self.backend._free_waf_main__checked_nginx_reload.side_effect = OSError('fixture')
        result = self.call('add_quick_ban', ip='192.0.2.17', scope='site',
                           siteName='fixture.example', duration_seconds='600')
        self.assertFalse(result['status'])
        self.assertTrue(result['saved'])
        self.assertFalse(result['runtime_verified'])

    def test_quick_global_uses_existing_blacklist_api_never_site_store(self):
        self.backend.add_ip_black = Mock(return_value=dict(status=False))
        result = self.call('add_quick_ban', ip='192.0.2.17', scope='global', duration_seconds='600')
        self.backend.add_ip_black.assert_called_once()
        params = self.backend.add_ip_black.call_args[0][0]
        self.assertEqual(params.start_ip, '192.0.2.17')
        self.assertEqual(params.end_ip, '192.0.2.17')
        self.assertFalse(result['runtime_verified'])
        self.assertFalse((self.root / 'manual_site_bans.json').exists())

    def test_remove_manual_resolves_server_identity_and_only_selected_site(self):
        self.manual()
        self.manual(site='other.example')
        row = next(row for row in self.call('get_active_bans')['rows'] if row['site'] == 'fixture.example')
        result = self.call('remove_active_ban', id=row['id'], revision=row['revision'],
                           scope='global', source='ip_black', ip='192.0.2.99', siteName='other.example')
        self.assertTrue(result['status'], result)
        remaining = json.loads((self.root / 'manual_site_bans.json').read_text())['entries']
        self.assertEqual([row['site'] for row in remaining], ['other.example'])
        self.backend._free_waf_main__ban_runtime_request.assert_not_called()

    def test_stale_identity_and_get_removal_cannot_write(self):
        self.manual()
        row = self.call('get_active_bans')['rows'][0]
        before = (self.root / 'manual_site_bans.json').read_bytes()
        self.assertFalse(self.call('remove_active_ban', id=row['id'], revision='f' * 64)['status'])
        self.backend._free_waf_main__update_request_is_post.return_value = False
        self.assertFalse(self.call('remove_active_ban', id=row['id'], revision=row['revision'])['status'])
        self.assertEqual(before, (self.root / 'manual_site_bans.json').read_bytes())

    def test_remove_cc_uses_narrow_runtime_route_and_retains_other_site(self):
        self.runtime_row()
        self.runtime_row(site='other.example', runtime_id='c' * 32)
        row = next(row for row in self.call('get_active_bans')['rows'] if row['site'] == 'fixture.example')

        def remove(path, params=None):
            self.assertEqual(path, '/remove_active_ban_runtime')
            self.assertEqual(params['id'], 'a' * 32)
            self.runtime['rows'] = [r for r in self.runtime['rows'] if r['runtime_id'] != params['id']]
            return dict(status=True)

        self.backend._free_waf_main__ban_runtime_request.side_effect = remove
        self.assertTrue(self.call('remove_active_ban', id=row['id'], revision=row['revision'])['status'])
        self.assertEqual(self.runtime['rows'][0]['site'], 'other.example')
        self.public.httpGet.assert_not_called()

    def test_repeat_ban_disabled_without_policy_and_active_only_with_matching_runtime_revision(self):
        record = dict(site='fixture.example', ip='192.0.2.17', started_at=self.now-10,
                      expires_at=self.now+590, duration=600, trigger_count=5,
                      window_seconds=86400, threshold=5, reason='cc', path='/')
        snapshot = dict(version=1, revision='d' * 32, bans=[record])
        (self.root / 'repeat_bans.json').write_text(json.dumps(snapshot))
        self.assertEqual(self.call('get_active_bans')['rows'][0]['enforcement'], 'disabled')
        self.sites['fixture.example']['repeat_ban_policy'] = dict(enabled=True, window_seconds=86400,
            tiers=[dict(threshold=5, ban_seconds=600)])
        self.write_config()
        self.runtime['policy_signature'] = self.context()['signature']
        self.runtime_row(source='repeat_bans', store_revision=snapshot['revision'], **record)
        row = self.call('get_active_bans')['rows'][0]
        self.assertEqual(row['enforcement'], 'active')
        self.runtime['rows'][0]['store_revision'] = 'e' * 32
        self.assertEqual(self.call('get_active_bans')['rows'][0]['enforcement'], 'unknown')

    def test_history_detail_accepts_exact_legacy_registration_scope_and_label(self):
        self.history([[self.now, '192.0.2.17', 'tenant:scope', '/', 60, 'cc'],
                      [self.now, '192.0.2.17', '手动封禁', '/', 60, 'manual_temp']])
        for site in ('tenant:scope', '手动封禁'):
            result = self.call('get_ban_history', site=site, reason='cc' if ':' in site else 'manual_temp', view='raw')
            self.assertTrue(result['status'], result)
            self.assertEqual(result['total'], 1)
            self.assertEqual(result['rows'][0]['site'], site)

    def test_runtime_failure_after_scoped_removal_is_not_success(self):
        self.runtime_row()
        row = self.call('get_active_bans')['rows'][0]
        self.backend._free_waf_main__ban_runtime_snapshot.side_effect = [self.runtime, OSError('fixture')]
        result = self.call('remove_active_ban', id=row['id'], revision=row['revision'])
        self.assertFalse(result['status'])
        self.assertFalse(result['runtime_verified'])

    def test_manual_write_readback_failure_reports_uncertain_not_unsaved(self):
        store = self.backend._free_waf_main__risk_store()
        self.backend._free_waf_main__risk_store = lambda: store
        original = store._read_bytes
        reads = []

        def read():
            reads.append(True)
            if len(reads) == 2:
                raise OSError('fixture readback failure')
            return original()

        with patch.object(store, '_read_bytes', side_effect=read):
            result = self.call('add_quick_ban', ip='192.0.2.17', scope='site',
                               siteName='fixture.example', duration_seconds='600')
        self.assertIsNone(result['saved'])
        self.assertTrue(result['save_uncertain'])
        self.assertFalse(result['runtime_verified'])
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()
        self.assertTrue((self.root / 'manual_site_bans.json').exists())

    def test_global_remove_can_verify_selected_source_despite_unrelated_partial_source(self):
        (self.root / 'rule/ip_black.json').write_text(json.dumps([
            [[192, 0, 2, 17], [192, 0, 2, 17], self.now + 300]]))
        self.runtime_row(source='ip_black', site='', expires_at=self.now + 300)
        self.runtime['coverage'] = dict(partial=True, sources=dict(ip_black=True))
        row = self.call('get_active_bans')['rows'][0]

        def reload():
            self.runtime['rows'] = []

        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        result = self.call('remove_active_ban', id=row['id'], revision=row['revision'])
        self.assertTrue(result['status'], result)
        self.assertTrue(result['saved'])
        self.assertTrue(result['runtime_verified'])
        self.backend._free_waf_main__ban_runtime_request.assert_not_called()

    def test_global_add_returns_honest_saved_and_runtime_verification(self):
        self.backend._free_waf_main__validate_rule = Mock()

        def reload():
            rules = json.loads((self.root / 'rule/ip_black.json').read_text())
            self.runtime_row(source='ip_black', site='', expires_at=rules[0][2])

        self.backend._free_waf_main__reload_panel_nginx = Mock(side_effect=reload)
        result = self.call('add_quick_ban', ip='192.0.2.17', scope='global', duration_seconds='600')
        self.assertTrue(result['status'], result)
        self.assertTrue(result['saved'])
        self.assertTrue(result['runtime_verified'])

    def test_global_add_waits_for_reload_snapshot_without_repeating_the_write(self):
        self.backend._free_waf_main__validate_rule = Mock()
        self.backend._free_waf_main__reload_panel_nginx = Mock()
        original = self.backend._free_waf_main__ban_collect
        calls = []

        def delayed():
            calls.append(1)
            if len(calls) == 2:
                rules = json.loads((self.root / 'rule/ip_black.json').read_text())
                self.runtime_row(source='ip_black', site='', expires_at=rules[0][2])
            return original()

        self.backend._free_waf_main__ban_collect = delayed
        result = self.call('add_quick_ban', ip='192.0.2.17', scope='global', duration_seconds='600')
        self.assertTrue(result['runtime_verified'], result)
        self.assertGreaterEqual(len(calls), 2)
        self.backend._free_waf_main__reload_panel_nginx.assert_called_once()

    def test_global_remove_waits_for_old_worker_to_retire_without_repeating_delete(self):
        (self.root / 'rule/ip_black.json').write_text(json.dumps([
            [[192, 0, 2, 17], [192, 0, 2, 17], self.now + 300]]))
        self.runtime_row(source='ip_black', site='', expires_at=self.now + 300)
        self.runtime['coverage'] = dict(partial=False, sources=dict(ip_black=True))
        row = self.call('get_active_bans')['rows'][0]
        calls = []

        def delayed():
            calls.append(1)
            if len(calls) >= 4:
                self.runtime['rows'] = []
            return self.runtime

        self.backend._free_waf_main__ban_runtime_snapshot.side_effect = delayed
        result = self.call('remove_active_ban', id=row['id'], revision=row['revision'])
        self.assertTrue(result['runtime_verified'], result)
        self.backend._free_waf_main__checked_nginx_reload.assert_called_once()

    def test_whitelist_and_disabled_global_are_not_active(self):
        self.runtime_row()
        (self.root / 'rule/ip_white.json').write_text(json.dumps([[[192, 0, 2, 17], [192, 0, 2, 17]]]))
        self.runtime['policy_signature'] = self.context()['signature']
        self.assertEqual(self.call('get_active_bans')['summary']['active_entries'], 0)
        self.global_config['open'] = False
        self.write_config()
        self.assertEqual(self.call('get_active_bans')['rows'][0]['enforcement'], 'disabled')

    def test_pending_recovery_and_config_change_block_quick_writes(self):
        directory = self.root / '.policy-recovery'
        directory.mkdir()
        (directory / 'pending.json').write_text('{}')
        result = self.call('add_quick_ban', ip='192.0.2.17', scope='site',
                           siteName='fixture.example', duration_seconds='600')
        self.assertFalse(result['saved'])
        self.assertFalse((self.root / 'manual_site_bans.json').exists())

    def test_runtime_transport_uses_fixed_loopback_and_post_for_narrow_removal(self):
        body = json.dumps(dict(status=True)).encode('ascii')
        wire = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode('ascii') + b'\r\n\r\n' + body
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.recv.side_effect = [wire, b'']
        backend = fixtures.load_backend(self.public)
        with patch('socket.create_connection', return_value=connection) as create:
            result = backend._free_waf_main__ban_runtime_request('/remove_active_ban_runtime',
                dict(id='a' * 32, revision='b' * 32))
        self.assertTrue(result['status'])
        self.assertEqual(create.call_args[0][0], ('127.0.0.1', 39091))
        self.assertTrue(connection.sendall.call_args[0][0].startswith(b'POST /remove_active_ban_runtime?'))

    def test_runtime_transport_bounds_bytes_rejects_redirects_and_invalid_json(self):
        for wire in (b'HTTP/1.1 302 Found\r\nContent-Length: 2\r\n\r\n{}',
                     b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx',
                     b'x' * (4 * 1024 * 1024 + 1)):
            connection = Mock()
            connection.__enter__ = Mock(return_value=connection)
            connection.__exit__ = Mock(return_value=False)
            connection.recv.side_effect = [wire, b'']
            backend = fixtures.load_backend(self.public)
            with patch('socket.create_connection', return_value=connection):
                with self.assertRaises((ValueError, OSError)):
                    backend._free_waf_main__ban_runtime_request('/get_active_bans_runtime')

    def test_invalid_whitelist_never_claims_verified_active_enforcement(self):
        self.runtime_row()
        (self.root / 'rule/ip_white.json').write_text('["invalid"]')
        self.runtime['policy_signature'] = self.context()['signature']
        result = self.call('get_active_bans')
        self.assertEqual(result['summary']['active_entries'], 0)
        self.assertTrue(result['coverage']['partial'])

    def test_unknown_stored_record_marks_coverage_partial_even_if_worker_available(self):
        self.manual()
        result = self.call('get_active_bans')
        self.assertEqual(result['summary']['unknown_entries'], 1)
        self.assertTrue(result['coverage']['partial'])

    def test_quick_site_stale_store_revision_is_rejected_without_uncertain_write(self):
        self.manual()
        row = self.call('get_active_bans')['rows'][0]
        self.manual(site='other.example')
        before = (self.root / 'manual_site_bans.json').read_bytes()
        result = self.call('remove_active_ban', id=row['id'], revision=row['revision'])
        self.assertFalse(result['status'])
        self.assertIs(result['saved'], False)
        self.assertEqual(before, (self.root / 'manual_site_bans.json').read_bytes())

    def test_invalid_blacklist_record_disables_removal_of_partially_read_rows(self):
        (self.root / 'rule/ip_black.json').write_text(json.dumps([
            [[192, 0, 2, 17], [192, 0, 2, 17], self.now + 300], 'invalid']))
        result = self.call('get_active_bans')
        self.assertTrue(result['coverage']['partial'])
        self.assertFalse(result['rows'][0]['removable'])
        row = result['rows'][0]
        before = (self.root / 'rule/ip_black.json').read_bytes()
        result = self.call('remove_active_ban', id=row['id'], revision=row['revision'])
        self.assertFalse(result['status'])
        self.assertEqual(before, (self.root / 'rule/ip_black.json').read_bytes())

    def test_configuration_changes_cannot_widen_scoped_removal(self):
        self.manual()
        row = self.call('get_active_bans')['rows'][0]
        self.global_config['open'] = False
        self.write_config()
        self.assertIs(self.call('remove_active_ban', id=row['id'], revision=row['revision'])['saved'], False)

    def test_site_ip_filters_and_pagination_preserve_unfiltered_scope_summary(self):
        self.runtime_row()
        self.runtime_row(site='other.example', runtime_id='c' * 32)
        result = self.call('get_active_bans', ip='::ffff:192.0.2.17', site='other.example', limit='1')
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['summary']['active_entries'], 1)
        self.assertEqual(result['rows'][0]['site'], 'other.example')

    def test_history_out_of_window_and_malformed_events_are_not_counted_as_valid(self):
        self.history([[self.now - 31*86400, '192.0.2.17', 'fixture.example', '/', 60, 'cc'],
                      [self.now, '192.0.2.17', 'fixture.example', '/', True, 'cc'],
                      [self.now, '192.0.2.17', 'fixture.example', '/', 60, 'cc']])
        result = self.call('get_ban_history', days='30')
        self.assertEqual(result['rows'][0]['count'], 1)
        self.assertEqual(result['coverage']['outside_window'], 1)
        self.assertEqual(result['coverage']['invalid_lines'], 1)
        self.assertFalse(result['total_exact'])

    def test_empty_site_search_means_all_active_but_exact_history_scope(self):
        self.runtime_row()
        self.runtime_row(site='other.example', runtime_id='c' * 32)
        self.assertEqual(self.call('get_active_bans', site='')['total'], 2)
        self.history([[self.now, '192.0.2.17', site, '/', 60, 'cc']
                      for site in ('', 'fixture.example', 'other.example')])
        self.assertEqual(self.call('get_ban_history')['total'], 3)
        self.assertEqual(self.call('get_ban_history', site='')['total'], 1)
        self.assertEqual(self.call('get_ban_history', site='', view='raw', reason='cc')['total'], 1)

    def test_inaccessible_history_file_is_not_treated_as_empty_exact_result(self):
        with patch('os.path.lexists', return_value=False), patch('os.lstat', side_effect=PermissionError('fixture')):
            result = self.call('get_ban_history')
        self.assertTrue(result['status'] is False or result['coverage']['partial'], result)

    def test_quick_ban_requires_preflight_revision_and_rejects_omission_or_stale(self):
        params = dict(ip='192.0.2.17', scope='site', siteName='fixture.example', duration_seconds='600')
        result = self.backend.add_quick_ban(types.SimpleNamespace(**params))
        self.assertFalse(result['status'])
        self.assertIs(result['saved'], False)
        self.assertFalse((self.root / 'manual_site_bans.json').exists())
        for revision in (None, True, 'a' * 63, 'A' * 64, 'f' * 64):
            result = self.call('add_quick_ban', config_revision=revision, **params)
            self.assertFalse(result['status'], result)
            self.assertIs(result['saved'], False)
        self.assertTrue(self.call('add_quick_ban', config_revision=self.context()['revision'], **params)['status'])


if __name__ == '__main__':
    unittest.main()
