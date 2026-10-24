import builtins
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_panel_performance import load_backend


FAMILIES = ['url_white', 'url_black', 'user_agent', 'user_agent_white',
            'header', 'cookie', 'args', 'post']


class ReviewBackendRegressionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'rule').mkdir()
        self.public = types.SimpleNamespace(
            readFile=lambda path: Path(path).read_text(encoding='utf-8') if Path(path).exists() else False,
            writeFile=self.write_file, serviceReload=Mock(return_value=True),
            WriteLog=Mock(), returnMsg=lambda status, msg: dict(status=status, msg=msg))
        self.backend = load_backend(self.public)
        self.backend._free_waf_main__path = str(self.root) + os.sep
        self.backend.import_rule_bundle.__globals__['RULE_BUNDLE_NAMES'] = FAMILIES
        self.backend._free_waf_main__checked_nginx_reload = Mock(return_value=True)
        self.save('site.json', {'fixture.example': {'disable_rule': {'post': [1]}}})
        for family in FAMILIES:
            self.save('rule/' + family + '.json', [])

    def write_file(self, path, text):
        Path(path).write_text(text, encoding='utf-8')
        return True

    def save(self, path, value):
        (self.root / path).write_text(json.dumps(value), encoding='utf-8')

    def read(self, path):
        return json.loads((self.root / path).read_text(encoding='utf-8'))

    def bundle(self, rules):
        return self.backend.import_rule_bundle(types.SimpleNamespace(pdata=json.dumps({'rules': rules})))

    def test_remove_preserves_the_same_disabled_rule(self):
        self.save('rule/post.json', [[1, p, p, 0] for p in ('A', 'B', 'C')])
        self.backend.remove_rule(types.SimpleNamespace(ruleName='post', index='0'))
        self.assertEqual(self.read('site.json')['fixture.example']['disable_rule']['post'], [0])

    def test_bundle_reorder_preserves_exception_by_rule_identity(self):
        self.save('rule/post.json', [[1, p, p, 0] for p in ('A', 'B', 'C')])
        self.assertTrue(self.bundle({'post': [[1, p, p, 0] for p in ('B', 'C', 'A')]})['status'])
        self.assertEqual(self.read('site.json')['fixture.example']['disable_rule']['post'], [0])

    def test_ua_whitelist_uses_runtime_structured_rows(self):
        row = [1, 'GoodBot', 'fixture', 1]
        self.assertTrue(self.bundle({'user_agent_white': [row]})['status'])
        self.assertEqual(self.read('rule/user_agent_white.json'), [row])
        self.assertFalse(self.bundle({'user_agent_white': ['GoodBot']})['status'])

    def test_delete_duplicate_pattern_preserves_exact_offset_identity(self):
        self.save('rule/post.json', [[0, 'A', 'first', 0], [1, 'A', 'second', 0]])
        result = self.backend.remove_rule(types.SimpleNamespace(ruleName='post', index='0'))
        self.assertTrue(result['status'])
        self.assertEqual(self.read('site.json')['fixture.example']['disable_rule']['post'], [0])

    def test_reload_failure_merges_unrelated_operator_site_changes_before_rule_rollback(self):
        self.save('rule/post.json', [[1, p, p, 0] for p in ('A', 'B', 'C')])
        def reload():
            sites = self.read('site.json')
            sites['fixture.example']['operator_note'] = 'keep'
            self.save('site.json', sites)
            raise RuntimeError('fixture reload failure')
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [reload, True]
        # unittest side_effect lists return callables, so use an explicit call counter.
        calls = []
        def fail_once():
            calls.append(1)
            if len(calls) == 1:
                return reload()
            return True
        self.backend._free_waf_main__checked_nginx_reload.side_effect = fail_once
        self.assertFalse(self.backend.remove_rule(types.SimpleNamespace(ruleName='post', index='0'))['status'])
        site = self.read('site.json')['fixture.example']
        self.assertEqual(site['operator_note'], 'keep')
        self.assertEqual(site['disable_rule']['post'], [1])
        self.assertEqual([row[1] for row in self.read('rule/post.json')], ['A', 'B', 'C'])

    def test_staging_cannot_overwrite_operator_site_change(self):
        self.save('rule/post.json', [[1, p, p, 0] for p in ('A', 'B', 'C')])
        writes = []
        def write(path, text):
            writes.append(path)
            result = self.write_file(path, text)
            if len(writes) == 2:
                sites = self.read('site.json')
                sites['fixture.example']['endpoint_limits'] = ['operator-fixture']
                self.save('site.json', sites)
            return result
        self.public.writeFile = write
        self.assertFalse(self.backend.remove_rule(types.SimpleNamespace(ruleName='post', index='0'))['status'])
        self.assertEqual(self.read('site.json')['fixture.example']['endpoint_limits'], ['operator-fixture'])

    def test_notifications_sort_out_of_order_file_before_limiting(self):
        events = self.events(30)
        events = events[15:] + events[:15]
        with self.log_environment({'fixture.example_2026-10-24.log': events}):
            result = self.backend.get_defense_notifications(types.SimpleNamespace(limit=10, days=1))
        self.assertEqual([row['uri'] for row in result['items']], ['/event-%d' % n for n in range(29, 19, -1)])

    def test_legacy_detail_budget_caps_large_single_line(self):
        from io import StringIO
        payload = json.dumps(['2026-10-24', '192.0.2.1', 'GET', '/' + 'x' * (9 * 1024 * 1024), '', 'post'])
        with patch.object(os.path, 'exists', return_value=True), patch('builtins.open', return_value=StringIO(payload)):
            result = self.backend.get_report_http_detail(types.SimpleNamespace(
                siteName='fixture.example', date='2026-10-24', line_no=1))
        self.assertFalse(result['status'])

    def test_total_site_cleanup_is_atomic_and_preserves_other_counters(self):
        from ban_store import BanStore
        self.backend._free_waf_main__ban_store_module = lambda: types.SimpleNamespace(BanStore=BanStore)
        path = self.root / 'total.json'
        self.save('total.json', {'total': 5, 'rules': {'post': 5},
                                'sites': {'fixture.example': {'post': 2}, 'other.example': {'post': 3}}})
        self.backend._free_waf_main__remove_log_file('fixture.example')
        self.assertTrue(path.with_name('total.json.lock').exists())
        self.assertEqual(self.read('total.json'), {'total': 5, 'rules': {'post': 5},
                                                 'sites': {'other.example': {'post': 3}}})

    def test_negative_delete_index_is_rejected_without_migration(self):
        self.save('rule/post.json', [[1, p, p, 0] for p in ('A', 'B', 'C')])
        self.assertFalse(self.backend.remove_rule(types.SimpleNamespace(ruleName='post', index='-1'))['status'])
        self.assertEqual([row[1] for row in self.read('rule/post.json')], ['A', 'B', 'C'])
        self.assertEqual(self.read('site.json')['fixture.example']['disable_rule']['post'], [1])

    def test_append_to_existing_duplicate_patterns_keeps_offsets(self):
        self.save('rule/post.json', [[0, 'A', 'first', 0], [1, 'A', 'second', 0]])
        result = self.backend.add_rule(types.SimpleNamespace(ruleName='post', ruleValue='B', ps='third'))
        self.assertTrue(result['status'])
        self.assertEqual([row[1] for row in self.read('rule/post.json')], ['A', 'A', 'B'])
        self.assertEqual(self.read('site.json')['fixture.example']['disable_rule']['post'], [1])

    def test_candidate_snapshot_cannot_be_rebased_over_operator_change(self):
        self.save('rule/post.json', [[1, p, p, 0] for p in ('A', 'B', 'C')])
        publish = self.backend._free_waf_main__publish_policy_files
        def intercept(*args, **kwargs):
            sites = self.read('site.json')
            sites['fixture.example']['open'] = False
            self.save('site.json', sites)
            return publish(*args, **kwargs)
        self.backend._free_waf_main__publish_policy_files = intercept
        self.assertFalse(self.backend.remove_rule(types.SimpleNamespace(ruleName='post', index='0'))['status'])
        self.assertIs(self.read('site.json')['fixture.example']['open'], False)
        self.assertEqual([row[1] for row in self.read('rule/post.json')], ['A', 'B', 'C'])

    def test_rollback_remaps_new_site_even_when_existing_exceptions_do_not_change(self):
        self.save('rule/post.json', [[1, p, p, 0] for p in ('A', 'B', 'C')])
        self.save('site.json', {'fixture.example': {'disable_rule': {'post': []}}})
        def fail():
            sites = self.read('site.json')
            sites['new.example'] = {'disable_rule': {'post': [0]}}
            self.save('site.json', sites)
            return False
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [fail, True]
        calls = []
        def once():
            calls.append(1)
            return fail() if len(calls) == 1 else True
        self.backend._free_waf_main__checked_nginx_reload.side_effect = once
        self.assertFalse(self.backend.remove_rule(types.SimpleNamespace(ruleName='post', index='0'))['status'])
        self.assertEqual(self.read('site.json')['new.example']['disable_rule']['post'], [1])
        self.assertEqual([row[1] for row in self.read('rule/post.json')], ['A', 'B', 'C'])

    def test_rollback_write_failure_compensates_to_a_coherent_group_and_blocks_retries(self):
        self.save('rule/post.json', [[1, p, p, 0] for p in ('A', 'B', 'C')])
        atomic = self.backend._free_waf_main__atomic_policy_text
        failures = []
        def fail_restore(path, text, **kwargs):
            if path.endswith('rule/post.json') and [r[1] for r in json.loads(text)] == ['A', 'B', 'C'] and not failures:
                failures.append(1)
                raise OSError('fixture restore failure')
            return atomic(path, text, **kwargs)
        self.backend._free_waf_main__atomic_policy_text = fail_restore
        self.backend._free_waf_main__checked_nginx_reload.return_value = False
        self.assertFalse(self.backend.remove_rule(types.SimpleNamespace(ruleName='post', index='0'))['status'])
        rows = self.read('rule/post.json')
        disabled = self.read('site.json')['fixture.example']['disable_rule']['post']
        self.assertEqual([rows[i][1] for i in disabled], ['B'])
        self.assertTrue((self.root / '.policy-recovery' / 'pending.json').exists())
        self.assertFalse(self.backend.add_rule(types.SimpleNamespace(ruleName='post', ruleValue='D', ps='stop'))['status'])

    def multifamily_migration(self, patterns='BC'):
        original = [[1, p, p, 0] for p in 'ABC']
        candidate = [[1, p, p, 0] for p in patterns]
        for name in ('header', 'post'):
            self.save('rule/' + name + '.json', original)
        self.save('site.json', {'fixture.example': {'disable_rule': {'header': [1], 'post': [1]}}})
        return original, dict(header=candidate, post=candidate)

    def test_multifamily_site_replace_proof_survives_failed_readback(self):
        original, candidate = self.multifamily_migration()
        read = self.public.readFile
        site_path = self.root / 'site.json'
        edits = []
        def edit_before_readback(path):
            raw = read(path)
            if Path(path) == site_path and raw and not edits:
                sites = json.loads(raw)
                if sites['fixture.example']['disable_rule'] == {'header': [0], 'post': [0]}:
                    sites['fixture.example']['disable_rule'] = {'header': [1], 'post': [1]}
                    sites['fixture.example']['operator_note'] = 'keep'
                    self.save('site.json', sites)
                    edits.append(1)
                    return read(path)
            return raw
        self.public.readFile = edit_before_readback
        self.assertFalse(self.bundle(candidate)['status'])
        self.assertEqual(edits, [1])
        for name in candidate:
            self.assertEqual(self.read('rule/' + name + '.json'), original)
        site = self.read('site.json')['fixture.example']
        self.assertEqual(site['operator_note'], 'keep')
        self.assertEqual(site['disable_rule'], {'header': [2], 'post': [2]})
        self.assertFalse((self.root / '.policy-recovery/pending.json').exists())

    def test_multifamily_compensation_keeps_preflight_snapshot(self):
        original, candidate = self.multifamily_migration()
        atomic = self.backend._free_waf_main__atomic_policy_text
        edits = []
        operator = [[1, 'OPERATOR', 'keep', 0]]
        def fail_restore_then_edit(path, text, **kwargs):
            name = Path(path).name
            if name == 'post.json' and json.loads(text) == original and not edits:
                edits.append('restore_failure')
                raise OSError('fixture restore failure')
            result = atomic(path, text, **kwargs)
            if name == 'header.json' and json.loads(text) == candidate['header'] and edits:
                self.save('rule/post.json', operator)
                edits.append('operator_after_preflight')
            return result
        self.backend._free_waf_main__atomic_policy_text = fail_restore_then_edit
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [False, True]
        self.assertFalse(self.bundle(candidate)['status'])
        self.assertEqual(edits, ['restore_failure', 'operator_after_preflight'])
        self.assertEqual(self.read('rule/post.json'), operator)
        self.assertTrue((self.root / '.policy-recovery/pending.json').exists())
        self.assertEqual(self.backend._free_waf_main__checked_nginx_reload.call_count, 1)

    def test_multifamily_compensation_preserves_candidate_only_exceptions(self):
        original, candidate = self.multifamily_migration('BCX')
        atomic = self.backend._free_waf_main__atomic_policy_text
        failures, reloads = [], []
        def fail_restore(path, text, **kwargs):
            if Path(path).name == 'post.json' and json.loads(text) == original and not failures:
                failures.append(1)
                raise OSError('fixture restore failure')
            return atomic(path, text, **kwargs)
        def edit_exceptions():
            reloads.append(1)
            sites = self.read('site.json')
            sites['fixture.example']['disable_rule'] = {'header': [2], 'post': [2]}
            sites['new.example'] = {'disable_rule': {'header': [2], 'post': [2]}}
            self.save('site.json', sites)
            return False
        self.backend._free_waf_main__atomic_policy_text = fail_restore
        self.backend._free_waf_main__checked_nginx_reload.side_effect = edit_exceptions
        self.assertFalse(self.bundle(candidate)['status'])
        self.assertEqual(failures, [1])
        self.assertEqual(reloads, [1])
        for name, rows in candidate.items():
            self.assertEqual(self.read('rule/' + name + '.json'), rows)
        for conf in self.read('site.json').values():
            self.assertEqual(conf['disable_rule'], {'header': [2], 'post': [2]})
        self.assertTrue((self.root / '.policy-recovery/pending.json').exists())

    def test_multifamily_partial_publish_compensation_uses_each_rule_table(self):
        original, candidate = self.multifamily_migration('BCX')
        atomic = self.backend._free_waf_main__atomic_policy_text
        failures = []
        def fail_apply_and_restore(path, text, **kwargs):
            name = Path(path).name
            if name == 'post.json' and json.loads(text) == candidate['post'] and not failures:
                sites = self.read('site.json')
                sites['new.example'] = {'disable_rule': {'header': [2], 'post': [2]}}
                self.save('site.json', sites)
                failures.append('apply_post')
                raise OSError('fixture publish failure')
            if name == 'header.json' and json.loads(text) == original and failures == ['apply_post']:
                failures.append('restore_header')
                raise OSError('fixture restore failure')
            return atomic(path, text, **kwargs)
        self.backend._free_waf_main__atomic_policy_text = fail_apply_and_restore
        self.assertFalse(self.bundle(candidate)['status'])
        self.assertEqual(failures, ['apply_post', 'restore_header'])
        for name, rows in candidate.items():
            self.assertEqual(self.read('rule/' + name + '.json'), rows)
        sites = self.read('site.json')
        self.assertEqual(sites['fixture.example']['disable_rule'], {'header': [0], 'post': [0]})
        self.assertEqual(sites['new.example']['disable_rule'], {'header': [2], 'post': [1]})
        self.assertTrue((self.root / '.policy-recovery/pending.json').exists())

    def test_multifamily_partial_publish_unknown_dependency_stops_recovery(self):
        original, candidate = self.multifamily_migration()
        atomic = self.backend._free_waf_main__atomic_policy_text
        edits = []
        operator = [[1, 'OPERATOR', 'keep', 0]]
        def fail_after_replace(path, text, **kwargs):
            result = atomic(path, text, **kwargs)
            if Path(path).name == 'header.json' and json.loads(text) == candidate['header'] and not edits:
                self.save('rule/post.json', operator)
                edits.append(1)
                raise OSError('fixture readback failure')
            return result
        self.backend._free_waf_main__atomic_policy_text = fail_after_replace
        self.assertFalse(self.bundle(candidate)['status'])
        self.assertEqual(edits, [1])
        self.assertEqual(self.read('rule/post.json'), operator)
        self.assertTrue((self.root / '.policy-recovery/pending.json').exists())
        self.assertEqual(self.read('rule/header.json'), candidate['header'])
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_drop_notifications_sort_entire_bounded_sample(self):
        from contextlib import ExitStack
        import time
        base = int(time.mktime(time.strptime('2026-10-24 12:00:00', '%Y-%m-%d %H:%M:%S')))
        values = list(range(15, 30)) + list(range(15))
        events = [[base+n, '192.0.2.1', 'fixture.example', '/event-%d' % n, 60, 'post'] for n in values]
        drop = self.root / 'drop.log'
        drop.write_text(''.join(json.dumps(row)+'\n' for row in events), encoding='utf-8')
        original_open = builtins.open
        def opened(path, *args, **kwargs):
            return original_open(drop if str(path) == '/www/server/free_waf/drop_ip.log' else path, *args, **kwargs)
        with ExitStack() as stack:
            stack.enter_context(patch('builtins.open', side_effect=opened))
            stack.enter_context(patch.object(os.path, 'exists', side_effect=lambda p: str(p) == '/www/server/free_waf/drop_ip.log'))
            self.backend._free_waf_main__date_list = lambda days: ['2026-10-24']
            result = self.backend.get_defense_notifications(types.SimpleNamespace(limit=10, days=1))
        self.assertEqual([r['uri'] for r in result['items']], ['/event-%d' % n for n in range(29, 19, -1)])

    def test_malformed_rows_never_reach_runtime(self):
        for row in (1, {}, [1], [1, 2, 'reason', 0], [True, 'x', 'reason', 0]):
            with self.subTest(row=row):
                self.assertFalse(self.bundle({'post': [row]})['status'])
                self.assertEqual(self.read('rule/post.json'), [])

    def test_bundle_validates_every_file_before_any_write(self):
        result = self.bundle({'url_white': ['^/public$'], 'post': 'bad'})
        self.assertFalse(result['status'])
        self.assertEqual(self.read('rule/url_white.json'), [])
        self.public.serviceReload.assert_not_called()
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_bundle_reloads_once(self):
        self.assertTrue(self.bundle({'url_white': ['^/public$'], 'url_black': ['^/private$']})['status'])
        self.assertEqual(self.backend._free_waf_main__checked_nginx_reload.call_count, 1)

    def test_write_failure_is_not_reported_as_success(self):
        self.public.writeFile = Mock(return_value=False)
        result = self.backend.add_url_white(types.SimpleNamespace(url_rule='^/public$'))
        self.assertFalse(result['status'])
        self.assertEqual(self.read('rule/url_white.json'), [])
        self.public.serviceReload.assert_not_called()
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_failed_reload_restores_all_bundle_files(self):
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [False, True]
        result = self.bundle({'url_white': ['^/public$'], 'url_black': ['^/private$']})
        self.assertFalse(result['status'])
        self.assertEqual(self.read('rule/url_white.json'), [])
        self.assertEqual(self.read('rule/url_black.json'), [])

    def test_unsafe_rule_name_is_rejected(self):
        result = self.backend.import_data(types.SimpleNamespace(s_Name='../config', pdata='["x"]'))
        self.assertFalse(result['status'])

    def log_environment(self, files):
        from contextlib import ExitStack
        stack = ExitStack()
        logs = self.root / 'logs'
        logs.mkdir(exist_ok=True)
        for name, rows in files.items():
            (logs / name).write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8', newline='')
        prefix = '/www/wwwlogs/free_waf_log/'
        real_open, real_exists, real_listdir, real_scandir = builtins.open, os.path.exists, os.listdir, os.scandir
        def mapped(path):
            return str(logs / str(path)[len(prefix):]) if str(path).startswith(prefix) else path
        stack.enter_context(patch('builtins.open', side_effect=lambda path, *a, **kw: real_open(mapped(path), *a, **kw)))
        stack.enter_context(patch.object(os.path, 'exists', side_effect=lambda path: False if str(path) == '/www/server/free_waf/drop_ip.log' else real_exists(mapped(path))))
        stack.enter_context(patch.object(os, 'listdir', side_effect=lambda path: real_listdir(mapped(path))))
        stack.enter_context(patch.object(os, 'scandir', side_effect=lambda path: real_scandir(mapped(path))))
        self.backend._free_waf_main__date_list = lambda days: ['2026-10-24']
        return stack

    def events(self, count):
        return [['2026-10-24 12:%02d:%02d' % (n // 60, n % 60), '192.0.2.1',
                 'GET', '/event-%d' % n, 'fixture', 'post', 'fixture'] for n in range(count)]

    def test_notifications_keep_latest_events_not_oldest(self):
        with self.log_environment({'fixture.example_2026-10-24.log': self.events(85)}):
            result = self.backend.get_defense_notifications(types.SimpleNamespace(limit=10, days=1))
        self.assertEqual([row['uri'] for row in result['items']], ['/event-%d' % n for n in range(84, 74, -1)])

    def test_search_has_bounded_work_and_honest_partial_total(self):
        self.backend.LEGACY_LOG_MAX_LINES = 30
        with self.log_environment({'fixture.example_2026-10-24.log': self.events(85)}):
            result = self.backend.get_report_search(types.SimpleNamespace(limit=10, p=1, days=1))
        self.assertEqual(result['rows'][0]['uri'], '/event-84')
        self.assertTrue(result.get('coverage', {}).get('partial'))
        self.assertFalse(result.get('total_exact', True))
        self.assertLessEqual(result['coverage']['scanned_lines'], 30)

    def test_reverse_reader_offsets_survive_multiple_blocks_and_unicode(self):
        path = self.root / 'large.log'
        data = ('x' * 200 + '\u4e2d\u6587\n') * 1000 + 'last'
        path.write_text(data, encoding='utf-8', newline='')
        budget = self.backend._free_waf_main__legacy_log_budget()
        rows = list(self.backend._free_waf_main__bounded_log_rows(str(path), budget))
        blob = path.read_bytes()
        self.assertEqual(len(rows), 1001)
        for offset, row in rows:
            self.assertEqual(blob[offset:].split(b'\n', 1)[0].decode(), row)

    def test_notification_merge_does_not_prefer_filename_over_time(self):
        with self.log_environment({'z.example_2026-10-24.log': self.events(15),
                                   'a.example_2026-10-24.log': self.events(85)}):
            result = self.backend.get_defense_notifications(types.SimpleNamespace(limit=10, days=1))
        self.assertEqual([row['uri'] for row in result['items']], ['/event-%d' % n for n in range(84, 74, -1)])

    def test_detail_reads_byte_offset_without_scanning_prefix(self):
        rows = self.events(85)
        offset = len(''.join(json.dumps(row) + '\n' for row in rows[:84]).encode())
        with self.log_environment({'fixture.example_2026-10-24.log': rows}):
            result = self.backend.get_report_http_detail(types.SimpleNamespace(
                siteName='fixture.example', date='2026-10-24', line_no=0, offset=offset))
        self.assertTrue(result['status'])
        self.assertEqual(result['data']['uri'], '/event-84')

    def test_legacy_ip_and_uri_stats_obey_the_same_read_budget(self):
        self.backend.LEGACY_LOG_MAX_LINES = 30
        self.backend._free_waf_main__ban_store = lambda: types.SimpleNamespace(active_exact_ips=lambda: [])
        for endpoint in (self.backend.get_ip_stats, self.backend.get_uri_stats):
            with self.subTest(endpoint=endpoint.__name__):
                with self.log_environment({'fixture.example_2026-10-24.log': self.events(85)}):
                    result = endpoint(types.SimpleNamespace(days=1))
                self.assertLessEqual(sum(row.get('total', row.get('count', 0)) for row in result), 30)

    def test_overview_and_dashboard_obey_read_budget(self):
        self.backend.LEGACY_LOG_MAX_LINES = 30
        self.backend.get_waf_drop_ip = lambda get: []
        for endpoint, key in ((self.backend.get_overview_report, 'total_protection'),
                              (self.backend.get_report_dashboard_summary, 'total_hits')):
            with self.subTest(endpoint=endpoint.__name__):
                with self.log_environment({'fixture.example_2026-10-24.log': self.events(85)}):
                    result = endpoint(types.SimpleNamespace(days=1))
                self.assertLessEqual(result['summary'][key], 30)
                self.assertTrue(result.get('coverage', {}).get('partial'))


if __name__ == '__main__':
    unittest.main()
