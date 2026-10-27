import collections
import contextlib
import html
import json
import os
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tests.test_panel_performance import load_backend


class ReportBackendRegressionTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / 'drop_ip.log'
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            readFile=Mock(), writeFile=Mock(), httpGet=Mock(), httpPost=Mock(), WriteLog=Mock())
        self.backend = load_backend(self.public)
        self.backend._free_waf_main__path = str(self.root) + os.sep
        self.backend.get_waf_drop_ip = Mock(return_value=['192.0.2.1'])
        self.opened = []
        original_open, original_exists = open, os.path.exists

        def mapped(path):
            return self.path if str(path) == '/www/server/free_waf/drop_ip.log' else path

        def open_file(path, *args, **kwargs):
            self.assertIn(args[0] if args else kwargs.get('mode', 'r'), ('r', 'rb'))
            stream = original_open(mapped(path), *args, **kwargs)
            self.opened.append(stream)
            return stream

        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch('builtins.open', side_effect=open_file))
        stack.enter_context(patch.object(os.path, 'exists', side_effect=lambda path: original_exists(mapped(path))))

    def rows(self, count):
        now = int(time.time())
        return [[now - count + i, '192.0.2.1', 'fixture.example', '/%d' % i, 60, 'cc']
                for i in range(count)]

    def write(self, rows, newline=False):
        self.path.write_text('\n'.join(json.dumps(row) for row in rows) + ('\n' if newline else ''),
                             encoding='utf-8')

    def read(self, **values):
        return self.backend.get_blockade_records(types.SimpleNamespace(**values))

    def test_sync_rule_returns_disabled_failure_without_calling_old_sync(self):
        self.backend.sync_cnlist = Mock(return_value=dict(status=False, msg='disabled'))
        result = self.backend.sync_rule(None)
        self.assertIs(result.get('status'), False)
        self.assertIn('\u505c\u7528', result.get('msg', ''))
        self.backend.sync_cnlist.assert_not_called()
        self.public.httpGet.assert_not_called()
        self.public.httpPost.assert_not_called()
        self.public.readFile.assert_not_called()
        self.public.writeFile.assert_not_called()
        self.public.WriteLog.assert_not_called()

    def test_pages_preserve_metadata_and_report_only_known_more_rows(self):
        self.write(self.rows(21))
        for page, size, more in ((1, 10, True), (2, 10, True), (3, 1, False), (4, 0, False)):
            with self.subTest(page=page):
                result = self.read(p=page, limit=10)
                self.assertEqual(len(result['rows']), size)
                self.assertEqual((result['p'], result['limit'], result['total']), (page, 10, 21))
                self.assertIs(result.get('has_more'), more)
                self.assertIs(result['total_exact'], True)
                self.assertIs(result['coverage']['partial'], False)
                self.assertEqual(result['coverage']['scanned_lines'], 21)
        self.assertTrue(all(stream.closed for stream in self.opened))

    def test_export_keeps_requested_page_and_coverage(self):
        self.write(self.rows(21))
        before = self.path.read_bytes()
        result = self.backend.export_blockade_records(types.SimpleNamespace(p=2, limit=10))
        self.assertEqual([row['uri'] for row in result['records']], ['/%d' % i for i in range(10, 0, -1)])
        self.assertEqual(result['total'], 21)
        self.assertEqual((result.get('p'), result.get('limit')), (2, 10))
        self.assertIs(result.get('has_more'), True)
        self.assertEqual(result.get('active_scope'), 'global_ip_only')
        self.assertIs(result['total_exact'], True)
        self.assertEqual(result['coverage']['scanned_lines'], 21)
        self.assertEqual(self.path.read_bytes(), before)
        self.public.writeFile.assert_not_called()

    def test_export_queries_active_ips_once(self):
        self.write(self.rows(1))
        self.backend.get_waf_drop_ip.side_effect = [['192.0.2.1'], ['192.0.2.2']]
        result = self.backend.export_blockade_records(types.SimpleNamespace(p=1, limit=10))
        self.backend.get_waf_drop_ip.assert_called_once_with(None)
        self.assertEqual(result['active_ips'], ['192.0.2.1'])
        self.assertIs(result['records'][0]['active'], True)

    def test_line_budget_marks_partial_without_an_infinite_next_page(self):
        self.write(self.rows(31))
        self.backend.LEGACY_LOG_MAX_LINES = 20
        first, last = self.read(p=1, limit=10), self.read(p=2, limit=10)
        self.assertEqual(first['total'], 20)
        self.assertIs(first.get('has_more'), True)
        self.assertIs(last.get('has_more'), False)
        self.assertIs(last['total_exact'], False)
        self.assertIs(last['coverage']['partial'], True)
        self.assertEqual(last['coverage']['scanned_lines'], 20)
        self.assertEqual(last['rows'][-1]['uri'], '/11')

    def test_byte_budget_is_retained_for_bad_lines(self):
        self.path.write_bytes(b'not-json\n' * 1000)
        self.backend.LEGACY_LOG_MAX_BYTES = 64
        result = self.read()
        self.assertEqual(result['rows'], [])
        self.assertLessEqual(result['coverage']['scanned_bytes'], 64)
        self.assertIs(result['coverage']['partial'], True)
        self.assertIs(result['total_exact'], False)
        self.assertIs(result.get('has_more'), False)

    def test_deadline_budget_is_retained(self):
        self.write(self.rows(21))
        self.backend.LEGACY_LOG_MAX_SECONDS = -1
        result = self.read()
        self.assertEqual(result['rows'], [])
        self.assertEqual(result['coverage']['scanned_bytes'], 0)
        self.assertIs(result['coverage']['partial'], True)
        self.assertIs(result['total_exact'], False)

    def test_malformed_rows_match_legacy_log_validation_and_do_not_hide_good_rows(self):
        now = int(time.time())
        valid = [now, '192.0.2.1', 'fixture.example', '/good', 60, 'cc']
        invalid = (['bad'], [], {}, 'text', None,
                   [None, '192.0.2.1', '', '/', 60],
                   [True, '192.0.2.1', '', '/', 60],
                   [now, 'not-ip', '', '/', 60],
                   [now, '192.0.2.1', {}, '/', 60],
                   [now, '192.0.2.1', '', '/', -1],
                   [now, '192.0.2.1', '', '/', float('nan')],
                   [now, '192.0.2.1', '', '/', float('inf')],
                   [now, '192.0.2.1', '', '/', 1.5])
        self.write([valid] + list(invalid) + [valid[:5]])
        result = self.read()
        self.assertEqual(result['total'], 2)
        self.assertEqual([row['uri'] for row in result['rows']], ['/good', '/good'])
        self.assertEqual(result['coverage']['scanned_lines'], len(invalid) + 2)
        self.assertIs(result['total_exact'], True)

    def test_bad_rows_still_consume_line_budget(self):
        self.write(self.rows(1) + [['bad']] * 40)
        self.backend.LEGACY_LOG_MAX_LINES = 5
        result = self.read()
        self.assertEqual(result['rows'], [])
        self.assertEqual(result['coverage']['scanned_lines'], 5)
        self.assertIs(result['coverage']['partial'], True)
        self.assertIs(result['total_exact'], False)

    def test_text_is_escaped_once_after_validation(self):
        row = self.rows(1)[0]
        row[2:4] = ['<site>&', '/<script>']
        self.write([row])
        result = self.read()['rows'][0]
        self.assertEqual(result['site'], html.escape(row[2], quote=True))
        self.assertEqual(result['uri'], html.escape(row[3], quote=True))

    def test_active_is_global_ip_presence_not_proof_of_record_or_site(self):
        now = int(time.time())
        self.write([[now - 300, '192.0.2.1', 'other.example', '/old', 60, 'cc'],
                    [now + 30, '192.0.2.1', 'fixture.example', '/future', 60, 'cc'],
                    [now, '192.0.2.2', 'fixture.example', '/not-active', 60, 'cc']])
        result = self.read()
        by_uri = {row['uri']: row for row in result['rows']}
        self.assertIs(by_uri['/old']['active'], True)
        self.assertIs(by_uri['/future']['active'], True)
        self.assertIs(by_uri['/not-active']['active'], False)
        for row in result['rows']:
            self.assertEqual(row.get('active_scope'), 'global_ip_only')
            self.assertIn('\u672a\u786e\u8ba4', row.get('active_notice', ''))
        self.assertEqual(result.get('active_scope'), 'global_ip_only')
        self.assertIn('\u672a\u786e\u8ba4', result.get('active_notice', ''))

    def test_missing_log_has_exact_empty_page(self):
        result = self.read()
        self.assertEqual(result['rows'], [])
        self.assertEqual(result['total'], 0)
        self.assertIs(result['total_exact'], True)
        self.assertIs(result.get('has_more'), False)

    def test_active_ipv6_uses_address_identity_and_keeps_original_display(self):
        cases = (
            ('2001:0DB8:0:0:0:0:0:1', '2001:db8::1', True),
            ('2001:db8::1', '2001:0DB8:0:0:0:0:0:1', True),
            ('::ffff:192.0.2.1', '::ffff:c000:201', True),
            ('::ffff:192.0.2.1', '192.0.2.1', False),
        )
        for logged, runtime, expected in cases:
            with self.subTest(logged=logged, runtime=runtime):
                self.backend.get_waf_drop_ip.return_value = [runtime]
                self.write([[int(time.time()), logged, 'fixture.example', '/', 60, 'cc']])
                result = self.read()
                self.assertIs(result['rows'][0]['active'], expected)
                self.assertEqual(result['rows'][0]['ip'], logged)
                self.assertEqual(result['active_ips'], [runtime])

    def test_legacy_ban_view_normalizes_ipv6_and_keeps_expiry_and_duplicate_rules(self):
        expanded, compressed = '2001:0DB8:0:0:0:0:0:1', '2001:db8::1'
        now = int(time.time())
        self.write([[now - 100, compressed, '', '/expired', 60, 'cc'],
                    [now - 10, compressed, '', '/older', 60, 'cc'],
                    [now - 5, expanded, '', '/latest', 60, 'cc'],
                    [now - 5, '::ffff:192.0.2.1', '', '/mapped', 60, 'cc']])
        for runtime in ([compressed, '192.0.2.1'], {compressed: 60, '192.0.2.1': 60}):
            with self.subTest(runtime=runtime):
                self.backend.get_waf_drop_ip.return_value = runtime
                rows = self.backend.get_safe_logs(types.SimpleNamespace(drop_ip='1', p=1))
                self.assertIsInstance(rows, list)
                by_uri = {row[3]: row for row in rows}
                self.assertIs(by_uri['/latest'][6], True)
                self.assertEqual(by_uri['/latest'][1], expanded)
                for uri in ('/expired', '/older', '/mapped'):
                    self.assertIs(by_uri[uri][6], False)

    def overview(self):
        with patch.object(self.backend, '_free_waf_main__bounded_waf_files', return_value=[]), \
                patch.object(self.backend, '_free_waf_main__local_service', side_effect=RuntimeError()), \
                patch.dict('sys.modules', {'maxminddb': None}):
            return self.backend.get_overview_report(None)

    def test_overview_matches_ipv6_by_identity_without_duplicate_runtime_rows(self):
        expanded, compressed = '2001:0DB8:0:0:0:0:0:1', '2001:db8::1'
        now = int(time.time())
        self.write([[now - 10, compressed, '', '/older', 60, 'cc'],
                    [now - 5, expanded, '', '/latest', 60, 'cc']])
        for runtime in ([compressed, expanded], {compressed: 60, expanded: 60}):
            with self.subTest(runtime=runtime):
                self.backend.get_waf_drop_ip.return_value = runtime
                result = self.overview()
                self.assertEqual(result['active_bans'], 1)
                self.assertEqual(result['summary']['active_bans'], 1)
                self.assertEqual(len(result['blocked_ips']), 1)
                row = result['blocked_ips'][0]
                self.assertIs(row['active'], True)
                self.assertEqual(row['ip'], expanded)
                self.assertEqual(row['total_count'], 2)

    def test_overview_does_not_treat_mapped_ipv6_as_ipv4(self):
        self.write([[int(time.time()), '::ffff:192.0.2.1', '', '/', 60, 'cc']])
        self.backend.get_waf_drop_ip.return_value = ['192.0.2.1']
        result = self.overview()
        rows = {row['ip']: row for row in result['blocked_ips']}
        self.assertIs(rows['::ffff:192.0.2.1']['active'], False)
        self.assertIs(rows['192.0.2.1']['active'], True)

    def test_overview_keeps_legacy_unrecognized_ip_text_as_inactive_history(self):
        addresses = ('fe80::1%eth0', '<unknown>&')
        self.write([[int(time.time()), ip, '', '/', 60, 'cc'] for ip in addresses])
        result = self.overview()
        rows = {row['ip']: row for row in result['blocked_ips']}
        for ip in addresses:
            row = rows[html.escape(ip, quote=True)]
            self.assertIs(row['active'], False)
            self.assertEqual(row['total_count'], 1)
            self.assertEqual(row['count_24h'], 1)

    def test_runtime_snapshot_accepts_dict_and_list_subclasses_but_not_iterators(self):
        class AddressList(list):
            pass

        self.write([[int(time.time()), '192.0.2.1', '', '/', 60, 'cc']])
        for data, expected in ((collections.OrderedDict([('192.0.2.1', 60)]), True),
                               (AddressList(['192.0.2.1']), True),
                               (iter(['192.0.2.1']), False)):
            with self.subTest(data=type(data).__name__):
                self.backend.get_waf_drop_ip.return_value = data
                result = self.read()
                self.assertIs(result['rows'][0]['active'], expected)
                self.assertEqual(result['active_ips'], ['192.0.2.1'] if expected else [])

    def test_runtime_ip_shapes_are_filtered_without_changing_valid_originals(self):
        expanded = '2001:0DB8:0:0:0:0:0:1'
        invalid = [None, 7, [], {}, 'not-ip', '10.0.0.0/8', 'a' * 46, 'fe80::1%eth0']
        self.write([[int(time.time()), '2001:db8::1', '', '/', 60, 'cc']])
        for runtime, originals in (([expanded] + invalid, [expanded]),
                                   ({expanded: 60, None: 7, 'not-ip': 3}, [expanded]),
                                   (invalid, []), (None, []), (7, []), (expanded, [])):
            with self.subTest(runtime=runtime):
                self.backend.get_waf_drop_ip.return_value = runtime
                result = self.read()
                self.assertEqual(result['active_ips'], originals)
                row = result['rows'][0]
                self.assertIs(row['active'], bool(originals))
                self.assertEqual(row['active_scope'], 'global_ip_only')
                self.assertIn('\u672a\u786e\u8ba4', row['active_notice'])
                overview = self.overview()
                self.assertEqual(overview['active_bans'], len(originals))

    def test_row_parsing_time_is_counted_by_the_shared_read_deadline(self):
        self.write(self.rows(21))
        clock = [1000.0]
        parse = self.backend._free_waf_main__parse_drop_row

        def slow_parse(*args):
            result = parse(*args)
            clock[0] += 2.0
            return result

        with patch.object(time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(self.backend, '_free_waf_main__parse_drop_row', side_effect=slow_parse):
            result = self.read()
        self.assertEqual(len(result['rows']), 1)
        self.assertEqual(result['coverage']['scanned_lines'], 1)
        self.assertIs(result['coverage']['partial'], True)
        self.assertIs(result['total_exact'], False)

    def test_search_missing_log_directory_has_complete_empty_metadata_without_reads(self):
        with patch.object(os.path, 'exists', return_value=False), \
                patch.object(self.backend, '_free_waf_main__bounded_waf_files') as files, \
                patch.object(self.backend, '_free_waf_main__merged_waf_rows') as rows:
            result = self.backend.get_report_search(types.SimpleNamespace(p=3, limit=10))
        self.assertEqual(result['rows'], [])
        self.assertEqual((result['total'], result['p'], result['limit']), (0, 3, 10))
        self.assertEqual(result['summary'], {'matched': 0})
        self.assertIs(result.get('has_more'), False)
        self.assertIs(result.get('total_exact'), True)
        self.assertEqual(result.get('coverage'), dict(partial=False, scanned_lines=0, scanned_bytes=0,
                                                    scanned_files=0, scope='bounded_recent_logs'))
        files.assert_not_called()
        rows.assert_not_called()
        self.assertEqual(self.opened, [])
        self.public.readFile.assert_not_called()
        self.public.writeFile.assert_not_called()
        self.backend.get_waf_drop_ip.assert_not_called()


class SafetyBaselineCCRegressionTest(unittest.TestCase):
    def setUp(self):
        self.public = types.SimpleNamespace(returnMsg=lambda status, msg: dict(status=status, msg=msg),
                                            readFile=Mock(), writeFile=Mock())
        self.backend = load_backend(self.public)
        self.backend.get_waf_drop_ip = Mock(return_value=[])
        self.backend._free_waf_main__get_rule = Mock(return_value=[])

    def baseline(self, global_endtime, site_endtime, runtime_safe=True):
        def read(path):
            if path.endswith('init.lua'):
                return 'local lock_time = tonumber(endtime) or 60' if runtime_safe else 'endtime * safe_count'
            if path.endswith('config.json'):
                return json.dumps(dict(cc=dict(endtime=global_endtime)))
            if path.endswith('site.json'):
                return json.dumps({'fixture.example': dict(cc=dict(endtime=site_endtime))})
            return False
        self.public.readFile.side_effect = read
        result = self.backend.get_safety_baseline(None)
        self.public.writeFile.assert_not_called()
        return next(row for row in result['items'] if row['key'] == 'cc_ban_60s')

    def test_one_to_sixty_seconds_is_safe_for_both_global_and_site(self):
        for global_endtime, site_endtime in ((1, 60), (60, 1), (30, 20), ('30', '45'), (60, 60)):
            with self.subTest(global_endtime=global_endtime, site_endtime=site_endtime):
                result = self.baseline(global_endtime, site_endtime)
                self.assertIs(result['status'], True)
                self.assertNotIn('\u56fa\u5b9a\u4e3a 60', result['detail'])
                self.assertIn('1', result['action'])

    def test_invalid_or_coercible_durations_are_not_safe(self):
        for duration in (0, -1, 61, True, False, 60.0, 60.1, None, '60.0', '+60', ' 60', '060', '\uff16\uff10'):
            for scope in ('global', 'site'):
                with self.subTest(duration=duration, scope=scope):
                    result = self.baseline(duration if scope == 'global' else 60,
                                           duration if scope == 'site' else 60)
                    self.assertIs(result['status'], False)

    def test_runtime_duration_escalation_is_not_safe_even_with_valid_config(self):
        self.assertIs(self.baseline(30, 30, runtime_safe=False)['status'], False)

    def test_read_or_parse_failure_names_the_configuration_file_without_writes(self):
        self.baseline(30, 30)
        read = self.public.readFile.side_effect
        for filename in ('config.json', 'site.json'):
            for failure in (None, '', 'bad-json', '[]', PermissionError('private path')):
                with self.subTest(filename=filename, failure=type(failure).__name__):
                    def broken(path):
                        if path.endswith(filename):
                            if isinstance(failure, Exception):
                                raise failure
                            return failure
                        return read(path)

                    self.public.readFile.side_effect = broken
                    result = self.backend.get_safety_baseline(None)
                    row = next(item for item in result['items'] if item['key'] == 'cc_ban_60s')
                    self.assertIs(row['status'], False)
                    self.assertIn(filename, html.unescape(row['detail']))
                    self.assertNotIn('private path', str(result))
        self.public.writeFile.assert_not_called()


if __name__ == '__main__':
    unittest.main()
