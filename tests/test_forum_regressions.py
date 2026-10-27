import builtins
import contextlib
import html
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tests.test_panel_performance import load_backend


class PanelArgs(types.SimpleNamespace):
    def __contains__(self, key):
        return hasattr(self, key)


class ForumLogRegressionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.drop = self.root / 'drop_ip.log'
        self.site = self.root / 'fixture.example_2026-10-25.log'
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            get_error_info=lambda: dict(status=False, error=type(sys.exc_info()[1]).__name__),
            ReadFile=lambda path: Path(path).read_text(encoding='utf-8'),
            WriteFile=lambda path, body: Path(path).write_text(body, encoding='utf-8'))
        self.backend = load_backend(self.public)
        self.backend.get_safe_logs.__globals__['sys'] = sys
        self.backend._free_waf_main__path = str(self.root) + os.sep
        self.backend._free_waf_main__PATH = str(self.root) + os.sep
        self.backend.get_waf_drop_ip = Mock(return_value=['192.0.2.1'])
        self.opens = []
        original_open, original_exists = open, os.path.exists

        def redirect(path):
            text = str(path)
            if text == '/www/server/free_waf/drop_ip.log':
                return self.drop
            if text.startswith('/www/wwwlogs/free_waf_log/'):
                return self.root / text.rsplit('/', 1)[-1]
            return path

        def open_file(path, *args, **kwargs):
            stream = original_open(redirect(path), *args, **kwargs)
            self.opens.append(stream)
            return stream

        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch('builtins.open', side_effect=open_file))
        stack.enter_context(patch.object(os.path, 'exists', side_effect=lambda path: original_exists(redirect(path))))
        self.addCleanup(lambda: [stream.close() for stream in self.opens if not stream.closed])

    def write_rows(self, rows, drop=False, newline=True):
        path = self.drop if drop else self.site
        path.write_text('\n'.join(json.dumps(row) for row in rows) + ('\n' if newline else ''), encoding='utf-8')

    def read(self, drop=False, **kwargs):
        arguments = dict(siteName='fixture.example', toDate='2026-10-25', p=1)
        arguments.update(kwargs)
        if drop:
            arguments['drop_ip'] = '1'
        return self.backend.get_safe_logs(PanelArgs(**arguments))

    def test_text_encoding_and_rule_addition_do_not_import_cgi(self):
        original_import = builtins.__import__

        def import_without_cgi(name, *args, **kwargs):
            if name == 'cgi':
                raise ModuleNotFoundError("No module named 'cgi'")
            return original_import(name, *args, **kwargs)

        (self.root / 'rule.json').write_text('[]', encoding='utf-8')
        with patch('builtins.__import__', side_effect=import_without_cgi):
            self.assertEqual(self.backend.xssencode('ordinary text'), 'ordinary text')
            result = self.backend.shell_add_rule(PanelArgs(rule='fixture-rule'))
        self.assertTrue(result['status'])

    def test_log_read_does_not_import_cgi(self):
        original_import = builtins.__import__

        def import_without_cgi(name, *args, **kwargs):
            if name == 'cgi':
                raise ModuleNotFoundError("No module named 'cgi'")
            return original_import(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=import_without_cgi):
            self.assertEqual(self.read(), [])

    def test_short_site_records_get_stable_detail_fields(self):
        self.write_rows([['2026-10-25 12:00:00', '192.0.2.1', 'POST', '/save', 'fixture', 'post']])
        rows = self.read()
        self.assertIsInstance(rows, list)
        self.assertEqual(len(rows), 1)
        self.assertGreaterEqual(len(rows[0]), 7)
        self.assertEqual(rows[0][6], '')

    def test_site_records_escape_only_after_json_decode(self):
        payload = '<script>& "quoted"'
        self.write_rows([['2026-10-25 12:00:00', '192.0.2.1', 'POST', '/save', payload, 'post', 'rule >> value']])
        row = self.read()[0]
        self.assertEqual(row[4], html.escape(payload, quote=True))
        self.assertEqual(row[6], 'rule &gt;&gt; value')

    def test_malformed_ban_rows_cannot_hide_valid_history(self):
        now = int(self.backend.get_safe_logs.__globals__['time'].time())
        valid = [now - 10, '192.0.2.1', 'fixture.example', '/save', 60, 'cc']
        self.write_rows([valid, ['bad'], {'time': now}, 'text', [None, '192.0.2.1', '', '', 60]], drop=True)
        rows = self.read(drop=True)
        self.assertIsInstance(rows, list)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], '192.0.2.1')
        self.assertTrue(rows[0][6])

    def test_legacy_five_field_ban_has_default_reason_and_boolean_state(self):
        now = int(self.backend.get_safe_logs.__globals__['time'].time())
        self.write_rows([[now - 5, '192.0.2.1', 'fixture.example', '/save', 60]], drop=True)
        rows = self.read(drop=True)
        self.assertEqual(rows[0][5], '')
        self.assertIs(rows[0][6], True)

    def test_ban_numbers_are_valid_finite_nonnegative_values(self):
        now = int(self.backend.get_safe_logs.__globals__['time'].time())
        self.write_rows([[stamp, '192.0.2.1', '', '', duration, 'cc']
                         for stamp, duration in [(float('nan'), 60), (now, float('inf')),
                                                 (True, 60), (now, -1), (now, 'bad')]], drop=True)
        self.assertEqual(self.read(drop=True), [])

    def test_expired_and_duplicate_bans_are_not_both_active(self):
        now = int(self.backend.get_safe_logs.__globals__['time'].time())
        self.write_rows([[now - 100, '192.0.2.1', '', '/', 60, 'cc'],
                         [now - 10, '192.0.2.1', '', '/', 60, 'cc'],
                         [now - 5, '192.0.2.1', '', '/', 60, 'cc']], drop=True)
        rows = self.read(drop=True)
        self.assertEqual([row[6] for row in rows], [True, False, False])

    def test_site_pagination_counts_only_valid_records_and_keeps_last_line(self):
        self.write_rows([['2026-10-25 12:00:00', '192.0.2.1', 'POST', '/%d' % i, '', 'post']
                         for i in range(21)], newline=False)
        self.assertEqual([row[3] for row in self.read()], ['/%d' % i for i in range(20, 10, -1)])
        self.assertEqual([row[3] for row in self.read(p=3)], ['/0'])
        self.assertTrue(all(stream.closed for stream in self.opens))

    def test_invalid_query_is_rejected_before_opening_a_log(self):
        for params in ({'siteName': '../secret'}, {'toDate': '../../secret'},
                       {'toDate': '2026-02-30'}, {'p': 0}, {'p': '1.0'}, {'p': True}):
            with self.subTest(params=params):
                self.opens.clear()
                result = self.read(**params)
                self.assertIsInstance(result, dict)
                self.assertIs(result.get('status'), False)
                self.assertFalse(self.opens)

    def test_empty_log_closes_the_file(self):
        self.site.write_bytes(b'')
        self.assertEqual(self.read(), [])
        self.assertTrue(self.opens)
        self.assertTrue(all(stream.closed for stream in self.opens))

    def test_invalid_rows_have_a_bounded_scan_budget(self):
        self.write_rows([['bad']] * 40, drop=True)
        self.backend.LEGACY_LOG_MAX_LINES = 5
        result = self.read(drop=True)
        self.assertIsInstance(result, dict)
        self.assertIs(result.get('status'), False)
        self.assertIn('msg', result)

    def test_ban_pagination_matches_ten_row_ui_and_deduplicates_across_pages(self):
        now = int(self.backend.get_safe_logs.__globals__['time'].time())
        self.write_rows([[now - i, '192.0.2.1', '', '/', 60, 'cc'] for i in range(25)], drop=True)
        first, second = self.read(drop=True), self.read(drop=True, p=2)
        self.assertEqual(len(first), 10)
        self.assertEqual(len(second), 10)
        self.assertEqual(sum(row[6] for row in first + second), 1)


class ForumLogDateListRegressionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.public = types.SimpleNamespace(returnMsg=lambda status, msg: dict(status=status, msg=msg))
        self.backend = load_backend(self.public)
        self.scandir = os.scandir

    def dates(self, site='fixture.example'):
        return self.backend.get_logs_list(PanelArgs(siteName=site))

    def test_fresh_install_without_log_directory_returns_an_empty_list(self):
        missing = self.root / 'missing'
        with patch.object(os, 'listdir', side_effect=FileNotFoundError()), \
                patch.object(os, 'scandir', side_effect=lambda path: self.scandir(missing)):
            self.assertEqual(self.dates(), [])
        self.assertFalse(missing.exists(), 'a read must not create the log directory')

    def test_date_listing_accepts_only_real_days_for_exact_site_regular_logs(self):
        for filename in ('fixture.example_2026-10-25.log', 'fixture.example_2024-02-29.log',
                         'fixture.example_2026-02-30.log', 'fixture.example_2026-13-01.log',
                         'fixture.example_2026-10-25.log.bak', 'fixture.example_other_2026-10-24.log',
                         'other.example_2026-10-25.log', 'fixture.example_%3Cscript%3E.log'):
            (self.root / filename).touch()
        (self.root / 'fixture.example_2026-10-26.log').mkdir()
        with patch.object(os, 'listdir', return_value=os.listdir(self.root)), \
                patch.object(os, 'scandir', side_effect=lambda path: self.scandir(self.root)):
            self.assertEqual(self.dates(), ['2026-10-25', '2024-02-29'])

    def test_invalid_site_is_rejected_without_enumerating_the_directory(self):
        with patch.object(os, 'listdir') as listing, patch.object(os, 'scandir') as scanning:
            for site in (None, '', '../secret', 'fixture.example/other'):
                with self.subTest(site=site):
                    result = self.dates(site)
                    self.assertIsInstance(result, dict)
                    self.assertIs(result.get('status'), False)
            listing.assert_not_called()
            scanning.assert_not_called()

    def test_unreadable_directory_is_a_safe_failure_not_no_logs(self):
        with patch.object(os, 'listdir', side_effect=PermissionError('private detail')), \
                patch.object(os, 'scandir', side_effect=PermissionError('private detail')):
            result = self.dates()
        self.assertIs(result.get('status'), False)
        self.assertNotIn('private detail', result.get('msg', ''))

    def test_listing_budget_does_not_return_an_apparently_complete_subset(self):
        for filename in ('unrelated-a', 'unrelated-b', 'fixture.example_2026-10-25.log'):
            (self.root / filename).touch()
        self.backend.LEGACY_LOG_MAX_LINES = 1
        with patch.object(os, 'listdir', return_value=os.listdir(self.root)), \
                patch.object(os, 'scandir', side_effect=lambda path: self.scandir(self.root)):
            result = self.dates()
        self.assertIsInstance(result, dict)
        self.assertIs(result.get('status'), False)


if __name__ == '__main__':
    unittest.main()
