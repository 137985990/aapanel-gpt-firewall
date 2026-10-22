import ast
import copy
import datetime
import html
import io
import json
import os
import re
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


PLUGIN_DIR = Path(__file__).resolve().parents[1]


def load_backend(public):
    # Execute the production class without importing the panel's process globals.
    source = ast.parse((PLUGIN_DIR / "free_waf_main.py").read_text(encoding="utf-8"))
    nodes = [node for node in source.body if isinstance(node, ast.ClassDef)]
    namespace = dict(os=os, json=json, time=time, re=re, public=public, html=html)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "free_waf_main.py", "exec"), namespace)
    return namespace["free_waf_main"]()


class PanelPerformanceTest(unittest.TestCase):
    def setUp(self):
        self.public = types.SimpleNamespace()
        self.backend = load_backend(self.public)

    def test_home_read_does_not_install_write_or_query_domains(self):
        config = {"open": True, "start_time": 0}
        totals = {"total": 10, "rules": {"args": 2, "url": 3}, "sites": {}}

        def read_file(path):
            if path.endswith("nginx.conf"):
                return "include luawaf.conf;"
            return json.dumps(config if path.endswith("config.json") else totals)

        self.public.readFile = read_file
        self.public.writeFile = Mock(side_effect=AssertionError("dashboard read wrote a file"))
        self.public.M = Mock(side_effect=AssertionError("dashboard read queried domain tables"))
        self.public.returnMsg = lambda status, msg: dict(status=status, msg=msg)
        self.backend._free_waf_main__check_cjson = Mock(
            side_effect=AssertionError("dashboard read attempted a runtime install")
        )
        with patch.object(os.path, "exists", return_value=True):
            result = self.backend.get_total_all(None)
        self.assertEqual(result["total"]["total"], 10)
        self.assertEqual(result["safe_day"], 0)
        self.public.writeFile.assert_not_called()
        self.public.M.assert_not_called()

    def test_format_total_keeps_existing_get_and_input_unchanged(self):
        counters = {"get": 7, "cc": 2}
        before = copy.deepcopy(counters)
        result = self.backend._free_waf_main__format_total(counters)
        self.assertEqual(next(row["value"] for row in result if row["key"] == "get"), 7)
        self.assertEqual(counters, before)

    def test_recent_window_yields_before_reading_the_whole_file(self):
        line = b'192.0.2.1 - - [22/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "test"\n'
        payload = line * 40000
        stream = io.BytesIO(payload)
        stream.bytes_read = 0
        original_read = stream.read

        def read(size=-1):
            data = original_read(size)
            stream.bytes_read += len(data)
            return data

        stream.read = read
        with patch("builtins.open", return_value=stream):
            rows = self.backend._free_waf_main__iter_recent_window_lines("access.log", 0)
            self.assertIn("GET /", next(rows))
            self.assertLess(stream.bytes_read, len(payload) // 2)
            rows.close()
        self.assertTrue(stream.closed)

    def test_recent_window_keeps_last_line_and_returns_newest_first(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"
            lines = [
                '192.0.2.1 - - [22/Oct/2026:12:00:0%d +0000] "GET /%d HTTP/1.1" 200 10 "-" "test"' % (i, i)
                for i in range(3)
            ]
            path.write_text("\n".join(lines), encoding="utf-8")
            actual = list(self.backend._free_waf_main__iter_recent_window_lines(str(path), 0))
            self.assertEqual(actual, list(reversed(lines)))

    def test_access_timestamp_honors_log_timezone(self):
        line = '192.0.2.1 - - [22/Oct/2026:12:00:00 +0800] "GET / HTTP/1.1" 200 10 "-" "test"'
        row = self.backend._free_waf_main__parse_nginx_access_line(line)
        expected = datetime.datetime(2026, 10, 22, 4, tzinfo=datetime.timezone.utc).timestamp()
        self.assertEqual(row["time_ts"], expected)

    def test_tail_fallback_reads_a_bounded_suffix(self):
        self.public.GetNumLines = Mock(side_effect=OSError("panel helper unavailable"))
        payload = b"old\n" * 500000 + b"new\n" * 50
        stream = io.BytesIO(payload)
        stream.bytes_read = 0
        original_read = stream.read

        def read(size=-1):
            data = original_read(size)
            stream.bytes_read += len(data)
            return data

        stream.read = read
        with patch("builtins.open", return_value=stream):
            lines = self.backend._free_waf_main__read_recent_lines("access.log", 50)
        self.assertEqual(lines, ["new"] * 50)
        self.assertLess(stream.bytes_read, 128 * 1024)

    def test_statistics_counts_window_and_selects_recent_rows_across_all_sites(self):
        self.public.GetNumLines = Mock(side_effect=OSError("no panel helper"))
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)

        def access_line(moment, uri="/old", status=200, ua="browser"):
            stamp = moment.strftime("%d/%b/%Y:%H:%M:%S %z")
            return '192.0.2.1 - - [%s] "GET %s HTTP/1.1" %d 10 "-" "%s"\n' % (stamp, uri, status, ua)

        def error_line(moment, message):
            stamp = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(moment.timestamp()))
            return "%s [error] 1#1: %s\n" % (stamp, message)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.backend._free_waf_main__access_log_path = directory
            earlier = now - datetime.timedelta(hours=1)
            (root / "a.example.log").write_text(access_line(earlier) * 220, encoding="utf-8")
            (root / "z.example.log").write_text(
                access_line(now - datetime.timedelta(days=2), "/excluded") +
                access_line(now, "/newest", 403, "testbot"), encoding="utf-8"
            )
            (root / "a.example.error.log").write_text(error_line(earlier, "old"), encoding="utf-8")
            (root / "z.example.error.log").write_text(
                error_line(now - datetime.timedelta(days=2), "excluded") + error_line(now, "newest"),
                encoding="utf-8",
            )
            result = self.backend._free_waf_main__build_website_statistics_summary(
                types.SimpleNamespace(days=1, siteName="", line_limit=800)
            )
        self.assertEqual(result["summary"]["total_requests"], 221)
        self.assertEqual(result["summary"]["total_bytes"], 2210)
        self.assertEqual(result["summary"]["error_requests"], 1)
        self.assertEqual(result["summary"]["spider_requests"], 1)
        self.assertEqual(len(result["recent_access"]), 80)
        self.assertEqual(result["recent_access"][0]["uri"], "/newest")
        self.assertEqual(result["recent_errors"][0]["site"], "z.example")
        self.assertEqual(len(result["recent_errors"]), 2)

    def test_overview_dynamics_show_latest_hits_instead_of_first_file_rows(self):
        self.backend.get_waf_drop_ip = lambda get: []
        now = datetime.datetime.now().replace(microsecond=0)
        old = (now - datetime.timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        latest = now.strftime('%Y-%m-%d %H:%M:%S')
        virtual_root = '/www/wwwlogs/free_waf_log/'
        original_open, original_exists, original_listdir = open, os.path.exists, os.listdir
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ('example_' + now.strftime('%Y-%m-%d') + '.log')
            entries = [[old, '192.0.2.1', 'GET', '/old', 'test', 'args']] * 30
            entries.append([latest, '192.0.2.1', 'GET', '/newest', 'test', 'args'])
            path.write_text('\n'.join(json.dumps(row) for row in entries), encoding='utf-8')

            def redirect(path):
                value = str(path)
                return str(Path(directory) / value[len(virtual_root):]) if value.startswith(virtual_root) else path

            with patch('builtins.open', side_effect=lambda path, *a, **kw: original_open(redirect(path), *a, **kw)), \
                 patch.object(os.path, 'exists', side_effect=lambda path: original_exists(redirect(path))), \
                 patch.object(os, 'listdir', side_effect=lambda path: original_listdir(redirect(path))):
                result = self.backend.get_overview_report(None)
        self.assertEqual(len(result['dynamics']), 20)
        self.assertEqual(result['dynamics'][0]['uri'], '/newest')


if __name__ == "__main__":
    unittest.main()
