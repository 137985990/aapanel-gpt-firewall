import datetime as dt
import importlib
import gzip
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 22, 12, 30, tzinfo=UTC)


class StatisticsContractTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("website_statistics"),
            "The independent statistics module must exist",
        )
        self.module = importlib.import_module("website_statistics")
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def service(self, **kwargs):
        return self.module.StatisticsService(self.root, now=NOW, **kwargs)

    def write_log(self, name, rows):
        payload = "".join(rows).encode("utf-8")
        if name.endswith(".gz"):
            with gzip.open(self.root / name, "wb") as stream:
                stream.write(payload)
        else:
            (self.root / name).write_bytes(payload)

    def line(self, moment=NOW, ip="192.0.2.1", uri="/", status=200,
             size=10, ua="browser", referer="-", protocol="HTTP/1.1", method="GET"):
        # Avoid dependence on the machine's locale for the English log month.
        month = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")[moment.month - 1]
        stamp = moment.strftime("%d/") + month + moment.strftime("/%Y:%H:%M:%S %z")
        return '%s - - [%s] "%s %s %s" %s %s "%s" "%s"\n' % (
            ip, stamp, method, uri, protocol, status, size, referer, ua,
        )

    def test_version_and_empty_response_preserve_legacy_contract(self):
        self.assertEqual(self.module.PLUGIN_VERSION, "0.1.6")
        result = self.service().build()
        self.assertEqual(result["schema_version"], 2)
        self.assertTrue(result["status"])
        self.assertTrue({
            "summary", "sites", "spiders", "clients", "status_codes",
            "top_uris", "referers", "common_clients", "recent_access",
            "recent_errors", "settings", "checked_at", "site_options",
            "trend", "browsers", "operating_systems", "devices", "coverage",
            "window", "server_errors",
        }.issubset(result))
        self.assertEqual(result["summary"], {
            "days": 7, "total_requests": 0, "unique_clients": 0,
            "total_bytes": 0, "error_requests": 0, "spider_requests": 0,
            "errors_4xx": 0, "errors_5xx": 0,
        })
        self.assertTrue(result["coverage"]["complete"])
        self.assertFalse(result["coverage"]["partial"])
        self.assertIn("发现", result["coverage"]["notice"])
        self.assertIn("历史", result["coverage"]["notice"])
        json.dumps(result, allow_nan=False)

    def test_empty_trends_are_calendar_days_or_hours(self):
        daily = self.service().build(days=7)
        self.assertEqual(len(daily["trend"]), 7)
        self.assertEqual(daily["window"]["start"], "2026-10-16T00:00:00+00:00")
        self.assertEqual(daily["window"]["end"], NOW.isoformat())
        self.assertEqual(daily["window"]["timezone"], "UTC")
        self.assertEqual([r["label"] for r in daily["trend"]], [
            "2026-10-16", "2026-10-17", "2026-10-18", "2026-10-19",
            "2026-10-20", "2026-10-21", "2026-10-22",
        ])
        hourly = self.service().build(days=1)
        self.assertEqual(len(hourly["trend"]), 24)
        self.assertEqual(hourly["trend"][0]["label"], "00:00")
        self.assertEqual(hourly["trend"][-1]["label"], "23:00")
        for row in daily["trend"] + hourly["trend"]:
            self.assertEqual(set(row), {"label", "time", "requests", "clients", "bytes", "errors"})
            self.assertEqual(row["requests"], 0)

    def test_discovery_reads_metadata_only_and_merges_ssl_rotations(self):
        for name in (
            "a.example.log", "a.example.ssl.log.1", "a.example.log.2.gz",
            "a.example.log-20261021.gz", "b.example_2026-10-20.log",
            "b.example.error.log", "nginx_error.log", "notes.txt",
        ):
            (self.root / name).touch()
        with patch("builtins.open", side_effect=AssertionError("discovery read content")), \
                patch("gzip.GzipFile", side_effect=AssertionError("discovery decompressed content")):
            sites = self.service().discover_sites()
        self.assertEqual(sites, [{"site": "a.example"}, {"site": "b.example"}])

    def test_today_excludes_yesterday_and_future_and_honors_offsets(self):
        offset = dt.timezone(dt.timedelta(hours=8))
        self.write_log("one.example.log", [
            self.line(NOW.replace(hour=0, minute=0)),
            self.line(dt.datetime(2026, 10, 22, 8, 1, tzinfo=offset), ip="2001:db8::1"),
            self.line(NOW - dt.timedelta(days=1)),
            self.line(NOW + dt.timedelta(seconds=1)),
        ])
        result = self.service().build(days=1)
        self.assertEqual(result["summary"]["total_requests"], 2)
        self.assertEqual(result["summary"]["unique_clients"], 2)
        self.assertEqual(result["trend"][0]["requests"], 2)
        self.assertEqual(result["trend"][0]["clients"], 2)
        self.assertEqual(sum(row["requests"] for row in result["trend"]), 2)

    def test_daily_trend_uses_local_calendar_and_nonadditive_unique_clients(self):
        zone = dt.timezone(dt.timedelta(hours=8), "UTC+08")
        now = dt.datetime(2026, 10, 22, 0, 30, tzinfo=zone)
        self.write_log("one.example.log", [
            self.line(dt.datetime(2026, 10, 20, 16, tzinfo=UTC)),
            self.line(dt.datetime(2026, 10, 21, 16, tzinfo=UTC)),
            self.line(dt.datetime(2026, 10, 20, 15, 59, tzinfo=UTC)),
        ])
        result = self.module.StatisticsService(self.root, now=lambda: now).build(days=2)
        self.assertEqual([row["requests"] for row in result["trend"]], [1, 1])
        self.assertEqual([row["clients"] for row in result["trend"]], [1, 1])
        self.assertEqual(result["summary"]["unique_clients"], 1)
        self.assertEqual(result["window"]["start"], "2026-10-21T00:00:00+08:00")

    def test_combined_fields_are_raw_json_with_explicit_unavailable_latency(self):
        self.write_log("site&example.log", [self.line(
            uri='/<img>?x=1&y=2', status=503, ua='<script>&"quoted"'.replace('"', r'\x22'),
            referer="https://example.test/?a=1&b=<x>", protocol="HTTP/2.0",
        )])
        result = self.service().build()
        row = result["recent_access"][0]
        self.assertEqual(row["uri"], '/<img>?x=1&y=2')
        self.assertEqual(row["site"], "site&example")
        self.assertEqual(row["protocol"], "HTTP/2.0")
        self.assertIsNone(row["request_time"])
        self.assertEqual(row["user_agent"], '<script>&"quoted"')
        self.assertEqual(result["top_uris"][0], {"uri": '/<img>?x=1&y=2', "count": 1})
        self.assertNotIn("uv", result["summary"])
        self.assertNotIn("latency", result["summary"])
        self.assertEqual(json.loads(json.dumps(result))["recent_access"][0], row)

    def test_http_errors_and_server_diagnostics_are_separate(self):
        self.write_log("one.example.log", [self.line(status=s) for s in (200, 302, 403, 404, 500, 503)])
        self.write_log("one.example.error.log", [
            '2026/10/22 11:00:00 [error] 1#1: unavailable, client: 192.0.2.1, '
            'server: one.example, request: "GET / HTTP/1.1"\n',
        ])
        result = self.service().build()
        self.assertEqual(result["summary"]["error_requests"], 4)
        self.assertEqual(result["summary"]["errors_4xx"], 2)
        self.assertEqual(result["summary"]["errors_5xx"], 2)
        self.assertEqual(sorted(row["status"] for row in result["recent_errors"]), [403, 404, 500, 503])
        self.assertEqual(len(result["server_errors"]), 1)
        self.assertEqual(result["server_errors"][0]["level"], "error")
        self.assertEqual(result["server_errors"][0]["client"], "192.0.2.1")

    def test_unavailable_or_incomplete_request_line_still_counts_http_errors(self):
        good = self.line(status=400)
        self.write_log("one.example.log", [good.replace("GET / HTTP/1.1", request)
                                            for request in ("-", "GET /", "broken")])
        result = self.service().build()
        self.assertEqual(result["summary"]["total_requests"], 3)
        self.assertEqual(result["summary"]["error_requests"], 3)
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual(len(result["recent_errors"]), 3)
        self.assertTrue(all(row["protocol"] == "" for row in result["recent_errors"]))
        self.assertTrue(all(row["request_time"] is None for row in result["recent_errors"]))

    def test_nginx_hex_escaped_utf8_is_decoded_as_text_not_mojibake(self):
        self.write_log("one.example.log", [self.line(ua=r"agent/\xE4\xB8\xAD\xE6\x96\x87")])
        result = self.service().build()
        self.assertEqual(result["recent_access"][0]["user_agent"], "agent/中文")

    def test_rotations_merge_without_mtime_shortcut_and_site_filter_is_exact(self):
        for name in ("one.example.log", "one.example.ssl.log.1", "one.example.log.2.gz",
                     "one.example.log-20261021.gz", "one.example_2026-10-20.log"):
            self.write_log(name, [self.line()])
        self.write_log("two.example.log", [self.line(size="-", status=404)])
        result = self.service().build(site_name="one.example")
        self.assertEqual(result["summary"]["total_requests"], 5)
        self.assertEqual(result["sites"], [{"site": "one.example", "requests": 5, "clients": 1,
                                           "bytes": 50, "errors": 0}])
        self.assertEqual(result["coverage"]["files_scanned"], 5)
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual(self.service().build(site_name="../one.example")["summary"]["total_requests"], 0)
        self.assertEqual(len(result["site_options"]), 2)
        self.assertEqual(self.service().build()["summary"]["total_bytes"], 50)

    def test_specific_spiders_precede_generic_bot_and_client_dimensions_are_separate(self):
        agents = ["Googlebot/2.1", "bingbot/2.0", "Baiduspider/2.0", "YandexBot/3.0",
                  "DuckDuckBot/1.0", "Sogou web spider/4.0", "randomcrawler/1.0",
                  "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537.36 Edg/130.0",
                  "Mozilla/5.0 (Linux; Android 14; Mobile) Chrome/130.0 Safari/537.36",
                  "Mozilla/5.0 (iPad; CPU OS 17) AppleWebKit/605.1 Version/17.0 Safari/604.1",
                  "-"]
        self.write_log("one.example.log", [self.line(ua=ua) for ua in agents])
        result = self.service().build()
        spiders = {r["spider"]: r["count"] for r in result["spiders"]}
        self.assertEqual(spiders, {"Googlebot": 1, "Bingbot": 1, "Baiduspider": 1, "Yandex": 1,
                                   "DuckDuckBot": 1, "Sogou": 1, "Other": 1})
        self.assertEqual(result["summary"]["spider_requests"], 7)
        for dimension in ("browsers", "operating_systems", "devices"):
            self.assertEqual(sum(r["count"] for r in result[dimension]), len(agents))
        self.assertIn({"name": "Edge", "count": 1}, result["browsers"])
        self.assertIn({"name": "Android", "count": 1}, result["operating_systems"])
        self.assertIn({"name": "Tablet", "count": 1}, result["devices"])

    def test_recent_samples_are_globally_sorted_and_not_aggregate_line_caps(self):
        rows = [self.line(NOW - dt.timedelta(seconds=i), uri="/row/%d" % i, status=404) for i in range(250)]
        self.write_log("a.example.log", list(reversed(rows[100:])))
        self.write_log("z.example.log", rows[:100])
        result = self.service().build(line_limit=100)
        self.assertEqual(result["summary"]["total_requests"], 250)
        self.assertEqual(len(result["recent_access"]), 80)
        self.assertEqual(len(result["recent_errors"]), 120)
        self.assertEqual(result["recent_access"][0]["uri"], "/row/0")
        self.assertEqual(result["recent_access"][-1]["uri"], "/row/79")
        default = self.service().build()
        self.assertEqual(len(default["recent_errors"]), 120)
        self.assertEqual(default["common_clients"], [{"ip": "192.0.2.1", "count": 250,
                                                     "sites": "a.example, z.example"}])

    def test_http_error_sample_is_independent_of_newer_successful_accesses(self):
        self.write_log("one.example.log", [self.line(NOW - dt.timedelta(seconds=i)) for i in range(100)] + [
            self.line(NOW - dt.timedelta(seconds=100 + i), status=500) for i in range(140)
        ])
        result = self.service().build()
        self.assertEqual(len(result["recent_errors"]), 120)
        self.assertTrue(all(row["status"] == 200 for row in result["recent_access"]))
        self.assertTrue(all(row["status"] == 500 for row in result["recent_errors"]))

    def assert_partial(self, result, reason):
        self.assertFalse(result["coverage"]["complete"])
        self.assertTrue(result["coverage"]["partial"])
        self.assertIn(reason, result["coverage"]["reasons"])

    def test_invalid_lines_are_counted_and_do_not_pretend_full_coverage(self):
        good = self.line()
        rows = [good, "not a log record\n", good.replace("22/Oct", "99/Oct"),
                good.replace("+0000", "+0861"), good.replace(" 200 ", " 600 "),
                good.replace("192.0.2.1", "invalid-IP"), "\n"]
        self.write_log("one.example.log", rows)
        with (self.root / "one.example.log").open("ab") as stream:
            stream.write(b"\xff\xfe\n")
        result = self.service().build()
        self.assertEqual(result["summary"]["total_requests"], 1)
        self.assertEqual(result["coverage"]["invalid_lines"], 6)
        self.assert_partial(result, "invalid_lines")

    def test_byte_budget_stops_before_counting_a_partial_line(self):
        line = self.line()
        self.write_log("one.example.log", [line] * 20)
        limit = len(line.encode()) * 2 + 7
        result = self.service(budgets={"max_bytes": limit}).build()
        self.assertEqual(result["summary"]["total_requests"], 2)
        self.assertLessEqual(result["coverage"]["bytes_read"], limit)
        self.assert_partial(result, "byte_budget")

    def test_large_plain_log_samples_recent_tail_instead_of_old_prefix(self):
        old = self.line(NOW - dt.timedelta(days=60), uri="/old")
        self.write_log("one.example.log", [old] * 100 + [self.line(uri="/recent")] * 3)
        result = self.service(budgets={"max_bytes": 1024}).build(days=1)
        self.assertEqual(result["summary"]["total_requests"], 3)
        self.assertEqual([row["uri"] for row in result["recent_access"]], ["/recent"] * 3)
        self.assertLessEqual(result["coverage"]["bytes_read"], 1024)
        self.assertLessEqual(result["coverage"]["source_bytes_read"], 1024)
        self.assertEqual(result["coverage"]["invalid_lines"], 0)
        self.assert_partial(result, "tail_sampling")
        self.assert_partial(result, "byte_budget")
        self.assertIn("尾部", result["coverage"]["notice"])
        self.assertIn("全量", result["coverage"]["notice"])

    def test_large_diagnostics_never_take_access_reading_budget_first(self):
        self.write_log("a.example.error.log", ["2026/10/22 12:00:00 [error] old diagnostic\n"] * 1000)
        old = self.line(NOW - dt.timedelta(days=60))
        self.write_log("z.example.log", [old] * 100 + [self.line(uri="/recent")] * 2)
        service = self.service(budgets={"max_bytes": 1024})
        opened = []
        original = service._open_file

        def record_open(name, *args):
            opened.append(name)
            return original(name, *args)

        with patch.object(service, "_open_file", side_effect=record_open):
            result = service.build(days=1)
        self.assertEqual(opened[0], "z.example.log")
        self.assertEqual(result["summary"]["total_requests"], 2)
        self.assert_partial(result, "byte_budget")

    def test_large_access_files_share_quota_and_small_logs_remain_complete(self):
        old = self.line(NOW - dt.timedelta(days=60), uri="/old")
        for site in ("a", "z"):
            self.write_log(site + ".example.log", [old] * 100 + [self.line(uri="/" + site)] * 3)
        self.write_log("small.example.log", [self.line(uri="/small")] * 2)
        result = self.service(budgets={"max_bytes": 2048}).build(days=1)
        self.assertEqual({row["site"]: row["requests"] for row in result["sites"]},
                         {"a.example": 3, "z.example": 3, "small.example": 2})
        self.assertEqual(result["coverage"]["files_scanned"], 3)
        self.assertLessEqual(result["coverage"]["bytes_read"], 2048)
        self.assertLessEqual(result["coverage"]["source_bytes_read"], 2048)
        self.assert_partial(result, "tail_sampling")

    def test_access_priority_also_applies_when_file_count_is_capped(self):
        self.write_log("a.example.error.log", ["2026/10/22 12:00:00 [error] diagnostic\n"])
        self.write_log("z.example.log", [self.line()])
        result = self.service(budgets={"max_files": 1}).build()
        self.assertEqual(result["summary"]["total_requests"], 1)
        self.assert_partial(result, "file_budget")

    def test_tail_start_fragment_is_discarded_but_final_unterminated_record_survives(self):
        final = self.line(uri="/last").rstrip("\n")
        payload = b"x" * 10000 + b"\n" + final.encode()
        (self.root / "one.example.log").write_bytes(payload)
        result = self.service(budgets={"max_bytes": len(final.encode()) + 50}).build()
        self.assertEqual(result["summary"]["total_requests"], 1)
        self.assertEqual(result["recent_access"][0]["uri"], "/last")
        self.assertEqual(result["coverage"]["invalid_lines"], 0)
        self.assert_partial(result, "tail_sampling")

    def test_incomplete_final_tail_record_is_not_counted(self):
        self.write_log("one.example.log", [self.line()] * 100 + ["192.0.2.1 - - [22/Oct/"])
        result = self.service(budgets={"max_bytes": 1024}).build()
        self.assertTrue(result["recent_access"])
        self.assertEqual(result["coverage"]["invalid_lines"], 1)
        self.assert_partial(result, "invalid_lines")

    def test_gzip_quota_exhaustion_does_not_prevent_next_candidate(self):
        for site in ("a", "z"):
            self.write_log(site + ".example.log.1.gz", [self.line(uri="/" + site)] * 1000)
        result = self.service(budgets={"max_bytes": 2048}).build()
        self.assertEqual({row["site"] for row in result["sites"]}, {"a.example", "z.example"})
        self.assertLessEqual(result["coverage"]["bytes_read"], 2048)
        self.assertLessEqual(result["coverage"]["source_bytes_read"], 2048)
        self.assertNotIn("tail_sampling", result["coverage"]["reasons"])
        self.assert_partial(result, "byte_budget")

    def test_compressed_input_has_a_decompressed_byte_limit(self):
        line = self.line()
        self.write_log("one.example.log.1.gz", [line] * 20000)
        result = self.service(budgets={"max_bytes": 1024}).build()
        self.assertLessEqual(result["coverage"]["bytes_read"], 1024)
        self.assertLess(result["summary"]["total_requests"], 20)
        self.assert_partial(result, "byte_budget")

    def test_exact_byte_budget_at_eof_is_not_a_false_partial(self):
        line = self.line()
        self.write_log("one.example.log", [line])
        result = self.service(budgets={"max_bytes": len(line.encode())}).build()
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual(result["summary"]["total_requests"], 1)

    def test_file_and_directory_entry_limits_are_reported(self):
        for i in range(5):
            self.write_log("site%d.log" % i, [self.line()])
        result = self.service(budgets={"max_files": 2}).build()
        self.assertLessEqual(result["coverage"]["files_scanned"], 2)
        self.assert_partial(result, "file_budget")
        result = self.service(budgets={"max_entries": 2}).build()
        self.assertLessEqual(len(result["site_options"]), 2)
        self.assert_partial(result, "entry_budget")

    def test_cardinality_budget_stops_aggregation_consistently(self):
        self.write_log("one.example.log", [self.line(ip="192.0.2.%d" % i, uri="/u/%d" % i) for i in range(1, 200)])
        result = self.service(budgets={"max_keys": 20}).build()
        self.assertGreater(result["summary"]["total_requests"], 0)
        self.assertLess(result["summary"]["total_requests"], 20)
        self.assertEqual(sum(row["requests"] for row in result["trend"]), result["summary"]["total_requests"])
        self.assertEqual(sum(row["requests"] for row in result["sites"]), result["summary"]["total_requests"])
        self.assert_partial(result, "cardinality_budget")

    def test_elapsed_time_budget_and_invalid_budget_values_are_safe(self):
        self.write_log("one.example.log", [self.line()] * 10)
        with patch.object(self.module.time, "monotonic", side_effect=range(10000)):
            result = self.service(budgets={"max_seconds": 0.5}).build()
        self.assert_partial(result, "time_budget")
        for value in (float("nan"), float("inf"), -1, "bad", None):
            with self.subTest(value=value):
                result = self.service(budgets={"max_seconds": value, "max_bytes": value}).build()
                self.assertEqual(result["summary"]["total_requests"], 10)

    def test_oversized_line_is_discarded_without_losing_following_valid_lines(self):
        self.write_log("one.example.log", ["x" * 10000 + "\n", self.line()])
        result = self.service(budgets={"max_line_bytes": 256}).build()
        self.assertEqual(result["summary"]["total_requests"], 1)
        self.assertEqual(result["coverage"]["invalid_lines"], 1)
        self.assert_partial(result, "line_too_long")

    def test_corrupt_gzip_and_missing_directory_are_partial_reports(self):
        (self.root / "bad.example.log.1.gz").write_bytes(b"not gzip\n")
        self.write_log("good.example.log", [self.line()])
        result = self.service().build()
        self.assertEqual(result["summary"]["total_requests"], 1)
        self.assert_partial(result, "file_unavailable")
        missing = self.module.StatisticsService(self.root / "missing", now=NOW).build()
        self.assert_partial(missing, "directory_unavailable")

    def test_parameter_clamping_and_service_reuse(self):
        self.write_log("one.example.log", [self.line()])
        service = self.service()
        self.assertEqual(service.build(days="invalid")["summary"]["days"], 7)
        self.assertEqual(service.build(days=99)["summary"]["days"], 30)
        self.assertEqual(service.build(days=0)["summary"]["days"], 1)
        self.assertEqual(service.build()["summary"]["total_requests"], 1)
        self.assertEqual(service.build()["summary"]["total_requests"], 1)

    def test_log_files_are_unchanged_by_build(self):
        self.write_log("one.example.log", [self.line()])
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        self.service().build()
        after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        self.assertEqual(before, after)

    def test_symlink_files_and_directories_are_not_followed(self):
        self.write_log("real.log", [self.line()])
        try:
            (self.root / "alias.log").symlink_to(self.root / "real.log")
            (self.root / "nested").mkdir()
            (self.root / "nested" / "hidden.log").write_text(self.line(), encoding="utf-8")
            (self.root / "linked").symlink_to(self.root / "nested", target_is_directory=True)
        except OSError as exc:
            self.skipTest("OS does not permit creating symlinks: %s" % exc)
        result = self.service().build()
        self.assertEqual(result["summary"]["total_requests"], 1)
        self.assertNotIn({"site": "alias"}, result["site_options"])
        self.assert_partial(result, "unsafe_file")
        linked = self.module.StatisticsService(self.root / "linked", now=NOW).build()
        self.assertEqual(linked["summary"]["total_requests"], 0)
        self.assert_partial(linked, "unsafe_directory")

    def test_symlink_in_parent_directory_is_rejected(self):
        (self.root / "parent" / "logs").mkdir(parents=True)
        (self.root / "parent" / "logs" / "one.log").write_text(self.line(), encoding="utf-8")
        try:
            (self.root / "alias").symlink_to(self.root / "parent", target_is_directory=True)
        except OSError as exc:
            self.skipTest("OS does not permit creating symlinks: %s" % exc)
        result = self.module.StatisticsService(self.root / "alias" / "logs", now=NOW).build()
        self.assertEqual(result["summary"]["total_requests"], 0)
        self.assert_partial(result, "unsafe_directory")

    def test_truncation_between_discovery_and_open_is_partial(self):
        self.write_log("one.example.log", [self.line()] * 4)
        service = self.service()
        original = service._discover

        def truncate_after_discovery(*args):
            discovered = original(*args)
            self.write_log("one.example.log", [self.line()])
            return discovered

        with patch.object(service, "_discover", side_effect=truncate_after_discovery):
            result = service.build()
        self.assert_partial(result, "file_changed")

    def test_replaced_or_deleted_files_after_discovery_are_not_read(self):
        for replacement in (True, False):
            with self.subTest(replacement=replacement):
                self.write_log("one.example.log", [self.line()])
                service = self.service()
                original = service._discover

                def remove_after_discovery(*args):
                    discovered = original(*args)
                    (self.root / "one.example.log").rename(self.root / "retired.txt")
                    if replacement:
                        self.write_log("one.example.log", [self.line(uri="/replacement")])
                    return discovered

                with patch.object(service, "_discover", side_effect=remove_after_discovery):
                    result = service.build()
                self.assertEqual(result["summary"]["total_requests"], 0)
                self.assert_partial(result, "file_changed" if replacement else "file_unavailable")
                (self.root / "retired.txt").unlink()

    def test_symlink_swap_after_discovery_never_reads_target(self):
        self.write_log("one.example.log", [self.line()])
        outside = self.root / "outside.txt"
        outside.write_text(self.line(uri="/must-not-read"), encoding="utf-8")
        service = self.service()
        original = service._discover

        def swap_after_discovery(*args):
            discovered = original(*args)
            (self.root / "one.example.log").unlink()
            try:
                (self.root / "one.example.log").symlink_to(outside)
            except OSError as exc:
                self.skipTest("OS does not permit creating symlinks: %s" % exc)
            return discovered

        with patch.object(service, "_discover", side_effect=swap_after_discovery):
            result = service.build()
        self.assertEqual(result["summary"]["total_requests"], 0)
        self.assert_partial(result, "unsafe_file")

    def test_unterminated_final_line_and_gzip_source_accounting(self):
        self.write_log("one.example.log", [self.line().rstrip("\n")])
        self.write_log("two.example.log.1.gz", [self.line()] * 10)
        result = self.service().build()
        self.assertEqual(result["summary"]["total_requests"], 11)
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual(result["coverage"]["source_bytes_read"],
                         sum(p.stat().st_size for p in self.root.iterdir()))
        self.assertEqual(result["coverage"]["bytes_read"], len(self.line().encode()) * 11 - 1)

    def test_truncated_and_bad_crc_gzip_are_partial(self):
        for kind in ("truncated", "crc"):
            with self.subTest(kind=kind):
                payload = bytearray(gzip.compress((self.line() * 10).encode()))
                if kind == "truncated":
                    payload = payload[:-4]
                else:
                    payload[-8] ^= 1
                (self.root / "one.example.log.1.gz").write_bytes(payload)
                result = self.service().build()
                self.assert_partial(result, "file_unavailable")

    def test_dst_hourly_buckets_include_both_folds_and_skip_missing_hour(self):
        try:
            from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        except ImportError:
            self.skipTest("requires zoneinfo for DST fixtures")
        try:
            zone = ZoneInfo("America/New_York")
        except ZoneInfoNotFoundError:
            self.skipTest("IANA timezone data unavailable")
        for month, day, count in ((3, 8, 23), (11, 1, 25)):
            with self.subTest(month=month):
                now = dt.datetime(2026, month, day, 23, 30, tzinfo=zone)
                start = now.replace(hour=0, minute=0)
                rows = [self.line(dt.datetime.fromtimestamp(start.timestamp() + index * 3600, UTC))
                        for index in range(count)]
                self.write_log("one.example.log", rows)
                service = self.module.StatisticsService(self.root, now=now)
                result = service.build(days=1)
                self.assertEqual(len(result["trend"]), count)
                self.assertEqual([row["requests"] for row in result["trend"]], [1] * count)
                self.assertEqual(len({row["time"] for row in result["trend"]}), count)
                self.assertEqual(result["window"]["timezone"], "America/New_York")
                daily = service.build(days=2)
                self.assertEqual([row["requests"] for row in daily["trend"]], [0, count])

    def test_date_like_site_suffix_is_only_removed_for_valid_calendar_dates(self):
        for name in ("one.example_2026-10-21.log", "two.example_2026-99-99.log",
                     "three.example.log-20260230.gz"):
            (self.root / name).touch()
        self.assertEqual(self.service().discover_sites(), [
            {"site": "one.example"}, {"site": "two.example_2026-99-99"},
        ])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_non_regular_log_does_not_block_or_get_opened(self):
        os.mkfifo(self.root / "pipe.log")
        result = self.service().build()
        self.assertEqual(result["coverage"]["files_scanned"], 0)
        self.assert_partial(result, "unsafe_file")


if __name__ == "__main__":
    unittest.main()
