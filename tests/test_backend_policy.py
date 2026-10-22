import re
import unittest
from pathlib import Path


class BackendPolicyTest(unittest.TestCase):
    def setUp(self):
        self.plugin_dir = Path(__file__).resolve().parents[1]
        self.backend = (self.plugin_dir / "free_waf_main.py").read_text(encoding="utf-8", errors="replace")
        self.frontend = (self.plugin_dir / "index.html").read_text(encoding="utf-8", errors="replace")

    def _function_body(self, name):
        match = re.search(
            r"^\s+def\s+" + re.escape(name) + r"\s*\([^)]*\):(.*?)(?=^\s+def\s+|\Z)",
            self.backend,
            re.S | re.M,
        )
        self.assertIsNotNone(match, name + " function not found")
        return match.group(1)

    def test_ip_stats_uses_ban_store_for_temporary_bans(self):
        body = self._function_body("get_ip_stats")
        self.assertNotIn("len(item) == 2", body)
        self.assertIn("__ban_store()", body)
        self.assertIn("active_exact_ips", body)

    def test_uri_stats_is_read_only_and_aggregates_log_uri(self):
        body = self._function_body("get_uri_stats")
        self.assertIn("collections.Counter", body)
        self.assertIn("row[3]", body)
        self.assertIn("most_common(100)", body)
        for unsafe in [
            "__write_rule",
            "public.serviceReload",
            "add_url_white",
            "add_ip_black",
            "add_permanent_ban",
            "remove_permanent_ban",
            "clean_waf_drop_ip",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_report_search_and_http_detail_are_read_only(self):
        search_body = self._function_body("get_report_search")
        detail_body = self._function_body("get_report_http_detail")
        for body in [search_body, detail_body]:
            with self.subTest(body=body[:40]):
                self.assertIn("free_waf_log", body)
                self.assertIn("json.loads", body)
                self.assertIn("escape", body)
                for unsafe in [
                    "__write_rule",
                    "__write_config",
                    "__write_site_config",
                    "public.serviceReload",
                    "add_url_white",
                    "add_ip_black",
                    "add_permanent_ban",
                    "remove_permanent_ban",
                    "clean_waf_drop_ip",
                    "remove_waf_drop_ip",
                ]:
                    with self.subTest(unsafe=unsafe):
                        self.assertNotIn(unsafe, body)

        self.assertIn("siteName", search_body)
        self.assertIn("ruleType", search_body)
        self.assertIn("keyword", search_body)
        self.assertIn("line_no", search_body)
        self.assertIn("raw", detail_body)

    def test_report_dashboard_summary_is_read_only_and_aggregates_official_report_data(self):
        body = self._function_body("get_report_dashboard_summary")
        for token in [
            "free_waf_log",
            "summary",
            "total_hits",
            "unique_ips",
            "unique_uris",
            "active_bans",
            "top_rules",
            "top_sites",
            "top_ips",
            "top_uris",
        ]:
            with self.subTest(token=token):
                self.assertIn(token, body)
        for unsafe in [
            "__write_rule",
            "__write_config",
            "__write_site_config",
            "public.serviceReload",
            "add_url_white",
            "add_ip_black",
            "add_permanent_ban",
            "remove_permanent_ban",
            "clean_waf_drop_ip",
            "remove_waf_drop_ip",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_website_statistics_summary_is_read_only_and_matches_official_sections(self):
        endpoint = self._function_body("get_website_statistics_summary")
        body = self._function_body("__build_website_statistics_summary")
        self.assertIn("website_reports.request", endpoint)
        self.assertIn("__build_website_statistics_summary", endpoint)
        self.assertIn("force=force", endpoint)
        self.assertIn("/www/wwwlogs", self.backend)
        for token in [
            "access_logs",
            "error_logs",
            "summary",
            "total_requests",
            "unique_clients",
            "total_bytes",
            "error_requests",
            "spider_requests",
            "sites",
            "spiders",
            "clients",
            "status_codes",
            "top_uris",
            "referers",
            "common_clients",
            "recent_access",
            "recent_errors",
            "settings",
            "siteName",
        ]:
            with self.subTest(token=token):
                self.assertIn(token, body)
        self.assertIn("__parse_nginx_access_line", self.backend)
        self.assertIn("__parse_nginx_error_line", self.backend)
        self.assertIn("__iter_recent_window_lines", self.backend)
        recent_window_body = self._function_body("__iter_recent_window_rows")
        self.assertIn("os.SEEK_END", recent_window_body)
        self.assertNotIn("__read_recent_lines", recent_window_body)
        self.assertIn("for row in self.__iter_recent_window_rows(path, since_ts, deadline=deadline):", body)
        self.assertNotIn("for line in self.__read_recent_lines(path, line_limit):", body)
        self.assertNotIn("for line in self.__iter_log_lines(path):", body)
        self.assertNotIn("for line in self.__read_recent_lines(path, recent_access_limit):", body)
        for unsafe in [
            "__write_rule",
            "__write_config",
            "__write_site_config",
            "public.serviceReload",
            "public.httpGet",
            "public.httpPost",
            "add_url_white",
            "add_ip_black",
            "add_permanent_ban",
            "remove_permanent_ban",
            "clean_waf_drop_ip",
            "remove_waf_drop_ip",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_blockade_records_and_export_are_read_only(self):
        records_body = self._function_body("get_blockade_records")
        export_body = self._function_body("export_blockade_records")
        for body in [records_body, export_body]:
            with self.subTest(body=body[:40]):
                self.assertIn("drop_ip.log", body)
                self.assertIn("get_waf_drop_ip", body)
                for unsafe in [
                    "__write_rule",
                    "__write_config",
                    "__write_site_config",
                    "public.serviceReload",
                    "add_ip_black",
                    "add_permanent_ban",
                    "remove_permanent_ban",
                    "clean_waf_drop_ip",
                    "remove_waf_drop_ip",
                ]:
                    with self.subTest(unsafe=unsafe):
                        self.assertNotIn(unsafe, body)

        self.assertIn("exported_at", export_body)
        self.assertIn("active_ips", export_body)

    def test_overview_report_is_read_only_and_aggregates_official_dashboard_data(self):
        body = self._function_body("get_overview_report")
        self.assertIn("trend", body)
        self.assertIn("top_sites", body)
        self.assertIn("dynamics", body)
        self.assertIn("top_rules", body)
        self.assertIn("free_waf_log", body)
        for unsafe in [
            "__write_rule",
            "__write_config",
            "__write_site_config",
            "public.serviceReload",
            "add_url_white",
            "add_ip_black",
            "add_permanent_ban",
            "remove_permanent_ban",
            "clean_waf_drop_ip",
            "remove_waf_drop_ip",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_overview_report_has_official_summary_fields(self):
        body = self._function_body("get_overview_report")
        required_tokens = [
            "summary",
            "blocked_ips",
            "attack_regions",
            "today_top_sites",
            "total_protection",
            "protection_24h",
            "cc_protection",
            "protection_days",
            "24h",
            "drop_ip.log",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, body)

        for unsafe in [
            "__write_rule",
            "__write_config",
            "__write_site_config",
            "public.serviceReload",
            "add_url_white",
            "add_ip_black",
            "add_permanent_ban",
            "remove_permanent_ban",
            "clean_waf_drop_ip",
            "remove_waf_drop_ip",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_defense_notifications_are_read_only_and_aggregate_logs(self):
        body = self._function_body("get_defense_notifications")
        self.assertIn("free_waf_log", body)
        self.assertIn("drop_ip.log", body)
        self.assertIn("summary", body)
        self.assertIn("items", body)
        self.assertIn("level", body)
        for unsafe in [
            "__write_rule",
            "__write_config",
            "__write_site_config",
            "public.serviceReload",
            "add_url_white",
            "add_ip_black",
            "add_permanent_ban",
            "remove_permanent_ban",
            "clean_waf_drop_ip",
            "remove_waf_drop_ip",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_simulate_attack_is_dry_run_and_rule_based(self):
        body = self._function_body("simulate_attack")
        self.assertIn("__simulate_rule_match", self.backend)
        for token in [
            "url_white",
            "user_agent_white",
            "url_black",
            "header",
            "cookie",
            "args",
            "post",
            "dry_run",
            "builtin_checks",
            "内置基础检测",
            r"[\s/?._-]",
            r"[\s/]",
        ]:
            with self.subTest(token=token):
                self.assertIn(token, body)
        for unsafe in [
            "public.httpGet",
            "public.httpPost",
            "__write_rule",
            "__write_config",
            "__write_site_config",
            "public.serviceReload",
            "add_url_white",
            "add_ip_black",
            "add_permanent_ban",
            "remove_permanent_ban",
            "clean_waf_drop_ip",
            "remove_waf_drop_ip",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_add_rule_creates_missing_rule_files_as_empty_lists(self):
        body = self._function_body("add_rule")
        self.assertIn("if not rule: rule = []", body)
        self.assertIn("__write_rule(get.ruleName, rule)", body)

    def test_frontend_methods_exist_in_backend(self):
        defs = set(re.findall(r"^\s+def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", self.backend, re.M))
        methods = set(re.findall(r"method\s*:\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", self.frontend))
        missing = sorted(m for m in methods if m not in defs)
        self.assertEqual([], missing)

    def test_rule_bundle_backup_excludes_runtime_ip_bans(self):
        export_body = self._function_body("get_rule_bundle")
        import_body = self._function_body("import_rule_bundle")
        for body in [export_body, import_body]:
            self.assertIn("RULE_BUNDLE_NAMES", body)
            self.assertNotIn("__write_rule('ip_black'", body)
            self.assertNotIn("__write_rule(\"ip_black\"", body)
            self.assertNotIn("add_ip_black", body)
            self.assertNotIn("add_permanent_ban", body)
            self.assertNotIn("clean_waf_drop_ip", body)

        self.assertIn("'url_white'", self.backend)
        self.assertIn("'user_agent_white'", self.backend)
        self.assertIn("'header'", self.backend)
        self.assertIn("'post'", self.backend)

    def test_config_health_report_is_read_only_and_summarizes_runtime_state(self):
        body = self._function_body("get_config_health_report")
        for token in [
            "config_health_report",
            "rule_files",
            "site_fields",
            "runtime_ban_sources",
            "rule_counts",
            "drop_ip.log",
            "RULE_BUNDLE_NAMES",
        ]:
            with self.subTest(token=token):
                self.assertIn(token, body)
        for unsafe in [
            "__write_rule",
            "__write_config",
            "__write_site_config",
            "public.serviceReload",
            "public.httpGet",
            "public.httpPost",
            "add_ip_black",
            "add_permanent_ban",
            "clean_waf_drop_ip",
            "remove_waf_drop_ip",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_clean_drop_ip_clears_persistent_exact_bans(self):
        body = self._function_body("clean_waf_drop_ip")
        self.assertIn("__ban_store()", body)
        self.assertIn("clear_exact_ips", body)

    def test_add_ip_black_supports_manual_duration_for_exact_ip_only(self):
        body = self._function_body("add_ip_black")
        for token in [
            "duration_seconds",
            "ban_seconds",
            "TEMP_BAN_SECONDS",
            "MANUAL_MAX_BAN_SECONDS",
            "store.add_temp_ban(get.start_ip, ban_seconds",
            "__write_drop_ip_entry(get.start_ip, drop_time=ban_seconds",
            "iplist.insert(0, ipn + [int(_t.time()) + ban_seconds])",
            "iplist.insert(0, ipn)",
        ]:
            with self.subTest(token=token):
                self.assertIn(token, body)

        for token in [
            "permanent_ban",
            "store.add_permanent_ban",
            "duration_seconds', '')).lower() in ['0', 'permanent']",
            "iplist.insert(0, ipn + [0])",
            "'永久'",
        ]:
            with self.subTest(forbidden=token):
                self.assertNotIn(token, body)
        self.assertIn("MANUAL_MAX_BAN_SECONDS = 315360000", self.backend)

    def test_site_config_includes_header_disable_rule(self):
        body = self._function_body("__get_site_conf")
        self.assertIn("'header': []", body)
        migrate = self._function_body("__check_site")
        self.assertIn("disable_rule", migrate)
        self.assertIn("'header'", migrate)

    def test_site_cdn_trusted_proxy_config_and_apis_exist(self):
        body = self._function_body("__get_site_conf")
        self.assertIn("'cdn_trusted_proxy': []", body)

        migrate = self._function_body("__check_site")
        self.assertIn("'cdn_trusted_proxy'", migrate)

        get_body = self._function_body("get_site_cdn_trusted_proxy")
        add_body = self._function_body("add_site_cdn_trusted_proxy")
        remove_body = self._function_body("remove_site_cdn_trusted_proxy")
        for body in [get_body, add_body, remove_body]:
            with self.subTest(body=body[:40]):
                self.assertIn("cdn_trusted_proxy", body)
                self.assertNotIn("__write_rule", body)
                self.assertNotIn("add_ip_black", body)
                self.assertNotIn("add_permanent_ban", body)

        self.assertIn("__format_ip(get.start_ip", add_body)
        self.assertIn("__format_ip(get.end_ip", add_body)
        self.assertIn("__is_ipn", add_body)
        self.assertIn("__write_site_config(site_config)", add_body)
        self.assertIn("__write_site_config(site_config)", remove_body)

    def test_safety_baseline_is_read_only_and_checks_core_policy(self):
        body = self._function_body("get_safety_baseline")
        self.assertIn("__safety_item", self.backend)
        for token in [
            "ban_empty_ua",
            "cc_ban_60s",
            "runtime_bans_empty",
            "ip_black_empty",
            "url_white_api_compat",
        ]:
            with self.subTest(token=token):
                self.assertIn(token, body)
        for pattern in [r"/v[0-9]+\b", r"\b[a-z0-9-]+\.vip\b", r"\bLLM\s*/\s*API\b"]:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(body, pattern)
        for unsafe in [
            "__write_rule",
            "__write_config",
            "__write_site_config",
            "public.serviceReload",
            "add_ip_black",
            "add_permanent_ban",
            "clean_waf_drop_ip",
            "remove_waf_drop_ip",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_official_feature_audit_is_read_only_and_tracks_main_features(self):
        body = self._function_body("get_official_feature_audit")
        for token in [
            "site_rule_application",
            "single_site_switch",
            "routine_filtering",
            "uri_encryption_protection",
            "uri_special_rules",
            "cdn_mode",
            "false_positive_safety",
            "官方功能对齐巡检",
        ]:
            with self.subTest(token=token):
                self.assertIn(token, body)
        for unsafe in [
            "__write_rule",
            "__write_config",
            "__write_site_config",
            "public.serviceReload",
            "add_ip_black",
            "add_permanent_ban",
            "clean_waf_drop_ip",
            "remove_waf_drop_ip",
            "set_",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_rule_risk_audit_is_read_only_and_checks_overbroad_rules(self):
        body = self._function_body("get_rule_risk_audit")
        self.assertIn("RULE_RISK_AUDIT_RULES", self.backend)
        self.assertIn("__rule_risk_item", self.backend)
        self.assertIn("__audit_rule_value", self.backend)
        self.assertIn("re.compile", self.backend)
        for token in [
            "url_black",
            "user_agent",
            "header",
            "cookie",
            "args",
            "post",
            "url_white",
            "user_agent_white",
            "match_all",
            "regex_error",
            "too_short",
            "broad_ua",
        ]:
            with self.subTest(token=token):
                self.assertIn(token, self.backend)
        for unsafe in [
            "__write_rule",
            "__write_config",
            "__write_site_config",
            "public.serviceReload",
            "add_ip_black",
            "add_permanent_ban",
            "clean_waf_drop_ip",
            "remove_waf_drop_ip",
            "import_rule_bundle",
            "remove_rule",
        ]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_known_backend_operator_messages_are_chinese(self):
        self.assertIn(u"URI加密保护", self.backend)
        for token in [
            "Connection to the cloud failed",
            "Permanent blacklist",
            "Unpack IP from the firewall",
            "Unblock all IPs from the firewall",
            "Failed to get data",
        ]:
            with self.subTest(token=token):
                self.assertNotIn(token, self.backend)


if __name__ == "__main__":
    unittest.main()
