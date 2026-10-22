import re
import unittest
from pathlib import Path


class FrontendUiContractTest(unittest.TestCase):
    def setUp(self):
        self.plugin_dir = Path(__file__).resolve().parents[1]
        self.frontend = (self.plugin_dir / "index.html").read_text(encoding="utf-8", errors="replace")

    def _init_body(self):
        marker = re.search(r"\binit\s*:\s*function\s*\(\)\s*\{", self.frontend)
        self.assertIsNotNone(marker, "init:function() block not found")
        next_method = re.search(r"\n\s*set_swicth_view\s*:\s*function\s*\(", self.frontend[marker.end():])
        self.assertIsNotNone(next_method, "method after init:function() not found")
        return self.frontend[marker.end(): marker.end() + next_method.start()]

    def _object_function_body(self, name):
        marker = re.search(r"\b" + re.escape(name) + r"\s*:\s*function\s*\([^)]*\)\s*\{", self.frontend)
        self.assertIsNotNone(marker, name + ":function() block not found")
        start = marker.end()
        depth = 1
        pos = start
        quote = None
        escaped = False
        line_comment = False
        block_comment = False
        while pos < len(self.frontend):
            char = self.frontend[pos]
            nxt = self.frontend[pos + 1] if pos + 1 < len(self.frontend) else ""

            if line_comment:
                if char in "\r\n":
                    line_comment = False
                pos += 1
                continue
            if block_comment:
                if char == "*" and nxt == "/":
                    block_comment = False
                    pos += 2
                    continue
                pos += 1
                continue
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                pos += 1
                continue

            if char == "/" and nxt == "/":
                line_comment = True
                pos += 2
                continue
            if char == "/" and nxt == "*":
                block_comment = True
                pos += 2
                continue
            if char in ("'", '"', "`"):
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return self.frontend[start:pos]
            pos += 1
        self.fail(name + ":function() block is not balanced")

    def _skip_balanced_brace(self, source, brace_pos):
        depth = 1
        pos = brace_pos + 1
        quote = None
        escaped = False
        line_comment = False
        block_comment = False
        while pos < len(source):
            char = source[pos]
            nxt = source[pos + 1] if pos + 1 < len(source) else ""

            if line_comment:
                if char in "\r\n":
                    line_comment = False
                pos += 1
                continue
            if block_comment:
                if char == "*" and nxt == "/":
                    block_comment = False
                    pos += 2
                    continue
                pos += 1
                continue
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                pos += 1
                continue

            if char == "/" and nxt == "/":
                line_comment = True
                pos += 2
                continue
            if char == "/" and nxt == "*":
                block_comment = True
                pos += 2
                continue
            if char in ("'", '"', "`"):
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return pos + 1
            pos += 1
        self.fail("nested function body is not balanced")

    def _init_top_level_code(self):
        body = self._init_body()
        output = []
        pos = 0
        quote = None
        escaped = False
        line_comment = False
        block_comment = False
        while pos < len(body):
            char = body[pos]
            nxt = body[pos + 1] if pos + 1 < len(body) else ""

            if line_comment:
                output.append(char)
                if char in "\r\n":
                    line_comment = False
                pos += 1
                continue
            if block_comment:
                output.append(char)
                if char == "*" and nxt == "/":
                    output.append(nxt)
                    block_comment = False
                    pos += 2
                    continue
                pos += 1
                continue
            if quote:
                output.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                pos += 1
                continue

            if char == "/" and nxt == "/":
                output.extend([char, nxt])
                line_comment = True
                pos += 2
                continue
            if char == "/" and nxt == "*":
                output.extend([char, nxt])
                block_comment = True
                pos += 2
                continue
            if char in ("'", '"', "`"):
                quote = char
                output.append(char)
                pos += 1
                continue

            is_function = (
                body.startswith("function", pos)
                and (pos == 0 or not re.match(r"[\w$]", body[pos - 1]))
                and (pos + 8 >= len(body) or not re.match(r"[\w$]", body[pos + 8]))
            )
            if is_function:
                brace_pos = body.find("{", pos)
                self.assertNotEqual(brace_pos, -1, "nested function has no body")
                output.append(body[pos:brace_pos])
                output.append("{/* nested callback body omitted */}")
                pos = self._skip_balanced_brace(body, brace_pos)
                continue

            output.append(char)
            pos += 1
        return "".join(output)

    def test_official_style_navigation_targets_exist(self):
        expected = {
            "home",
            "site",
            "overall",
            "history",
            "blacklist",
            "whitelist",
            "ipstats",
            "statistics",
            "notification",
            "logs",
            "webshell",
        }
        nav_targets = set(re.findall(r"<li\b[^>]*\bdata-target=['\"]([^'\"]+)['\"]", self.frontend))
        item_targets = set(
            re.findall(
                r"<div\b(?=[^>]*\bclass=['\"][^'\"]*\bitem_con\b)(?=[^>]*\bdata-type=['\"]([^'\"]+)['\"])",
                self.frontend,
            )
        )

        self.assertTrue(expected.issubset(nav_targets), sorted(expected - nav_targets))
        self.assertTrue(expected.issubset(item_targets), sorted(expected - item_targets))

    def test_critical_dom_contract_is_preserved(self):
        required_ids = [
            "overall_table",
            "site_list_view",
            "site_detail_view",
            "site_detail_title",
            "site_detail_back",
            "site_detail_header_rules",
            "site_detail_cookie_rules",
            "site_detail_args_rules",
            "site_detail_post_rules",
            "site_detail_rule_override_card",
            "site_detail_rule_override_title",
            "site_detail_rule_override_desc",
            "site_detail_rule_override_refresh",
            "site_detail_rule_override_table",
            "site_detail_cdn_headers",
            "site_detail_cdn_header_rule",
            "site_detail_cdn_header_table",
            "site_detail_cdn_proxy_start_ip",
            "site_detail_cdn_proxy_end_ip",
            "site_detail_add_cdn_proxy",
            "site_detail_refresh_cdn_proxy",
            "site_detail_cdn_proxy_table",
            "site_detail_url_white",
            "site_detail_url_white_card",
            "site_detail_url_white_rule",
            "site_detail_add_url_white",
            "site_detail_refresh_url_white",
            "site_detail_url_white_table",
            "site_detail_uri_rules",
            "site_detail_uri_tell",
            "site_detail_url_rule_uri",
            "site_detail_url_rule_body",
            "site_detail_url_rule_table",
            "site_detail_url_tell_uri",
            "site_detail_url_tell_param",
            "site_detail_url_tell_pass",
            "site_detail_url_tell_table",
            "site_table",
            "history_table",
            "blacklist_ip_region_table",
            "blacklist_url_table",
            "blacklist_ua_table",
            "blacklist_header_table",
            "blacklist_cookie_table",
            "blacklist_args_table",
            "blacklist_post_table",
            "whitelist_ip_region_table",
            "whitelist_url_table",
            "whitelist_ua_table",
            "logs_table",
            "ipstats_tbody",
            "ipstats_refresh",
            "ipstats_site_filter",
            "ipstats_ban_all",
            "uristats_days",
            "uristats_site_filter",
            "uristats_refresh",
            "uristats_summary",
            "uristats_tbody",
            "safety_baseline_status",
            "safety_baseline_refresh",
            "safety_baseline_table",
            "official_feature_status",
            "official_feature_refresh",
            "official_feature_table",
            "fp_uri_rule",
            "fp_ua_rule",
            "rule_backup_status",
            "rule_bundle_text",
            "config_health_refresh",
            "config_health_status",
            "config_health_table",
            "rule_risk_status",
            "rule_risk_refresh",
            "rule_risk_table",
            "overview_trend_table",
            "overview_top_sites_table",
            "overview_dynamics_table",
            "overview_rule_table",
            "report_search_site",
            "report_search_type",
            "report_search_ip",
            "report_search_uri",
            "report_search_keyword",
            "report_search_refresh",
            "report_search_tbody",
            "report_search_summary",
            "history_export",
            "history_detail_table",
            "notification_refresh",
            "notification_summary",
            "notification_table",
            "simulation_uri",
            "simulation_user_agent",
            "simulation_args",
            "simulation_post",
            "simulation_cookie",
            "simulation_header",
            "simulation_run",
            "simulation_result",
            "simulation_templates",
            "cc_mode_basic",
            "cc_mode_general",
            "cc_mode_auto",
            "cc_mode_enhanced",
        ]
        for dom_id in required_ids:
            with self.subTest(dom_id=dom_id):
                self.assertRegex(self.frontend, r"\bid=['\"]" + re.escape(dom_id) + r"['\"]")

    def test_init_does_not_call_destructive_methods(self):
        body = self._init_top_level_code()
        destructive_methods = [
            "clean_waf_drop_ip",
            "add_ip_black",
            "remove_ip_black",
            "add_permanent_ban",
            "remove_permanent_ban",
        ]
        for method in destructive_methods:
            with self.subTest(method=method):
                self.assertNotIn(method, body)

    def test_core_ui_is_chinese_and_has_no_business_hardcode(self):
        required_tokens = [
            ">概览<",
            ">站点<",
            ">全局<",
            ">封禁<",
            ">黑名单<",
            ">白名单<",
            ">报表<",
            ">通知<",
            ">日志<",
            ">工具<",
            "空 User-Agent",
            "以当前配置和巡检结果为准",
            "安全基线巡检",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)
        for pattern in [r"\b[a-z0-9-]+\.vip\b", r"/v[0-9]+\b", r"\bLLM\s*/\s*API\b", r"URL[-]white\w+"]:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.frontend, pattern)

    def test_known_english_ui_leftovers_are_removed(self):
        forbidden_tokens = [
            ">NO<",
            ">OFF<",
            "Starting IP",
            "End IP",
            "Ready to export or import editable rules.",
            "封禁 8h",
        ]
        for token in forbidden_tokens:
            with self.subTest(token=token):
                self.assertNotIn(token, self.frontend)

    def test_blacklist_ip_manual_duration_controls_exist(self):
        for token in [
            "blacklist_ban_duration",
            "封禁时长",
            "30分钟",
            "1小时",
            "8小时",
            "10年",
            "315360000",
            "仅单 IP 生效",
            "duration_seconds:duration_seconds",
        ]:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)
        self.assertNotIn("永封", self.frontend)

        add_body = self._object_function_body("add_ip_black")
        self.assertIn("duration_seconds:obj.duration_seconds", add_body)

        init_body = self._object_function_body("init")
        self.assertIn("#blacklist_ban_duration", init_body)
        self.assertIn("duration_seconds:duration_seconds", init_body)

    def test_official_priority_reference_is_present(self):
        priority = (
            "IP白名单 > IP黑名单 > UA白名单 > UA黑名单 > "
            "URL关键字拦截 > URL CC防御 > URL白名单 > "
            "URL黑名单 > 非浏览器 > User-Agent > CC防御 > Cookie > "
            "URI过滤 > URL参数 > POST > 站点自定义防御"
        )
        self.assertIn("规则优先级参考", self.frontend)
        self.assertIn(priority, self.frontend)
        self.assertIn("部分控制项尚未实现", self.frontend)

    def test_plugin_panel_uses_viewport_sized_layout(self):
        self.assertRegex(self.frontend, r"\bfit_panel_shell\s*:\s*function\s*\(")
        self.assertIn("window.innerWidth", self.frontend)
        self.assertIn("window.innerHeight", self.frontend)
        self.assertIn("resize.free_waf_panel", self.frontend)
        self.assertIn(".layui-layer-content", self.frontend)
        self.assertIn("calc(100vh - 64px)", self.frontend)
        self.assertNotIn("min-height:680px", self.frontend)
        self.assertNotIn("Math.max(960", self.frontend)
        self.assertNotIn("Math.max(680", self.frontend)
        self.assertIn(".closest('.layui-layer-page')", self.frontend)
        self.assertNotIn("var $layer = $('.layui-layer-page')", self.frontend)
        self.assertNotIn(".width(1200)", self.frontend)
        self.assertNotIn("clientHeight-1100", self.frontend)

    def test_site_config_uses_full_page_detail_view(self):
        required_tokens = [
            "show_site_list_view",
            "site_detail_view",
            "site_detail_title",
            "site_detail_back",
            "site_detail_header_rules",
            "site_detail_cookie_rules",
            "site_detail_args_rules",
            "site_detail_post_rules",
            "site_detail_rule_override_card",
            "site_detail_rule_override_table",
            "show_site_rule_override",
            "render_site_rule_override",
            "site_detail_cdn_headers",
            "site_detail_cdn_header_rule",
            "site_detail_cdn_header_table",
            "render_site_cdn_headers",
            "site_detail_cdn_proxy_start_ip",
            "site_detail_cdn_proxy_end_ip",
            "site_detail_cdn_proxy_table",
            "render_site_cdn_trusted_proxy",
            "site_detail_url_white",
            "site_detail_url_white_rule",
            "site_detail_url_white_table",
            "render_site_url_white_rules",
            "site_detail_uri_rules",
            "site_detail_uri_tell",
            "render_site_url_rules",
            "render_site_url_tell_rules",
            "render_site_config({siteName:siteName}",
            "ruleName:'header'",
            "ruleName:'cookie'",
            "ruleName:'args'",
            "ruleName:'post'",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        body = self._object_function_body("set_site_config_view")
        self.assertNotIn("layer.open", body)
        self.assertIn("#site_list_view", body)
        self.assertIn("#site_detail_view", body)
        self.assertIn("site_config_switch", body)
        self.assertIn("show_site_rule_override", body)
        self.assertIn("render_site_cdn_headers", body)
        self.assertIn("render_site_url_white_rules", body)
        self.assertIn("render_site_url_rules", body)
        self.assertIn("render_site_url_tell_rules", body)

    def test_site_url_whitelist_uses_full_page_detail(self):
        required_tokens = [
            "站点URL白名单",
            "site_detail_url_white",
            "site_detail_url_white_card",
            "site_detail_url_white_rule",
            "site_detail_add_url_white",
            "site_detail_refresh_url_white",
            "site_detail_url_white_table",
            "render_site_url_white_rules",
            "ruleName:'url_white'",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        render_body = self._object_function_body("render_site_url_white_rules")
        self.assertIn("#site_detail_url_white_table", render_body)
        self.assertIn("get_site_rule", render_body)
        self.assertIn("remove_site_rule", render_body)
        self.assertIn("escapeHTML", render_body)
        self.assertNotIn("add_url_white", render_body)
        self.assertNotIn("layer.open", render_body)

        add_body = self._object_function_body("add_site_rule")
        self.assertIn("ruleValue:obj.ruleValue", add_body)

    def test_site_rule_overrides_are_full_page(self):
        required_tokens = [
            "规则覆盖",
            "site_detail_rule_override_card",
            "site_detail_rule_override_title",
            "site_detail_rule_override_desc",
            "site_detail_rule_override_refresh",
            "site_detail_rule_override_table",
            "show_site_rule_override({siteName:_this.current_site_name,name:'Header规则覆盖',ruleName:'header'})",
            "show_site_rule_override({siteName:_this.current_site_name,name:'Cookie规则覆盖',ruleName:'cookie'})",
            "show_site_rule_override({siteName:_this.current_site_name,name:'GET参数规则覆盖',ruleName:'args'})",
            "show_site_rule_override({siteName:_this.current_site_name,name:'POST规则覆盖',ruleName:'post'})",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        show_body = self._object_function_body("show_site_rule_override")
        self.assertIn("#site_detail_rule_override_card", show_body)
        self.assertIn("render_site_rule_override", show_body)
        self.assertNotIn("layer.open", show_body)

        render_body = self._object_function_body("render_site_rule_override")
        self.assertIn("#site_detail_rule_override_table", render_body)
        self.assertIn("get_site_disable_rule", render_body)
        self.assertIn("set_site_disable_rule", render_body)
        self.assertIn("escapeHTML", render_body)
        self.assertNotIn("layer.open", render_body)

    def test_site_uri_custom_rules_use_full_page_detail(self):
        required_tokens = [
            "URI自定义拦截",
            "URI加密保护",
            "参数口令",
            "口令值",
            "site_detail_add_url_rule",
            "site_detail_refresh_url_rule",
            "site_detail_add_url_tell",
            "site_detail_refresh_url_tell",
            "ruleName:'url_rule'",
            "ruleName:'url_tell'",
            "ruleUri",
            "rulePass",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        for name in ["render_site_url_rules", "render_site_url_tell_rules"]:
            body = self._object_function_body(name)
            self.assertIn("get_site_rule", body)
            self.assertIn("remove_site_rule", body)
            self.assertIn("escapeHTML", body)
            self.assertNotIn("layer.open", body)

        add_body = self._object_function_body("add_site_rule")
        self.assertIn("ruleUri:obj.ruleUri", add_body)
        self.assertIn("rulePass:obj.rulePass", add_body)

    def test_black_white_list_extended_controls_exist(self):
        required_tokens = [
            "blacklist_url_rule",
            "blacklist_ua_rule",
            "blacklist_header_rule",
            "blacklist_cookie_rule",
            "blacklist_args_rule",
            "blacklist_post_rule",
            "whitelist_ua_rule",
            "add_blacklist_url_rule",
            "refresh_blacklist_url_rule",
            "add_blacklist_ua_rule",
            "refresh_blacklist_ua_rule",
            "add_blacklist_header_rule",
            "refresh_blacklist_header_rule",
            "add_blacklist_cookie_rule",
            "refresh_blacklist_cookie_rule",
            "add_blacklist_args_rule",
            "refresh_blacklist_args_rule",
            "add_blacklist_post_rule",
            "refresh_blacklist_post_rule",
            "add_whitelist_ua_rule",
            "refresh_whitelist_ua_rule",
            "render_blacklist_url",
            "render_blacklist_ua",
            "render_blacklist_header",
            "render_blacklist_cookie",
            "render_blacklist_args",
            "render_blacklist_post",
            "render_whitelist_ua",
            "user_agent_white",
            "user_agent",
            "ruleName:'header'",
            "ruleName:'cookie'",
            "ruleName:'args'",
            "ruleName:'post'",
            "data-type=\"bl_url\"",
            "data-type=\"bl_ua\"",
            "data-type=\"bl_header\"",
            "data-type=\"bl_cookie\"",
            "data-type=\"bl_args\"",
            "data-type=\"bl_post\"",
            "data-type=\"wl_ua\"",
            "UA黑名单",
            "Header黑名单",
            "Cookie黑名单",
            "GET参数黑名单",
            "POST黑名单",
            "UA白名单",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

    def test_uri_report_controls_exist_and_escape_user_content(self):
        required_tokens = [
            "URI报表",
            "render_uri_stats",
            "render_uri_stats_table",
            "get_uri_stats",
            "uristats_whitelist",
            "add_url_white",
            "URL白名单",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        body = self._object_function_body("render_uri_stats_table")
        self.assertIn("escapeHTML", body)
        for field in ["row.uri", "k", "row.sites.join(', ')"]:
            with self.subTest(field=field):
                self.assertRegex(body, r"escapeHTML\s*\(\s*" + re.escape(field) + r"\s*\)")

    def test_tools_false_positive_and_rule_backup_exist(self):
        required_tokens = [
            "false_positive",
            "rule_backup",
            "fp_uri_rule",
            "fp_ua_rule",
            "fp_add_url_white",
            "fp_add_ua_white",
            "rule_backup_export",
            "rule_backup_import",
            "rule_bundle_text",
            "get_rule_bundle",
            "import_rule_bundle",
            "download_rule_bundle",
            "import_rule_bundle_view",
            "手动处理",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        body = self._object_function_body("bind_false_positive_tools")
        self.assertIn("add_url_white", body)
        self.assertIn("add_overall_rule", body)
        for unsafe in ["add_ip_black", "add_permanent_ban", "ipstats_ban_ip", "clean_waf_drop_ip"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_tools_config_health_report_exists_and_is_read_only(self):
        required_tokens = [
            "配置诊断",
            "config_health",
            "config_health_refresh",
            "config_health_status",
            "config_health_table",
            "render_config_health_report",
            "get_config_health_report",
            "规则文件",
            "站点字段",
            "运行封禁来源",
            "规则数量",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        body = self._object_function_body("render_config_health_report")
        self.assertIn("get_config_health_report", body)
        self.assertIn("escapeHTML", body)
        for field in ["item.title", "item.detail", "item.action"]:
            with self.subTest(field=field):
                self.assertRegex(body, r"escapeHTML\s*\(\s*" + re.escape(field) + r"\s*\)")
        for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip", "add_url_white", "import_rule_bundle"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_home_safety_baseline_audit_exists_and_is_read_only(self):
        required_tokens = [
            "安全基线巡检",
            "safety_baseline_status",
            "safety_baseline_refresh",
            "safety_baseline_table",
            "render_safety_baseline",
            "get_safety_baseline",
            "empty_ua",
            "CC封禁时长",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        body = self._object_function_body("render_safety_baseline")
        self.assertIn("get_safety_baseline", body)
        self.assertIn("escapeHTML", body)
        for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip", "add_url_white"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_home_safety_baseline_is_manual_only(self):
        self.assertIn("点击刷新基线后开始检查", self.frontend)

        init_body = self._object_function_body("init")
        self.assertIn("#safety_baseline_refresh", init_body)
        self.assertIn("_this.render_safety_baseline()", init_body)

        refresh_body = self._object_function_body("refresh_data_total")
        self.assertNotIn("this.render_safety_baseline()", refresh_body)
        self.assertNotIn("_this.render_safety_baseline()", refresh_body)

    def test_home_all_audits_are_manual_and_tools_are_lazy(self):
        body = self._object_function_body("refresh_data_total")
        home = body.split("case 'home':", 1)[1].split("case 'overall':", 1)[0]
        self.assertIn("get_total_all", home)
        self.assertIn("render_overview_report", home)
        for name in ["render_safety_baseline", "render_official_feature_audit", "render_rule_risk_audit"]:
            self.assertNotIn(name, home)
        init = self._init_top_level_code()
        self.assertNotIn("this.return_site_list(", init)
        self.assertNotIn("this.render_san_webshell(", init)

    def test_frontend_has_no_external_blocking_resources(self):
        self.assertNotRegex(self.frontend, r'<(?:script|link)\b[^>]*(?:src|href)=["\'](?:https?:)?//')
        self.assertNotIn("jquery.fixedheadertable", self.frontend)
        self.assertNotRegex(self.frontend, r"(?m)^\s*table tr td\s*\{")

    def test_policy_notices_do_not_assert_unverified_server_settings(self):
        for text in ["当前采用低误封策略：", "空 User-Agent 全局放行", "CC 封禁时长固定为", "404 扫描类阈值为每小时 80 次"]:
            self.assertNotIn(text, self.frontend)
        self.assertIn("近7日", self.frontend)

    def test_request_lifecycle_has_bounded_timeouts_and_cleanup(self):
        body = self._object_function_body("http")
        self.assertIn("30000", body)
        self.assertNotIn("99999999", body)
        self.assertIn("return xhr", body)
        self.assertIn("obj.complete", body)
        self.assertIn("statusTarget", body)
        self.assertNotIn("$(document).unbind('click')", self.frontend)
        for name in ["webshell_san_dir", "upload_file_url", "webshell_send_baota"]:
            self.assertIn("120000", self._object_function_body(name))

    def test_statistics_background_state_contract_and_lifecycle_exist(self):
        body = self._object_function_body("render_website_statistics")
        for token in ["res.loading", "res.error", "res.checked_at", "2000", "_statistics_sequence", "statistics_is_active"]:
            self.assertIn(token, body)
        wrapper = self._object_function_body("get_website_statistics_summary")
        self.assertIn("force", wrapper)
        self.assertIn("return this.http", wrapper)
        for name in ["destroy", "stop_statistics_polling"]:
            self.assertRegex(self.frontend, r"\b" + name + r"\s*:\s*function")

    def test_home_official_feature_audit_exists_and_is_read_only(self):
        required_tokens = [
            "官方功能对齐巡检",
            "official_feature_status",
            "official_feature_refresh",
            "official_feature_table",
            "render_official_feature_audit",
            "get_official_feature_audit",
            "站点级规则应用",
            "URI加密保护",
            "CDN模式",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        body = self._object_function_body("render_official_feature_audit")
        self.assertIn("get_official_feature_audit", body)
        self.assertIn("escapeHTML", body)
        for field in ["item.title", "item.detail", "item.action"]:
            with self.subTest(field=field):
                self.assertRegex(body, r"escapeHTML\s*\(\s*" + re.escape(field) + r"\s*\)")
        for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip", "add_url_white", "import_rule_bundle"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_home_rule_risk_audit_exists_and_is_read_only(self):
        required_tokens = [
            "规则风险巡检",
            "rule_risk_status",
            "rule_risk_refresh",
            "rule_risk_table",
            "render_rule_risk_audit",
            "get_rule_risk_audit",
            "过宽规则",
            "正则错误",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        body = self._object_function_body("render_rule_risk_audit")
        self.assertIn("get_rule_risk_audit", body)
        self.assertIn("escapeHTML", body)
        for field in ["item.scope", "item.rule_name", "item.rule_value", "item.reason", "item.action"]:
            with self.subTest(field=field):
                self.assertRegex(body, r"escapeHTML\s*\(\s*" + re.escape(field) + r"\s*\)")
        for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip", "add_url_white", "import_rule_bundle"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_official_dashboard_report_search_and_blockade_controls_exist(self):
        required_tokens = [
            "攻击趋势",
            "站点TOP",
            "防御动态",
            "规则分布",
            "render_overview_report",
            "get_overview_report",
            "日志搜索",
            "HTTP详情",
            "get_report_search",
            "get_report_http_detail",
            "render_report_search",
            "show_report_http_detail",
            "封禁明细",
            "导出封禁记录",
            "get_blockade_records",
            "export_blockade_records",
            "render_blockade_records",
            "download_blockade_records",
            "基础模式",
            "普通模式",
            "自动模式",
            "增强模式",
            "apply_cc_mode_preset",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        overview_body = self._object_function_body("render_overview_report")
        self.assertIn("get_overview_report", overview_body)
        self.assertIn("escapeHTML", overview_body)
        for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip", "add_url_white"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, overview_body)

        search_body = self._object_function_body("render_report_search")
        self.assertIn("get_report_search", search_body)
        self.assertIn("escapeHTML", search_body)
        self.assertIn("report_http_detail", search_body)
        for field in ["row.site", "row.ip", "row.uri", "row.user_agent", "row.rule_type"]:
            with self.subTest(field=field):
                self.assertRegex(search_body, r"escapeHTML\s*\(\s*" + re.escape(field) + r"\s*\)")
        for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, search_body)

        detail_body = self._object_function_body("show_report_http_detail")
        self.assertIn("get_report_http_detail", detail_body)
        self.assertIn("escapeHTML", detail_body)
        self.assertNotIn("add_ip_black", detail_body)

        blockade_body = self._object_function_body("render_blockade_records")
        self.assertIn("get_blockade_records", blockade_body)
        self.assertIn("escapeHTML", blockade_body)
        self.assertIn("history_detail_table", blockade_body)
        self.assertNotIn("add_ip_black", blockade_body)
        self.assertNotIn("add_permanent_ban", blockade_body)

    def test_report_dashboard_summary_layout_exists_and_is_read_only(self):
        required_ids = [
            "report_summary_refresh",
            "report_summary_hits",
            "report_summary_ips",
            "report_summary_uris",
            "report_summary_bans",
            "report_rule_distribution_table",
            "report_site_distribution_table",
            "report_top_ip_table",
            "report_top_uri_table",
        ]
        for dom_id in required_ids:
            with self.subTest(dom_id=dom_id):
                self.assertRegex(self.frontend, r"\bid=['\"]" + re.escape(dom_id) + r"['\"]")

        required_tokens = [
            "报表总览",
            "攻击总数",
            "攻击IP数",
            "触发URI数",
            "当前封禁",
            "规则类型分布",
            "站点拦截分布",
            "TOP IP",
            "TOP URI",
            "render_report_dashboard_summary",
            "get_report_dashboard_summary",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        body = self._object_function_body("render_report_dashboard_summary")
        self.assertIn("get_report_dashboard_summary", body)
        self.assertIn("escapeHTML", body)
        for selector in required_ids:
            with self.subTest(selector=selector):
                self.assertIn("#" + selector, body)
        for field in [
            "item.rule_type",
            "item.site",
            "item.ip",
            "item.uri",
        ]:
            with self.subTest(field=field):
                self.assertRegex(body, r"escapeHTML\s*\(\s*" + re.escape(field) + r"\s*\)")
        for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip", "add_url_white"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_website_statistics_page_exists_and_is_read_only(self):
        required_ids = [
            "website_stats_days", "website_stats_site_filter", "website_stats_refresh",
            "website_stats_status", "website_stats_requests", "website_stats_clients",
            "website_stats_bytes", "website_stats_errors", "website_stats_spiders",
            "website_stats_site_table", "website_stats_spider_table", "website_stats_client_table",
            "website_stats_status_table", "website_stats_top_uri_table", "website_stats_referer_table",
            "website_stats_common_ip_table", "website_stats_access_table", "website_stats_error_table",
            "website_stats_settings_table", "website_stats_http_error_table", "website_stats_trend",
            "website_stats_window", "website_stats_coverage", "website_stats_browser_table",
            "website_stats_os_table", "website_stats_device_table",
        ]
        for dom_id in required_ids:
            with self.subTest(dom_id=dom_id):
                self.assertRegex(self.frontend, r"\bid=['\"]" + re.escape(dom_id) + r"['\"]")

        for token in [
            "网站统计", "网站日志报告", "独立 IP", "响应体流量", "疑似蜘蛛（UA）",
            "HTTP 错误请求", "Nginx 诊断日志", "统计说明（只读）", "自然日",
            "不等同于真实人数或 UV", "UA 为客户端自报", "waf-website-summary-grid",
            ".waf-summary-grid.waf-website-summary-grid{grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}",
        ]:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        self.assertEqual(
            re.findall(r'class="website_stats_tab[^"]*"[^>]*data-stats-page="([^"]+)"', self.frontend),
            ["overview", "sites", "spiders", "clients", "access", "errors", "settings"],
        )
        bodies = {name: self._object_function_body(name) for name in [
            "get_website_statistics_summary", "render_website_statistics", "render_statistics_report",
            "statistics_table", "render_statistics_samples", "render_statistics_trend",
            "select_statistics_page", "init_statistics_samples",
        ]}
        request = bodies["render_website_statistics"]
        report = bodies["render_statistics_report"]
        table = bodies["statistics_table"]
        samples = bodies["render_statistics_samples"]
        trend = bodies["render_statistics_trend"]
        self.assertIn("get_website_statistics_summary", request)
        self.assertIn("_this.render_statistics_report(res)", request)
        self.assertIn("waf_dashboard.text(optItem.site)", request)
        self.assertIn("waf_dashboard.text(currentSite)", request)
        for body in [report, table, samples, trend]:
            self.assertRegex(body, r"\besc\s*=\s*waf_dashboard\.text")
        self.assertIn("esc(row.site)", report)
        self.assertIn("esc((row || {})[field]", table)
        for field in ["row.time", "row.site", "row.ip", "row.method", "row.uri", "row.status", "row.raw", "row.client"]:
            with self.subTest(sample_field=field):
                self.assertIn(field, samples)
        self.assertIn("esc(row.raw)", samples)
        self.assertIn("esc(value == null ? '--' : value)", samples)
        self.assertIn("esc(label)", trend)

        for call in [
            "this.statistics_table('spider',res.spiders,['spider','count'])",
            "this.statistics_table('client',res.clients,['ip','count'])",
            "this.statistics_table('status',res.status_codes,['status','count'])",
            "this.statistics_table('top_uri',res.top_uris,['uri','count'])",
            "this.statistics_table('referer',res.referers,['referer','count'])",
            "this.statistics_table('common_ip',res.common_clients,['ip','sites','count'])",
            "this.statistics_table('settings',res.settings,['key','value'])",
            "this.statistics_table('browser',res.browsers,['name','count'])",
            "this.statistics_table('os',res.operating_systems,['name','count'])",
            "this.statistics_table('device',res.devices,['name','count'])",
            "_this.render_statistics_samples(kind)",
            "this.render_statistics_trend(res.trend,res.window)",
        ]:
            with self.subTest(render_chain=call):
                self.assertIn(call, report)
        self.assertIn("schema2 ? res.server_errors : res.recent_errors", samples)
        self.assertIn("kind === 'http_error' && schema2 ? res.recent_errors : res.recent_access", samples)
        self.assertIn("$('#website_stats_window').text(", report)
        self.assertIn("$('#website_stats_coverage').text(", report)
        self.assertIn("$('#website_stats_status').text(", request)

        escaper = re.search(r"function text\(value\)\{([^\n]+)", self.frontend)
        self.assertIsNotNone(escaper, "raw-text HTML escaper not found")
        for entity in ["&amp;", "&lt;", "&gt;", "&quot;", "&#39;"]:
            with self.subTest(escaped_entity=entity):
                self.assertIn(entity, escaper.group(1))
        self.assertIn("text:text", self.frontend)
        for name, body in bodies.items():
            for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip", "add_url_white", "set_cc_conf"]:
                with self.subTest(method=name, unsafe=unsafe):
                    self.assertNotIn(unsafe, body)

    def test_official_overview_dashboard_layout_exists(self):
        required_ids = [
            "overview_total_protection",
            "overview_24h_protection",
            "overview_cc_protection",
            "overview_protection_days",
            "overview_active_bans",
            "overview_dashboard_shield",
            "overview_attack_map",
            "overview_blocked_ip_table",
            "overview_trend_chart",
            "overview_today_top_sites_table",
        ]
        for dom_id in required_ids:
            with self.subTest(dom_id=dom_id):
                self.assertRegex(self.frontend, r"\bid=['\"]" + re.escape(dom_id) + r"['\"]")

        required_tokens = [
            "近7日防护次数",
            "24小时防护",
            "CC防护",
            "防护天数",
            "封禁IP",
            "攻击地图",
            "7日拦截趋势",
            "今日站点拦截TOP5",
            "防御动态",
            "防护概览",
            'id="overview_report_refresh"',
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        self.assertIn("#overview_report_refresh", self._object_function_body("init"))
        body = self._object_function_body("render_overview_report")
        for selector in required_ids:
            with self.subTest(selector=selector):
                if selector == "overview_attack_map":
                    self.assertIn("render_dashboard_charts", body)
                    self.assertIn("#" + selector, self._object_function_body("render_dashboard_charts"))
                else:
                    self.assertIn("#" + selector, body)
        for field in [
            "res.summary.total_protection",
            "res.summary.protection_24h",
            "res.summary.cc_protection",
            "res.summary.protection_days",
            "res.summary.active_bans",
        ]:
            with self.subTest(field=field):
                self.assertIn(field, body)
        for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip", "add_url_white"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, body)

    def test_notification_center_and_simulation_tools_exist_and_are_safe(self):
        required_tokens = [
            "防护通知",
            "通知中心",
            "get_defense_notifications",
            "render_defense_notifications",
            "notification_table",
            "notification_refresh",
            "模拟攻击",
            "simulate_attack",
            "run_attack_simulation",
            "render_attack_simulation_result",
            "simulation_templates",
            "simulation_result",
            "本地规则演练",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        notification_body = self._object_function_body("render_defense_notifications")
        self.assertIn("get_defense_notifications", notification_body)
        self.assertIn("escapeHTML", notification_body)
        for field in ["item.time", "item.level_text", "item.site", "item.ip", "item.uri", "item.message"]:
            with self.subTest(field=field):
                self.assertRegex(notification_body, r"escapeHTML\s*\(\s*" + re.escape(field) + r"\s*\)")
        for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip", "add_url_white"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, notification_body)

        simulation_body = self._object_function_body("run_attack_simulation")
        self.assertIn("simulate_attack", simulation_body)
        self.assertNotIn("$.ajax", simulation_body)
        for unsafe in ["add_ip_black", "add_permanent_ban", "clean_waf_drop_ip", "add_url_white"]:
            with self.subTest(unsafe=unsafe):
                self.assertNotIn(unsafe, simulation_body)

        result_body = self._object_function_body("render_attack_simulation_result")
        self.assertIn("escapeHTML", result_body)
        for field in ["item.rule_name", "item.pattern", "item.reason"]:
            with self.subTest(field=field):
                self.assertRegex(result_body, r"escapeHTML\s*\(\s*" + re.escape(field) + r"\s*\)")

    def test_rule_backup_import_is_manual_and_escaped(self):
        export_body = self._object_function_body("download_rule_bundle")
        import_body = self._object_function_body("import_rule_bundle_view")
        self.assertIn("get_rule_bundle", export_body)
        self.assertIn("render_download_link", export_body)
        self.assertIn("layer.confirm", import_body)
        self.assertIn("import_rule_bundle", import_body)
        self.assertIn("escapeHTML", import_body)

    def test_cdn_full_page_manager_uses_site_detail_table(self):
        body = self._object_function_body("render_site_cdn_headers")
        self.assertIn("#site_detail_cdn_header_table", body)
        self.assertIn("get_site_cdn_header", body)
        self.assertIn("remove_site_cdn_header", body)
        self.assertIn("escapeHTML", body)
        self.assertNotIn("#other_rule_table", body)

        legacy_body = self._object_function_body("render_cdn_table")
        self.assertNotIn("callback(data)", legacy_body)

    def test_cdn_trusted_proxy_manager_exists(self):
        required_tokens = [
            "可信代理来源",
            "site_detail_cdn_proxy_start_ip",
            "site_detail_cdn_proxy_end_ip",
            "site_detail_add_cdn_proxy",
            "site_detail_refresh_cdn_proxy",
            "site_detail_cdn_proxy_table",
            "render_site_cdn_trusted_proxy",
            "get_site_cdn_trusted_proxy",
            "add_site_cdn_trusted_proxy",
            "remove_site_cdn_trusted_proxy",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, self.frontend)

        body = self._object_function_body("render_site_cdn_trusted_proxy")
        self.assertIn("#site_detail_cdn_proxy_table", body)
        self.assertIn("get_site_cdn_trusted_proxy", body)
        self.assertIn("remove_site_cdn_trusted_proxy", body)
        self.assertIn("escapeHTML", body)
        self.assertNotIn("add_ip_black", body)
        self.assertNotIn("add_permanent_ban", body)

    def test_webshell_nav_binding_is_scoped(self):
        self.assertIn('.item_con[data-type="webshell"] .waf_nav_group span', self.frontend)
        self.assertNotIn("$('.waf_nav_group span').click", self.frontend)

    def test_logs_rendering_uses_escape_html_for_user_controlled_fields(self):
        self.assertRegex(self.frontend, r"\bescapeHTML\s*:\s*function\s*\(")

        try:
            area = self._object_function_body("render_site_logs")
        except AssertionError:
            match = re.search(r"site_logs_table|logs_table", self.frontend)
            self.assertIsNotNone(match, "logs rendering area not found")
            start = max(0, match.start() - 3000)
            end = min(len(self.frontend), match.end() + 6000)
            area = self.frontend[start:end]

        self.assertIn("escapeHTML", area)
        for field in ["row[0]", "row[1]", "row[2]", "row[3]", "row[4]", "row[5]"]:
            with self.subTest(field=field):
                self.assertRegex(area, r"escapeHTML\s*\(\s*" + re.escape(field) + r"\s*\)")


if __name__ == "__main__":
    unittest.main()
