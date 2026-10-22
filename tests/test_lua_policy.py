import re
import unittest
from pathlib import Path


class LuaPolicyTest(unittest.TestCase):
    def setUp(self):
        runtime_path = Path(__file__).resolve().parents[1] / "init.lua"
        self.init_lua = runtime_path.read_text(encoding="utf-8", errors="replace")

    def _function_body(self, name):
        match = re.search(r"function\s+" + re.escape(name) + r"\s*\([^)]*\)(.*?)\nend", self.init_lua, re.S)
        self.assertIsNotNone(match, name + " function not found")
        return match.group(1)

    def _call_pos(self, body, call):
        match = re.search(r"^\s*" + re.escape(call) + r"\s*$", body, re.M)
        self.assertIsNotNone(match, call + " call not found")
        return match.start()

    def test_write_log_does_not_use_drop_list_as_retry_counter(self):
        body = self._function_body("write_log")
        self.assertNotRegex(body, r"free_waf_drop_ip:(get|incr)\(")
        self.assertIn("free_waf:get(retry_key)", body)

    def test_write_log_does_not_escalate_regular_hits_to_ip_ban(self):
        body = self._function_body("write_log")
        self.assertNotIn("free_waf_drop_ip:set", body)
        self.assertNotIn("write_drop_ip('inc'", body)

    def test_disable_path_blocks_request_without_ip_ban(self):
        body = self._function_body("url_path")
        self.assertNotIn("add_ip_black_exact", body)
        self.assertNotIn("free_waf_drop_ip:set", body)
        self.assertNotIn("write_drop_ip", body)
        self.assertIn("write_log(\"url_path\"", body)

    def test_drop_list_only_blocks_explicit_bans(self):
        body = self._function_body("drop")
        self.assertRegex(body, r"free_waf_drop_ip:get\(ip\)")
        self.assertNotIn("free_waf:get", body)

    def test_clean_drop_ip_removes_exact_persistent_temp_bans(self):
        body = self._function_body("clean_btwaf_drop_ip")
        self.assertIn("read_file('ip_black')", body)
        self.assertIn("encode_json_array(new_rules)", body)
        self.assertIn("ip_black_rules = new_rules", body)
        self.assertIn("table.concat(rule[1],'.')", body)

    def test_internal_routes_are_available_before_open_gate(self):
        body = self._function_body("run_btwaf")
        self.assertLess(body.index("min_route()"), body.index("if not config['open']"))

    def test_ip_whitelist_has_highest_runtime_priority(self):
        body = self._function_body("run_btwaf")
        self.assertLess(self._call_pos(body, "if ip_white() then return true end"), self._call_pos(body, "drop()"))
        self.assertLess(self._call_pos(body, "if ip_white() then return true end"), self._call_pos(body, "ip_black()"))

    def test_real_bans_run_before_url_whitelist(self):
        body = self._function_body("run_btwaf")
        self.assertLess(self._call_pos(body, "drop()"), self._call_pos(body, "if url_white() then return true end"))
        self.assertLess(self._call_pos(body, "ip_black()"), self._call_pos(body, "if url_white() then return true end"))

    def test_url_whitelist_runs_before_attack_rules(self):
        body = self._function_body("run_btwaf")
        whitelist_pos = self._call_pos(body, "if url_white() then return true end")
        for call in [
            "ban_empty_ua()",
            "url_black()",
            "drop_abroad()",
            "cc()",
            "cc2()",
            "user_agent()",
            "url()",
            "args()",
            "cookie()",
            "scan_black()",
            "post()",
        ]:
            self.assertLess(whitelist_pos, self._call_pos(body, call), call)

    def test_user_agent_whitelist_precedes_user_agent_blacklist(self):
        self.assertIn("local user_agent_white_rules = select_rule(read_file('user_agent_white'))", self.init_lua)
        body = self._function_body("run_btwaf")
        self.assertLess(
            self._call_pos(body, "if user_agent_white() then return true end"),
            self._call_pos(body, "user_agent()"),
        )
        self.assertLess(
            self._call_pos(body, "ip_black()"),
            self._call_pos(body, "if user_agent_white() then return true end"),
        )
        helper = self._function_body("user_agent_white")
        self.assertIn("user_agent_white_rules", helper)
        self.assertIn("request_header['user-agent']", helper)

    def test_header_rule_is_loaded_and_runs_before_cookie_body_rules(self):
        self.assertIn("local header_rules = select_rule(read_file('header'))", self.init_lua)
        helper = self._function_body("header_rule")
        self.assertIn("request_header", helper)
        self.assertIn("header_rules", helper)
        self.assertIn("'header'", helper)
        body = self._function_body("run_btwaf")
        header_pos = self._call_pos(body, "header_rule()")
        self.assertLess(header_pos, self._call_pos(body, "cookie()"))
        self.assertLess(header_pos, self._call_pos(body, "post()"))

    def test_json_post_requests_skip_legacy_form_post_rules(self):
        self.assertIn("function is_json_request", self.init_lua)
        body = self._function_body("post")
        self.assertIn("is_json_request()", body)
        self.assertLess(body.index("is_json_request()"), body.index("ngx.req.get_post_args()"))
        self.assertLess(body.index("is_json_request()"), body.index("is_ngx_match(post_rules,request_args,'post')"))

    def test_llm_api_compatibility_is_not_domain_or_path_hardcoded(self):
        for snippet in ["customer.example.invalid", "/v1", "/chat/completions", "/responses"]:
            with self.subTest(snippet=snippet):
                self.assertNotIn(snippet, self.init_lua)

    def test_missing_site_disable_rule_keys_are_safe(self):
        helper = self._function_body("is_ngx_match")
        self.assertIn("disabled_rules = {}", helper)
        self.assertIn("site_config[server_name]['disable_rule'][rule_name]", helper)

    def test_empty_user_agent_is_globally_ignored(self):
        body = self._function_body("ban_empty_ua")
        self.assertIn("return false", body)
        self.assertNotIn("write_log", body)
        self.assertNotIn("empty_ua", body)
        self.assertNotIn("free_waf_drop_ip:set", body)
        self.assertNotIn("write_drop_ip", body)
        self.assertNotIn("ngx.exit", body)
        self.assertNotIn("return_html", body)

    def test_404_auto_ban_requires_scan_like_path_and_higher_threshold(self):
        body = self._function_body("ban_404_accumulate")
        self.assertIn("is_scan_like_404_path(current_uri)", body)
        self.assertIn("cnt >= 80", body)

    def test_scan_like_404_path_is_narrow(self):
        body = self._function_body("is_scan_like_404_path")
        self.assertIn("wp-admin", body)
        self.assertIn("phpmyadmin", body)
        self.assertIn("\\.env", body)

    def test_cdn_client_ip_uses_validated_forwarded_ip(self):
        body = self._function_body("get_client_ip")
        self.assertIn("first_client_ip_from_header(header_tmp)", body)
        self.assertNotIn("split_bylog(header_tmp,',')[1]", body)
        helper = self._function_body("first_client_ip_from_header")
        self.assertIn("is_ipaddr(candidate)", helper)
        self.assertIn("compare_ip_block(candidate)", helper)

    def test_cdn_forwarded_ip_can_require_trusted_proxy_source(self):
        self.assertIn("function is_trusted_cdn_proxy(site_conf)", self.init_lua)
        self.assertIn("function is_ip_in_range(client_ip, ip_range)", self.init_lua)
        trusted_helper = self._function_body("is_trusted_cdn_proxy")
        self.assertIn("site_conf['cdn_trusted_proxy']", trusted_helper)
        self.assertIn("ngx.var.remote_addr", trusted_helper)
        self.assertIn("return true", trusted_helper)
        self.assertIn("return false", trusted_helper)

        body = self._function_body("get_client_ip")
        self.assertIn("is_trusted_cdn_proxy(site_config[server_name])", body)
        self.assertIn("return client_ip", body)
        self.assertLess(
            body.index("is_trusted_cdn_proxy(site_config[server_name])"),
            body.index("first_client_ip_from_header(header_tmp)"),
        )

    def test_cc_ban_duration_is_capped_at_60_seconds(self):
        for name in ["cc", "cc2"]:
            with self.subTest(name=name):
                body = self._function_body(name)
                self.assertIn("local lock_time = tonumber(endtime) or 60", body)
                self.assertIn("if lock_time <= 0 then lock_time = 60 end", body)
                self.assertIn("if lock_time > 60 then lock_time = 60 end", body)
                self.assertNotIn("if lock_time > 86400", body)
                self.assertNotIn("endtime * safe_count", body)


if __name__ == "__main__":
    unittest.main()
