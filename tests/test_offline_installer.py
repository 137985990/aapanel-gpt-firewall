import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


PLUGIN_SOURCE = Path(__file__).resolve().parents[1]
# Synthetic data with the legacy runtime's actual JSON container shapes.
RULE_FIXTURES = {
    "cn": [[[192, 0, 2, 0], [192, 0, 2, 255]]],
    "scan_black": {"cookie": "fixture-cookie", "args": "fixture-args", "header": "fixture-header"},
    "ip_black": [[[198, 51, 100, 1], [198, 51, 100, 1], 4102444800]],
    "ip_white": [[[203, 0, 113, 1], [203, 0, 113, 1]]],
    "url_white": ["^/fixture-public$"],
    "url_black": [],
    "user_agent_white": [],
    "user_agent": [[1, "fixture-agent", "fixture rule", 0]],
    "header": [],
    "post": [[1, "fixture-post", "fixture rule", 0]],
    "cookie": [],
    "args": [[1, "fixture-args", "fixture rule", 0]],
    "url": [[1, "fixture-url", "fixture rule", 0]],
    "head_white": [],
}
NEW_LUA = (
    'local cpath = "/www/server/free_waf/"\n'
    'function run_btwaf() end\n-- packaged runtime\n'
)
OLD_LUA = NEW_LUA.replace("packaged runtime", "existing runtime")
WAF_INCLUDE = '''lua_package_path "/www/server/free_waf/?.lua;;";
lua_shared_dict free_waf 20m;
lua_shared_dict free_waf_drop_ip 10m;
lua_shared_dict free_waf_drop_sum 10m;
init_by_lua_file /www/server/free_waf/init.lua;
access_by_lua_file /www/server/free_waf/waf.lua;
log_by_lua_block { if ban_404_accumulate then ban_404_accumulate() end }
'''
MOCK_NGINX = r'''#!/bin/bash
set -eu
root="${BASH_SOURCE[0]%/www/server/nginx/sbin/nginx}"
candidate=false
if grep -q 'packaged runtime' "$root/www/server/free_waf/init.lua"; then candidate=true; fi
printf '%s|candidate=%s\n' "$*" "$candidate" >> "$root/nginx-calls.log"
case "$1" in
    -T) cat "$root/nginx-dump.txt" ;;
    -t)
        if [ -e "$root/fail-baseline-test" ]; then exit 1; fi
        if $candidate && [ -e "$root/fail-candidate-test" ]; then exit 1; fi
        ;;
    -s)
        [ "$2" = reload ] || exit 90
        if $candidate && [ -e "$root/fail-candidate-reload" ]; then exit 1; fi
        if ! $candidate && [ -e "$root/fail-rollback-reload" ]; then exit 1; fi
        ;;
    *) exit 91 ;;
esac
'''


def find_bash():
    if os.name == "nt":
        git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
        if git_bash.is_file():
            return str(git_bash)
    return shutil.which("bash")


class OfflineInstallerTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue((PLUGIN_SOURCE / "install.sh").is_file(), "offline install.sh is missing")
        self.bash = find_bash()
        if not self.bash:
            self.skipTest("Bash is required to exercise the installer")
        self.temp = tempfile.TemporaryDirectory(prefix="gpt-firewall-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plugin = self.root / "www/server/panel/plugin/free_waf"
        self.runtime = self.root / "www/server/free_waf"
        self.nginx = self.root / "www/server/nginx/sbin/nginx"
        self.conf = self.root / "www/server/nginx/conf/nginx.conf"
        self.include = self.root / "www/server/panel/vhost/nginx/free_waf.conf"
        self.write(self.plugin / "install.sh", (PLUGIN_SOURCE / "install.sh").read_text(encoding="utf-8"))
        self.write(self.plugin / "init.lua", NEW_LUA)
        for name in ("free_waf_main.py", "ban_store.py", "report_store.py", "website_statistics.py", "update_service.py"):
            self.write(self.plugin / name, "# imported backend; prior version unavailable\n")
        self.write(self.plugin / "index.html", "<html>already imported UI</html>\n")
        self.write_json(self.plugin / "info.json", {"name": "free_waf", "versions": "0.1.4"})
        self.write_json(self.plugin / "rule.json", ["scanner_signature"])
        self.write(self.runtime / "init.lua", OLD_LUA)
        self.write(self.runtime / "waf.lua", "run_btwaf()\n")
        self.write_json(self.runtime / "site.json", {"example.invalid": {"open": True}})
        self.write_json(self.runtime / "total.json", {"total": 9, "sites": {}, "rules": {}})
        self.write(self.runtime / "drop_ip.log", "existing ban history\n")
        self.write_json(self.runtime / "rule/ip_black_meta.json", {"fixture": {"expires": 123}})
        for name, data in RULE_FIXTURES.items():
            self.write_json(self.runtime / "rule" / (name + ".json"), data)
        config = {
            "open": True, "retry": 6, "retry_time": 600, "retry_cycle": 60,
            "cc": {"open": True, "cycle": 60, "endtime": 600, "limit": 100, "status": 403},
            "logs_path": "/www/wwwlogs/free_waf_log",
            "reqfile_path": "/www/server/free_waf/html",
        }
        for key, template in (("get", "get"), ("post", "post"), ("cookie", "cookie"),
                              ("user-agent", "user_agent"), ("other", "other")):
            config[key] = {"status": 403, "reqfile": template + ".html"}
            if key != "other":
                config[key]["open"] = True
            self.write(self.runtime / "html" / (template + ".html"), "<p>existing template</p>\n")
        for key in ("scan", "drop_abroad", "url_black"):
            config[key] = {"open": True, "status": 403}
        self.write_json(self.runtime / "config.json", config)
        self.write(self.root / "www/wwwlogs/free_waf_log/history.log", "existing request history\n")
        self.write(self.conf, "http { include /www/server/panel/vhost/nginx/*.conf; }\n")
        self.write(self.include, WAF_INCLUDE)
        self.write(self.nginx, MOCK_NGINX)
        self.nginx.chmod(0o755)
        python = self.root / "www/server/panel/pyenv/bin/python"
        if os.name == "nt":
            self.write(python, "#!/bin/bash\nexec '" + Path(sys.executable).as_posix() + "' \"$@\"\n")
            python.chmod(0o755)
        else:
            python.parent.mkdir(parents=True)
            python.symlink_to(sys.executable)
        self.set_active(True)
        self.network_bin = self.root / "no-network-bin"
        for name in ("wget", "curl", "apt", "apt-get", "yum", "dnf", "pip", "pip3", "nginx"):
            tool = self.network_bin / name
            self.write(tool, '#!/bin/bash\nprintf "forbidden command\\n" >&2\nexit 99\n')
            tool.chmod(0o755)

    @staticmethod
    def write(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    def write_json(self, path, data):
        self.write(path, json.dumps(data))

    def set_active(self, active):
        dump = "# configuration file /www/server/nginx/conf/nginx.conf:\n"
        dump += self.conf.read_text(encoding="utf-8")
        if active:
            dump += "# configuration file /www/server/panel/vhost/nginx/free_waf.conf:\n"
            dump += self.include.read_text(encoding="utf-8")
        self.write(self.root / "nginx-dump.txt", dump)

    def run_installer(self, operation="install", test_mode=True):
        environment = os.environ.copy()
        environment["PYTHONUTF8"] = "1"
        environment["PYTHONIOENCODING"] = "utf-8"
        environment["GPT_FIREWALL_TEST_ROOT"] = self.root.as_posix()
        environment["PATH"] = str(self.network_bin) + os.pathsep + environment["PATH"]
        args = [self.bash, str(self.plugin / "install.sh"), operation]
        if test_mode:
            args.append("--test-mode")
        return subprocess.run(args, env=environment, capture_output=True, encoding="utf-8", timeout=20)

    def status(self):
        return json.loads((self.plugin / "install-status.json").read_text(encoding="utf-8"))

    def calls(self):
        path = self.root / "nginx-calls.log"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def state_snapshot(self):
        paths = [p for p in self.runtime.rglob("*") if p.is_file() and p.name != "init.lua"]
        paths += [self.include, self.conf, self.root / "www/wwwlogs/free_waf_log/history.log"]
        return {str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mtime_ns, stat.S_IMODE(p.stat().st_mode))
                for p in paths if p.is_file() and ".gpt-firewall-" not in str(p)}

    def assert_failed_without_runtime_change(self, result, before):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.status()["status"], "failed")
        self.assertEqual((self.runtime / "init.lua").read_text(encoding="utf-8"), OLD_LUA)
        self.assertEqual(self.state_snapshot(), before)
        self.assertFalse(any("-s reload" in call for call in self.calls()))
        self.assertFalse(list(self.runtime.glob(".gpt-firewall-backup.*")))

    def test_upgrades_only_runtime_code_and_keeps_imported_plugin_files(self):
        before = self.state_snapshot()
        backend = (self.plugin / "free_waf_main.py").read_bytes()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.runtime / "init.lua").read_text(encoding="utf-8"), NEW_LUA)
        self.assertEqual(self.state_snapshot(), before)
        self.assertEqual((self.plugin / "free_waf_main.py").read_bytes(), backend)
        status = self.status()
        self.assertEqual(status["status"], "success")
        self.assertEqual(status["version"], "0.1.4")
        self.assertEqual(status["plugin_name"], "free_waf")
        self.assertTrue(status["waf_active"])
        self.assertTrue(status["runtime_changed"])
        self.assertFalse(status["plugin_rollback_available"])
        self.assertFalse(status["lua_execution_verified"])
        backups = list(self.runtime.glob(".gpt-firewall-backup.*/init.lua"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(encoding="utf-8"), OLD_LUA)
        self.assertEqual(len([c for c in self.calls() if "-s reload" in c]), 1)
        self.assertGreaterEqual(len([c for c in self.calls() if c.startswith("-t ")]), 2)

    def test_missing_runtime_assets_refuse_fresh_install(self):
        for relative in ("init.lua", "waf.lua", "config.json", "site.json", "total.json",
                         "drop_ip.log", "rule/cn.json", "rule/header.json", "html/get.html"):
            with self.subTest(asset=relative):
                path = self.runtime / relative
                saved = path.read_bytes()
                path.unlink()
                before = self.state_snapshot()
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.status()["status"], "failed")
                self.assertEqual(self.state_snapshot(), before)
                self.assertFalse(path.exists())
                self.assertFalse(list(self.runtime.glob(".gpt-firewall-backup.*")))
                self.assertFalse(any("-s reload" in call for call in self.calls()))
                path.write_bytes(saved)

    def test_missing_imported_dependency_refuses_without_touching_state(self):
        (self.plugin / "report_store.py").unlink()
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())

    def test_invalid_json_refuses_without_resetting_configuration(self):
        self.write(self.runtime / "config.json", "{broken json")
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())

    def test_incomplete_config_refuses_without_resetting_configuration(self):
        self.write_json(self.runtime / "config.json", {"open": True})
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())

    def test_other_template_without_open_is_supported_and_preserved(self):
        config = json.loads((self.runtime / "config.json").read_text(encoding="utf-8"))
        self.assertNotIn("open", config["other"])
        before = self.state_snapshot()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.status()["status"], "success")
        self.assertEqual(self.state_snapshot(), before)

    def test_other_template_with_open_is_supported_and_preserved(self):
        path = self.runtime / "config.json"
        config = json.loads(path.read_text(encoding="utf-8"))
        config["other"]["open"] = False
        self.write_json(path, config)
        before = self.state_snapshot()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.status()["status"], "success")
        self.assertEqual(self.state_snapshot(), before)

    def test_other_template_still_requires_status_and_reqfile(self):
        path = self.runtime / "config.json"
        original = path.read_text(encoding="utf-8")
        for field in ("status", "reqfile"):
            with self.subTest(field=field):
                config = json.loads(original)
                del config["other"][field]
                self.write_json(path, config)
                before = self.state_snapshot()
                result = self.run_installer()
                self.assert_failed_without_runtime_change(result, before)
                self.assertIn("响应模板配置不完整", result.stderr)
                self.assertFalse(self.calls())

    def test_feature_templates_still_require_open(self):
        path = self.runtime / "config.json"
        original = path.read_text(encoding="utf-8")
        for key in ("get", "post", "cookie", "user-agent"):
            with self.subTest(template=key):
                config = json.loads(original)
                del config[key]["open"]
                self.write_json(path, config)
                before = self.state_snapshot()
                result = self.run_installer()
                self.assert_failed_without_runtime_change(result, before)
                self.assertIn("响应模板配置不完整", result.stderr)
                self.assertFalse(self.calls())

    def test_wrong_package_identity_is_rejected(self):
        self.write_json(self.plugin / "info.json", {"name": "gpt_firewall", "versions": "0.1.4"})
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())

    def test_wrong_package_version_is_rejected(self):
        self.write_json(self.plugin / "info.json", {"name": "free_waf", "versions": "5.0"})
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())

    def test_wrong_runtime_entrypoint_is_rejected_before_copying(self):
        self.write(self.plugin / "init.lua", "-- not the legacy runtime entrypoint\n")
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())

    def test_incompatible_existing_waf_entrypoint_is_rejected(self):
        self.write(self.runtime / "waf.lua", "run_a_different_waf()\n")
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())

    def test_rule_schema_failure_preserves_the_invalid_rule_for_manual_repair(self):
        self.write_json(self.runtime / "rule/ip_black.json", {"invalid": "not an array"})
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())

    def test_scan_black_list_values_are_supported_without_rewriting_rules(self):
        self.write_json(self.runtime / "rule/scan_black.json", {
            "cookie": ["fixture-cookie"], "args": ["fixture-args", "fixture-other"], "header": [],
        })
        before = self.state_snapshot()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.status()["status"], "success")
        self.assertEqual((self.runtime / "init.lua").read_text(encoding="utf-8"), NEW_LUA)
        self.assertEqual(self.state_snapshot(), before)

    def test_invalid_scan_black_shapes_fail_before_runtime_changes(self):
        invalid = [
            ["not a map"],
            {"cookie": [], "args": []},
            *[{"cookie": value, "args": [], "header": []}
              for value in (None, 1, True, {}, [1], [[]])],
        ]
        for data in invalid:
            with self.subTest(schema=data):
                self.write_json(self.runtime / "rule/scan_black.json", data)
                before = self.state_snapshot()
                result = self.run_installer()
                self.assert_failed_without_runtime_change(result, before)
                self.assertIn("scan_black.json", result.stderr)
                self.assertEqual(self.status()["stage"], "preflight")
                self.assertFalse(self.calls())

    def test_cn_map_is_rejected_without_rewriting_rules(self):
        self.write_json(self.runtime / "rule/cn.json", {"invalid": "expected array"})
        before = self.state_snapshot()
        result = self.run_installer()
        self.assert_failed_without_runtime_change(result, before)
        self.assertIn("cn.json", result.stderr)
        self.assertFalse(self.calls())

    def test_missing_log_directory_is_not_created(self):
        (self.root / "www/wwwlogs/free_waf_log/history.log").unlink()
        (self.root / "www/wwwlogs/free_waf_log").rmdir()
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())
        self.assertFalse((self.root / "www/wwwlogs/free_waf_log").exists())

    def test_missing_panel_nginx_never_falls_back_to_host_nginx(self):
        self.nginx.unlink()
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())
        self.assertFalse(self.calls())

    def test_baseline_nginx_failure_does_not_update_runtime(self):
        self.write(self.root / "fail-baseline-test", "1")
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())
        self.assertEqual(self.status().get('diagnostic_code'), 'nginx_test_failed')

    def test_foreign_active_runtime_path_is_not_rewritten(self):
        self.write(self.include, WAF_INCLUDE.replace("/free_waf/init.lua", "/other_waf/init.lua"))
        self.set_active(True)
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())

    def test_missing_nginx_include_is_not_created(self):
        self.include.unlink()
        self.set_active(False)
        before = self.state_snapshot()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.include.exists())
        self.assertEqual((self.runtime / "init.lua").read_text(encoding="utf-8"), NEW_LUA)
        self.assertEqual(self.state_snapshot(), before)
        self.assertFalse(self.status()["waf_active"])
        self.assertFalse(any("-s reload" in call for call in self.calls()))

    def test_missing_include_does_not_bypass_runtime_schema_checks(self):
        self.include.unlink()
        self.set_active(False)
        self.write_json(self.runtime / "site.json", [])
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())
        self.assertEqual(self.status().get("diagnostic_code"), "json_schema")
        self.assertEqual(self.status().get("diagnostic_resource"), "site.json")

    def test_missing_include_does_not_bypass_effective_hook_validation(self):
        self.include.unlink()
        self.set_active(False)
        dump = self.root / "nginx-dump.txt"
        self.write(dump, dump.read_text(encoding="utf-8") + WAF_INCLUDE.replace(
            "/free_waf/waf.lua", "/other_waf/waf.lua"))
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())
        self.assertEqual(self.status().get("diagnostic_code"), "integration_conflict")

    def test_missing_include_supports_compatible_alternative_integration(self):
        self.include.unlink()
        self.set_active(False)
        dump = self.root / "nginx-dump.txt"
        self.write(dump, dump.read_text(encoding="utf-8") + WAF_INCLUDE)
        before = self.state_snapshot()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.status()["waf_active"])
        self.assertEqual(self.state_snapshot(), before)
        self.assertFalse(self.include.exists())
        self.assertEqual(len([c for c in self.calls() if "-s reload" in c]), 1)

    def test_empty_existing_include_is_not_treated_as_absent(self):
        self.write(self.include, "")
        self.set_active(False)
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())
        self.assertEqual(self.status().get("diagnostic_code"), "invalid_resource")
        self.assertEqual(self.status().get("diagnostic_resource"), "free_waf.conf")

    @unittest.skipIf(os.name == "nt", "POSIX symlink checks")
    def test_dangling_include_symlink_is_not_treated_as_absent(self):
        self.include.unlink()
        self.include.symlink_to(self.root / "missing-include-target")
        self.set_active(False)
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())
        self.assertEqual(self.status().get("diagnostic_code"), "unsafe_resource")

    def test_preflight_diagnostics_do_not_copy_configured_paths_or_values(self):
        path = self.runtime / "config.json"
        config = json.loads(path.read_text(encoding="utf-8"))
        config["reqfile_path"] = "PRIVATE_SECRET_not_absolute"
        self.write_json(path, config)
        self.assert_failed_without_runtime_change(self.run_installer(), self.state_snapshot())
        self.assertEqual(self.status().get("diagnostic_code"), "unsafe_resource")
        self.assertNotIn("PRIVATE_SECRET", json.dumps(self.status()))

    def test_inactive_runtime_update_does_not_reload(self):
        self.set_active(False)
        before = self.state_snapshot()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.status()["waf_active"])
        self.assertEqual((self.runtime / "init.lua").read_text(encoding="utf-8"), NEW_LUA)
        self.assertEqual(self.state_snapshot(), before)
        self.assertFalse(any("-s reload" in call for call in self.calls()))

    def test_commented_hooks_do_not_trigger_a_reload(self):
        self.set_active(False)
        dump = self.root / "nginx-dump.txt"
        self.write(dump, dump.read_text(encoding="utf-8") + "\n".join("# " + line for line in WAF_INCLUDE.splitlines()))
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.status()["waf_active"])
        self.assertFalse(any("-s reload" in call for call in self.calls()))

    def test_quoted_hooks_are_recognized_without_rewriting_the_include(self):
        self.write(self.include, WAF_INCLUDE.replace("file /www/server/free_waf/init.lua;", 'file "/www/server/free_waf/init.lua";')
                   .replace("file /www/server/free_waf/waf.lua;", "file '/www/server/free_waf/waf.lua';"))
        self.set_active(True)
        before = self.state_snapshot()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.status()["waf_active"])
        self.assertEqual(self.state_snapshot(), before)

    def test_empty_existing_drop_log_is_supported_and_not_rewritten(self):
        self.write(self.runtime / "drop_ip.log", "")
        before = self.state_snapshot()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state_snapshot(), before)

    def test_identical_init_does_not_backup_rewrite_or_reload(self):
        self.write(self.runtime / "init.lua", NEW_LUA)
        before = (self.runtime / "init.lua").stat().st_mtime_ns
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.status()["runtime_changed"])
        self.assertEqual((self.runtime / "init.lua").stat().st_mtime_ns, before)
        self.assertFalse(list(self.runtime.glob(".gpt-firewall-backup.*")))
        self.assertFalse(any("-s reload" in call for call in self.calls()))

    def test_candidate_nginx_test_failure_rolls_back_and_reloads_old_runtime(self):
        self.write(self.root / "fail-candidate-test", "1")
        before = self.state_snapshot()
        old_mtime = (self.runtime / "init.lua").stat().st_mtime_ns
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.status()["status"], "failed")
        self.assertEqual(self.status()["rollback"], "restored")
        self.assertEqual((self.runtime / "init.lua").read_text(encoding="utf-8"), OLD_LUA)
        self.assertAlmostEqual((self.runtime / "init.lua").stat().st_mtime_ns / 1e9, old_mtime / 1e9, places=4)
        self.assertEqual(self.state_snapshot(), before)
        self.assertEqual(len([c for c in self.calls() if "-s reload" in c]), 1)
        self.assertIn("candidate=false", self.calls()[-1])

    def test_candidate_reload_failure_rolls_back_and_attempts_restore_reload(self):
        self.write(self.root / "fail-candidate-reload", "1")
        before = self.state_snapshot()
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.status().get('diagnostic_code'), 'nginx_reload_failed')
        self.assertEqual(self.status()["rollback"], "restored")
        self.assertEqual(self.status()["status"], "failed")
        self.assertEqual((self.runtime / "init.lua").read_text(encoding="utf-8"), OLD_LUA)
        self.assertEqual(self.state_snapshot(), before)
        reloads = [c for c in self.calls() if "-s reload" in c]
        self.assertEqual(len(reloads), 2)
        self.assertIn("candidate=true", reloads[0])
        self.assertIn("candidate=false", reloads[1])

    def test_rollback_reload_failure_is_reported_not_hidden(self):
        self.write(self.root / "fail-candidate-reload", "1")
        self.write(self.root / "fail-rollback-reload", "1")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.status()["rollback"], "restore_reload_failed")
        self.assertEqual(self.status()["status"], "failed")
        self.assertEqual((self.runtime / "init.lua").read_text(encoding="utf-8"), OLD_LUA)

    def test_active_uninstall_refuses_with_chinese_instructions_and_retains_data(self):
        before = self.state_snapshot()
        result = self.run_installer("uninstall")
        self.assert_failed_without_runtime_change(result, before)
        self.assertRegex(self.status()["message"], r"[\u4e00-\u9fff]")
        self.assertIn("Nginx", self.status()["message"])

    def test_inactive_uninstall_retains_runtime_and_state(self):
        self.set_active(False)
        before = self.state_snapshot()
        result = self.run_installer("uninstall")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.status()["status"], "success")
        self.assertEqual((self.runtime / "init.lua").read_text(encoding="utf-8"), OLD_LUA)
        self.assertEqual(self.state_snapshot(), before)
        self.assertTrue(self.plugin.exists())
        self.assertFalse(any("-s reload" in call for call in self.calls()))

    def test_test_root_override_requires_explicit_test_mode(self):
        before = self.state_snapshot()
        result = self.run_installer(test_mode=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state_snapshot(), before)
        self.assertFalse(self.calls())

    def test_unknown_operation_fails_with_status_and_no_runtime_changes(self):
        self.assert_failed_without_runtime_change(self.run_installer("update"), self.state_snapshot())

    def test_script_contains_no_network_or_dependency_install_commands(self):
        source = (self.plugin / "install.sh").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"\b(?:wget|curl|apt-get|yum|dnf|pip3?)\b")
        self.assertNotIn("/etc/init.d/nginx", source)
        self.assertNotIn("systemctl", source)

    @unittest.skipIf(os.name == "nt", "POSIX ownership/modes require a POSIX filesystem")
    @unittest.skipUnless(getattr(os, "geteuid", lambda: 1)() == 0,
                         "Mode-600 importer repair requires root, as in aaPanel")
    def test_repairs_importer_directory_modes_and_preserves_runtime_permissions(self):
        self.write(self.plugin / "data/nested/retained.json", "{}")
        original = self.runtime / "init.lua"
        original.chmod(0o640)
        original_mode = stat.S_IMODE(original.stat().st_mode)
        original_owner = (original.stat().st_uid, original.stat().st_gid)
        for path in sorted(self.plugin.rglob("*"), reverse=True):
            path.chmod(0o600)
        self.plugin.chmod(0o600)
        self.addCleanup(lambda: [p.chmod(0o755) for p in [self.plugin, *self.plugin.rglob("*")] if p.is_dir()])
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for directory in [self.plugin, *[p for p in self.plugin.rglob("*") if p.is_dir()]]:
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.plugin / "install-status.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(original.stat().st_mode), original_mode)
        self.assertEqual((original.stat().st_uid, original.stat().st_gid), original_owner)


if __name__ == "__main__":
    unittest.main()
