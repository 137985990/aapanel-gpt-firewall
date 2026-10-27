import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def lua_string(value):
    delimiter = "="
    while "]" + delimiter + "]" in value:
        delimiter += "="
    return "[" + delimiter + "[" + value + "]" + delimiter + "]"


class LuaStateRegressionsTest(unittest.TestCase):
    """Run real Lua helpers with fixture-only storage, locally or via opt-in SSH."""

    @classmethod
    def setUpClass(cls):
        executable = os.environ.get("FREE_WAF_LUAJIT") or shutil.which("luajit")
        remote_host = os.environ.get("FREE_WAF_LUA_TEST_SSH")
        if executable:
            cls.command = [executable, "-"]
        elif remote_host:
            ssh = shutil.which("ssh")
            if not ssh:
                raise unittest.SkipTest("SSH is unavailable")
            cls.command = [
                ssh,
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                "--", remote_host,
                "cd /tmp && exec luajit -",
            ]
        else:
            raise unittest.SkipTest(
                "LuaJIT unavailable; set FREE_WAF_LUAJIT or explicitly set FREE_WAF_LUA_TEST_SSH to a test host"
            )

    def run_fixture(self, name):
        source = (ROOT / "init.lua").read_text(encoding="utf-8")
        fixture = (ROOT / "tools" / name).read_text(encoding="utf-8")
        payload = (
            "WAF_RUNTIME_SOURCE = " + lua_string(source) + "\n"
            "assert(loadstring(WAF_RUNTIME_SOURCE, '@init.lua'))\n" + fixture
        )
        result = subprocess.run(
            self.command,
            input=payload,
            encoding="utf-8",
            capture_output=True,
            timeout=45,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("isolated_fixture=true", result.stdout)
        self.assertNotIn("FAIL ", result.stdout)
        print(result.stdout.strip())

    def test_registration_state(self):
        self.run_fixture("audit_registration_state.lua")

    def test_rule_identity(self):
        self.run_fixture("audit_rule_identity.lua")

    def test_full_runtime_routes(self):
        self.run_fixture("audit_runtime_routes.lua")

    def test_retired_endpoint_policy_and_shared_cc_helpers(self):
        self.run_fixture("audit_endpoint_policy.lua")

    def test_repeat_ban(self):
        self.run_fixture("audit_repeat_ban.lua")


class EmbeddedRetiredPolicyTest(unittest.TestCase):
    def test_registration_listing_and_cleanup_in_embedded_luajit(self):
        try:
            from lupa.luajit21 import LuaRuntime
        except ImportError:
            self.skipTest('optional embedded LuaJIT unavailable')
        runtime = LuaRuntime(unpack_returned_tuples=True)
        runtime.globals().WAF_RUNTIME_SOURCE = (ROOT / 'init.lua').read_text(encoding='utf-8')
        runtime.execute((ROOT / 'tools/audit_registration_state.lua').read_text(encoding='utf-8'))

    def test_retired_policy_and_shared_cc_in_embedded_luajit(self):
        try:
            from lupa.luajit21 import LuaRuntime
        except ImportError:
            self.skipTest('optional embedded LuaJIT unavailable')
        runtime = LuaRuntime(unpack_returned_tuples=True)
        runtime.globals().WAF_RUNTIME_SOURCE = (ROOT / 'init.lua').read_text(encoding='utf-8')
        # This memory codec tests execution, not cjson serialization compatibility.
        runtime.execute('''
            local objects, serial = {}, 0
            package.preload.cjson = function()
                return {
                    encode = function(value)
                        serial = serial + 1
                        local token = 'fixture-json-' .. serial
                        objects[token] = value
                        return token
                    end,
                    decode = function(token) return assert(objects[token]) end
                }
            end
            assert(loadstring(WAF_RUNTIME_SOURCE, '@init.lua'))
        ''')
        runtime.execute((ROOT / 'tools/audit_endpoint_policy.lua').read_text(encoding='utf-8'))


if __name__ == "__main__":
    unittest.main()
