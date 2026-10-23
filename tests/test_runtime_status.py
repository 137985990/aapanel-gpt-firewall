import json
import os
import subprocess
import sys
import types
import unittest
from unittest.mock import Mock, patch

from test_panel_performance import load_backend


HOOKS = '''http {
    init_by_lua_file /www/server/free_waf/init.lua;
    access_by_lua_file /www/server/free_waf/waf.lua;
    lua_shared_dict free_waf 10m;
    lua_shared_dict free_waf_drop_ip 10m;
    lua_shared_dict free_waf_drop_sum 10m;
}'''


class RuntimeStatusTest(unittest.TestCase):
    def setUp(self):
        self.public = types.SimpleNamespace(
            readFile=lambda path: json.dumps({'open': True, 'start_time': 0}),
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            writeFile=Mock(side_effect=AssertionError('read changed a file')),
            serviceReload=Mock(side_effect=AssertionError('read reloaded Nginx')),
        )
        self.backend = load_backend(self.public)

    def test_home_needs_no_luawaf_marker_and_does_not_inspect_or_enable(self):
        self.backend.get_total = Mock(return_value={'total': 0, 'rules': [], 'sites': {}})
        with patch.object(os.path, 'exists', return_value=False), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('automatic inspection')):
            result = self.backend.get_total_all(None)
        self.assertEqual(result['total']['total'], 0)
        self.assertTrue(result['open'])
        self.assertEqual(result['runtime_status']['integration'], 'unverified')
        self.assertIs(result['runtime_status']['execution_verified'], False)
        self.public.writeFile.assert_not_called()
        self.public.serviceReload.assert_not_called()

    def inspect(self, body):
        self.backend._free_waf_main__read_nginx_configuration = Mock(return_value=body)
        return self.backend.get_runtime_status(types.SimpleNamespace(command='reload', path='/untrusted'))

    def test_manual_missing_hooks_reports_not_integrated_without_config_changes(self):
        result = self.inspect('http { server { listen 80; } }')
        self.assertIs(result['status'], True)
        self.assertEqual(result['integration'], 'missing')
        self.assertIs(result['configured_open'], True)
        self.assertIs(result['execution_verified'], False)
        self.assertNotIn('http {', json.dumps(result))
        self.public.writeFile.assert_not_called()
        self.public.serviceReload.assert_not_called()

    def test_matching_configuration_does_not_claim_lua_execution(self):
        result = self.inspect(HOOKS)
        self.assertEqual(result['integration'], 'configured')
        self.assertIs(result['execution_verified'], False)

    def test_commented_hooks_are_not_integration(self):
        result = self.inspect('\n'.join('# ' + line for line in HOOKS.splitlines()))
        self.assertEqual(result['integration'], 'missing')

    def test_partial_duplicate_and_conflicting_hooks_are_not_configured(self):
        for body in (HOOKS.replace('access_by_lua_file', '# access_by_lua_file'),
                     HOOKS + '\ninit_by_lua_file /www/server/free_waf/init.lua;',
                     HOOKS.replace('waf.lua;', 'other.lua;'),
                     HOOKS.replace('lua_shared_dict free_waf 10m;', ''),
                     'init_by_lua_file /www/server/free_waf/init.lua;'):
            with self.subTest(body=body):
                self.assertEqual(self.inspect(body)['integration'], 'incomplete')

    def test_quoted_paths_and_comments_are_handled(self):
        body = HOOKS.replace('/www/server/free_waf/init.lua;', '"/www/server/free_waf/init.lua"; # comment')
        self.assertEqual(self.inspect(body)['integration'], 'configured')

    def test_quoted_delimiters_cannot_inject_directives(self):
        body = 'http { log_format fake "{" "init_by_lua_file" "/www/server/free_waf/init.lua" ";" '
        body += '"access_by_lua_file" "/www/server/free_waf/waf.lua" ";" '
        body += '"lua_shared_dict" "free_waf" "10m" ";" '
        body += '"lua_shared_dict" "free_waf_drop_ip" "10m" ";" '
        body += '"lua_shared_dict" "free_waf_drop_sum" "10m" ";"; }'
        self.assertEqual(self.inspect(body)['integration'], 'missing')

    def test_inline_lua_is_opaque_including_comments_and_long_strings(self):
        lua = '''server { content_by_lua_block {
            -- Don't expose anything sensitive. }
            local sample = [==[ } ' " # init_by_lua_file /www/server/free_waf/init.lua; ]==]
            --[=[ } Don't parse comments as directives. ]=]
            local t = { text = "}\\\"", other = '{' }
        } }'''
        self.assertEqual(self.inspect(HOOKS + lua)['integration'], 'configured')
        self.assertEqual(self.inspect(lua)['integration'], 'missing')

    def test_inline_lua_strings_are_not_hook_evidence(self):
        body = 'http { init_by_lua_block { local sample = [==[' + HOOKS + ']==] } }'
        self.assertEqual(self.inspect(body)['integration'], 'missing')

    def test_set_by_lua_variable_blocks_are_opaque(self):
        body = 'http { set_by_lua_block $sample { local text = [==[' + HOOKS + ']==] } }'
        self.assertEqual(self.inspect(body)['integration'], 'missing')
        comment = "server { set_by_lua_block $sample { -- Don't inspect Lua as Nginx.\n return 1 } }"
        self.assertEqual(self.inspect(HOOKS + comment)['integration'], 'configured')

    def test_non_nginx_escapes_or_literal_quotes_do_not_fabricate_dictionary_names(self):
        for name in (r'fr\ee_waf', 'free_"waf"', 'free_waf#example\n'):
            with self.subTest(name=name):
                body = HOOKS.replace('lua_shared_dict free_waf 10m;', 'lua_shared_dict ' + name + ' 10m;')
                self.assertNotEqual(self.inspect(body)['integration'], 'configured')

    def test_failure_returns_only_fixed_diagnostic_not_exception_or_configuration(self):
        for code in ('nginx_timeout', 'nginx_output_limit', 'nginx_check_failed', 'secret=value'):
            with self.subTest(code=code):
                self.backend._free_waf_main__read_nginx_configuration = Mock(side_effect=RuntimeError(code))
                result = self.backend.get_runtime_status(None)
                self.assertIs(result['status'], False)
                self.assertEqual(result['integration'], 'unknown')
                self.assertNotIn('secret=value', json.dumps(result))
                self.assertIs(result['execution_verified'], False)

    @unittest.skipIf(os.name == 'nt', 'Nginx inspection uses Linux pipe selectors')
    def test_inspection_uses_fixed_panel_binary_and_kills_bounded_children(self):
        real_popen = subprocess.Popen
        args = ['/www/server/nginx/sbin/nginx', '-T', '-p', '/www/server/nginx/',
                '-c', '/www/server/nginx/conf/nginx.conf']
        for source, code in (("print('http {}')", None),
                             ("import sys; sys.stdout.write('x' * (2 * 1024 * 1024 + 1))", 'nginx_output_limit'),
                             ("import time; time.sleep(10)", 'nginx_timeout'),
                             ("raise SystemExit(1)", 'nginx_check_failed')):
            with self.subTest(code=code):
                children = []

                def spawn(arguments, **kwargs):
                    self.assertEqual(arguments, args)
                    self.assertIs(kwargs['shell'], False)
                    child = real_popen([sys.executable, '-I', '-S', '-c', source], **kwargs)
                    children.append(child)
                    return child

                with patch.object(subprocess, 'Popen', side_effect=spawn):
                    if code:
                        with self.assertRaisesRegex(RuntimeError, code):
                            self.backend._free_waf_main__read_nginx_configuration()
                    else:
                        self.assertEqual(self.backend._free_waf_main__read_nginx_configuration().strip(), 'http {}')
                self.assertTrue(all(child.poll() is not None for child in children))
                self.assertTrue(all(child.stdout.closed for child in children))


if __name__ == '__main__':
    unittest.main()
