import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import update_service
from test_panel_performance import load_backend


class IntegrationRepairTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.server = Path(self.temp.name) / 'www/server'
        self.plugin = self.server / 'panel/plugin/free_waf'
        self.plugin.mkdir(parents=True)
        self.runtime = self.server / 'free_waf'
        self.runtime.mkdir()
        self.target = self.server / 'panel/vhost/nginx/free_waf.conf'
        self.target.parent.mkdir(parents=True)
        self.main = self.server / 'nginx/conf/nginx.conf'
        self.main.parent.mkdir(parents=True)
        self.body = 'http { include /www/server/panel/vhost/nginx/*.conf; }'
        self.main.write_text(self.body)
        binary = self.server / 'nginx/sbin/nginx'
        binary.parent.mkdir(parents=True)
        binary.write_text('fixture only')
        (self.plugin / 'init.lua').write_text('function run_btwaf() end')
        (self.runtime / 'init.lua').write_bytes((self.plugin / 'init.lua').read_bytes())
        (self.runtime / 'waf.lua').write_text('run_btwaf()\n')
        self.config = {'open': True, 'cc': {'cycle': 60, 'limit': 120, 'endtime': 60},
                       'reqfile_path': '/www/server/free_waf/html', 'logs_path': '/www/wwwlogs/free_waf_log'}
        self.config.update(retry=6, retry_time=60, retry_cycle=60)
        self.config['cc'].update(open=True, status=403)
        for key in ('scan', 'drop_abroad'):
            self.config[key] = {'open': False, 'status': 403}
        for key in ('get', 'post', 'cookie', 'user-agent', 'other'):
            self.config[key] = {'reqfile': key + '.html', 'status': 403, 'open': True}
        (self.runtime / 'html').mkdir()
        for key in ('get', 'post', 'cookie', 'user-agent', 'other'):
            (self.runtime / 'html' / (key + '.html')).write_text('fixture')
        (self.server.parent / 'wwwlogs/free_waf_log').mkdir(parents=True)
        (self.runtime / 'config.json').write_text(json.dumps(self.config))
        self.sites = {'example.invalid': {'open': True, 'cc': dict(self.config['cc']),
                      'retry': 6, 'retry_time': 60, 'retry_cycle': 60,
                      'disable_php_path': [], 'disable_path': [], 'disable_ext': [],
                      'disable_upload_ext': [], 'url_rule': [], 'url_tell': []}}
        (self.runtime / 'site.json').write_text(json.dumps(self.sites))
        (self.runtime / 'total.json').write_text(json.dumps({'sites': {}, 'rules': {}}))
        (self.runtime / 'rule').mkdir()
        for name in ('cn', 'ip_black', 'ip_white', 'url_white', 'url_black', 'user_agent_white',
                     'user_agent', 'header', 'post', 'cookie', 'args', 'url', 'head_white'):
            (self.runtime / 'rule' / (name + '.json')).write_text('[]')
        (self.runtime / 'rule/scan_black.json').write_text(json.dumps({'args': [], 'header': [], 'cookie': []}))
        self.backend = load_backend(types.SimpleNamespace())
        cls = getattr(update_service, 'IntegrationRepairService', None)
        self.assertIsNotNone(cls, 'confirmed integration repair service is missing')
        self.service = cls(self.plugin, read_configuration=lambda: self.body,
                           directives=self.backend._free_waf_main__nginx_directives, test_mode=True)
        self.commands = []
        self.service._command = lambda args, **kw: self.commands.append(args) or (0, '')
        self.service._probe = Mock(return_value={'execution_verified': True, 'worker_pid': 123})
        self.service._check_probe_port = Mock()

    def hashes(self):
        return {str(p.relative_to(self.runtime)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.runtime.rglob('*') if p.is_file()}

    def plan(self):
        result = self.service.preview()
        self.assertIs(result['status'], True, result)
        return result

    def apply(self, revision=None):
        return self.service.repair(revision or self.plan()['revision'], 'REPAIR_NGINX_INTEGRATION')

    def test_preview_never_writes_or_reloads(self):
        before = self.hashes()
        result = self.plan()
        self.assertIs(result['can_repair'], True)
        self.assertTrue(result['configured_open'])
        self.assertEqual(result['enabled_sites'], 1)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.service.store.exists())
        self.assertEqual(self.commands, [])
        self.assertEqual(self.hashes(), before)

    def test_explicit_repair_preserves_rules_and_switches_and_proves_only_local_probe(self):
        before = self.hashes()
        result = self.apply()
        self.assertIs(result['status'], True, result)
        self.assertIs(result['execution_verified'], True)
        self.assertEqual(result['verification_scope'], 'local_health_probe')
        self.assertIn('access_by_lua_file /www/server/free_waf/waf.lua;', self.target.read_text())
        self.assertIn('listen 127.0.0.1:39091;', self.target.read_text())
        self.assertNotIn('listen 39091', self.target.read_text())
        self.assertEqual(self.hashes(), before)
        self.assertEqual(self.main.read_text(), self.body)
        self.assertEqual([cmd[1] for cmd in self.commands], ['-t', '-s'])
        self.assertTrue((Path(result['backup']) / 'manifest.json').is_file())

    def test_confirmation_or_revision_missing_never_writes(self):
        for revision, confirm in (('', ''), ('a' * 64, ''), ('../file', 'REPAIR_NGINX_INTEGRATION')):
            result = self.service.repair(revision, confirm)
            self.assertIs(result['status'], False)
        self.assertFalse(self.target.exists())
        self.assertEqual(self.commands, [])

    def test_configuration_changes_after_preview_invalidate_confirmation(self):
        revision = self.plan()['revision']
        (self.runtime / 'site.json').write_text('{}')
        result = self.apply(revision)
        self.assertIs(result['status'], False)
        self.assertFalse(self.target.exists())

    def test_existing_file_and_foreign_lua_are_never_overwritten(self):
        for body in ('http { init_by_lua_file /other.lua; }',
                     'http { access_by_lua_block { local x = 1 } }',
                     'http { lua_shared_dict free_waf 1m; }',
                     'http { server {} }'):
            self.body = body
            result = self.service.preview()
            self.assertIs(result['status'], False, body)
            self.assertFalse(self.target.exists())
        self.body = 'http { include /www/server/panel/vhost/nginx/*.conf; }'
        self.target.write_text('preserve this foreign file')
        self.assertIs(self.service.preview()['status'], False)
        self.assertEqual(self.target.read_text(), 'preserve this foreign file')

    def test_test_failure_removes_only_our_include_without_reloading(self):
        self.service._command = lambda args, **kw: (1, 'private secret configuration')
        result = self.apply()
        self.assertIs(result['status'], False)
        self.assertEqual(result['rollback'], 'restored')
        self.assertFalse(self.target.exists())
        self.assertNotIn('private secret', json.dumps(result))

    def test_probe_failure_restores_missing_include_and_reloads_previous_configuration(self):
        self.service._probe = Mock(side_effect=RuntimeError('secret'))
        result = self.apply()
        self.assertIs(result['status'], False)
        self.assertEqual(result['rollback'], 'restored')
        self.assertFalse(self.target.exists())
        self.assertEqual([cmd[1] for cmd in self.commands], ['-t', '-s', '-t', '-s'])

    def test_reload_failure_attempts_rollback_even_if_signal_result_is_ambiguous(self):
        calls = []
        def command(args, **kwargs):
            calls.append(args[1])
            return (1 if len(calls) == 2 else 0, '')
        self.service._command = command
        result = self.apply()
        self.assertFalse(result['status'])
        self.assertEqual(calls, ['-t', '-s', '-t', '-s'])
        self.assertEqual(result['rollback'], 'restored')

    def test_concurrent_include_change_is_preserved_and_requires_manual_recovery(self):
        def probe():
            self.target.write_text('concurrent administrator edit')
            raise RuntimeError('probe failed')
        self.service._probe = probe
        result = self.apply()
        self.assertIs(result['status'], False)
        self.assertEqual(result['rollback'], 'recovery_required')
        self.assertEqual(self.target.read_text(), 'concurrent administrator edit')
        self.assertFalse(self.service.preview()['status'])

    def test_missing_runtime_or_invalid_json_prevents_activation(self):
        (self.runtime / 'rule/args.json').write_text('invalid')
        result = self.service.preview()
        self.assertIs(result['status'], False)
        self.assertFalse(self.target.exists())

    def test_installer_lock_or_queued_update_prevents_activation(self):
        lock = self.plugin / '.gpt-firewall-install.lock'
        lock.mkdir()
        self.assertFalse(self.apply()['status'])
        self.assertFalse(self.target.exists())

    @unittest.skipIf(__import__('os').name == 'nt', 'POSIX symlink checks')
    def test_symlink_target_or_parent_never_changes_link_destination(self):
        victim = self.server / 'victim'
        victim.write_text('preserved')
        self.target.symlink_to(victim)
        self.assertFalse(self.service.preview()['status'])
        self.assertEqual(victim.read_text(), 'preserved')

    def test_disabled_master_is_preserved_and_not_claimed_active(self):
        self.config['open'] = False
        (self.runtime / 'config.json').write_text(json.dumps(self.config))
        result = self.apply()
        self.assertIs(result['status'], True)
        self.assertIs(result['configured_open'], False)
        self.assertIs(json.loads((self.runtime / 'config.json').read_text())['open'], False)

    def test_identical_replacement_is_not_ours_to_remove(self):
        def probe():
            replacement = self.target.with_suffix('.replacement')
            replacement.write_bytes(self.target.read_bytes())
            os.replace(replacement, self.target)
            raise RuntimeError('probe failed')
        self.service._probe = probe
        result = self.apply()
        self.assertFalse(result['status'])
        self.assertEqual(result['rollback'], 'recovery_required')
        self.assertTrue(self.target.exists(), 'must retain a replacement even with identical bytes')

    def test_concurrent_main_edit_after_test_prevents_forward_reload(self):
        def command(args, **kwargs):
            self.commands.append(args)
            if len(self.commands) == 1:
                self.main.write_text(self.body + '\n# concurrent edit\n')
            return 0, ''
        self.service._command = command
        result = self.apply()
        self.assertFalse(result['status'])
        self.assertNotIn('-s', [cmd[1] for cmd in self.commands])
        self.assertEqual(result['rollback'], 'recovery_required')

    def test_concurrent_main_edit_after_reload_prevents_recovery_reload(self):
        def probe():
            self.main.write_text(self.body + '\n# administrator changed config\n')
            raise RuntimeError('probe failed')
        self.service._probe = probe
        result = self.apply()
        self.assertFalse(result['status'])
        self.assertEqual(result['rollback'], 'recovery_required')
        self.assertEqual([cmd[1] for cmd in self.commands].count('-s'), 1)

    def test_publication_cleanup_failure_does_not_orphan_an_include(self):
        original = os.unlink
        failed = []
        def unlink(path, *args, **kwargs):
            if Path(path).name.startswith('.gpt-firewall-') and not failed:
                failed.append(True)
                raise PermissionError('fixture cleanup failure')
            return original(path, *args, **kwargs)
        with patch('update_service.os.unlink', side_effect=unlink):
            result = self.apply()
        self.assertFalse(result['status'])
        self.assertFalse(self.target.exists())
        self.assertEqual(result['rollback'], 'restored')

    def test_installer_exclusion_is_held_during_test_reload_and_probe(self):
        def command(args, **kwargs):
            lock = self.plugin / '.gpt-firewall-install.lock'
            self.assertTrue(lock.is_dir())
            with self.assertRaises(FileExistsError):
                lock.mkdir()
            self.commands.append(args)
            return 0, ''
        self.service._command = command
        self.assertTrue(self.apply()['status'])
        self.assertFalse((self.plugin / '.gpt-firewall-install.lock').exists())

    def test_missing_normal_request_configuration_blocks_activation(self):
        for key in ('scan', 'drop_abroad', 'retry', 'retry_time', 'retry_cycle'):
            with self.subTest(key=key):
                broken = dict(self.config)
                del broken[key]
                (self.runtime / 'config.json').write_text(json.dumps(broken))
                self.assertFalse(self.service.preview()['status'])
        (self.runtime / 'config.json').write_text(json.dumps(self.config))
        for key in ('cc', 'disable_php_path', 'disable_path', 'disable_ext', 'url_rule', 'url_tell'):
            with self.subTest(site_key=key):
                broken = dict(self.sites['example.invalid'])
                del broken[key]
                (self.runtime / 'site.json').write_text(json.dumps({'example.invalid': broken}))
                self.assertFalse(self.service.preview()['status'])
        self.assertFalse(self.target.exists())

    def test_malformed_scan_or_selected_rules_block_activation(self):
        for name, broken in (('scan_black', {'args': []}), ('user_agent', [42]),
                             ('header', [[1, 42]]), ('url_white', [42])):
            with self.subTest(rule=name):
                path = self.runtime / 'rule' / (name + '.json')
                original = path.read_bytes()
                path.write_text(json.dumps(broken))
                self.assertFalse(self.service.preview()['status'])
                path.write_bytes(original)

    def test_queued_or_failed_recovery_update_blocks_activation(self):
        for state, rollback in (('queued', {}), ('failed', {'state': 'failed'}),
                                ('failed', {'state': 'recovery_required'})):
            with self.subTest(state=state, rollback=rollback):
                self.service._save(self.service.store / 'job.json', {
                    'id': 'a' * 32, 'state': state, 'target_version': '0.1.7',
                    'tag': 'v0.1.7', 'rollback': rollback})
                self.assertFalse(self.apply()['status'])
                self.assertFalse(self.target.exists())

    def test_malformed_trusted_proxy_data_blocks_activation(self):
        for value in (42, [42], [[[127, 0, 0, 1]]], [[['127.0.0.1'], [127, 0, 0, 1]]]):
            with self.subTest(value=value):
                self.sites['example.invalid'].update(cdn=True, cdn_header=['x-forwarded-for'], cdn_trusted_proxy=value)
                (self.runtime / 'site.json').write_text(json.dumps(self.sites))
                self.assertFalse(self.service.preview()['status'])
        self.assertFalse(self.target.exists())

    def test_health_listener_overrides_inherited_connection_closing_defaults(self):
        self.assertIn(b'keepalive_timeout 5s;', self.service.INCLUDE)
        self.assertIn(b'keepalive_requests 100;', self.service.INCLUDE)


if __name__ == '__main__':
    unittest.main()
