import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from tests.test_panel_performance import load_backend


ROOT = Path(__file__).resolve().parents[1]
REMOVED_APIS = ('get_endpoint_policies', 'save_endpoint_policy',
                'delete_endpoint_policy', 'get_endpoint_policy_events')
REMOVED_HELPERS = ('__endpoint_id', '__endpoint_path', '__endpoint_rule', '__endpoint_site',
                   '__endpoint_event', '__write_endpoint_policies',
                   '__save_endpoint_policy_locked', '__delete_endpoint_policy_locked')


class EndpointPolicyRemovalTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / 'site.json'
        self.logs = self.root / 'logs'
        self.logs.mkdir()
        self.history = {
            self.logs / 'endpoint_2020-01-01.jsonl': b'{"action":"ban","rule_id":"historical"}\n',
            self.logs / 'endpoint_2020-01-02.jsonl': b'legacy invalid sample\n\xff\n',
        }
        for path, data in self.history.items():
            path.write_bytes(data)
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            readFile=Mock(side_effect=lambda path: Path(path).read_text(encoding='utf-8')),
            writeFile=Mock(side_effect=AssertionError('unchecked writer')),
            httpGet=Mock(side_effect=AssertionError('unexpected network')),
            httpPost=Mock(side_effect=AssertionError('unexpected network')),
            serviceReload=Mock(), WriteLog=Mock(), M=Mock())
        self.backend = load_backend(self.public)
        self.backend._free_waf_main__path = str(self.root) + os.sep
        self.backend._free_waf_main__PATH = str(ROOT) + os.sep
        self.backend._free_waf_main__update_request_is_post = Mock(return_value=True)
        self.backend._free_waf_main__checked_nginx_reload = Mock(return_value=True)
        self.backend._free_waf_main__write_site_domains = Mock()
        self.backend.get_config = Mock(return_value=dict(
            logs_path=str(self.logs), log_save=1, retry=10, retry_cycle=60, retry_time=60,
            cc=dict(open=True, cycle=60, limit=10, endtime=60),
            get=dict(open=True), post=dict(open=True), cookie=dict(open=True),
            **{'user-agent': dict(open=True), 'scan': dict(open=True)}))
        template = self.backend._free_waf_main__get_site_conf()
        template['log_size'] = 0
        self.legacy_rules = [dict(
            id='a' * 32, name='Legacy login', enabled=True, action='ban',
            match='exact', path='/api/login', method='POST', window_seconds=60,
            max_requests=10, ban_seconds=60)]
        self.config = {'fixture.example': copy.deepcopy(template),
                       'other.example': copy.deepcopy(template)}
        self.config['fixture.example']['endpoint_limits'] = copy.deepcopy(self.legacy_rules)
        self.config['other.example']['endpoint_limits'] = {'unknown': ['keep', None]}
        self.write(self.config)
        self.public.M.return_value.field.return_value.select.return_value = [
            dict(name=site) for site in self.config]
        exists = os.path.exists
        panel_logs = patch('os.path.exists', side_effect=lambda path:
                           True if path == '/www/wwwlogs/free_waf_log' else exists(path))
        panel_logs.start()
        self.addCleanup(panel_logs.stop)

    def write(self, config):
        self.path.write_bytes((json.dumps(config, indent=2) + '\r\n').encode('utf-8'))

    def read(self):
        return json.loads(self.path.read_bytes())

    def save_repeat(self):
        return self.backend.save_repeat_ban_policy(types.SimpleNamespace(
            siteName='fixture.example',
            policy=json.dumps(self.backend._free_waf_main__repeat_defaults()),
            revision=hashlib.sha256(self.path.read_bytes()).hexdigest()))

    def assert_history_preserved(self):
        for site, conf in self.config.items():
            self.assertEqual(self.read()[site]['endpoint_limits'], conf['endpoint_limits'])
        self.assertEqual(set(self.logs.iterdir()), set(self.history))
        for path, data in self.history.items():
            self.assertEqual(path.read_bytes(), data)

    def site_view(self):
        return self.backend.get_site_config(None)

    def test_management_apis_are_removed_not_disabled_stubs(self):
        for name in REMOVED_APIS:
            with self.subTest(api=name):
                self.assertFalse(hasattr(type(self.backend), name), name + ' still defined')
                self.assertFalse(hasattr(self.backend, name), name + ' still exposed')

    def test_dedicated_validators_sample_reader_and_writers_are_removed(self):
        for name in REMOVED_HELPERS:
            with self.subTest(helper=name):
                self.assertFalse(hasattr(self.backend, '_free_waf_main' + name), name + ' still defined')

    def test_backend_has_no_legacy_endpoint_data_or_sampling_paths(self):
        tree = ast.parse((ROOT / 'free_waf_main.py').read_text(encoding='utf-8'))
        consumers = [node.value for node in ast.walk(tree)
                     if isinstance(node, ast.Constant) and isinstance(node.value, str)
                     and node.value in ('endpoint_limits', 'endpoint_')]
        self.assertEqual(consumers, [])

    def test_shared_helpers_remain_available_to_repeat_and_site_configuration(self):
        for name in ('__endpoint_transaction', '__endpoint_site_name', '__checked_nginx_reload'):
            with self.subTest(helper=name):
                self.assertTrue(callable(getattr(type(self.backend), '_free_waf_main' + name, None)))

    def test_shared_transaction_reuses_historical_lock_path_without_replacing_it(self):
        path = self.root / '.endpoint-policy.lock'
        path.write_bytes(b'legacy lock identity')
        before = path.stat()
        with self.backend._free_waf_main__endpoint_transaction():
            with self.backend._free_waf_main__endpoint_transaction():
                self.assertEqual(path.stat().st_ino, before.st_ino)
        self.assertEqual(path.read_bytes(), b'legacy lock identity')
        self.assertEqual(list(self.root.glob('*.lock')), [path])

    def test_repeat_reads_ignore_legacy_rules_without_migration_or_log_reads(self):
        open_regular = self.backend._free_waf_main__open_regular_file
        with patch.object(self.backend, '_free_waf_main__open_regular_file', wraps=open_regular) as opened:
            for legacy in (self.legacy_rules, {'invalid': True}, None, 'opaque legacy data'):
                with self.subTest(legacy=legacy):
                    config = copy.deepcopy(self.config)
                    config['fixture.example']['endpoint_limits'] = legacy
                    self.write(config)
                    original = self.path.read_bytes()
                    self.assertTrue(self.backend.get_repeat_ban_sites(None)['status'])
                    result = self.backend.get_repeat_ban_policy(types.SimpleNamespace(siteName='fixture.example'))
                    self.assertTrue(result['status'])
                    self.assertFalse(result['policy']['enabled'])
                    self.assertEqual(self.path.read_bytes(), original)
            self.assertTrue(opened.call_args_list)
            self.assertTrue(all(Path(call.args[0]) == self.path for call in opened.call_args_list))
        self.write(self.config)
        self.assert_history_preserved()
        self.public.writeFile.assert_not_called()
        self.public.serviceReload.assert_not_called()
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()
        self.backend._free_waf_main__write_site_domains.assert_not_called()

    def test_repeat_save_preserves_enabled_and_malformed_legacy_config_and_logs(self):
        self.assertTrue(self.save_repeat()['status'])
        self.assert_history_preserved()
        self.assertEqual(self.read()['fixture.example']['repeat_ban_policy'],
                         self.backend._free_waf_main__repeat_defaults())
        self.assertEqual(self.read()['other.example'], self.config['other.example'])
        self.assertEqual(len(list(self.root.glob('*.bak'))), 1)
        self.public.writeFile.assert_not_called()

    def test_repeat_rollback_restores_exact_config_and_keeps_history(self):
        original = self.path.read_bytes()
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [False, True]
        self.assertFalse(self.save_repeat()['status'])
        self.assertEqual(self.path.read_bytes(), original)
        self.assert_history_preserved()
        self.assertEqual(self.backend._free_waf_main__checked_nginx_reload.call_count, 2)

    def test_site_read_keeps_historical_fields_and_logs_without_a_cleanup_migration(self):
        original = self.path.read_bytes()
        result = self.site_view()
        self.assertEqual(result, self.config)
        self.assertEqual(self.path.read_bytes(), original)
        self.assert_history_preserved()
        self.public.writeFile.assert_not_called()
        self.public.serviceReload.assert_not_called()
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_existing_site_migration_retains_opaque_legacy_fields_and_sample_logs(self):
        config = copy.deepcopy(self.config)
        del config['fixture.example']['registration_guard']
        self.write(config)
        result = self.site_view()
        self.assertIn('registration_guard', result['fixture.example'])
        self.assert_history_preserved()

    def test_legacy_site_save_preserves_historical_policy_in_both_sites(self):
        real_refresh = type(self.backend)._free_waf_main__write_site_domains.__get__(self.backend)
        self.public.readFile.side_effect = lambda path: (
            Path(path).read_text(encoding='utf-8') if Path(path).exists() else False)
        tables = {
            'sites': [dict(id=7, name='fixture.example'), dict(id=8, name='other.example')],
            'domain': [dict(pid=7, name='new.fixture.example')],
            'binding': [dict(pid=7, domain='bound.fixture.example')]}
        self.public.M.side_effect = lambda table: types.SimpleNamespace(
            field=lambda fields: types.SimpleNamespace(select=lambda: tables[table]))
        display_fields = ('top', 'siteName', 'log_size', 'total')
        for domestic in (False, True):
            with self.subTest(domestic=domestic):
                config = copy.deepcopy(self.config)
                for site, conf in config.items():
                    conf.update(top={'not': 'site policy'}, siteName=site, log_size=832, total=[])
                self.write(config)
                global_config = dict(self.backend.get_config.return_value,
                                     compatibility_profile='bt-free-waf-8.4' if domestic else None,
                                     site_aliases={'old.fixture.example': 'fixture.example'})
                (self.root / 'config.json').write_text(json.dumps(global_config), encoding='utf-8')
                (self.root / 'domains.json').write_text(json.dumps([
                    dict(name='fixture.example', domains=['old.fixture.example'])]), encoding='utf-8')
                expected = {site: {key: value for key, value in conf.items() if key not in display_fields}
                            for site, conf in config.items()}
                expected['fixture.example']['cdn'] = True
                before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
                self.site_view()
                self.assertEqual({path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}, before)
                stages = []

                def verify_snapshot(stage):
                    lock = os.path.normcase(os.path.abspath(str(self.root / '.endpoint-policy.lock')))
                    self.assertIn((os.getpid(), lock), self.backend._free_waf_main__site_config_locks.paths)
                    self.assertTrue(Path(lock).exists())
                    self.assertEqual(self.read(), expected)
                    stages.append(stage)
                    return True

                def reload():
                    verify_snapshot('reload')
                    if domestic:
                        current = json.loads((self.root / 'config.json').read_bytes())
                        self.assertEqual(current['site_aliases'], {
                            'new.fixture.example': 'fixture.example', 'bound.fixture.example': 'fixture.example'})
                        self.assertEqual(json.loads((self.root / 'domains.json').read_bytes()), [
                            dict(name='fixture.example', domains=['bound.fixture.example', 'new.fixture.example']),
                            dict(name='other.example', domains=[])])
                    return True

                refresh = Mock(wraps=real_refresh) if domestic else Mock(side_effect=lambda: verify_snapshot('domains'))

                def stage_journal(path, content):
                    staged = Path(path)
                    self.assertEqual(staged.parent, self.root / '.policy-recovery')
                    self.assertTrue(staged.name.startswith('.policy-'))
                    staged.write_text(content, encoding='utf-8')
                    return True

                checked = self.backend._free_waf_main__checked_nginx_reload
                checked.reset_mock()
                checked.side_effect = reload
                with patch.object(self.backend, '_free_waf_main__write_site_domains', refresh), \
                        patch.object(self.public, 'writeFile', side_effect=stage_journal) as journal_writer:
                    result = self.backend.set_site_cdn_state(types.SimpleNamespace(siteName='fixture.example'))
                self.assertTrue(result['status'])
                self.assertEqual(self.read(), expected)
                if domestic:
                    refresh.assert_called_once_with(expected)
                    self.assertEqual(journal_writer.call_count, 1)
                else:
                    refresh.assert_called_once_with()
                    journal_writer.assert_not_called()
                checked.assert_called_once_with()
                self.assertEqual(stages, ['reload'] if domestic else ['domains', 'reload'])
                self.assert_history_preserved()
                self.public.writeFile.assert_not_called()
                self.public.serviceReload.assert_not_called()

    def test_repeat_save_does_not_add_legacy_policy_fields_when_absent(self):
        config = copy.deepcopy(self.config)
        for conf in config.values():
            conf.pop('endpoint_limits')
        self.write(config)
        self.assertTrue(self.save_repeat()['status'])
        self.assertTrue(all('endpoint_limits' not in conf for conf in self.read().values()))
        self.assertNotIn('endpoint_limits', self.backend._free_waf_main__get_site_conf())
        for path, data in self.history.items():
            self.assertEqual(path.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
