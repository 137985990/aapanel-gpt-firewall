import copy
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch

from tests.test_panel_performance import load_backend


class EndpointPolicyTest(unittest.TestCase):
    def setUp(self):
        self.config = {'fixture.example': {'open': True, 'cc': {'limit': 10}},
                       'other.example': {'open': False}}
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            readFile=Mock(side_effect=lambda path: json.dumps(self.config)),
            writeFile=Mock(side_effect=self.persist),
            httpGet=Mock(side_effect=AssertionError('network')),
            httpPost=Mock(side_effect=AssertionError('network')),
            serviceReload=Mock(side_effect=AssertionError('read reloaded runtime')),
        )
        self.backend = load_backend(self.public)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend._free_waf_main__path = self.directory.name + os.sep
        self.backend._free_waf_main__update_request_is_post = Mock(return_value=True)
        self.backend._free_waf_main__write_site_config = Mock(side_effect=AssertionError('unchecked legacy writer'))
        self.backend._free_waf_main__checked_nginx_reload = Mock()
        self.backend.get_site_config = Mock(side_effect=AssertionError('legacy getter migrates/prunes logs'))

    def persist(self, path, content):
        self.config = json.loads(content)
        return True

    def rule(self, **changes):
        data = dict(name='Login', match='exact', path='/api/login', method='POST',
                    window_seconds=60, max_requests=10, ban_seconds=60)
        data.update(changes)
        return data

    def call(self, method, **args):
        function = getattr(self.backend, method, None)
        self.assertTrue(callable(function), method + ' API missing')
        return function(types.SimpleNamespace(**args))

    def save(self, rule=None, site='fixture.example', **args):
        return self.call('save_endpoint_policy', siteName=site,
                         policy=json.dumps(self.rule() if rule is None else rule), **args)

    def test_absent_rules_read_as_empty_without_migrating_or_writing(self):
        before = copy.deepcopy(self.config)
        self.assertEqual(self.call('get_endpoint_policies', siteName='fixture.example'),
                         dict(status=True, siteName='fixture.example', rules=[]))
        self.assertEqual(self.config, before)
        self.backend._free_waf_main__write_site_config.assert_not_called()
        self.public.serviceReload.assert_not_called()

    def test_create_defaults_disabled_observe_and_server_uuid(self):
        result = self.save()
        self.assertTrue(result['status'])
        self.assertEqual(result['siteName'], 'fixture.example')
        rule = result['rules'][0]
        self.assertRegex(rule['id'], r'^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$')
        self.assertIs(rule['enabled'], False)
        self.assertEqual(rule['action'], 'observe')
        self.assertEqual(self.config['fixture.example']['cc'], {'limit': 10})
        self.assertEqual(self.config['other.example'], {'open': False})

    def test_update_keeps_identity_and_replaces_only_selected_rule(self):
        first = self.save()['rules'][0]
        second = self.save(self.rule(path='/next'))['rules'][1]
        result = self.save(self.rule(id=first['id'], enabled=True, action='ban', max_requests=2))
        self.assertTrue(result['status'])
        self.assertEqual([r['id'] for r in result['rules']], [first['id'], second['id']])
        self.assertEqual(result['rules'][0]['max_requests'], 2)

    def test_unknown_or_cross_site_id_cannot_create_a_rule(self):
        existing = self.save()['rules'][0]
        for site, ident in [('fixture.example', 'a' * 32), ('other.example', existing['id'])]:
            with self.subTest(site=site):
                self.assertFalse(self.save(self.rule(id=ident), site=site)['status'])
        self.assertNotIn('endpoint_limits', self.config['other.example'])

    def test_mutations_require_post_before_reading_arguments_or_config(self):
        self.backend._free_waf_main__update_request_is_post.return_value = False
        self.assertFalse(self.save()['status'])
        self.assertFalse(self.call('delete_endpoint_policy')['status'])
        self.public.readFile.assert_not_called()
        self.backend._free_waf_main__write_site_config.assert_not_called()

    def test_missing_or_unknown_sites_fail_without_creating_site_config(self):
        for site in ('', 'missing.example', '../site.json', 'fixture.example/path', None):
            with self.subTest(site=site):
                self.assertFalse(self.save(site=site)['status'])
                self.assertFalse(self.call('get_endpoint_policies', siteName=site)['status'])
        self.backend._free_waf_main__write_site_config.assert_not_called()

    def test_schema_rejects_unknown_fields_wrong_types_and_invalid_bounds(self):
        invalid = [dict(enabled=1), dict(enabled='false'), dict(action='drop'), dict(match='regex'),
                   dict(method='get'), dict(name=''), dict(name='x' * 129), dict(name='bad\nname'),
                   dict(path=3), dict(id=''), dict(open=True), dict(siteName='other.example'),
                   dict(window_seconds=0), dict(window_seconds=3601), dict(window_seconds=True),
                   dict(window_seconds='60'), dict(max_requests=0), dict(max_requests=100001),
                   dict(max_requests=1.5), dict(ban_seconds=0), dict(ban_seconds=28801),
                   dict(ban_seconds=False)]
        for changes in invalid:
            with self.subTest(changes=changes):
                self.assertFalse(self.save(self.rule(**changes))['status'])
        self.backend._free_waf_main__write_site_config.assert_not_called()

    def test_rejects_nonobject_json_missing_fields_and_frontend_paths(self):
        for policy in ('[]', 'null', '{', 'true', '"/frontend/path"', '{}'):
            with self.subTest(policy=policy):
                self.assertFalse(self.call('save_endpoint_policy', siteName='fixture.example', policy=policy)['status'])
        incomplete = self.rule()
        del incomplete['path']
        self.assertFalse(self.save(incomplete)['status'])

    def test_path_rejects_queries_controls_encoding_dot_segments_and_regex_syntax(self):
        for path in ('api', '/api?secret=x', '/api#fragment', '/a\nb', '/a\x00b', '/a\\b',
                     '/a/../b', '/./a', '/a/.', '/a/..', '//api', '/a//b', '/%2fapi',
                     '/%252e%252e', '/a%20b', '/a%ZZ', '/api.*', '/(api)', '/' + 'x' * 512):
            with self.subTest(path=path):
                self.assertFalse(self.save(self.rule(path=path))['status'])

    def test_all_enum_values_and_inclusive_numeric_bounds(self):
        for method in ('ALL', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
            self.assertTrue(self.save(self.rule(method=method, match='prefix', path='/api/',
                                               window_seconds=1, max_requests=1, ban_seconds=1))['status'])
        self.assertTrue(self.save(self.rule(path='/', window_seconds=3600,
                                           max_requests=100000, ban_seconds=28800))['status'])

    def test_limit_fifty_allows_edit_and_delete_but_not_fifty_first(self):
        for _ in range(50):
            result = self.save()
            self.assertTrue(result['status'])
        self.assertFalse(self.save()['status'])
        ident = result['rules'][0]['id']
        self.assertTrue(self.save(self.rule(id=ident, action='reject'))['status'])
        result = self.call('delete_endpoint_policy', siteName='fixture.example', id=ident)
        self.assertTrue(result['status'])
        self.assertEqual(len(result['rules']), 49)
        self.assertTrue(self.save()['status'])

    def test_delete_requires_valid_existing_id_in_selected_site(self):
        ident = self.save()['rules'][0]['id']
        for args in ({}, {'id': '../file'}, {'id': 'a' * 32}, {'id': ident, 'siteName': 'other.example'}):
            data = dict(siteName='fixture.example')
            data.update(args)
            self.assertFalse(self.call('delete_endpoint_policy', **data)['status'])
        result = self.call('delete_endpoint_policy', siteName='fixture.example', id=ident)
        self.assertEqual(result, dict(status=True, siteName='fixture.example', rules=[]))

    def test_invalid_stored_schema_is_not_silently_overwritten(self):
        self.config['fixture.example']['endpoint_limits'] = {'bad': 'data'}
        self.assertFalse(self.save()['status'])
        self.assertFalse(self.call('get_endpoint_policies', siteName='fixture.example')['status'])
        self.backend._free_waf_main__write_site_config.assert_not_called()

    def test_writer_failure_never_reports_success(self):
        for failure in (OSError('disk full'), False):
            writer = self.public.writeFile
            writer.side_effect = failure if isinstance(failure, Exception) else None
            writer.return_value = False
            self.assertFalse(self.save()['status'])

    def test_save_reload_failure_restores_original_config_and_reports_failure(self):
        before = copy.deepcopy(self.config)
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [RuntimeError('reload failed'), None]
        self.assertFalse(self.save()['status'])
        self.assertEqual(self.config, before)
        self.assertEqual(self.backend._free_waf_main__checked_nginx_reload.call_count, 2)

    def test_delete_reload_failure_restores_rule_and_reports_failure(self):
        ident = self.save()['rules'][0]['id']
        before = copy.deepcopy(self.config)
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [RuntimeError('reload failed'), None]
        self.assertFalse(self.call('delete_endpoint_policy', siteName='fixture.example', id=ident)['status'])
        self.assertEqual(self.config, before)

    def test_partial_file_write_failure_also_attempts_rollback(self):
        before = copy.deepcopy(self.config)
        def partial_write(path, content):
            self.persist(path, content)
            return self.public.writeFile.call_count > 1
        self.public.writeFile.side_effect = partial_write
        self.assertFalse(self.save()['status'])
        self.assertEqual(self.config, before)

    def test_checked_reload_uses_only_fixed_argv_and_never_unchecked_service_reload(self):
        del self.backend._free_waf_main__checked_nginx_reload
        with patch('subprocess.run', return_value=types.SimpleNamespace(returncode=0)) as run:
            self.assertTrue(self.save()['status'])
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['/www/server/nginx/sbin/nginx', '-t'],
            ['/www/server/nginx/sbin/nginx', '-s', 'reload']])
        self.public.serviceReload.assert_not_called()

    def test_successful_write_without_persisted_content_does_not_report_success(self):
        before = copy.deepcopy(self.config)
        self.public.writeFile.side_effect = None
        self.public.writeFile.return_value = True
        self.assertFalse(self.save()['status'])
        self.assertEqual(self.config, before)

    def test_false_reload_result_is_also_a_failure(self):
        before = copy.deepcopy(self.config)
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [False, None]
        self.assertFalse(self.save()['status'])
        self.assertEqual(self.config, before)

    def test_edit_without_optional_defaults_preserves_enabled_action(self):
        rule = self.save(self.rule(enabled=True, action='ban'))['rules'][0]
        result = self.save(self.rule(id=rule['id'], max_requests=2))
        self.assertTrue(result['status'])
        self.assertIs(result['rules'][0]['enabled'], True)
        self.assertEqual(result['rules'][0]['action'], 'ban')

    def test_unicode_control_path_characters_are_rejected(self):
        self.assertFalse(self.save(self.rule(path='/api\u0085login'))['status'])

    def test_rollback_preserves_unrelated_concurrent_settings(self):
        def reload_with_concurrent_setting():
            if self.backend._free_waf_main__checked_nginx_reload.call_count == 1:
                self.config['other.example']['open'] = True
                self.config['fixture.example']['cc']['limit'] = 20
                raise RuntimeError('reload failed')
        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload_with_concurrent_setting
        self.assertFalse(self.save()['status'])
        self.assertNotIn('endpoint_limits', self.config['fixture.example'])
        self.assertTrue(self.config['other.example']['open'])
        self.assertEqual(self.config['fixture.example']['cc']['limit'], 20)

    def test_rollback_restores_exact_original_bytes_without_concurrent_edits(self):
        original = json.dumps(self.config, indent=2) + '\n'
        storage = [original]
        self.public.readFile.side_effect = lambda path: storage[0]
        def write(path, content):
            storage[0] = content
            return True
        self.public.writeFile.side_effect = write
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [RuntimeError('reload'), None]
        self.assertFalse(self.save()['status'])
        self.assertEqual(storage[0], original)

    def test_overlapping_saves_cannot_both_succeed_and_lose_a_site_policy(self):
        entered, release = threading.Event(), threading.Event()
        results = []
        def paused_write(path, content):
            if threading.current_thread().name == 'first-policy-save':
                entered.set()
                if not release.wait(5):
                    raise TimeoutError('test write was not released')
            return self.persist(path, content)
        self.public.writeFile.side_effect = paused_write
        first = threading.Thread(target=lambda: results.append(self.save()), name='first-policy-save')
        first.start()
        try:
            self.assertTrue(entered.wait(5))
            conflicting = self.save(site='other.example')
        finally:
            release.set()
            first.join(5)
        self.assertFalse(first.is_alive())
        self.assertTrue(results[0]['status'])
        self.assertFalse(conflicting['status'])
        self.assertTrue(self.save(site='other.example')['status'])
        self.assertEqual(len(self.config['fixture.example']['endpoint_limits']), 1)
        self.assertEqual(len(self.config['other.example']['endpoint_limits']), 1)

    def test_transaction_rejects_link_lock_before_reading_configuration(self):
        target = Path(self.directory.name) / 'other-lock'
        target.write_bytes(b'private')
        try:
            (Path(self.directory.name) / '.endpoint-policy.lock').symlink_to(target)
        except OSError as error:
            self.skipTest('symlink unavailable: ' + str(error))
        self.assertFalse(self.save()['status'])
        self.public.readFile.assert_not_called()
        self.public.writeFile.assert_not_called()
        self.assertEqual(target.read_bytes(), b'private')

    @unittest.skipUnless(os.name == 'posix', 'production cross-process lock requires POSIX')
    def test_another_panel_process_prevents_policy_mutation(self):
        path = str(Path(self.directory.name) / '.endpoint-policy.lock')
        code = ('import fcntl,sys; f=open(sys.argv[1],"a+"); '
                'fcntl.flock(f,fcntl.LOCK_EX); print("locked",flush=True); sys.stdin.read(1)')
        process = subprocess.Popen([sys.executable, '-I', '-c', code, path],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(process.stdout.readline().strip(), b'locked')
            self.assertFalse(self.save()['status'])
            self.public.readFile.assert_not_called()
            self.public.writeFile.assert_not_called()
        finally:
            process.communicate(input=b'x', timeout=5)
        self.assertTrue(self.save()['status'])


class EndpointEventsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.public = types.SimpleNamespace(returnMsg=lambda status, msg: dict(status=status, msg=msg))
        self.backend = load_backend(self.public)
        self.backend.get_config = Mock(return_value={'logs_path': str(self.root)})
        self.today = datetime.date.today()

    def event(self, **changes):
        row = dict(timestamp=self.today.isoformat() + ' 12:00:00', site='fixture.example',
                   ip='192.0.2.10', path='/api/login', method='POST', rule_id='a' * 32,
                   rule_name='Login', action='observe', count=11, limit=10, window_seconds=60, retry_after=0)
        row.update(changes)
        return row

    def write_events(self, rows, day=None):
        path = self.root / ('endpoint_' + (day or self.today).isoformat() + '.jsonl')
        path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
        return path

    def call(self, **args):
        function = getattr(self.backend, 'get_endpoint_policy_events', None)
        self.assertTrue(callable(function), 'events API missing')
        return function(types.SimpleNamespace(**args))

    def test_empty_events_have_sampled_record_notice_and_recorded_only_summary(self):
        result = self.call()
        self.assertTrue(result['status'])
        self.assertEqual(result['events'], [])
        self.assertIs(result['coverage']['partial'], False)
        self.assertIn('\u91c7\u6837', result['coverage']['notice'])
        self.assertEqual(result['summary'], dict(recorded_events=0, observed=0, rejected=0, banned=0))

    def test_latest_first_site_rule_filter_and_recorded_summary(self):
        self.write_events([self.event(timestamp=self.today.isoformat() + ' 10:00:00'),
                           self.event(action='reject', retry_after=60),
                           self.event(site='other.example', action='ban'),
                           self.event(rule_id='b' * 32)])
        result = self.call(days='1', siteName='fixture.example', rule_id='a' * 32)
        self.assertTrue(result['status'])
        self.assertEqual([row['action'] for row in result['events']], ['reject', 'observe'])
        self.assertEqual(result['summary'], dict(recorded_events=2, observed=1, rejected=1, banned=0))

    def test_evidence_is_allowlisted_and_query_body_credentials_never_returned(self):
        self.write_events([self.event(path='/api/login?token=secret#fragment', rule_name='<b>Login</b>',
                                      headers={'Cookie': 'secret'}, body='private', cookie='private', query='secret')])
        result = self.call()
        row = result['events'][0]
        self.assertEqual(set(row), set(self.event()))
        self.assertEqual(row['path'], '/api/login')
        self.assertEqual(row['rule_name'], '<b>Login</b>')
        self.assertNotIn('secret', json.dumps(result))
        self.assertNotIn('private', json.dumps(result))

    def test_bad_rows_are_skipped_not_coerced_or_echoed(self):
        self.write_events([self.event(), [], self.event(ip='not-an-ip'), self.event(count=True),
                           self.event(path='/../private'), self.event(action='drop'),
                           self.event(timestamp='not-a-time'), self.event(rule_id='../private')])
        result = self.call()
        self.assertEqual(len(result['events']), 1)
        self.assertTrue(result['coverage']['partial'])

    def test_query_parameters_are_validated_before_any_log_read(self):
        for args in ({'days': '0'}, {'days': '8'}, {'days': True}, {'days': '1.5'},
                     {'rule_id': '../private'}, {'siteName': '../private'}, {'siteName': 'a\nb'}):
            with self.subTest(args=args), patch('builtins.open', side_effect=AssertionError('unexpected file read')):
                self.assertFalse(self.call(**args)['status'])

    def test_frontend_file_arguments_are_ignored_and_only_fixed_daily_names_opened(self):
        self.write_events([self.event()])
        secret = self.root / 'secret.jsonl'
        secret.write_text('private')
        result = self.call(path=str(secret), filename=str(secret), logs_path=str(secret), days=1)
        self.assertEqual(len(result['events']), 1)

    def test_max_two_hundred_events_and_one_megabyte_total_across_seven_days(self):
        for offset in range(7):
            self.write_events([self.event()] * 5000, self.today - datetime.timedelta(days=offset))
        original_fdopen = os.fdopen
        bytes_read = []

        class Meter:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                self.stream.__enter__()
                return self
            def __exit__(self, *args):
                return self.stream.__exit__(*args)
            def __getattr__(self, name):
                return getattr(self.stream, name)
            def read(self, size=-1):
                data = self.stream.read(size)
                bytes_read.append(len(data))
                return data

        with patch('os.fdopen', side_effect=lambda *a, **k: Meter(original_fdopen(*a, **k))):
            result = self.call(days=7)
        self.assertEqual(len(result['events']), 200)
        self.assertTrue(result['coverage']['partial'])
        self.assertGreater(sum(bytes_read), 0)
        self.assertLessEqual(sum(bytes_read), 1024 * 1024)

    def test_unterminated_last_record_is_kept_and_partial_first_record_is_discarded(self):
        path = self.write_events([])
        path.write_bytes(b'x' * (1024 * 1024) + b'\n' + json.dumps(self.event()).encode())
        result = self.call()
        self.assertEqual(result['events'], [self.event()])
        self.assertTrue(result['coverage']['partial'])

    def test_log_symlink_is_never_followed(self):
        secret = self.root / 'private'
        secret.write_text(json.dumps(self.event()) + '\n')
        path = self.root / ('endpoint_' + self.today.isoformat() + '.jsonl')
        try:
            path.symlink_to(secret)
        except OSError as exc:
            self.skipTest('symlink creation unavailable: ' + str(exc))
        result = self.call()
        self.assertEqual(result['events'], [])
        self.assertTrue(result['coverage']['partial'])

    def test_deeply_nested_invalid_record_is_skipped_not_an_api_error(self):
        path = self.write_events([])
        path.write_text('[' * 3000 + '0' + ']' * 3000 + '\n' + json.dumps(self.event()), encoding='utf-8')
        try:
            result = self.call()
        except RecursionError:
            self.fail('a corrupt bounded record crashed the events API')
        self.assertEqual(len(result['events']), 1)
        self.assertTrue(result['coverage']['partial'])

    def test_evidence_keeps_literal_normalized_paths_not_just_policy_pattern_characters(self):
        self.write_events([self.event(path='/api/a+b/(draft)/[item]/100%?token=secret')])
        result = self.call()
        self.assertEqual(len(result['events']), 1)
        self.assertEqual(result['events'][0]['path'], '/api/a+b/(draft)/[item]/100%')

    def test_evidence_strings_are_raw_json_values_for_single_ui_escape(self):
        name = '<b>Login & audit</b>'
        path = '/api/a&b/<draft>"/[]()+'
        self.write_events([self.event(path=path, rule_name=name)])
        row = self.call()['events'][0]
        self.assertEqual(row['site'], 'fixture.example')
        self.assertEqual(row['rule_name'], name)
        self.assertEqual(row['path'], path)


if __name__ == '__main__':
    unittest.main()
