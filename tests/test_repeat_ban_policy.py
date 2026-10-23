import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch

from tests.test_panel_performance import load_backend


ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = dict(enabled=False, window_seconds=86400,
                tiers=[dict(threshold=5, ban_seconds=604800),
                       dict(threshold=10, ban_seconds=2592000)])


def record(**changes):
    row = dict(site='fixture.example', ip='192.0.2.1', started_at=1000,
               expires_at=605800, duration=604800, trigger_count=5,
               window_seconds=86400, threshold=5, reason='cc', path='/api/login')
    row.update(changes)
    return row


class RepeatBanPolicyTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.site_path = self.root / 'site.json'
        self.snapshot_path = self.root / 'repeat_bans.json'
        self.config = {'fixture.example': {'open': True, 'cc': {'limit': 10}},
                       'other.example': {'open': False}}
        self.original = (json.dumps(self.config, ensure_ascii=False, indent=2) + '\r\n').encode('utf-8')
        self.site_path.write_bytes(self.original)
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            readFile=Mock(side_effect=AssertionError('use original UTF-8 bytes')),
            writeFile=Mock(side_effect=AssertionError('use safe atomic writer')),
            httpGet=Mock(side_effect=AssertionError('unexpected network')),
            serviceReload=Mock(side_effect=AssertionError('unchecked reload')))
        self.backend = load_backend(self.public)
        self.backend._free_waf_main__path = str(self.root) + os.sep
        self.backend._free_waf_main__PATH = str(ROOT) + os.sep
        self.backend._free_waf_main__update_request_is_post = Mock(return_value=True)
        self.backend._free_waf_main__checked_nginx_reload = Mock()
        self.backend._free_waf_main__write_site_config = Mock(side_effect=AssertionError('legacy writer'))
        self.backend.get_site_config = Mock(side_effect=AssertionError('legacy migration/pruning'))

    def call(self, method, **args):
        function = getattr(self.backend, method, None)
        self.assertTrue(callable(function), method + ' API missing')
        return function(types.SimpleNamespace(**args))

    def revision(self):
        return hashlib.sha256(self.site_path.read_bytes()).hexdigest()

    def config_read(self):
        return json.loads(self.site_path.read_bytes())

    def config_write(self, config):
        self.site_path.write_bytes(json.dumps(config).encode('utf-8'))

    def save(self, policy_data=None, **args):
        params = dict(siteName='fixture.example', policy=json.dumps(DEFAULTS if policy_data is None else policy_data),
                      revision=self.revision())
        params.update(args)
        return self.call('save_repeat_ban_policy', **params)

    def snapshot(self, rows):
        self.snapshot_path.write_bytes(json.dumps(dict(version=1, revision='a' * 32, bans=rows)).encode())

    def test_missing_policy_is_disabled_defaults_and_hashes_original_bytes(self):
        result = self.call('get_repeat_ban_policy', siteName='fixture.example')
        self.assertEqual(result, dict(status=True, siteName='fixture.example',
                                      policy=DEFAULTS, revision=hashlib.sha256(self.original).hexdigest()))
        self.assertEqual(self.site_path.read_bytes(), self.original)

    def test_site_discovery_is_raw_read_only_and_reports_limits(self):
        before = sorted(self.root.iterdir())
        result = self.call('get_repeat_ban_sites')
        self.assertTrue(result['status'])
        self.assertEqual(result['sites'], [dict(siteName='fixture.example'), dict(siteName='other.example')])
        self.assertEqual(result['defaults'], DEFAULTS)
        self.assertEqual(result['limits']['window_seconds'], dict(min=60, max=604800))
        self.assertEqual(result['limits']['threshold'], dict(min=2, max=1000))
        self.assertEqual(result['limits']['ban_seconds'], dict(min=60, max=31536000))
        self.assertEqual(result['limits']['tiers'], dict(min=1, max=8))
        self.assertEqual(sorted(self.root.iterdir()), before)
        self.public.readFile.assert_not_called()
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_policy_save_preserves_other_settings_and_independent_exact_backup(self):
        policy = copy.deepcopy(DEFAULTS)
        policy['enabled'] = True
        result = self.save(policy)
        self.assertTrue(result['status'], result)
        self.assertEqual(result['policy'], policy)
        self.assertEqual(result['revision'], self.revision())
        self.assertEqual(self.config_read()['fixture.example']['cc'], {'limit': 10})
        self.assertEqual(self.config_read()['other.example'], self.config['other.example'])
        backups = list(self.root.glob('.repeat-ban-policy-*.bak'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.original)
        self.assertFalse(backups[0].is_symlink())
        self.backend._free_waf_main__checked_nginx_reload.assert_called_once()
        self.backend._free_waf_main__write_site_config.assert_not_called()

    def test_policy_numeric_bounds_and_one_to_eight_tiers(self):
        for policy in (dict(enabled=False, window_seconds=60, tiers=[dict(threshold=2, ban_seconds=60)]),
                       dict(enabled=True, window_seconds=604800, tiers=[dict(threshold=1000, ban_seconds=31536000)]),
                       dict(enabled=True, window_seconds=86400,
                            tiers=[dict(threshold=2 + i, ban_seconds=60 + i) for i in range(8)])):
            with self.subTest(policy=policy):
                self.assertTrue(self.save(policy)['status'])

    def test_invalid_policy_types_fields_and_tiers_never_write_or_reload(self):
        invalid = [None, [], True, {}, dict(DEFAULTS, enabled=1), dict(DEFAULTS, enabled='false'),
                   dict(DEFAULTS, window_seconds=True), dict(DEFAULTS, window_seconds='60'),
                   dict(DEFAULTS, window_seconds=60.0), dict(DEFAULTS, window_seconds=59),
                   dict(DEFAULTS, window_seconds=604801), dict(DEFAULTS, threshold=5),
                   dict(DEFAULTS, tiers=[]), dict(DEFAULTS, tiers={}), dict(DEFAULTS, tiers=[None]),
                   dict(DEFAULTS, tiers=[dict(threshold=2)]),
                   dict(DEFAULTS, tiers=[dict(threshold=5, ban_seconds=60, extra=True)]),
                   dict(DEFAULTS, tiers=[dict(threshold=2 + i, ban_seconds=60 + i) for i in range(9)])]
        for changes in (dict(threshold=1), dict(threshold=1001), dict(threshold=True),
                        dict(threshold='5'), dict(ban_seconds=59), dict(ban_seconds=31536001),
                        dict(ban_seconds=False), dict(ban_seconds=60.5)):
            invalid.append(dict(DEFAULTS, tiers=[dict(dict(threshold=5, ban_seconds=604800), **changes)]))
        for tiers in ([dict(threshold=5, ban_seconds=604800)] * 2,
                      [dict(threshold=10, ban_seconds=60), dict(threshold=5, ban_seconds=120)],
                      [dict(threshold=5, ban_seconds=604800), dict(threshold=10, ban_seconds=604800)],
                      [dict(threshold=5, ban_seconds=604800), dict(threshold=10, ban_seconds=60)]):
            invalid.append(dict(DEFAULTS, tiers=tiers))
        for policy in invalid:
            with self.subTest(policy=policy):
                self.assertFalse(self.save(policy, policy=json.dumps(policy))['status'])
                self.assertEqual(self.site_path.read_bytes(), self.original)
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_json_errors_duplicates_and_legacy_schema_are_rejected(self):
        for text in ('{', 'null', '[]', 'true', '"policy"',
                     '{"enabled":false,"enabled":true,"window_seconds":86400,"tiers":[]}',
                     json.dumps(dict(enabled=False, window_seconds=86400, threshold=28, ban_seconds=2592000))):
            with self.subTest(text=text):
                self.assertFalse(self.save(policy=text)['status'])
        self.assertEqual(self.site_path.read_bytes(), self.original)

    def test_mutations_require_post_before_arguments_or_io(self):
        self.backend._free_waf_main__update_request_is_post.return_value = False
        with patch('os.open', side_effect=AssertionError('GET attempted file IO')):
            self.assertFalse(self.call('save_repeat_ban_policy')['status'])
            self.assertFalse(self.call('remove_repeat_ban')['status'])
        self.public.httpGet.assert_not_called()

    def test_missing_unknown_and_invalid_site_names_fail_without_creating_config(self):
        for site in ('', None, '../site.json', 'fixture.example/path', 'a..b', 'a\nb', 'missing.example'):
            with self.subTest(site=site):
                self.assertFalse(self.call('get_repeat_ban_policy', siteName=site)['status'])
                self.assertFalse(self.save(siteName=site)['status'])
                self.assertFalse(self.call('get_repeat_bans', siteName=site)['status'])
        self.assertEqual(self.site_path.read_bytes(), self.original)

    def test_stale_revision_including_unrelated_edit_never_writes(self):
        stale = self.revision()
        changed = copy.deepcopy(self.config)
        changed['other.example']['open'] = True
        self.config_write(changed)
        for revision in (stale, '', None, 'a' * 63, 'A' * 64, 1):
            with self.subTest(revision=revision):
                result = self.save(revision=revision)
                self.assertFalse(result['status'])
        self.assertEqual(self.config_read(), changed)
        self.assertEqual(list(self.root.glob('*.bak')), [])
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_invalid_stored_policy_or_config_is_not_silently_replaced(self):
        for raw in (b'{', b'[]', b'null', b'\xff',
                    json.dumps({'fixture.example': {'repeat_ban_policy': None}}).encode()):
            with self.subTest(raw=raw):
                self.site_path.write_bytes(raw)
                self.assertFalse(self.call('get_repeat_ban_policy', siteName='fixture.example')['status'])
                self.assertFalse(self.save()['status'])
                self.assertEqual(self.site_path.read_bytes(), raw)

    def test_backup_failure_never_edits_configuration(self):
        with patch('tempfile.mkstemp', side_effect=OSError('disk full')):
            self.assertFalse(self.save()['status'])
        self.assertEqual(self.site_path.read_bytes(), self.original)
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_backup_replaced_with_symlink_before_verification_prevents_config_edit(self):
        target = self.root / 'private-backup'
        target.write_bytes(b'private')
        probe = self.root / 'link-probe'
        try:
            probe.symlink_to(target)
            probe.unlink()
        except OSError as error:
            self.skipTest('symlink unavailable: ' + str(error))
        original_close = os.close
        replaced = []
        def close(descriptor):
            original_close(descriptor)
            if not replaced:
                for backup in self.root.glob('*.bak'):
                    backup.unlink()
                    backup.symlink_to(target)
                    replaced.append(backup)
        with patch('os.close', side_effect=close):
            self.assertFalse(self.save()['status'])
        self.assertTrue(replaced)
        self.assertEqual(target.read_bytes(), b'private')
        self.assertEqual(self.site_path.read_bytes(), self.original)
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_writer_failure_does_not_report_success(self):
        with patch.object(self.backend, '_free_waf_main__write_repeat_site_config',
                          side_effect=OSError('disk full'), create=True):
            result = self.save()
        self.assertFalse(result['status'])
        self.assertEqual(self.site_path.read_bytes(), self.original)

    def test_noop_writer_success_is_not_reported_as_success(self):
        with patch.object(self.backend, '_free_waf_main__write_repeat_site_config', return_value=None, create=True):
            self.assertFalse(self.save()['status'])
        self.assertEqual(self.site_path.read_bytes(), self.original)

    def test_partial_valid_write_failure_rolls_back(self):
        writer = getattr(self.backend, '_free_waf_main__write_repeat_site_config', None)
        self.assertTrue(callable(writer), 'safe config writer missing')
        calls = []
        def partial(content, *args, **kwargs):
            calls.append(content)
            writer(content, *args, **kwargs)
            if len(calls) == 1:
                return False
        with patch.object(self.backend, '_free_waf_main__write_repeat_site_config', side_effect=partial):
            self.assertFalse(self.save()['status'])
        self.assertEqual(self.site_path.read_bytes(), self.original)

    def test_reload_failure_restores_exact_original_bytes_and_absence(self):
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [RuntimeError('reload'), None]
        result = self.save()
        self.assertFalse(result['status'])
        self.assertIn('\u5df2\u6062\u590d', result['msg'])
        self.assertEqual(self.site_path.read_bytes(), self.original)
        self.assertEqual(self.backend._free_waf_main__checked_nginx_reload.call_count, 2)

    def test_reload_failure_restores_existing_multitier_policy(self):
        config = self.config_read()
        config['fixture.example']['repeat_ban_policy'] = copy.deepcopy(DEFAULTS)
        self.config_write(config)
        original = self.site_path.read_bytes()
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [False, None]
        self.assertFalse(self.save(dict(DEFAULTS, enabled=True))['status'])
        self.assertEqual(self.site_path.read_bytes(), original)

    def test_failed_reload_of_identical_policy_restores_original_formatting(self):
        config = self.config_read()
        config['fixture.example']['repeat_ban_policy'] = copy.deepcopy(DEFAULTS)
        original = (json.dumps(config, indent=4) + '\r\n').encode('utf-8')
        self.site_path.write_bytes(original)
        self.backend._free_waf_main__checked_nginx_reload.side_effect = [RuntimeError('reload'), None]
        self.assertFalse(self.save()['status'])
        self.assertEqual(self.site_path.read_bytes(), original)

    def test_success_response_hashes_actual_bytes_after_unrelated_reload_edit(self):
        def reload():
            config = self.config_read()
            config['other.example']['open'] = True
            self.config_write(config)
        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        result = self.save()
        self.assertTrue(result['status'])
        self.assertTrue(self.config_read()['other.example']['open'])
        self.assertEqual(result['revision'], self.revision())

    def test_rollback_preserves_concurrent_unrelated_settings(self):
        def reload():
            if self.backend._free_waf_main__checked_nginx_reload.call_count == 1:
                config = self.config_read()
                config['fixture.example']['cc']['limit'] = 99
                config['other.example']['new_setting'] = 'retained'
                self.config_write(config)
                raise RuntimeError('reload')
        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        self.assertFalse(self.save()['status'])
        config = self.config_read()
        self.assertNotIn('repeat_ban_policy', config['fixture.example'])
        self.assertEqual(config['fixture.example']['cc']['limit'], 99)
        self.assertEqual(config['other.example']['new_setting'], 'retained')

    def test_conflicting_policy_edit_is_not_overwritten_by_rollback(self):
        def reload():
            config = self.config_read()
            config['fixture.example']['repeat_ban_policy']['window_seconds'] = 60
            self.config_write(config)
            raise RuntimeError('reload')
        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        result = self.save()
        self.assertFalse(result['status'])
        self.assertIn('\u672a\u786e\u8ba4', result['msg'])
        self.assertEqual(self.config_read()['fixture.example']['repeat_ban_policy']['window_seconds'], 60)

    def test_rollback_reload_failure_is_reported_honestly(self):
        self.backend._free_waf_main__checked_nginx_reload.side_effect = RuntimeError('reload')
        result = self.save()
        self.assertFalse(result['status'])
        self.assertIn('\u672a\u786e\u8ba4', result['msg'])
        self.assertEqual(self.site_path.read_bytes(), self.original)

    def test_checked_reload_uses_fixed_baota_arguments(self):
        del self.backend._free_waf_main__checked_nginx_reload
        with patch('subprocess.run', return_value=types.SimpleNamespace(returncode=0)) as run:
            self.assertTrue(self.save()['status'])
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['/www/server/nginx/sbin/nginx', '-t'], ['/www/server/nginx/sbin/nginx', '-s', 'reload']])
        self.public.serviceReload.assert_not_called()

    def test_same_thread_configuration_lock_allows_nested_policy_save(self):
        locked = getattr(self.backend, '_free_waf_main__endpoint_transaction')
        with locked():
            self.assertTrue(self.save()['status'])
        self.assertEqual(self.config_read()['fixture.example']['repeat_ban_policy'], DEFAULTS)
        self.assertTrue(self.save()['status'])

    def test_save_rechecks_bytes_after_backup(self):
        original_mkstemp = tempfile.mkstemp
        def backup(*args, **kwargs):
            result = original_mkstemp(*args, **kwargs)
            if kwargs.get('suffix') == '.bak':
                config = self.config_read()
                config['other.example']['open'] = True
                self.config_write(config)
            return result
        with patch('tempfile.mkstemp', side_effect=backup):
            self.assertFalse(self.save()['status'])
        self.assertTrue(self.config_read()['other.example']['open'])
        self.assertNotIn('repeat_ban_policy', self.config_read()['fixture.example'])

    def test_atomic_writer_does_not_lose_settings_changed_during_staging(self):
        original_mkstemp = tempfile.mkstemp
        def create(*args, **kwargs):
            result = original_mkstemp(*args, **kwargs)
            if kwargs.get('suffix') == '.tmp':
                config = self.config_read()
                config['other.example']['open'] = True
                self.config_write(config)
            return result
        with patch('tempfile.mkstemp', side_effect=create):
            result = self.save()
        self.assertFalse(result['status'])
        self.assertTrue(self.config_read()['other.example']['open'])
        self.assertNotIn('repeat_ban_policy', self.config_read()['fixture.example'])

    def test_corrupt_concurrent_file_is_not_overwritten_and_backup_is_retained(self):
        def reload():
            self.site_path.write_bytes(b'{')
            raise RuntimeError('concurrent malformed config')
        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        result = self.save()
        self.assertFalse(result['status'])
        self.assertIn('\u672a\u786e\u8ba4', result['msg'])
        self.assertEqual(self.site_path.read_bytes(), b'{')
        self.assertEqual(next(self.root.glob('*.bak')).read_bytes(), self.original)

    def test_atomic_replace_failure_leaves_original_and_backup(self):
        with patch('os.replace', side_effect=OSError('rename failed')):
            self.assertFalse(self.save()['status'])
        self.assertEqual(self.site_path.read_bytes(), self.original)
        self.assertEqual(next(self.root.glob('*.bak')).read_bytes(), self.original)
        self.assertEqual(list(self.root.glob('*.tmp')), [])

    def test_atomic_replace_preserves_config_owner_and_group_when_supported(self):
        info = self.site_path.stat()
        with patch('os.fchown', create=True) as chown:
            self.assertTrue(self.save()['status'])
        self.assertEqual(chown.call_count, 1)
        self.assertEqual(chown.call_args.args[1:], (info.st_uid, info.st_gid))

    def test_overlapping_saves_share_lock_and_old_revision_becomes_stale(self):
        entered, release = threading.Event(), threading.Event()
        original_mkstemp = tempfile.mkstemp
        revision = self.revision()
        results = []
        def create(*args, **kwargs):
            if threading.current_thread().name == 'repeat-policy-save' and kwargs.get('suffix') == '.bak':
                entered.set()
                if not release.wait(5):
                    raise TimeoutError('test backup was not released')
            return original_mkstemp(*args, **kwargs)
        with patch('tempfile.mkstemp', side_effect=create):
            worker = threading.Thread(target=lambda: results.append(self.save()), name='repeat-policy-save')
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                self.assertFalse(self.save(siteName='other.example', revision=revision)['status'])
            finally:
                release.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(results[0]['status'])
        self.assertFalse(self.save(siteName='other.example', revision=revision)['status'])
        self.assertTrue(self.save(siteName='other.example')['status'])
        self.assertIn('repeat_ban_policy', self.config_read()['fixture.example'])
        self.assertIn('repeat_ban_policy', self.config_read()['other.example'])

    def test_lock_symlink_is_rejected_before_reading_configuration(self):
        target = self.root / 'private-lock'
        target.write_bytes(b'private')
        try:
            (self.root / '.endpoint-policy.lock').symlink_to(target)
        except OSError as error:
            self.skipTest('symlink unavailable: ' + str(error))
        self.assertFalse(self.save()['status'])
        self.assertEqual(target.read_bytes(), b'private')
        self.assertEqual(self.site_path.read_bytes(), self.original)

    @unittest.skipUnless(os.name == 'posix', 'production cross-process lock requires POSIX')
    def test_another_process_holding_config_lock_blocks_repeat_policy_save(self):
        code = ('import fcntl,sys; f=open(sys.argv[1],"a+"); '
                'fcntl.flock(f,fcntl.LOCK_EX); print("locked",flush=True); sys.stdin.read(1)')
        process = subprocess.Popen([sys.executable, '-I', '-c', code, str(self.root / '.endpoint-policy.lock')],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(process.stdout.readline().strip(), b'locked')
            self.assertFalse(self.save()['status'])
        finally:
            process.communicate(input=b'x', timeout=5)
        self.assertEqual(self.site_path.read_bytes(), self.original)
        self.assertTrue(self.save()['status'])

    def test_policy_config_symlink_is_rejected_without_changing_target(self):
        target = self.root / 'private.json'
        self.site_path.rename(target)
        try:
            self.site_path.symlink_to(target)
        except OSError as error:
            self.skipTest('symlink unavailable: ' + str(error))
        self.assertFalse(self.call('get_repeat_ban_policy', siteName='fixture.example')['status'])
        self.assertFalse(self.save()['status'])
        self.assertEqual(target.read_bytes(), self.original)

    def test_empty_list_is_read_only_and_honestly_describes_memory_limits(self):
        before = sorted(self.root.iterdir())
        result = self.call('get_repeat_bans', siteName='fixture.example')
        self.assertTrue(result['status'])
        self.assertEqual(result['rows'], [])
        self.assertEqual((result['total'], result['page'], result['per_page']), (0, 1, 20))
        self.assertIs(result['policy_enabled'], False)
        self.assertIs(type(result['now']), int)
        notes = ''.join(result['notes'])
        for word in ('\u5171\u4eab\u5185\u5b58', '\u5e73\u6ed1\u91cd\u8f7d', '\u91cd\u542f', '\u6301\u4e45'):
            self.assertIn(word, notes)
        self.assertEqual(sorted(self.root.iterdir()), before)
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_list_site_filter_expiry_pagination_and_disabled_rows_remain_visible(self):
        rows = [record(ip='192.0.2.' + str(i)) for i in range(1, 6)]
        self.snapshot(rows + [record(site='other.example'), record(ip='192.0.2.9', started_at=1, expires_at=604801)])
        before = self.snapshot_path.read_bytes()
        with patch('time.time', return_value=604801):
            result = self.call('get_repeat_bans', siteName='fixture.example', page='2', per_page='2')
        self.assertTrue(result['status'])
        self.assertEqual(result['total'], 5)
        self.assertEqual(len(result['rows']), 2)
        self.assertEqual(result['now'], 604801)
        self.assertIs(result['policy_enabled'], False)
        self.assertTrue(all(row['site'] == 'fixture.example' for row in result['rows']))
        self.assertEqual(self.snapshot_path.read_bytes(), before)
        self.assertEqual(self.site_path.read_bytes(), self.original)

    def test_invalid_pagination_fails_before_opening_snapshot(self):
        for args in (dict(page=0), dict(page=True), dict(page='1.0'), dict(page=-1),
                     dict(per_page=0), dict(per_page=201), dict(per_page=False), dict(per_page='-1')):
            with self.subTest(args=args):
                self.assertFalse(self.call('get_repeat_bans', siteName='fixture.example', **args)['status'])

    def test_corrupt_snapshot_is_failure_not_empty_success(self):
        self.snapshot_path.write_bytes(b'{')
        self.assertFalse(self.call('get_repeat_bans', siteName='fixture.example')['status'])

    def test_remove_uses_fixed_loopback_route_and_verifies_all_persisted_rows(self):
        self.snapshot([record(ip='2001:db8::1'), record(site='other.example')])
        def unban(url):
            self.assertEqual(url, 'http://127.0.0.1/remove_repeat_ban?site=fixture.example&ip=2001%3Adb8%3A%3A1&reset_counts=0')
            self.snapshot([record(site='other.example')])
            return '{"status":true}'
        self.public.httpGet.side_effect = unban
        result = self.call('remove_repeat_ban', siteName='fixture.example', ip='2001:0DB8:0:0:0:0:0:1',
                           url='http://evil.example', endpoint='/clear')
        self.assertTrue(result['status'], result)
        self.assertIn('\u4fdd\u7559\u7d2f\u8ba1', result['msg'])
        self.public.httpGet.assert_called_once()
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()
        self.assertEqual(self.site_path.read_bytes(), self.original)

    def test_remove_never_touches_manual_or_base_ban_apis(self):
        self.backend.remove_ip_black_exact = Mock(side_effect=AssertionError('manual ban removed'))
        self.backend._free_waf_main__ban_store = Mock(side_effect=AssertionError('legacy bans accessed'))
        self.public.httpGet.side_effect = lambda url: '{"status":true}'
        self.assertTrue(self.call('remove_repeat_ban', siteName='fixture.example', ip='192.0.2.1')['status'])

    def test_remove_reset_counts_strict_bool_or_form_string_and_default_retains_counts(self):
        self.public.httpGet.side_effect = None
        self.public.httpGet.return_value = '{"status":true}'
        for reset, expected in ((False, '0'), (True, '1'), ('0', '0'), ('1', '1')):
            with self.subTest(reset=reset):
                result = self.call('remove_repeat_ban', siteName='fixture.example', ip='192.0.2.1', reset_counts=reset)
                self.assertTrue(result['status'])
                self.assertTrue(self.public.httpGet.call_args.args[0].endswith('&reset_counts=' + expected))
                self.assertIn('\u6e05\u96f6' if expected == '1' else '\u4fdd\u7559\u7d2f\u8ba1', result['msg'])

    def test_invalid_reset_counts_are_rejected_before_runtime_or_file_io(self):
        for reset in ('', 'true', 'false', 'yes', '00', ' 1', '1&ip=other', 0, 1, None, [], {}):
            with self.subTest(reset=reset), patch('os.open', side_effect=AssertionError('invalid reset read config')) as opened:
                self.assertFalse(self.call('remove_repeat_ban', siteName='fixture.example',
                                           ip='192.0.2.1', reset_counts=reset)['status'])
                opened.assert_not_called()
        self.public.httpGet.assert_not_called()

    def test_list_notes_explain_default_tier_lifecycle_without_promising_tenth_event(self):
        result = self.call('get_repeat_bans', siteName='fixture.example')
        self.assertTrue(result['status'])
        notes = ''.join(result['notes'])
        for text in ('5', '7', '10', '24', '\u63d0\u524d', '\u4fdd\u7559\u7d2f\u8ba1', '\u81ea\u7136', '\u6e05\u96f6'):
            self.assertIn(text, notes)

    def test_remove_invalid_input_does_not_call_runtime(self):
        for site, ip in (('missing.example', '192.0.2.1'), ('fixture.example', '127.1'),
                         ('fixture.example', '192.0.2.1&site=other.example'),
                         ('fixture.example', 'fe80::1%eth0'), ('fixture.example', None)):
            with self.subTest(site=site, ip=ip):
                self.assertFalse(self.call('remove_repeat_ban', siteName=site, ip=ip)['status'])
        self.public.httpGet.assert_not_called()

    def test_remove_runtime_failures_or_remaining_expired_row_never_report_success(self):
        self.snapshot([record(started_at=1, expires_at=604801)])
        for response in ('{}', '[]', '{', '{"status":1}', '{"status":false}', '{"status":true}'):
            with self.subTest(response=response):
                self.public.httpGet.side_effect = None
                self.public.httpGet.return_value = response
                self.assertFalse(self.call('remove_repeat_ban', siteName='fixture.example', ip='192.0.2.1')['status'])
        self.public.httpGet.side_effect = OSError('connection refused')
        self.assertFalse(self.call('remove_repeat_ban', siteName='fixture.example', ip='192.0.2.1')['status'])

    def test_remove_cannot_confirm_success_if_snapshot_is_corrupt(self):
        self.public.httpGet.side_effect = None
        self.public.httpGet.return_value = '{"status":true}'
        self.snapshot_path.write_bytes(b'{')
        result = self.call('remove_repeat_ban', siteName='fixture.example', ip='192.0.2.1')
        self.assertFalse(result['status'])
        self.assertIn('\u672a\u786e\u8ba4', result['msg'])

    def test_source_loader_ignores_stale_imported_module_and_same_stamp_bytecode(self):
        plugin = self.root / 'plugin'
        plugin.mkdir()
        module_path = plugin / 'ban_store.py'
        shutil.copyfile(ROOT / 'ban_store.py', module_path)
        self.backend._free_waf_main__PATH = str(plugin) + os.sep
        with patch.dict(sys.modules, {'ban_store': types.SimpleNamespace()}):
            self.assertTrue(self.call('get_repeat_bans', siteName='fixture.example')['status'])
            stamp = module_path.stat()
            source = module_path.read_bytes()
            module_path.write_bytes(b'raise RuntimeError("updated source")\n' + source[36:])
            os.utime(module_path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            self.assertFalse(self.call('get_repeat_bans', siteName='fixture.example')['status'])


class SiteConfigTransactionTest(unittest.TestCase):
    WRITERS = {'set_site_obj_open', 'set_site_cc_conf', 'set_site_retry', 'set_site_cdn_state',
               'add_site_cdn_header', 'remove_site_cdn_header', 'add_site_cdn_trusted_proxy',
               'remove_site_cdn_trusted_proxy', 'add_site_rule', 'remove_site_rule',
               'set_site_disable_rule', '__check_site'}

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / 'site.json'
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            readFile=Mock(side_effect=lambda path: Path(path).read_text(encoding='utf-8')),
            writeFile=Mock(side_effect=self.persist), serviceReload=Mock(), WriteLog=Mock(), M=Mock())
        self.backend = load_backend(self.public)
        self.backend._free_waf_main__path = str(self.root) + os.sep
        self.backend._free_waf_main__PATH = str(ROOT) + os.sep
        self.backend._free_waf_main__write_site_domains = Mock()
        self.backend._free_waf_main__checked_nginx_reload = Mock()
        self.backend._free_waf_main__update_request_is_post = Mock(return_value=True)
        self.backend.get_config = Mock(return_value=dict(
            logs_path=str(self.root), log_save=100, retry=10, retry_cycle=60, retry_time=60,
            cc=dict(open=True, cycle=60, limit=10, endtime=60),
            get=dict(open=True), post=dict(open=True), cookie=dict(open=True),
            **{'user-agent': dict(open=True), 'scan': dict(open=True)}))
        template = self.backend._free_waf_main__get_site_conf()
        template['cdn_header'] = ['x-remove']
        template['cdn_trusted_proxy'] = [[[192, 0, 2, 1], [192, 0, 2, 9]]]
        template['url_white'] = ['/remove']
        template['log_size'] = 0
        self.config = {'fixture.example': template, 'other.example': copy.deepcopy(template)}
        self.write(self.config)
        self.public.M.return_value.field.return_value.select.return_value = [dict(name=site) for site in self.config]
        original_exists = os.path.exists
        exists = patch('os.path.exists', side_effect=lambda path: True if path == '/www/wwwlogs/free_waf_log' else original_exists(path))
        exists.start()
        self.addCleanup(exists.stop)

    def persist(self, path, content):
        Path(path).write_text(content, encoding='utf-8')
        return True

    def write(self, config):
        self.path.write_bytes(json.dumps(config).encode('utf-8'))

    def read(self):
        return json.loads(self.path.read_bytes())

    def save_repeat(self, site='fixture.example'):
        return self.backend.save_repeat_ban_policy(types.SimpleNamespace(
            siteName=site, policy=json.dumps(DEFAULTS), revision=hashlib.sha256(self.path.read_bytes()).hexdigest()))

    def save_endpoint(self, site='other.example'):
        return self.backend.save_endpoint_policy(types.SimpleNamespace(siteName=site, policy=json.dumps(dict(
            name='Login', match='exact', path='/login', method='POST', window_seconds=60,
            max_requests=10, ban_seconds=60))))

    def args(self, **changes):
        data = dict(siteName='fixture.example', obj='open', cycle='60', limit='20', endtime='60',
                    increase='0', retry='11', retry_cycle='60', retry_time='60', cdn_header='x-remove',
                    start_ip='192.0.2.1', end_ip='192.0.2.9', ruleName='url_white',
                    ruleValue='/new', index='0')
        data.update(changes)
        return types.SimpleNamespace(**data)

    def invoke(self, name):
        if name == '__check_site':
            return self.backend._free_waf_main__check_site(copy.deepcopy(self.config))
        args = self.args()
        if name == 'add_site_cdn_header':
            args.cdn_header = 'x-added'
        if name == 'add_site_cdn_trusted_proxy':
            args.start_ip, args.end_ip = '198.51.100.1', '198.51.100.9'
        if name == 'set_site_disable_rule':
            args.ruleName = 'header'
        return getattr(self.backend, name)(args)

    def test_ast_all_twelve_legacy_writer_callers_hold_a_transaction(self):
        tree = ast.parse((ROOT / 'free_waf_main.py').read_text(encoding='utf-8'))
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'free_waf_main')
        callers = {method.name: method for method in cls.body if isinstance(method, ast.FunctionDef)
                   and any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                           and node.func.attr == '__write_site_config' for node in ast.walk(method))}
        self.assertEqual(set(callers), self.WRITERS)
        for name, method in callers.items():
            with self.subTest(name=name):
                self.assertTrue(any(isinstance(node, ast.Name) and node.id == '__site_config_locked'
                                    for node in method.decorator_list), name + ' missing transaction')

    def test_all_eleven_legacy_public_mutations_still_succeed_without_changing_other_sites(self):
        for name in sorted(self.WRITERS - {'__check_site'}):
            with self.subTest(name=name):
                self.write(self.config)
                result = self.invoke(name)
                self.assertTrue(result['status'], result)
                self.assertEqual(self.read()['other.example'], self.config['other.example'])

    def test_every_legacy_writer_is_rejected_before_read_or_side_effect_when_another_thread_owns_lock(self):
        locked = threading.Event()
        release = threading.Event()
        errors = []
        def owner():
            try:
                with self.backend._free_waf_main__endpoint_transaction():
                    locked.set()
                    if not release.wait(5):
                        raise TimeoutError('test lock not released')
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=owner)
        worker.start()
        try:
            self.assertTrue(locked.wait(5))
            before = self.path.read_bytes()
            for name in sorted(self.WRITERS - {'__check_site'}):
                with self.subTest(name=name):
                    self.assertFalse(self.invoke(name)['status'])
            for name in ('__check_site', '__write_site_config'):
                with self.subTest(name=name), self.assertRaises((OSError, ValueError)):
                    getattr(self.backend, '_free_waf_main' + name)(copy.deepcopy(self.config))
            self.assertFalse(self.backend.get_site_config(None)['status'])
            for name in ('get_site_config_byname', 'get_site_cdn_header', 'get_site_cdn_trusted_proxy',
                         'get_site_rule', 'get_site_disable_rule'):
                with self.subTest(name=name):
                    self.assertFalse(getattr(self.backend, name)(self.args())['status'])
            self.public.readFile.assert_not_called()
            self.public.writeFile.assert_not_called()
            self.public.M.assert_not_called()
            self.public.WriteLog.assert_not_called()
            self.public.serviceReload.assert_not_called()
            self.assertEqual(self.path.read_bytes(), before)
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])

    def test_legacy_get_migrate_write_nested_locks_use_one_descriptor(self):
        config = copy.deepcopy(self.config)
        del config['fixture.example']['registration_guard']
        self.write(config)
        real_open = os.open
        descriptors = []
        def opened(path, *args, **kwargs):
            result = real_open(path, *args, **kwargs)
            if str(path).endswith('.endpoint-policy.lock'):
                descriptors.append(result)
            return result
        with patch('os.open', side_effect=opened):
            result = self.backend.set_site_obj_open(self.args())
        self.assertTrue(result['status'], result)
        self.assertEqual(len(descriptors), 1)
        self.assertIn('registration_guard', self.read()['fixture.example'])
        self.assertIs(self.read()['fixture.example']['open'], False)

    def test_nested_transaction_is_path_keyed_and_reentrant_across_instances(self):
        second = type(self.backend)()
        second._free_waf_main__path = str(self.root / '.') + os.sep
        held = self.backend._free_waf_main__endpoint_transaction
        with held():
            try:
                with second._free_waf_main__endpoint_transaction():
                    with held():
                        pass
            except OSError as error:
                self.fail('same-thread same-path nesting failed: ' + str(error))
            independent = self.root / 'independent'
            independent.mkdir()
            second._free_waf_main__path = str(independent) + os.sep
            with second._free_waf_main__endpoint_transaction():
                pass
        self.assertTrue(self.save_repeat()['status'])

    def test_nested_exception_cleans_thread_state_and_releases_descriptor(self):
        held = self.backend._free_waf_main__endpoint_transaction
        with self.assertRaisesRegex(RuntimeError, 'body failed'):
            with held():
                with held():
                    raise RuntimeError('body failed')
        result = []
        worker = threading.Thread(target=lambda: result.append(self.save_repeat()))
        worker.start()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(result[0]['status'], result)

    def test_inherited_thread_state_never_grants_lock_ownership_to_another_process(self):
        held = self.backend._free_waf_main__endpoint_transaction
        with held():
            with patch('os.getpid', return_value=os.getpid() + 1):
                with self.assertRaises(OSError):
                    with held():
                        pass
        self.assertTrue(self.save_repeat()['status'])

    def overlap_legacy_read(self, first, concurrent):
        entered, release = threading.Event(), threading.Event()
        original_read = self.public.readFile.side_effect
        first_result = []
        errors = []
        def read(path):
            raw = original_read(path)
            if threading.current_thread().name == 'legacy-reader' and str(path).endswith('site.json'):
                entered.set()
                if not release.wait(5):
                    raise TimeoutError('test legacy read not released')
            return raw
        def work():
            try:
                first_result.append(first())
            except BaseException as error:
                errors.append(error)
        self.public.readFile.side_effect = read
        worker = threading.Thread(target=work, name='legacy-reader')
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            second_result = concurrent()
        finally:
            release.set()
            worker.join(5)
            self.public.readFile.side_effect = original_read
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        return first_result[0], second_result

    def test_old_read_cannot_overlap_repeat_save_and_lose_either_sites_setting(self):
        first, conflicting = self.overlap_legacy_read(
            lambda: self.backend.set_site_obj_open(self.args(siteName='other.example')), self.save_repeat)
        self.assertTrue(first['status'])
        self.assertFalse(conflicting['status'])
        self.assertTrue(self.save_repeat()['status'])
        config = self.read()
        self.assertIs(config['other.example']['open'], False)
        self.assertEqual(config['fixture.example']['repeat_ban_policy'], DEFAULTS)

    def test_old_read_cannot_overlap_endpoint_policy_save(self):
        first, conflicting = self.overlap_legacy_read(
            lambda: self.backend.set_site_cdn_state(self.args()), self.save_endpoint)
        self.assertTrue(first['status'])
        self.assertFalse(conflicting['status'])
        self.assertTrue(self.save_endpoint()['status'])
        self.assertIs(self.read()['fixture.example']['cdn'], True)
        self.assertEqual(len(self.read()['other.example']['endpoint_limits']), 1)

    def test_two_legacy_site_mutations_cannot_read_same_unlocked_snapshot(self):
        first, conflicting = self.overlap_legacy_read(
            lambda: self.backend.set_site_obj_open(self.args()),
            lambda: self.backend.set_site_cdn_state(self.args(siteName='other.example')))
        self.assertTrue(first['status'])
        self.assertFalse(conflicting['status'])
        self.assertTrue(self.backend.set_site_cdn_state(self.args(siteName='other.example'))['status'])
        self.assertIs(self.read()['fixture.example']['open'], False)
        self.assertIs(self.read()['other.example']['cdn'], True)

    def test_get_site_config_migration_cannot_read_then_overwrite_a_repeat_policy(self):
        config = copy.deepcopy(self.config)
        del config['fixture.example']['registration_guard']
        self.write(config)
        migrated, conflicting = self.overlap_legacy_read(lambda: self.backend.get_site_config(None), self.save_repeat)
        self.assertIn('registration_guard', migrated['fixture.example'])
        self.assertFalse(conflicting['status'])
        self.assertTrue(self.save_repeat()['status'])
        self.assertIn('registration_guard', self.read()['fixture.example'])
        self.assertEqual(self.read()['fixture.example']['repeat_ban_policy'], DEFAULTS)

    def test_repeat_save_holds_lock_until_replace_so_legacy_cannot_write_in_the_gap(self):
        entered, release = threading.Event(), threading.Event()
        actual_replace = os.replace
        results = []
        def replacing(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('test replace not released')
            return actual_replace(*args, **kwargs)
        with patch('os.replace', side_effect=replacing):
            worker = threading.Thread(target=lambda: results.append(self.save_repeat()))
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                conflict = self.backend.set_site_obj_open(self.args(siteName='other.example'))
            finally:
                release.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(results[0]['status'])
        self.assertFalse(conflict['status'])
        self.assertTrue(self.backend.set_site_obj_open(self.args(siteName='other.example'))['status'])
        self.assertEqual(self.read()['fixture.example']['repeat_ban_policy'], DEFAULTS)
        self.assertIs(self.read()['other.example']['open'], False)

    def test_legacy_writer_uses_safe_atomic_verified_update_not_unchecked_public_writer(self):
        before = self.path.read_bytes()
        with patch('os.replace', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.backend.set_site_obj_open(self.args())
        self.assertEqual(self.path.read_bytes(), before)
        self.public.writeFile.assert_not_called()
        self.public.serviceReload.assert_not_called()

    def test_legacy_writer_verifies_persistence_before_domains_or_reload(self):
        with patch.object(self.backend, '_free_waf_main__write_repeat_site_config', return_value=None):
            with self.assertRaises(OSError):
                self.backend.set_site_obj_open(self.args())
        self.backend._free_waf_main__write_site_domains.assert_not_called()
        self.public.serviceReload.assert_not_called()

    def test_external_panel_process_blocks_legacy_before_its_initial_read(self):
        code = ('import os,sys\nf=open(sys.argv[1],"a+b")\n'
                'if os.name == "posix":\n'
                ' import fcntl\n fcntl.flock(f,fcntl.LOCK_EX)\n'
                'else:\n import msvcrt\n msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)\n'
                'print("locked",flush=True)\nsys.stdin.read(1)')
        process = subprocess.Popen([sys.executable, '-I', '-c', code, str(self.root / '.endpoint-policy.lock')],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(process.stdout.readline().strip(), b'locked')
            self.assertFalse(self.backend.set_site_obj_open(self.args())['status'])
            self.public.readFile.assert_not_called()
        finally:
            process.communicate(input=b'x', timeout=5)
        self.assertTrue(self.backend.set_site_obj_open(self.args())['status'])


class BanEscalationStoreTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / 'repeat_bans.json'
        spec = importlib.util.spec_from_file_location('_repeat_store_tests', ROOT / 'ban_store.py')
        self.module = importlib.util.module_from_spec(spec)
        exec(compile((ROOT / 'ban_store.py').read_bytes(), str(ROOT / 'ban_store.py'), 'exec'), self.module.__dict__)

    def store(self):
        cls = getattr(self.module, 'BanEscalationStore', None)
        self.assertTrue(callable(cls), 'BanEscalationStore missing')
        return cls(self.path, now_fn=lambda: 604801)

    def snapshot(self, rows=None, **changes):
        data = dict(version=1, revision='a' * 32, bans=[record()] if rows is None else rows)
        data.update(changes)
        self.path.write_bytes(json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))

    def test_missing_snapshot_is_empty_and_does_not_create_a_file(self):
        self.assertEqual(self.store().active_bans('fixture.example'), [])
        self.assertFalse(self.path.exists())

    def test_expired_and_other_site_rows_are_filtered_without_pruning(self):
        self.snapshot([record(), record(site='other.example'), record(ip='192.0.2.9', started_at=1, expires_at=604801)])
        before = self.path.read_bytes()
        self.assertEqual(self.store().active_bans('fixture.example'), [record()])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(len(self.store().read_snapshot()['bans']), 3)

    def test_all_reasons_canonical_ipv6_and_trigger_count_above_threshold_are_valid(self):
        for reason in ('cc', 'registration_abuse_verify', 'registration_abuse_register', 'endpoint_limit', '404_flood'):
            row = record(reason=reason, ip='2001:db8::1', trigger_count=1000, path='/a+b/(draft)/[x]/100%')
            self.snapshot([row])
            self.assertEqual(self.store().active_bans('fixture.example'), [row])

    def test_invalid_record_anywhere_invalidates_entire_snapshot(self):
        bad = [[], None, dict(record(), extra='private'),
               {key: value for key, value in record().items() if key != 'reason'}]
        for changes in (dict(site='../site'), dict(ip='192.000.2.1'), dict(ip='2001:DB8::1'),
                        dict(ip='2001:0db8::1'), dict(ip='fe80::1%eth0'), dict(ip=1),
                        dict(started_at=True), dict(started_at=0), dict(started_at=-1), dict(expires_at=9007199254740992),
                        dict(expires_at=1000), dict(expires_at=605801), dict(duration=0),
                        dict(duration=1, expires_at=1001), dict(duration=31536001),
                        dict(trigger_count=4), dict(trigger_count=1001),
                        dict(trigger_count=True), dict(threshold=1), dict(threshold=1001),
                        dict(window_seconds=59), dict(window_seconds=604801), dict(reason='manual'),
                        dict(path='/a?token=secret'), dict(path='/a#fragment'), dict(path='/a\\b'),
                        dict(path='/a\u0085b'), dict(path='relative'), dict(path='/' + 'x' * 512),
                        dict(path='/' + '\u4e2d' * 171)):
            bad.append(dict(record(), **changes))
        for row in bad:
            with self.subTest(row=row):
                self.snapshot([record(site='other.example'), row])
                with self.assertRaises((ValueError, OSError)):
                    self.store().active_bans('other.example')

    def test_invalid_container_duplicate_keys_and_duplicate_site_ip_are_rejected(self):
        for changes in (dict(version=True), dict(version=2), dict(revision='A' * 32),
                        dict(revision='a' * 31), dict(revision=None), dict(bans={}), dict(extra=True)):
            self.snapshot(**changes)
            with self.assertRaises(ValueError):
                self.store().read_snapshot()
        for body in (b'{', b'[]', b'null', b'\xff',
                     b'{"version":1,"version":1,"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bans":[]}',
                     b'[' * 3000 + b'0' + b']' * 3000):
            self.path.write_bytes(body)
            with self.assertRaises(ValueError):
                self.store().read_snapshot()
        self.snapshot([record(), record()])
        with self.assertRaises(ValueError):
            self.store().read_snapshot()

    def test_snapshot_limits_are_inclusive_and_read_is_bounded(self):
        rows = [record(ip='2001:db8::' + format(i, 'x')) for i in range(1, 4097)]
        self.snapshot(rows)
        self.assertLessEqual(self.path.stat().st_size, 1024 * 1024)
        self.assertEqual(len(self.store().read_snapshot()['bans']), 4096)
        self.snapshot(rows + [record(ip='2001:db8::1001')])
        with self.assertRaises(ValueError):
            self.store().read_snapshot()
        self.snapshot([])
        raw = self.path.read_bytes()
        self.path.write_bytes(raw + b' ' * (1024 * 1024 - len(raw)))
        self.assertEqual(self.store().read_snapshot()['bans'], [])
        self.path.write_bytes(self.path.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            self.store().read_snapshot()

    def test_snapshot_symlink_is_not_followed(self):
        target = self.root / 'private'
        target.write_bytes(b'private')
        try:
            self.path.symlink_to(target)
        except OSError as error:
            self.skipTest('symlink unavailable: ' + str(error))
        with self.assertRaises((ValueError, OSError)):
            self.store().read_snapshot()
        self.assertEqual(target.read_bytes(), b'private')

    def test_snapshot_permission_failure_is_not_empty_success(self):
        self.snapshot([])
        with patch('os.open', side_effect=PermissionError('permission denied')):
            with self.assertRaises(PermissionError):
                self.store().read_snapshot()

    def test_snapshot_io_read_is_bounded_and_never_uses_text_normalization(self):
        self.snapshot([])
        original_fdopen = os.fdopen
        sizes = []
        class Meter:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                self.stream.__enter__()
                return self
            def __exit__(self, *args):
                return self.stream.__exit__(*args)
            def read(self, size=-1):
                sizes.append(size)
                return self.stream.read(size)
        with patch('os.fdopen', side_effect=lambda *a, **k: Meter(original_fdopen(*a, **k))):
            self.assertEqual(self.store().read_snapshot()['bans'], [])
        self.assertEqual(sizes, [1024 * 1024 + 1])

    def test_symlink_parent_and_nonregular_snapshot_are_rejected(self):
        self.path.mkdir()
        with self.assertRaises(ValueError):
            self.store().read_snapshot()
        alias = self.root / 'alias'
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except OSError as error:
            self.skipTest('symlink unavailable: ' + str(error))
        cls = type(self.store())
        with self.assertRaises((ValueError, OSError)):
            cls(alias / 'missing.json').read_snapshot()


if __name__ == '__main__':
    unittest.main()
