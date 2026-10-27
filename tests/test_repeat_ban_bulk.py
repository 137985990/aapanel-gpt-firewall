import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch

from tests.test_panel_performance import load_backend
from tests.test_repeat_ban_policy import DEFAULTS


ROOT = Path(__file__).resolve().parents[1]
LADDER = dict(window_seconds=3600, tiers=[dict(threshold=3, ban_seconds=600),
                                        dict(threshold=7, ban_seconds=7200)])
TARGETS = ['other.example', 'fixture.example', 'disabled.example']


class RepeatBanBulkTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / 'site.json'
        self.config = {
            'fixture.example': dict(open=True, cc=dict(limit=10),
                                    repeat_ban_policy=dict(copy.deepcopy(DEFAULTS), enabled=True)),
            'other.example': dict(open=False),
            'disabled.example': dict(open=True, repeat_ban_policy=copy.deepcopy(DEFAULTS)),
            'untouched.example': dict(open=True, repeat_ban_policy=copy.deepcopy(DEFAULTS))}
        self.original = (json.dumps(self.config, indent=2) + '\r\n').encode('utf-8')
        self.path.write_bytes(self.original)
        self.protected = {}
        for name in ('repeat_bans.json', 'counters.json', 'config.json'):
            body = ('do not touch ' + name).encode('utf-8')
            (self.root / name).write_bytes(body)
            self.protected[name] = body
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            readFile=Mock(side_effect=AssertionError('legacy read/migration')),
            writeFile=Mock(side_effect=AssertionError('unsafe writer')),
            httpGet=Mock(side_effect=AssertionError('unexpected network')),
            serviceReload=Mock(side_effect=AssertionError('unchecked reload')))
        self.backend = load_backend(self.public)
        self.backend._free_waf_main__path = str(self.root) + os.sep
        self.backend._free_waf_main__PATH = str(ROOT) + os.sep
        self.backend._free_waf_main__update_request_is_post = Mock(return_value=True)
        self.backend._free_waf_main__checked_nginx_reload = Mock()
        self.backend.get_site_config = Mock(side_effect=AssertionError('legacy migration/pruning'))
        self.backend.save_repeat_ban_policy = Mock(side_effect=AssertionError('per-site saver loop'))
        for method in ('get_repeat_ban_policies', 'save_repeat_ban_policies'):
            self.assertTrue(callable(getattr(self.backend, method, None)), method + ' API missing')

    def call(self, method, **args):
        function = getattr(self.backend, method, None)
        self.assertTrue(callable(function), method + ' API missing')
        return function(types.SimpleNamespace(**args))

    def read(self):
        return json.loads(self.path.read_bytes())

    def write(self, config):
        self.path.write_bytes(json.dumps(config).encode('utf-8'))

    def revision(self):
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def get(self, **args):
        params = dict(siteNames=json.dumps(TARGETS))
        params.update(args)
        return self.call('get_repeat_ban_policies', **params)

    def save(self, **args):
        params = dict(siteNames=json.dumps(TARGETS), revision=self.revision(),
                      policy=json.dumps(LADDER), enabled_action='preserve')
        params.update(args)
        return self.call('save_repeat_ban_policies', **params)

    def assert_protected(self):
        for name, body in self.protected.items():
            self.assertEqual((self.root / name).read_bytes(), body)
        self.public.readFile.assert_not_called()
        self.public.writeFile.assert_not_called()
        self.public.httpGet.assert_not_called()
        self.public.serviceReload.assert_not_called()
        self.backend.save_repeat_ban_policy.assert_not_called()

    def assert_not_saved(self, original=None):
        self.assertEqual(self.path.read_bytes(), self.original if original is None else original)
        self.assertEqual(list(self.root.glob('*.bak')), [])
        self.assertEqual(list(self.root.glob('*.tmp')), [])
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()
        self.assert_protected()

    def assert_response(self, result):
        self.assertIs(result['status'], True, result)
        self.assertEqual(result['sites'], [dict(siteName=site, policy=self.read()[site]['repeat_ban_policy'])
                                           for site in TARGETS])
        self.assertEqual(result['revision'], self.revision())

    def test_read_returns_ordered_snapshots_and_original_byte_revision_without_side_effects(self):
        before = set(self.root.iterdir())
        with patch('os.replace', side_effect=AssertionError('read wrote config')), \
                patch('tempfile.mkstemp', side_effect=AssertionError('read staged config')):
            result = self.get()
        self.assertEqual(result, dict(status=True, sites=[
            dict(siteName=site, policy=self.config[site].get('repeat_ban_policy', DEFAULTS))
            for site in TARGETS], revision=hashlib.sha256(self.original).hexdigest()))
        self.assertEqual(set(self.root.iterdir()), before)
        self.assert_not_saved()

    def test_targets_require_strict_json_string_unique_valid_existing_names(self):
        invalid = [None, TARGETS, {}, 1, True, '', '{', '{}', 'null', 'true', '"fixture.example"',
                   '[]', '["fixture.example", "fixture.example"]', '["missing.example"]',
                   '["fixture.example", "missing.example"]', '[null]', '[true]', '[1]', '[[]]', '[{}]']
        for name in ('', '../site.json', 'a..b', 'fixture.example/path', 'a\nb', ' a', 'a ',
                     'a' * 254, '\u4e2d.example'):
            invalid.append(json.dumps(['fixture.example', name]))
        for raw in invalid:
            with self.subTest(raw=raw):
                self.assertIs(self.get(siteNames=raw)['status'], False)
                self.assertIs(self.save(siteNames=raw)['status'], False)
                self.assert_not_saved()

    def test_targets_are_required_for_both_apis(self):
        self.assertIs(self.call('get_repeat_ban_policies')['status'], False)
        self.assertIs(self.call('save_repeat_ban_policies')['status'], False)
        self.assert_not_saved()

    def test_target_count_accepts_one_and_500_but_rejects_501(self):
        config = {'site-' + str(i): {} for i in range(501)}
        self.write(config)
        original = self.path.read_bytes()
        names = list(config)
        for size in (1, 500):
            raw = json.dumps(names[:size])
            self.assertEqual(len(self.get(siteNames=raw)['sites']), size)
            result = self.save(siteNames=raw)
            self.assertIs(result['status'], True, result)
            self.assertEqual(len(result['sites']), size)
        self.backend._free_waf_main__checked_nginx_reload.reset_mock()
        for backup in self.root.glob('*.bak'):
            backup.unlink()
        current = self.path.read_bytes()
        self.assertIs(self.get(siteNames=json.dumps(names))['status'], False)
        self.assertIs(self.save(siteNames=json.dumps(names))['status'], False)
        self.assert_not_saved(current)
        self.assertNotEqual(current, original)

    def test_target_json_byte_limit_is_inclusive_and_checked_before_config_read(self):
        text = json.dumps(TARGETS)
        exact = text + ' ' * (128 * 1024 - len(text))
        self.assertIs(self.get(siteNames=exact)['status'], True)
        self.assertIs(self.save(siteNames=exact)['status'], True)
        with patch.object(self.backend, '_free_waf_main__repeat_config_bytes',
                          side_effect=AssertionError('oversized request read config')) as read:
            for raw in (exact + ' ', '["' + '\u00e9' * 65536 + '"]'):
                self.assertIs(self.get(siteNames=raw)['status'], False)
                self.assertIs(self.save(siteNames=raw)['status'], False)
            read.assert_not_called()

    def test_invalid_last_current_policy_blocks_entire_batch_before_backup(self):
        bad = [None, {}, dict(DEFAULTS, enabled=1), dict(DEFAULTS, window_seconds=True),
               dict(DEFAULTS, tiers=[dict(threshold=3, ban_seconds=60),
                                    dict(threshold=3, ban_seconds=600)])]
        for policy in bad:
            with self.subTest(policy=policy):
                config = copy.deepcopy(self.config)
                config[TARGETS[-1]]['repeat_ban_policy'] = policy
                self.write(config)
                original = self.path.read_bytes()
                self.assertIs(self.get()['status'], False)
                self.assertIs(self.save()['status'], False)
                self.assert_not_saved(original)

    def test_invalid_config_or_target_container_is_not_replaced(self):
        for raw in (b'{', b'null', b'[]', b'\xff', b'{"other.example":{},"other.example":{}}',
                    json.dumps(dict(self.config, **{TARGETS[-1]: []})).encode('utf-8')):
            with self.subTest(raw=raw):
                self.path.write_bytes(raw)
                self.assertIs(self.get()['status'], False)
                self.assertIs(self.save()['status'], False)
                self.assert_not_saved(raw)

    def test_policy_requires_exact_ladder_fields_and_strict_bounded_json(self):
        bad = [None, LADDER, '', '{', 'null', '[]', 'true', ' ' * 16385,
               json.dumps(dict(LADDER, enabled=False)), json.dumps(dict(LADDER, extra=1)),
               json.dumps(dict(window_seconds=60)), json.dumps(dict(tiers=[])),
               '{"window_seconds":60,"window_seconds":120,"tiers":[{"threshold":2,"ban_seconds":60}]}',
               '{"window_seconds":60,"tiers":[{"threshold":2,"threshold":3,"ban_seconds":60}]}']
        for change in (dict(window_seconds=True), dict(window_seconds=59), dict(window_seconds=604801),
                       dict(window_seconds=60.0), dict(window_seconds='60'), dict(tiers=[]),
                       dict(tiers={}), dict(tiers=[dict(threshold=2, ban_seconds=60)] * 9),
                       dict(tiers=[dict(threshold=True, ban_seconds=60)]),
                       dict(tiers=[dict(threshold=1, ban_seconds=60)]),
                       dict(tiers=[dict(threshold=1001, ban_seconds=60)]),
                       dict(tiers=[dict(threshold=2, ban_seconds=59)]),
                       dict(tiers=[dict(threshold=2, ban_seconds=31536001)]),
                       dict(tiers=[dict(threshold=2, ban_seconds=True)]),
                       dict(tiers=[dict(threshold=2, ban_seconds=60, extra=1)]),
                       dict(tiers=[dict(threshold=2, ban_seconds=120), dict(threshold=3, ban_seconds=60)])):
            bad.append(json.dumps(dict(LADDER, **change)))
        for raw in bad:
            with self.subTest(raw=raw):
                self.assertIs(self.save(policy=raw)['status'], False)
                self.assert_not_saved()

    def test_enabled_action_is_required_and_exact(self):
        for action in (None, '', True, 1, [], {}, 'Preserve', ' enable', 'enable ', 'enabled'):
            with self.subTest(action=action):
                self.assertIs(self.save(enabled_action=action)['status'], False)
                self.assert_not_saved()
        self.assertIs(self.call('save_repeat_ban_policies', siteNames=json.dumps(TARGETS),
                                policy=json.dumps(LADDER), revision=self.revision())['status'], False)
        self.assert_not_saved()

    def test_post_guard_precedes_arguments_locks_and_file_io(self):
        self.backend._free_waf_main__update_request_is_post.return_value = False
        with patch('os.open', side_effect=AssertionError('GET performed file IO')):
            self.assertIs(self.call('save_repeat_ban_policies')['status'], False)
        self.assert_not_saved()

    def test_stale_missing_and_malformed_revision_never_start_backup(self):
        stale = self.revision()
        config = self.read()
        config['untouched.example']['open'] = False
        self.write(config)
        original = self.path.read_bytes()
        for revision in (stale, None, '', 1, True, 'a' * 63, 'A' * 64, 'a' * 65):
            with self.subTest(revision=revision):
                self.assertIs(self.save(revision=revision)['status'], False)
                self.assert_not_saved(original)

    def test_success_uses_one_shared_lock_backup_atomic_write_and_checked_reload(self):
        lock = self.backend._free_waf_main__endpoint_transaction
        stage = self.backend._free_waf_main__repeat_stage
        writer = self.backend._free_waf_main__write_repeat_site_config
        with patch.object(self.backend, '_free_waf_main__endpoint_transaction', wraps=lock) as locked, \
                patch.object(self.backend, '_free_waf_main__repeat_stage', wraps=stage) as staged, \
                patch.object(self.backend, '_free_waf_main__write_repeat_site_config', wraps=writer) as written, \
                patch('os.replace', wraps=os.replace) as replaced:
            result = self.save()
        self.assert_response(result)
        locked.assert_called_once_with()
        written.assert_called_once()
        self.assertEqual(written.call_args[1], dict(expected=self.original))
        replaced.assert_called_once()
        self.assertEqual([call[0][1] for call in staged.call_args_list], ['.bak', '.tmp'])
        backups = list(self.root.glob('*.bak'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.original)
        self.assertFalse(backups[0].is_symlink())
        self.assertNotEqual(backups[0].stat().st_ino, self.path.stat().st_ino)
        self.backend._free_waf_main__checked_nginx_reload.assert_called_once_with()
        self.assertEqual(self.read()['untouched.example'], self.config['untouched.example'])
        for site in TARGETS:
            remaining = dict(self.read()[site])
            remaining.pop('repeat_ban_policy')
            before = dict(self.config[site])
            before.pop('repeat_ban_policy', None)
            self.assertEqual(remaining, before)
        self.assert_protected()

    def test_preserve_keeps_mixed_activation_and_missing_policy_defaults_disabled(self):
        result = self.save()
        self.assert_response(result)
        for site in TARGETS:
            expected = dict(LADDER, enabled=site == 'fixture.example')
            self.assertEqual(self.read()[site]['repeat_ban_policy'], expected)

    def test_enable_and_disable_apply_to_every_target(self):
        for action in ('enable', 'disable'):
            with self.subTest(action=action):
                result = self.save(enabled_action=action)
                self.assert_response(result)
                for site in TARGETS:
                    self.assertEqual(self.read()[site]['repeat_ban_policy'], dict(LADDER, enabled=action == 'enable'))
        self.assert_protected()

    def test_valid_ladder_numeric_and_tier_boundaries(self):
        ladders = [dict(window_seconds=60, tiers=[dict(threshold=2, ban_seconds=60)]),
                   dict(window_seconds=604800, tiers=[dict(threshold=1000, ban_seconds=31536000)]),
                   dict(window_seconds=120, tiers=[dict(threshold=i + 2, ban_seconds=(i + 1) * 60)
                                                  for i in range(8)])]
        for ladder in ladders:
            with self.subTest(ladder=ladder):
                self.assert_response(self.save(policy=json.dumps(ladder)))

    def test_backup_failure_or_unverified_backup_prevents_write_and_reload(self):
        with patch('tempfile.mkstemp', side_effect=OSError('disk full')):
            self.assertIs(self.save()['status'], False)
        self.assert_not_saved()
        stage = self.backend._free_waf_main__repeat_stage

        def corrupt(body, suffix):
            path = stage(body, suffix)
            if suffix == '.bak':
                Path(path).write_bytes(b'incomplete backup')
            return path

        with patch.object(self.backend, '_free_waf_main__repeat_stage', side_effect=corrupt), \
                patch.object(self.backend, '_free_waf_main__write_repeat_site_config') as written:
            self.assertIs(self.save()['status'], False)
            written.assert_not_called()
        self.assertEqual(self.path.read_bytes(), self.original)
        self.backend._free_waf_main__checked_nginx_reload.assert_not_called()

    def test_concurrent_edit_during_backup_or_write_staging_is_preserved(self):
        real_stage = self.backend._free_waf_main__repeat_stage
        for suffix in ('.bak', '.tmp'):
            self.path.write_bytes(self.original)
            self.backend._free_waf_main__checked_nginx_reload.reset_mock()
            changed = []

            def stage(body, ending):
                path = real_stage(body, ending)
                if ending == suffix and not changed:
                    config = self.read()
                    config['fixture.example']['cc']['limit'] = 99
                    self.write(config)
                    changed.append(self.path.read_bytes())
                return path

            with self.subTest(suffix=suffix), \
                    patch.object(self.backend, '_free_waf_main__repeat_stage', side_effect=stage):
                self.assertIs(self.save()['status'], False)
            self.assertEqual(self.path.read_bytes(), changed[0])
            self.assertEqual(self.read()['fixture.example']['repeat_ban_policy'], self.config['fixture.example']['repeat_ban_policy'])
            self.assertNotIn('repeat_ban_policy', self.read()['other.example'])
        self.assert_protected()

    def test_writer_exception_false_or_noop_never_reports_success(self):
        for behavior in (dict(side_effect=OSError('disk full')), dict(return_value=False), dict(return_value=None)):
            with self.subTest(behavior=behavior), \
                    patch.object(self.backend, '_free_waf_main__write_repeat_site_config', **behavior):
                self.assertIs(self.save()['status'], False)
                self.assertEqual(self.path.read_bytes(), self.original)
        self.assert_protected()

    def test_published_write_failure_restores_all_original_policies_and_bytes(self):
        writer = self.backend._free_waf_main__write_repeat_site_config
        calls = []

        def fail_after_publish(body, **kwargs):
            calls.append(body)
            writer(body, **kwargs)
            if len(calls) == 1:
                raise OSError('fsync failed after publish')

        with patch.object(self.backend, '_free_waf_main__write_repeat_site_config', side_effect=fail_after_publish):
            result = self.save()
        self.assertIs(result['status'], False)
        self.assertIn('\u5df2\u6062\u590d', result['msg'])
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(len(calls), 2)
        self.assertEqual(next(self.root.glob('*.bak')).read_bytes(), self.original)
        self.assert_protected()

    def test_reload_exception_or_false_restores_all_policies_once_and_exact_bytes(self):
        for failure in (RuntimeError('reload failed'), False):
            self.path.write_bytes(self.original)
            self.backend._free_waf_main__checked_nginx_reload.reset_mock()
            self.backend._free_waf_main__checked_nginx_reload.side_effect = [failure, None]
            writer = self.backend._free_waf_main__write_repeat_site_config
            with self.subTest(failure=failure), \
                    patch.object(self.backend, '_free_waf_main__write_repeat_site_config', wraps=writer) as written:
                result = self.save()
            self.assertIs(result['status'], False)
            self.assertIn('\u5df2\u6062\u590d', result['msg'])
            self.assertEqual(self.path.read_bytes(), self.original)
            self.assertEqual(written.call_count, 2)
            self.assertEqual(self.backend._free_waf_main__checked_nginx_reload.call_count, 2)
        self.assert_protected()

    def test_rollback_merges_unrelated_concurrent_changes_including_selected_site_fields(self):
        def reload():
            if self.backend._free_waf_main__checked_nginx_reload.call_count == 1:
                config = self.read()
                config['fixture.example']['cc']['limit'] = 99
                config['other.example']['new_setting'] = 'retained'
                config['untouched.example']['repeat_ban_policy']['window_seconds'] = 60
                config['new.example'] = dict(open=False)
                self.write(config)
                raise RuntimeError('reload failed')

        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        writer = self.backend._free_waf_main__write_repeat_site_config
        with patch.object(self.backend, '_free_waf_main__write_repeat_site_config', wraps=writer) as written:
            result = self.save()
        self.assertIs(result['status'], False)
        self.assertIn('\u5df2\u6062\u590d', result['msg'])
        self.assertEqual(written.call_count, 2)
        current = self.read()
        for site in TARGETS:
            self.assertEqual(current[site].get('repeat_ban_policy'), self.config[site].get('repeat_ban_policy'))
            self.assertEqual('repeat_ban_policy' in current[site], 'repeat_ban_policy' in self.config[site])
        self.assertEqual(current['fixture.example']['cc']['limit'], 99)
        self.assertEqual(current['other.example']['new_setting'], 'retained')
        self.assertEqual(current['untouched.example']['repeat_ban_policy']['window_seconds'], 60)
        self.assertEqual(current['new.example'], dict(open=False))
        self.assert_protected()

    def test_one_conflicting_target_refuses_entire_recovery_without_restoring_other_targets(self):
        changed = []

        def reload():
            config = self.read()
            config[TARGETS[-1]]['repeat_ban_policy']['window_seconds'] = 60
            self.write(config)
            changed.append(self.path.read_bytes())
            raise RuntimeError('reload failed')

        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        writer = self.backend._free_waf_main__write_repeat_site_config
        with patch.object(self.backend, '_free_waf_main__write_repeat_site_config', wraps=writer) as written:
            result = self.save()
        self.assertIs(result['status'], False)
        self.assertIn('\u672a\u786e\u8ba4', result['msg'])
        self.assertEqual(self.path.read_bytes(), changed[0])
        written.assert_called_once()
        self.backend._free_waf_main__checked_nginx_reload.assert_called_once()
        self.assertEqual(self.read()['fixture.example']['repeat_ban_policy']['window_seconds'], LADDER['window_seconds'])
        self.assertEqual(next(self.root.glob('*.bak')).read_bytes(), self.original)

    def test_missing_target_corrupt_config_and_invalid_target_policy_refuse_recovery(self):
        for change in ('missing', 'container', 'corrupt', 'boolean-number'):
            self.path.write_bytes(self.original)
            self.backend._free_waf_main__checked_nginx_reload.reset_mock()
            changed = []

            def reload():
                config = self.read()
                if change == 'missing':
                    del config[TARGETS[-1]]
                elif change == 'container':
                    config[TARGETS[-1]] = []
                elif change == 'boolean-number':
                    config[TARGETS[-1]]['repeat_ban_policy']['enabled'] = 0
                self.write(config)
                if change == 'corrupt':
                    self.path.write_bytes(b'{')
                changed.append(self.path.read_bytes())
                raise RuntimeError('reload failed')

            self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
            with self.subTest(change=change):
                result = self.save()
                self.assertIs(result['status'], False)
                self.assertIn('\u672a\u786e\u8ba4', result['msg'])
                self.assertEqual(self.path.read_bytes(), changed[0])
                self.backend._free_waf_main__checked_nginx_reload.assert_called_once()

    def test_already_restored_target_does_not_prevent_atomic_recovery_of_remaining_targets(self):
        def reload():
            if self.backend._free_waf_main__checked_nginx_reload.call_count == 1:
                config = self.read()
                config['fixture.example']['repeat_ban_policy'] = self.config['fixture.example']['repeat_ban_policy']
                config['fixture.example']['cc']['limit'] = 99
                self.write(config)
                raise RuntimeError('reload failed')

        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        result = self.save()
        self.assertIs(result['status'], False)
        self.assertIn('\u5df2\u6062\u590d', result['msg'])
        self.assertEqual(self.read()['fixture.example']['cc']['limit'], 99)
        self.assertNotIn('repeat_ban_policy', self.read()['other.example'])
        self.assertEqual(self.read()['disabled.example'], self.config['disabled.example'])

    def test_failed_recovery_write_or_reload_reports_uncertainty(self):
        writer = self.backend._free_waf_main__write_repeat_site_config
        calls = []

        def failed_restore(body, **kwargs):
            calls.append(body)
            if len(calls) > 1:
                raise OSError('restore failed')
            return writer(body, **kwargs)

        self.backend._free_waf_main__checked_nginx_reload.side_effect = RuntimeError('reload failed')
        with patch.object(self.backend, '_free_waf_main__write_repeat_site_config', side_effect=failed_restore):
            result = self.save()
        self.assertIs(result['status'], False)
        self.assertIn('\u672a\u786e\u8ba4', result['msg'])
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.read()['other.example']['repeat_ban_policy']['window_seconds'], LADDER['window_seconds'])
        self.path.write_bytes(self.original)
        result = self.save()
        self.assertIs(result['status'], False)
        self.assertIn('\u672a\u786e\u8ba4', result['msg'])
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_concurrent_edit_during_restore_staging_is_not_overwritten(self):
        stage = self.backend._free_waf_main__repeat_stage
        stages = []
        changed = []

        def staging(body, suffix):
            path = stage(body, suffix)
            if suffix == '.tmp':
                stages.append(path)
                if len(stages) == 2:
                    config = self.read()
                    config['fixture.example']['cc']['limit'] = 99
                    self.write(config)
                    changed.append(self.path.read_bytes())
            return path

        self.backend._free_waf_main__checked_nginx_reload.side_effect = [False, None]
        with patch.object(self.backend, '_free_waf_main__repeat_stage', side_effect=staging):
            result = self.save()
        self.assertIs(result['status'], False)
        self.assertIn('\u672a\u786e\u8ba4', result['msg'])
        self.assertEqual(self.path.read_bytes(), changed[0])

    def test_fresh_readback_of_every_target_detects_last_policy_change_after_reload(self):
        changed = []

        def reload():
            config = self.read()
            config[TARGETS[-1]]['repeat_ban_policy']['window_seconds'] = 60
            self.write(config)
            changed.append(self.path.read_bytes())

        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        result = self.save()
        self.assertIs(result['status'], False)
        self.assertIn('\u672a\u786e\u8ba4', result['msg'])
        self.assertEqual(self.path.read_bytes(), changed[0])
        self.backend._free_waf_main__checked_nginx_reload.assert_called_once()

    def test_success_response_revision_uses_fresh_bytes_after_unrelated_reload_edit(self):
        def reload():
            config = self.read()
            config['fixture.example']['cc']['limit'] = 99
            config['untouched.example']['open'] = False
            self.write(config)

        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        self.assert_response(self.save())
        self.assertEqual(self.read()['fixture.example']['cc']['limit'], 99)
        self.assertIs(self.read()['untouched.example']['open'], False)

    def test_readback_requires_explicit_saved_policy_not_disabled_defaults_for_missing_field(self):
        def reload():
            config = self.read()
            config['other.example'].pop('repeat_ban_policy', None)
            self.write(config)

        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        ladder = {key: value for key, value in DEFAULTS.items() if key != 'enabled'}
        result = self.save(policy=json.dumps(ladder))
        self.assertIs(result['status'], False)
        self.assertNotIn('repeat_ban_policy', self.read()['other.example'])

    def test_rollback_verifies_every_target_again_after_recovery_reload(self):
        def reload():
            if self.backend._free_waf_main__checked_nginx_reload.call_count == 1:
                raise RuntimeError('reload failed')
            config = self.read()
            config[TARGETS[-1]]['repeat_ban_policy']['window_seconds'] = 60
            self.write(config)

        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        result = self.save()
        self.assertIs(result['status'], False)
        self.assertIn('\u672a\u786e\u8ba4', result['msg'])
        self.assertEqual(self.read()[TARGETS[-1]]['repeat_ban_policy']['window_seconds'], 60)

    def test_existing_shared_lock_blocks_bulk_before_read_and_reads_never_create_lock(self):
        self.assertFalse((self.root / '.endpoint-policy.lock').exists())
        self.assertIs(self.get()['status'], True)
        self.assertFalse((self.root / '.endpoint-policy.lock').exists())
        entered, release = threading.Event(), threading.Event()
        errors = []

        def hold():
            try:
                with self.backend._free_waf_main__endpoint_transaction():
                    entered.set()
                    if not release.wait(5):
                        raise TimeoutError('lock not released')
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=hold)
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            with patch.object(self.backend, '_free_waf_main__repeat_config_bytes',
                              side_effect=AssertionError('read outside lock')) as read:
                self.assertIs(self.save(revision=hashlib.sha256(self.original).hexdigest())['status'], False)
                self.assertIs(self.get()['status'], False)
                read.assert_not_called()
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assert_not_saved()

    def test_bulk_holds_shared_lock_through_publish_reload_and_recovery(self):
        entered, release = threading.Event(), threading.Event()
        results, conflicts = [], []
        revision = self.revision()
        policy_single = type(self.backend).save_repeat_ban_policy

        def reload():
            entered.set()
            if not release.wait(5):
                raise TimeoutError('reload not released')
            if self.backend._free_waf_main__checked_nginx_reload.call_count == 1:
                raise RuntimeError('reload failed')

        self.backend._free_waf_main__checked_nginx_reload.side_effect = reload
        worker = threading.Thread(target=lambda: results.append(self.save()))
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            conflicts.append(self.save(revision=revision))
            conflicts.append(policy_single(self.backend, types.SimpleNamespace(
                siteName='untouched.example', revision=revision, policy=json.dumps(DEFAULTS))))
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(all(result['status'] is False for result in conflicts))
        self.assertIs(results[0]['status'], False)
        self.assertIn('\u5df2\u6062\u590d', results[0]['msg'])
        self.assertEqual(self.path.read_bytes(), self.original)
        self.backend._free_waf_main__checked_nginx_reload.side_effect = None
        self.assert_response(self.save())

    def test_external_process_shared_lock_blocks_bulk_save(self):
        code = ('import os,sys\nf=open(sys.argv[1],"a+b")\n'
                'if os.name == "posix":\n import fcntl\n fcntl.flock(f,fcntl.LOCK_EX)\n'
                'else:\n import msvcrt\n msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)\n'
                'print("locked",flush=True)\nsys.stdin.read(1)')
        process = subprocess.Popen([sys.executable, '-I', '-c', code, str(self.root / '.endpoint-policy.lock')],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(process.stdout.readline().strip(), b'locked')
            self.assertIs(self.save()['status'], False)
            self.assert_not_saved()
        finally:
            process.communicate(input=b'x', timeout=5)
        self.assert_response(self.save())

    def test_same_thread_nested_shared_lock_remains_reentrant(self):
        with self.backend._free_waf_main__endpoint_transaction():
            self.assert_response(self.save())

    def test_checked_reload_uses_only_baota_test_then_reload(self):
        del self.backend._free_waf_main__checked_nginx_reload
        with patch('subprocess.run', return_value=types.SimpleNamespace(returncode=0)) as run:
            self.assert_response(self.save())
        self.assertEqual([call[0][0] for call in run.call_args_list], [
            ['/www/server/nginx/sbin/nginx', '-t'], ['/www/server/nginx/sbin/nginx', '-s', 'reload']])
        self.assert_protected()

    def test_symlinked_config_or_lock_is_rejected_without_touching_target(self):
        target = self.root / 'private.json'
        target.write_bytes(self.original)
        probe = self.root / 'probe'
        try:
            probe.symlink_to(target)
            probe.unlink()
        except OSError as error:
            self.skipTest('symlink unavailable: ' + str(error))
        self.path.unlink()
        self.path.symlink_to(target)
        self.assertIs(self.get()['status'], False)
        self.assertIs(self.save()['status'], False)
        self.assertEqual(target.read_bytes(), self.original)
        self.path.unlink()
        self.path.write_bytes(self.original)
        lock = self.root / '.endpoint-policy.lock'
        if lock.exists():
            lock.unlink()
        lock.symlink_to(target)
        self.assertIs(self.get()['status'], False)
        self.assertIs(self.save()['status'], False)
        self.assert_not_saved()
        self.assertEqual(target.read_bytes(), self.original)


if __name__ == '__main__':
    unittest.main()
