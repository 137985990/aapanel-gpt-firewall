import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

from tests.test_panel_performance import load_backend


ROOT = Path(__file__).resolve().parents[1]


class SecurityBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'site'
        self.root.mkdir()
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            M=Mock(), httpGet=Mock(side_effect=AssertionError('network egress')),
            httpPost=Mock(side_effect=AssertionError('network egress')),
            get_url=Mock(side_effect=AssertionError('legacy network URL lookup')),
            ExecShell=Mock(side_effect=AssertionError('shell execution')),
            readFile=Mock(side_effect=AssertionError('unexpected panel read')),
            ReadFile=Mock(side_effect=AssertionError('unexpected panel read')),
            writeFile=Mock(side_effect=AssertionError('unexpected panel write')),
        )
        self.public.M.return_value.field.return_value.select.return_value = [
            dict(name='fixture.example', path=str(self.root))]
        self.backend = load_backend(self.public)
        self.backend.insert_log = Mock()

    def fixture(self, name='index.php', content='fixture-marker'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return path

    def test_spider_and_ip_sync_stubs_do_not_inspect_arguments_or_credentials(self):
        class Poison:
            def __getattribute__(self, name):
                raise AssertionError('argument or credential read: ' + name)
        for method in ('getSpiders', 'addSpider', 'sync_cnlist'):
            with self.subTest(method=method):
                self.assertTrue(callable(getattr(self.backend, method, None)), method)
                result = getattr(self.backend, method)(Poison())
                self.assertIs(result['status'], False)
                self.assertIn('\u505c\u7528', result['msg'])
        self.assertFalse(self.backend.sync_cnlist(None)['status'])
        self.public.M.assert_not_called()
        self.public.httpGet.assert_not_called()
        self.public.readFile.assert_not_called()

    def test_dormant_http_compiler_helper_is_removed_not_just_disconnected(self):
        self.assertFalse(hasattr(self.backend, '_free_waf_main__check_cjson'))

    def test_backend_has_no_shell_entrypoints_or_external_http_literals(self):
        tree = ast.parse((ROOT / 'free_waf_main.py').read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, ('ExecShell', 'system', 'popen', 'httpPost'))
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.startswith(('http://', 'https://')):
                    self.assertTrue(node.value.startswith('http://127.0.0.1/'), node.value)

    def test_scan_preserves_local_match_list_and_never_invokes_upload(self):
        path = self.fixture()
        self.backend.send_baota2 = Mock(side_effect=AssertionError('upload'))
        self.assertEqual(self.backend.scan([str(path)], ['fixture-marker']),
                         [{str(path): 'fixture-marker'}])
        self.backend.send_baota2.assert_not_called()
        self.public.M.assert_called_with('sites')
        self.public.M.return_value.field.assert_called_with('name,path')

    def test_scan_does_not_open_files_outside_roots_or_traversal_aliases(self):
        outside = Path(self.directory.name) / 'secret.php'
        outside.write_text('fixture-marker')
        path = self.fixture()
        forbidden = [str(outside), str(self.root / '..' / 'secret.php'),
                     str(self.root / '..' / 'site' / path.name)]
        with patch('builtins.open', side_effect=AssertionError('unconfined read')) as file_open:
            self.assertEqual(self.backend.scan(forbidden, ['fixture-marker']), [])
            file_open.assert_not_called()
        self.backend.insert_log.assert_not_called()

    def test_scan_and_listing_fail_closed_without_configured_roots(self):
        path = self.fixture()
        self.public.M.return_value.field.return_value.select.return_value = []
        self.assertEqual(self.backend.scan([str(path)], ['fixture-marker']), [])
        self.assertFalse(self.backend.getdir_list(types.SimpleNamespace(path=str(self.root))))

    def test_scan_rejects_non_php_and_nonregular_candidates(self):
        text = self.fixture('private.txt')
        directory = self.root / 'directory.php'
        directory.mkdir()
        self.assertEqual(self.backend.scan([str(text), str(directory)], ['fixture-marker']), [])

    def test_listing_confines_roots_and_does_not_spawn_shells(self):
        good = self.fixture('nested/a.PHP')
        self.fixture('ignore.txt')
        self.assertEqual(self.backend.getdir_list(types.SimpleNamespace(path=str(self.root))), [str(good)])
        self.assertFalse(self.backend.getdir_list(types.SimpleNamespace(path=self.directory.name)))
        self.public.ExecShell.assert_not_called()

    def test_listing_does_not_exclude_hackcnm_names_or_directories(self):
        paths = [self.fixture('hackcnm.php'), self.fixture('hackcnm/nested.php')]
        listed = self.backend.getdir_list(types.SimpleNamespace(path=str(self.root)))
        self.assertEqual(set(listed), {str(path) for path in paths})
        self.assertEqual(self.backend.scan(listed, ['fixture-marker']),
                         [{path: 'fixture-marker'} for path in listed])
        self.assertFalse(self.backend.get_security_boundary_report(None)['scan']['partial'])

    def test_regex_runs_in_one_isolated_fixed_argv_process_with_stdin_only_data(self):
        marker = 'private-fixture-marker-not-a-command'
        paths = [self.fixture('first.php', marker), self.fixture('second.php', marker)]
        processes = []
        original = subprocess.Popen

        def start(*args, **kwargs):
            process = original(*args, **kwargs)
            process.communicate = Mock(wraps=process.communicate)
            processes.append(process)
            return process

        with patch('subprocess.Popen', side_effect=start) as spawn:
            with patch('re.compile', side_effect=AssertionError('regex compiled in panel process')):
                result = self.backend.scan([str(path) for path in paths], [marker])
        self.assertEqual(result, [{str(path): marker} for path in paths])
        spawn.assert_called_once()
        argv = spawn.call_args.args[0]
        self.assertEqual(argv[:5], [sys.executable, '-I', '-S', '-B', '-c'])
        self.assertEqual(len(argv), 6)
        self.assertEqual(argv[5], self.backend.SCAN_REGEX_WORKER)
        self.assertNotIn(marker, ' '.join(argv))
        self.assertNotIn(str(self.root), ' '.join(argv))
        options = spawn.call_args.kwargs
        self.assertIs(options['shell'], False)
        self.assertEqual(options['stdin'], subprocess.PIPE)
        self.assertEqual(options['stdout'], subprocess.PIPE)
        self.assertEqual(options['stderr'], subprocess.DEVNULL)
        self.assertIs(options['close_fds'], True)
        sent = processes[0].communicate.call_args.kwargs
        self.assertEqual(json.loads(sent['input']), dict(files=[marker, marker], rules=[marker]))
        self.assertEqual(sent['timeout'], self.backend.SCAN_REGEX_SECONDS)

    def test_catastrophic_regex_times_out_and_worker_is_reaped(self):
        self.assertTrue(hasattr(self.backend, 'SCAN_REGEX_SECONDS'), 'missing regex CPU deadline')
        path = self.fixture(content='a' * 256 + '!')
        self.backend.SCAN_REGEX_SECONDS = 0.2
        processes = []
        original = subprocess.Popen

        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process

        started = time.monotonic()
        with patch('subprocess.Popen', side_effect=spawn):
            self.assertEqual(self.backend.scan([str(path)], [r'(a+)+$']), [])
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertTrue(processes[0].stdin.closed)
        self.assertTrue(processes[0].stdout.closed)
        coverage = self.backend.get_security_boundary_report(None)['scan']
        self.assertTrue(coverage['partial'])
        self.assertTrue(coverage['timed_out'])
        self.assertIn('\u8d85\u65f6', coverage['notice'])
        self.backend.insert_log.assert_not_called()

    def test_regex_result_records_are_capped_and_coverage_is_partial(self):
        self.assertTrue(hasattr(self.backend, 'SCAN_MAX_MATCHES'), 'missing result record bound')
        paths = [self.fixture('first.php'), self.fixture('second.php')]
        result = self.backend.scan([str(path) for path in paths], ['fixture-marker'] * 1000)
        self.assertEqual(len(result), self.backend.SCAN_MAX_MATCHES)
        self.assertEqual(self.backend.insert_log.call_count, len(result))
        self.assertTrue(self.backend.get_security_boundary_report(None)['scan']['partial'])

    def test_invalid_regex_is_partial_without_losing_valid_matches(self):
        path = self.fixture()
        self.assertEqual(self.backend.scan([str(path)], ['(', 'fixture-marker']),
                         [{str(path): 'fixture-marker'}])
        coverage = self.backend.get_security_boundary_report(None)['scan']
        self.assertTrue(coverage['partial'])
        self.assertFalse(coverage.get('timed_out', False))

    def test_overlong_regex_is_rejected_before_starting_a_worker(self):
        self.assertTrue(hasattr(self.backend, 'SCAN_MAX_RULE_BYTES'), 'missing pattern byte bound')
        path = self.fixture()
        with patch('subprocess.Popen', side_effect=AssertionError('overlong pattern spawned worker')):
            self.assertEqual(self.backend.scan([str(path)], ['x' * (self.backend.SCAN_MAX_RULE_BYTES + 1)]), [])
        self.assertTrue(self.backend.get_security_boundary_report(None)['scan']['partial'])

    def test_worker_start_failure_is_partial_not_a_clean_scan(self):
        path = self.fixture()
        with patch('subprocess.Popen', side_effect=OSError('fixture worker unavailable')):
            self.assertEqual(self.backend.scan([str(path)], ['fixture-marker']), [])
        coverage = self.backend.get_security_boundary_report(None)['scan']
        self.assertTrue(coverage['partial'])
        self.assertIn('\u8fdb\u7a0b', coverage['notice'])

    def test_failed_or_invalid_worker_output_is_partial_and_never_logged(self):
        path = self.fixture()
        outputs = [b'not json', b'x' * (self.backend.SCAN_MAX_WORKER_OUTPUT + 1)]
        for matches in ([[9999, 0]], [[0, 9999]], [[False, 0]], [[0, 0], [0, 0]],
                        [[0, 0]] * (self.backend.SCAN_MAX_MATCHES + 1)):
            outputs.append(json.dumps(dict(matches=matches, partial=False, limited=False)).encode())
        for returncode, output in [(1, b'')] + [(0, output) for output in outputs]:
            with self.subTest(returncode=returncode, output=output):
                process = Mock(returncode=returncode)
                process.communicate.return_value = (output, None)
                with patch('subprocess.Popen', return_value=process):
                    self.assertEqual(self.backend.scan([str(path)], ['fixture-marker']), [])
                self.assertTrue(self.backend.get_security_boundary_report(None)['scan']['partial'])
        self.backend.insert_log.assert_not_called()

    def test_timeout_discards_unfinished_batch_even_after_an_earlier_match(self):
        self.assertTrue(hasattr(self.backend, 'SCAN_REGEX_SECONDS'), 'missing regex CPU deadline')
        paths = [self.fixture('first.php'), self.fixture('second.php', 'a' * 256 + '!')]
        self.backend.SCAN_REGEX_SECONDS = 0.2
        self.assertEqual(self.backend.scan([str(path) for path in paths],
                                           ['fixture-marker', r'(a+)+$']), [])
        self.backend.insert_log.assert_not_called()
        self.assertTrue(self.backend.get_security_boundary_report(None)['scan']['timed_out'])

    def test_quadratic_regex_on_a_file_within_byte_limits_is_timed_out(self):
        self.assertTrue(hasattr(self.backend, 'SCAN_REGEX_SECONDS'), 'missing regex CPU deadline')
        path = self.fixture(content='eval(' * 200000)
        self.backend.SCAN_REGEX_SECONDS = 0.2
        started = time.monotonic()
        self.assertEqual(self.backend.scan([str(path)], [r'eval\(.*\)']), [])
        self.assertLess(time.monotonic() - started, 3)
        coverage = self.backend.get_security_boundary_report(None)['scan']
        self.assertTrue(coverage['partial'])
        self.assertTrue(coverage['timed_out'])
        self.assertEqual(coverage['bytes_read'], 1000000)

    def test_san_dir_returns_structured_matches_and_coverage(self):
        path = self.fixture()
        self.backend.shell_get_rule = Mock(return_value=['fixture-marker'])
        self.backend.path_json = Mock(side_effect=lambda path, data: data)
        result = self.backend.san_dir(types.SimpleNamespace(path=str(self.root)))
        self.assertIsInstance(result, dict)
        self.assertTrue(result['status'])
        self.assertEqual(result['data'], [{str(path): 'fixture-marker'}])
        self.assertFalse(result['coverage']['partial'])

    def test_san_dir_reports_empty_and_capped_empty_listings_truthfully(self):
        args = types.SimpleNamespace(path=str(self.root))
        result = self.backend.san_dir(args)
        self.assertTrue(result['status'])
        self.assertEqual(result['data'], [])
        self.assertFalse(result['coverage']['partial'])
        self.fixture('ignore.txt')
        self.backend.SCAN_MAX_ENTRIES = 0
        result = self.backend.san_dir(args)
        self.assertTrue(result['status'])
        self.assertEqual(result['data'], [])
        self.assertTrue(result['coverage']['partial'])
        self.assertIn('\u90e8\u5206', result['coverage']['notice'])

    def test_san_dir_timeout_returns_partial_coverage_with_empty_legacy_data(self):
        self.assertTrue(hasattr(self.backend, 'SCAN_REGEX_SECONDS'), 'missing regex CPU deadline')
        self.fixture(content='a' * 256 + '!')
        self.backend.SCAN_REGEX_SECONDS = 0.2
        self.backend.shell_get_rule = Mock(return_value=[r'(a+)+$'])
        self.backend.path_json = Mock(side_effect=lambda path, data: data)
        result = self.backend.san_dir(types.SimpleNamespace(path=str(self.root)))
        self.assertTrue(result['status'])
        self.assertEqual(result['data'], [])
        self.assertTrue(result['coverage']['partial'])
        self.assertTrue(result['coverage']['timed_out'])
        self.assertIn('\u8d85\u65f6', result['coverage']['notice'])

    def test_san_dir_invalid_path_and_missing_rules_cannot_claim_complete_coverage(self):
        result = self.backend.san_dir(types.SimpleNamespace(path=self.directory.name))
        self.assertFalse(result['status'])
        self.assertIn('data', result)
        self.assertIn('coverage', result)
        self.assertEqual(result['data'], [])
        self.assertTrue(result['coverage']['partial'])
        self.fixture()
        self.backend.shell_get_rule = Mock(return_value=False)
        result = self.backend.san_dir(types.SimpleNamespace(path=str(self.root)))
        self.assertFalse(result['status'])
        self.assertIn('data', result)
        self.assertIn('coverage', result)
        self.assertEqual(result['data'], [])
        self.assertTrue(result['coverage']['partial'])

    def test_symlink_files_directories_and_configured_root_are_rejected(self):
        good = self.fixture()
        link = self.root / 'link.php'
        try:
            link.symlink_to(good)
            linked_dir = self.root / 'linked'
            linked_dir.symlink_to(self.root, target_is_directory=True)
        except OSError as exc:
            self.skipTest('symlink creation unavailable: ' + str(exc))
        self.assertEqual(self.backend.scan([str(link), str(linked_dir / good.name)], ['fixture-marker']), [])
        self.assertEqual(self.backend.getdir_list(types.SimpleNamespace(path=str(self.root))), [str(good)])
        self.public.M.return_value.field.return_value.select.return_value = [dict(name='fixture', path=str(linked_dir))]
        self.assertEqual(self.backend.scan([str(good)], ['fixture-marker']), [])

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO fixture requires POSIX')
    def test_scan_never_opens_a_fifo(self):
        fifo = self.root / 'pipe.php'
        os.mkfifo(fifo)
        self.assertEqual(self.backend.scan([str(fifo)], ['fixture-marker']), [])

    def test_scan_bounds_files_bytes_and_exposes_partial_coverage_without_changing_list_shape(self):
        first = self.fixture('one.php', 'x' * 40 + 'fixture-marker')
        second = self.fixture('two.php')
        self.backend.SCAN_MAX_FILES = 1
        self.backend.SCAN_MAX_FILE_BYTES = 16
        self.backend.SCAN_MAX_TOTAL_BYTES = 16
        self.assertEqual(self.backend.scan([str(first), str(second)], ['fixture-marker']), [])
        self.assertTrue(callable(getattr(self.backend, 'get_security_boundary_report', None)))
        report = self.backend.get_security_boundary_report(None)
        self.assertTrue(report['status'])
        self.assertTrue(report['scan']['partial'])
        self.assertLessEqual(report['scan']['bytes_read'], 16)
        self.assertIn('\u90e8\u5206', report['scan']['notice'])
        self.public.httpGet.assert_not_called()

    def test_listing_depth_and_file_count_are_bounded(self):
        first = self.fixture('one.php')
        self.fixture('deep/deeper/hidden.php')
        self.backend.SCAN_MAX_DEPTH = 1
        self.backend.SCAN_MAX_FILES = 1
        self.assertEqual(self.backend.getdir_list(types.SimpleNamespace(path=str(self.root))), [str(first)])
        self.assertTrue(self.backend.get_security_boundary_report(None)['scan']['partial'])

    def test_public_hash_helper_cannot_bypass_scan_boundary(self):
        outside = Path(self.directory.name) / 'secret.php'
        outside.write_text('secret')
        with patch('builtins.open', side_effect=AssertionError('unconfined hash read')):
            self.assertFalse(self.backend.read_file_md5(str(outside)))

    def test_new_explicit_scan_does_not_inherit_stale_partial_status(self):
        path = self.fixture()
        self.backend.scan([str(self.root / 'missing.php')], ['fixture-marker'])
        self.backend.scan([str(path)], ['fixture-marker'])
        self.assertFalse(self.backend.get_security_boundary_report(None)['scan']['partial'])

    def test_listing_reports_actual_file_count_when_capped(self):
        self.fixture('one.php')
        self.fixture('two.php')
        self.backend.SCAN_MAX_FILES = 1
        paths = self.backend.getdir_list(types.SimpleNamespace(path=str(self.root)))
        report = self.backend.get_security_boundary_report(None)
        self.assertEqual(report['scan']['files'], len(paths))
        self.backend.scan(paths, ['fixture-marker'])
        self.assertTrue(self.backend.get_security_boundary_report(None)['scan']['partial'])

    def test_local_service_accepts_v014_and_replaces_cached_v012(self):
        self.backend._free_waf_main__PATH = str(ROOT) + os.sep
        for name in ('update_service', 'website_statistics'):
            with self.subTest(name=name):
                try:
                    module = self.backend._free_waf_main__local_service(name)
                except ValueError as exc:
                    self.fail('v0.1.12 service rejected: ' + str(exc))
                self.assertEqual(module.PLUGIN_VERSION, '0.1.12')
                module.PLUGIN_VERSION = '0.1.2'
                refreshed = self.backend._free_waf_main__local_service(name)
                self.assertIsNot(module, refreshed)
                self.assertEqual(refreshed.PLUGIN_VERSION, '0.1.12')


if __name__ == '__main__':
    unittest.main()
