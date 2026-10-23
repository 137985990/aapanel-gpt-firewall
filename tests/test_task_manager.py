import importlib
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import website_statistics as tasks
from test_panel_performance import load_backend


def proc_stat(pid=12, name='worker (safe)', ticks=20, identity=400, rss=3):
    fields = ['S', '1'] + ['0'] * 48
    for index, value in {11: ticks, 12: 0, 17: 2, 19: identity, 20: 8192, 21: rss}.items():
        fields[index] = str(value)
    return '%d (%s) %s\n' % (pid, name, ' '.join(fields))


class TaskManagerTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(tasks, 'TaskManagerService'), 'read-only task service is missing')
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'net').mkdir()
        (self.root / 'stat').write_text('btime 1000\n')
        (self.root / 'meminfo').write_text('MemTotal: 1000 kB\n')
        (self.root / 'loadavg').write_text('1.00 0.50 0.25 1/5 12\n')
        (self.root / 'net/dev').write_text('header\nheader\n eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n')
        for protocol in ('tcp', 'tcp6', 'udp', 'udp6'):
            (self.root / ('net/' + protocol)).write_text('header\n')

    def process(self, pid=12, **kwargs):
        folder = self.root / str(pid)
        folder.mkdir(exist_ok=True)
        (folder / 'stat').write_text(proc_stat(pid=pid, **kwargs))
        (folder / 'io').write_text('read_bytes: 100\nwrite_bytes: 200\n')
        (folder / 'status').write_text('Uid:\t1000\t1000\t1000\t1000\nVmSwap: 4 kB\n')
        (folder / 'fd').mkdir(exist_ok=True)
        (folder / 'cmdline').write_text('secret-token-never-read')
        (folder / 'environ').write_text('PASSWORD=never-read')
        return folder

    def reader(self, **kwargs):
        return tasks._TaskSnapshotReader(self.root, hz=100, page_size=4096, sleep=lambda value: None, **kwargs)

    def params(self, operation='processes', **kwargs):
        return tasks.TaskManagerService.validate(operation, kwargs)

    def test_rejects_unknown_operations_paths_and_unbounded_parameters(self):
        for operation, params in [('kill', {}), ('processes', {'page': '-1'}),
                                  ('processes', {'per_page': 100000}), ('processes', {'sort': 'cmdline'}),
                                  ('network', {'port': '80;curl bad'}), ('network', {'state': 'x'}),
                                  ('detail', {'pid': '../../etc/passwd', 'identity': '1'}),
                                  ('detail', {'pid': 12, 'identity': ''}),
                                  ('processes', {'search': 'a' * 81})]:
            with self.subTest(operation=operation, params=params):
                with self.assertRaises(ValueError):
                    self.params(operation, **params)
        self.assertNotIn('path', self.params(path='/etc/shadow'))

    def test_process_snapshot_safe_fields_and_unknown_first_rates(self):
        self.process()
        result = self.reader().collect('processes', self.params())
        self.assertIs(result['status'], True)
        row = result['items'][0]
        self.assertEqual(row['name'], 'worker (safe)')
        self.assertEqual(row['identity'], '400')
        self.assertEqual(row['rss_bytes'], 12288)
        self.assertEqual(result['summary']['memory_total_bytes'], 1024000)
        self.assertEqual(result['summary']['load'], [1.0, 0.5, 0.25])
        self.assertNotIn('secret-token', json.dumps(result))
        self.assertNotIn('PASSWORD', json.dumps(result))
        self.assertNotIn('cmdline', row)
        self.assertEqual(set(row), {'pid', 'ppid', 'name', 'uid', 'state', 'identity', 'cpu_percent',
                                   'rss_bytes', 'vms_bytes', 'read_rate', 'write_rate', 'started_at', 'threads'})

    def test_cpu_io_use_elapsed_sample_and_stable_identity(self):
        folder = self.process()
        now = [0.0]
        reader = self.reader(clock=lambda: now[0])
        def advance(value):
            now[0] = .25
            (folder / 'stat').write_text(proc_stat(ticks=30))
            (folder / 'io').write_text('read_bytes: 200\nwrite_bytes: 400\n')
        reader.sleep = advance
        result = reader.collect('processes', self.params())
        row = result['items'][0]
        self.assertEqual(row['cpu_percent'], 40.0)
        self.assertEqual(row['read_rate'], 400.0)
        self.assertEqual(row['write_rate'], 800.0)

    def test_missing_io_counters_are_unknown_and_reported(self):
        folder = self.process()
        (folder / 'io').unlink()
        result = self.reader().collect('processes', self.params())
        self.assertIsNone(result['items'][0]['read_rate'])
        self.assertIn('io_unavailable', result['reasons'])

    def test_exited_or_malformed_process_does_not_break_list(self):
        self.process()
        folder = self.process(pid=13)
        (folder / 'stat').write_text('bad stat')
        result = self.reader().collect('processes', self.params())
        self.assertEqual([row['pid'] for row in result['items']], [12])
        self.assertIn('process_unavailable', result['reasons'])

    def test_reused_pid_is_omitted_from_two_sample_results(self):
        folder = self.process()
        reader = self.reader()
        reader.sleep = lambda value: (folder / 'stat').write_text(proc_stat(identity=401))
        result = reader.collect('processes', self.params())
        self.assertEqual(result['items'], [])
        self.assertTrue(result['partial'])

    def test_pid_reused_inside_second_sample_cannot_mix_replacement_uid_and_io(self):
        folder = self.process()
        now = [0.0]
        reader = self.reader(clock=lambda: now[0])
        original = reader._read
        def read(path, maximum=65536):
            if path == '12/status' and now[0] > 0:
                (folder / 'stat').write_text(proc_stat(identity=401))
                (folder / 'status').write_text('Uid:\t2000\t2000\t2000\t2000\n')
                (folder / 'io').write_text('read_bytes: 10100\nwrite_bytes: 200\n')
            return original(path, maximum)
        reader._read = read
        reader.sleep = lambda value: now.__setitem__(0, .25)
        result = reader.collect('processes', self.params())
        self.assertEqual(result['items'], [])
        self.assertIn('process_changed', result['reasons'])

    def test_detail_refuses_changed_identity(self):
        self.process(identity=401)
        result = self.reader().collect('detail', self.params('detail', pid=12, identity='400'))
        self.assertIs(result['status'], False)
        self.assertEqual(result['code'], 'process_changed')

    def test_detail_missing_smaps_is_partial_not_failure_and_no_paths(self):
        self.process()
        result = self.reader().collect('detail', self.params('detail', pid=12, identity='400'))
        self.assertIs(result['status'], True)
        self.assertIsNone(result['process']['pss_bytes'])
        self.assertEqual(result['process']['swap_bytes'], 4096)
        self.assertTrue(result['partial'])
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_detail_uses_rollup_only_on_demand(self):
        folder = self.process()
        (folder / 'smaps_rollup').write_text('Pss: 8 kB\nPrivate_Clean: 2 kB\nPrivate_Dirty: 3 kB\nSwap: 4 kB\n')
        result = self.reader().collect('detail', self.params('detail', pid=12, identity='400'))
        self.assertEqual(result['process']['pss_bytes'], 8192)
        self.assertEqual(result['process']['uss_bytes'], 5120)

    def test_missing_memory_fields_are_unknown_and_explicitly_partial(self):
        folder = self.process()
        (folder / 'smaps_rollup').write_text('Rss: 8 kB\n')
        result = self.reader().collect('detail', self.params('detail', pid=12, identity='400'))
        self.assertIsNone(result['process']['pss_bytes'])
        self.assertIsNone(result['process']['uss_bytes'])
        self.assertIn('memory_unavailable', result['reasons'])

    def test_filter_sort_paging_and_partial_process_limit(self):
        for pid in range(12, 43):
            self.process(pid=pid, name='web', rss=pid)
        reader = self.reader()
        result = reader.collect('processes', self.params(sort='rss_bytes', order='desc', page=2, search='web'))
        self.assertEqual(result['total'], 31)
        self.assertEqual(result['items'][0]['pid'], 17)
        self.assertEqual(len(result['items']), 6)
        reader.MAX_PROCESSES = 2
        result = reader.collect('processes', self.params())
        self.assertEqual(len(result['items']), 2)
        self.assertIn('process_limit', result['reasons'])

    def test_ipv4_ipv6_udp_and_network_filter(self):
        (self.root / 'net/tcp').write_text('header\n 0: 0100007F:01BB 020200C0:C000 01 0:0 0:0 0 1000 0 55\n')
        (self.root / 'net/tcp6').write_text('header\n 1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 0:0 0:0 0 1000 0 56\n')
        (self.root / 'net/udp').write_text('header\n 2: 00000000:0035 00000000:0000 07 0:0 0:0 0 1000 0 57\n')
        result = self.reader().collect('network', self.params('network'))
        self.assertEqual(result['total'], 3)
        self.assertEqual(result['summary']['listen_count'], 1)
        rows = {row['protocol']: row for row in result['items']}
        self.assertEqual(rows['tcp']['local_address'], '127.0.0.1')
        self.assertEqual(rows['tcp']['remote_address'], '192.0.2.2')
        self.assertEqual(rows['tcp6']['local_address'], '::1')
        self.assertEqual(rows['udp']['state'], 'UNCONN')
        self.assertIsNone(rows['tcp']['pid'])
        filtered = self.reader().collect('network', self.params('network', port=443, protocol='tcp', state='ESTABLISHED'))
        self.assertEqual(filtered['total'], 1)
        self.assertEqual(result['interfaces'][0]['name'], 'eth0')

    def test_malformed_or_missing_net_tables_are_not_silent_empty_success(self):
        (self.root / 'net/tcp').write_text('header\nnot-a-socket\n')
        (self.root / 'net/udp6').unlink()
        result = self.reader().collect('network', self.params('network'))
        self.assertTrue(result['partial'])
        self.assertIn('socket_unavailable', result['reasons'])

    def test_interface_rates_and_counter_resets(self):
        now = [0.0]
        reader = self.reader(clock=lambda: now[0])
        def advance(value):
            now[0] = .25
            (self.root / 'net/dev').write_text('header\nheader\n eth0: 200 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0\n')
        reader.sleep = advance
        result = reader.collect('network', self.params('network'))
        self.assertEqual(result['interfaces'][0]['receive_rate'], 400.0)
        self.assertIsNone(result['interfaces'][0]['send_rate'])

    def test_socket_row_and_time_limits_are_explicit(self):
        (self.root / 'net/tcp').write_text('header\n' + ' 0: 0100007F:01BB 020200C0:C000 01 0:0 0:0 0 1000 0 55\n' * 4)
        reader = self.reader()
        reader.MAX_SOCKET_ROWS = 2
        result = reader.collect('network', self.params('network'))
        self.assertEqual(result['summary']['socket_count'], 2)
        self.assertIn('socket_limit', result['reasons'])
        reader = self.reader()
        reader.deadline = -1
        result = reader.collect('processes', self.params())
        self.assertTrue(result['partial'])
        self.assertIn('time_limit', result['reasons'])

    @unittest.skipIf(os.name == 'nt', 'Linux proc socket descriptors are symlinks')
    def test_socket_ownership_is_best_effort_without_exposing_non_socket_targets(self):
        folder = self.process()
        (folder / 'fd/3').symlink_to('socket:[55]')
        (folder / 'fd/4').symlink_to('/private/path/password-file')
        (self.root / 'net/tcp').write_text('header\n 0: 0100007F:01BB 020200C0:C000 01 0:0 0:0 0 1000 0 55\n')
        result = self.reader().collect('network', self.params('network'))
        self.assertEqual(result['items'][0]['pid'], 12)
        self.assertEqual(result['items'][0]['process_name'], 'worker (safe)')
        self.assertNotIn('password-file', json.dumps(result))

    def test_invalid_or_oversized_worker_results_are_fixed_errors(self):
        for output, returncode in ((b'secret-error', 0), (b'{"status": true}', 1),
                                   (b'[]', 0), (b'x' * (512 * 1024 + 1), 0)):
            child = Mock(returncode=returncode)
            child.communicate.return_value = (output, None)
            with patch.object(tasks.subprocess, 'Popen', return_value=child), patch.object(tasks.os, 'name', 'posix'):
                result = tasks.TaskManagerService().collect('processes', {})
            self.assertEqual(result['code'], 'unavailable')
            self.assertNotIn('secret-error', json.dumps(result))

    def test_worker_timeout_is_fixed_error_and_reaps_child(self):
        child = Mock()
        child.communicate.side_effect = [subprocess.TimeoutExpired('private-argv', 4), (b'', b'private-error')]
        with patch.object(tasks, 'subprocess', create=True) as runner, patch.object(tasks.os, 'name', 'posix'):
            runner.Popen.return_value = child
            runner.TimeoutExpired = subprocess.TimeoutExpired
            runner.PIPE = subprocess.PIPE
            runner.DEVNULL = subprocess.DEVNULL
            result = tasks.TaskManagerService().collect('processes', {})
        self.assertIs(result['status'], False)
        self.assertEqual(result['code'], 'timeout')
        child.kill.assert_called_once()
        self.assertEqual(child.communicate.call_count, 2)
        self.assertNotIn('private', json.dumps(result))

    def test_invalid_params_do_not_spawn_any_process(self):
        with patch.object(tasks, 'subprocess', create=True) as runner:
            result = tasks.TaskManagerService().collect('detail', {'pid': '../1', 'identity': '1'})
        self.assertIs(result['status'], False)
        runner.Popen.assert_not_called()


class TaskEndpointTests(unittest.TestCase):
    def test_endpoints_forward_only_known_fields_without_mutation(self):
        public = types.SimpleNamespace(returnMsg=lambda status, msg: dict(status=status, msg=msg))
        backend = load_backend(public)
        self.assertTrue(hasattr(backend, 'get_task_processes'), 'read-only endpoints are missing')
        service = Mock()
        service.collect.return_value = {'status': True, 'items': []}
        backend._free_waf_main__task_service = Mock(return_value=service)
        request = types.SimpleNamespace(page='2', path='/etc/shadow', command='kill')
        self.assertTrue(backend.get_task_processes(request)['status'])
        args = service.collect.call_args[0]
        self.assertEqual(args[0], 'processes')
        self.assertNotIn('path', args[1])
        self.assertNotIn('command', args[1])
        backend.get_task_network(request)
        self.assertEqual(service.collect.call_args[0][0], 'network')
        backend.get_task_process_detail(types.SimpleNamespace(pid=12, identity='400'))
        self.assertEqual(service.collect.call_args[0][0], 'detail')

    def test_service_failure_never_returns_internal_exception(self):
        backend = load_backend(types.SimpleNamespace())
        self.assertTrue(hasattr(backend, 'get_task_processes'), 'read-only endpoints are missing')
        backend._free_waf_main__task_service = Mock(side_effect=RuntimeError('secret-path'))
        result = backend.get_task_processes(None)
        self.assertIs(result['status'], False)
        self.assertNotIn('secret-path', json.dumps(result))


@unittest.skipUnless(sys.platform.startswith('linux') and Path('/proc/self/stat').exists(), 'real Linux procfs')
class TaskRuntimeTests(unittest.TestCase):
    def test_worker_does_not_reuse_stale_same_second_bytecode(self):
        source = """class TaskManagerService:
    MAX_OUTPUT_BYTES = 524288
    @staticmethod
    def validate(operation, params): return params
class _TaskSnapshotReader:
    def collect(self, operation, params): return dict(status=True, marker='before')
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'snapshot.py'
            path.write_text(source)
            py_compile.compile(str(path), doraise=True)
            original = path.stat()
            path.write_text(source.replace('before', 'after_'))
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
            with patch.object(tasks, '__file__', str(path)):
                result = tasks.TaskManagerService().collect('processes', {})
        self.assertEqual(result.get('marker'), 'after_')

    def test_actual_isolated_worker_reads_processes_and_network_without_optional_dependencies(self):
        service = tasks.TaskManagerService()
        processes = service.collect('processes', {})
        self.assertIs(processes.get('status'), True, processes.get('code'))
        self.assertGreater(processes['summary']['process_count'], 0)
        self.assertLessEqual(len(processes['items']), 25)
        self.assertTrue(all(row['identity'].isdigit() for row in processes['items']))
        network = service.collect('network', {})
        self.assertIs(network.get('status'), True, network.get('code'))
        self.assertLessEqual(len(network['items']), 25)
        self.assertIn('interfaces', network)
        self.assertNotIn('cmdline', json.dumps(processes))
