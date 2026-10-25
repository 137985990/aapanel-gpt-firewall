import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import stat
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.request
import warnings
import zipfile

try:
    import update_service as updater
except ModuleNotFoundError:
    updater = None


FILES = (
    'info.json', 'install.sh', 'free_waf_main.py', 'index.html', 'init.lua',
    'ban_store.py', 'report_store.py', 'website_statistics.py', 'update_service.py',
    'html/get.html', 'html/post.html', 'html/cookie.html', 'html/user_agent.html',
    'html/other.html', 'README.md', 'NOTICE.md', 'CHANGELOG.md', 'SECURITY.md',
    'docs/UPGRADE.md', 'docs/UPDATES.md', 'docs/images/overview.png',
)
REPO = '137985990/aapanel-gpt-firewall'
API = 'https://api.github.com/repos/' + REPO + '/releases'
DOWNLOAD = 'https://github.com/' + REPO + '/releases/download/v0.1.1/'
ASSET = 'aapanel-gpt-firewall-0.1.1-upgrade.zip'


class UpdateServiceTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(updater, 'update_service.py has not been implemented')
        self.temp = tempfile.TemporaryDirectory(prefix='firewall-update-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plugin = self.root / 'www/server/panel/plugin/free_waf'
        self.runtime = self.root / 'www/server/free_waf'
        for name in FILES:
            if name in ('website_statistics.py', 'update_service.py'):
                continue
            self.write(self.plugin / name, b'# old managed code\n')
        self.write(self.plugin / 'info.json', json.dumps({'name': 'free_waf', 'versions': '0.1'}).encode())
        self.write(self.runtime / 'init.lua', b'old runtime\n')
        for name in ('rule.json', 'config.json', 'site.json', 'data/keep.json', 'data/nested/log.txt'):
            self.write(self.plugin / name, b'preserve private plugin state')
        for name in ('config.json', 'site.json', 'rule/scan_black.json', 'rule/ip_black.json', 'drop_ip.log'):
            self.write(self.runtime / name, b'preserve private runtime state')
        self.write(self.root / 'www/wwwlogs/site.log', b'preserve requests')
        self.now = 1000000.0
        self.requests = []
        self.spawn_calls = []
        self.install_calls = []
        self.reload_calls = []
        self.payload = self.archive()
        self.configure_release()
        self.service = self.make_service()

    @staticmethod
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def archive(self, changes=None, extra=None):
        payloads = {name: b'# new managed code\n' for name in FILES}
        payloads['info.json'] = json.dumps({'name': 'free_waf', 'versions': '0.1.1'}).encode()
        payloads['init.lua'] = b'new runtime\n'
        payloads['install.sh'] = b'#!/bin/bash\nexit 0\n'
        payloads.update(changes or {})
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, value in payloads.items():
                entry = zipfile.ZipInfo('free_waf/' + name)
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, value)
            for entry, value in (extra or []):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    archive.writestr(entry, value)
        return stream.getvalue()

    def configure_release(self, **overrides):
        self.checksums = (hashlib.sha256(self.payload).hexdigest() + '  ' + ASSET + '\n').encode()
        self.release = {
            'tag_name': 'v0.1.1', 'draft': False, 'prerelease': True,
            'published_at': '2026-10-22T12:00:00Z', 'name': 'Upgrade prerelease', 'body': 'release notes',
            'assets': [
                {'name': ASSET, 'size': len(self.payload), 'state': 'uploaded',
                 'browser_download_url': DOWNLOAD + ASSET,
                 'digest': 'sha256:' + hashlib.sha256(self.payload).hexdigest()},
                {'name': 'SHA256SUMS', 'size': len(self.checksums), 'state': 'uploaded',
                 'browser_download_url': DOWNLOAD + 'SHA256SUMS'},
            ],
        }
        self.release.update(overrides)
        self.releases = [self.release]

    def transport(self, url, *, timeout, max_bytes):
        self.requests.append((url, timeout, max_bytes))
        if url == API + '?per_page=100':
            return json.dumps(self.releases).encode()
        if url == API + '/tags/v0.1.1':
            return json.dumps(self.release).encode()
        if url == DOWNLOAD + ASSET:
            return self.payload
        if url == DOWNLOAD + 'SHA256SUMS':
            return self.checksums
        raise AssertionError('Unexpected network request: ' + url)

    def spawn(self, argv, **kwargs):
        self.spawn_calls.append((argv, kwargs))
        return mock.Mock(pid=123456)

    def installer(self, plugin):
        self.install_calls.append(plugin)
        self.write(self.runtime / 'init.lua', (plugin / 'init.lua').read_bytes())
        self.write(plugin / 'install-status.json', json.dumps({
            'status': 'success', 'stage': 'complete', 'operation': 'install',
            'version': '0.1.1', 'plugin_name': 'free_waf', 'waf_active': True,
            'runtime_changed': True,
            'task_id': json.loads((plugin / '.gpt-firewall-install.lock/owner.json').read_text())['task_id'],
            'runtime_write': dict(dev=(self.runtime / 'init.lua').stat().st_dev,
                                  ino=(self.runtime / 'init.lua').stat().st_ino,
                                  sha256=hashlib.sha256((self.runtime / 'init.lua').read_bytes()).hexdigest()),
        }).encode())
        return 0

    def make_service(self, **kwargs):
        options = dict(transport=self.transport, spawn=self.spawn, installer=self.installer,
                       test_mode=True, clock=lambda: self.now)
        options.update(kwargs)
        return updater.UpdateService(self.plugin, **options)

    def snapshot(self):
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob('*') if path.is_file()
                and '/data/updates/' not in path.as_posix() and path.name != 'install-status.json'}

    def run_job(self):
        started = self.service.start('v0.1.1')
        self.assertTrue(started['status'], started)
        self.service.run_job(started['job_id'])
        return self.service.status()['job']

    def assert_rejected_package(self, payload):
        self.payload = payload
        self.configure_release()
        before = self.snapshot()
        job = self.run_job()
        self.assertEqual(job['state'], 'failed', job)
        self.assertFalse(self.install_calls)
        self.assertEqual(self.snapshot(), before)

    def test_version_and_bridge_contract_includes_published_prereleases(self):
        result = self.service.check()
        self.assertTrue(result['status'], result)
        self.assertEqual(updater.PLUGIN_VERSION, '0.1.9')
        self.assertEqual(result['current_version'], '0.1')
        self.assertEqual(result['latest_version'], '0.1.1')
        self.assertEqual(result['tag'], 'v0.1.1')
        self.assertTrue(result['available'])
        self.assertTrue(result['prerelease'])
        self.assertIn('notes', result)
        self.assertFalse(result['error'])
        self.assertIn('签名', result['warning'])
        self.assertEqual(set(updater.MANAGED_FILES), set(FILES))

    def test_published_v018_can_discover_v019_without_installing(self):
        self.write(self.plugin / 'info.json', json.dumps({'name': 'free_waf', 'versions': '0.1.8'}).encode())
        self.releases = [json.loads(json.dumps(self.release).replace('0.1.1', '0.1.9'))]
        result = self.service.check()
        self.assertTrue(result['status'], result)
        self.assertEqual(result['current_version'], '0.1.8')
        self.assertEqual(result['latest_version'], '0.1.9')
        self.assertEqual(result['tag'], 'v0.1.9')
        self.assertTrue(result['available'], result)
        self.assertFalse(self.spawn_calls)
        self.assertFalse(self.install_calls)

    def test_numeric_order_draft_filter_and_short_version_equivalence(self):
        other = dict(self.release, tag_name='v0.1.10', assets=[])
        draft = dict(self.release, tag_name='v99.0.0', draft=True)
        short = dict(self.release, tag_name='v0.1', assets=[])
        self.releases = [self.release, draft, short, other]
        result = self.service.check()
        self.assertEqual([r['version'] for r in result['releases']], ['0.1.10', '0.1.1', '0.1.0'])
        self.assertEqual(updater.parse_version('v0.1'), updater.parse_version('0.1.0'))

    def test_cache_six_hours_and_forced_checks_rate_limited(self):
        self.assertTrue(self.service.check()['status'])
        self.assertTrue(self.make_service().check()['cached'])
        self.service.check(force=True)
        self.assertEqual(len(self.requests), 1)
        self.now += 61
        self.service.check(force=True)
        self.assertEqual(len(self.requests), 2)
        self.now += 6 * 3600 + 1
        self.service.check()
        self.assertEqual(len(self.requests), 3)
        self.assertTrue(all(timeout == 10 for _, timeout, _ in self.requests))

    def test_network_failure_is_safe_chinese_and_retry_bounded(self):
        def broken(*args, **kwargs):
            self.requests.append('failed')
            raise OSError('SECRET token and /private/path')
        service = self.make_service(transport=broken)
        result = service.check(force=True)
        self.assertFalse(result['status'])
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertRegex(result['error'], '[\u4e00-\u9fff]')
        service.check(force=True)
        self.assertEqual(len(self.requests), 1)

    def test_bad_tags_and_current_or_older_versions_never_spawn(self):
        for tag in ('https://evil.invalid/x', '../v0.1.1', 'v0.1.1;id', 'v0.1', 'v0.0.9', 'v0.1.0', 'v2.0.0'):
            with self.subTest(tag=tag):
                self.assertFalse(self.service.start(tag)['status'])
        self.assertFalse(self.spawn_calls)

    def test_start_persists_before_spawn_and_does_not_install_inline(self):
        def spawn(argv, **kwargs):
            status = self.make_service().status()
            self.assertEqual(status['job']['state'], 'queued')
            self.assertEqual(argv[-2], '--job')
            self.assertEqual(argv[1], '-B')
            self.assertTrue(kwargs['start_new_session'])
            self.assertFalse(kwargs.get('shell', False))
            return mock.Mock(pid=123456)
        service = self.make_service(spawn=spawn)
        result = service.start('v0.1.1')
        self.assertTrue(result['status'], result)
        self.assertFalse(self.install_calls)
        self.assertEqual(service.status()['job']['id'], result['job_id'])

    def test_success_preserves_private_state_and_backs_up_only_managed_code(self):
        before = self.snapshot()
        job = self.run_job()
        self.assertEqual(job['state'], 'succeeded', job)
        self.assertEqual(job['target_version'], '0.1.1')
        self.assertEqual((self.runtime / 'init.lua').read_bytes(), b'new runtime\n')
        for name, data in before.items():
            relative = Path(name)
            if str(relative).startswith(str(self.plugin.relative_to(self.root))) and relative.relative_to(self.plugin.relative_to(self.root)).as_posix() in FILES:
                continue
            if relative == (self.runtime / 'init.lua').relative_to(self.root):
                continue
            self.assertEqual((self.root / name).read_bytes(), data)
        backup = self.plugin / 'data/updates' / job['id'] / 'backup'
        self.assertEqual((backup / 'runtime/init.lua').read_bytes(), b'old runtime\n')
        self.assertFalse(list(backup.rglob('rule.json')))
        self.assertFalse(list(backup.rglob('site.json')))
        self.assertNotIn(str(self.root), json.dumps(self.service.status()))

    def test_installer_failure_restores_every_code_file_runtime_and_new_module_absence(self):
        def failing(plugin):
            self.installer(plugin)
            return 1
        self.service = self.make_service(installer=failing)
        before = self.snapshot()
        with mock.patch.object(self.service, '_restore_nginx', side_effect=lambda: self.reload_calls.append('restore')):
            job = self.run_job()
        self.assertEqual(job['state'], 'failed', job)
        self.assertEqual(job['rollback']['state'], 'restored')
        self.assertEqual(self.reload_calls, ['restore'])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.plugin / 'website_statistics.py').exists())

    def test_wrong_installer_status_version_is_failure_and_restores_runtime(self):
        def wrong(plugin):
            self.installer(plugin)
            status = json.loads((plugin / 'install-status.json').read_text())
            status['version'] = '0.1'
            self.write(plugin / 'install-status.json', json.dumps(status).encode())
            return 0
        self.service = self.make_service(installer=wrong)
        before = self.snapshot()
        with mock.patch.object(self.service, '_restore_nginx'):
            job = self.run_job()
        self.assertEqual(job['state'], 'failed')
        self.assertEqual(self.snapshot(), before)

    def test_missing_or_stale_installer_status_is_failure(self):
        self.write(self.plugin / 'install-status.json', json.dumps({
            'status': 'success', 'version': '0.1.1', 'plugin_name': 'free_waf',
            'operation': 'install', 'stage': 'complete',
        }).encode())
        self.service = self.make_service(installer=lambda plugin: 0)
        before = self.snapshot()
        with mock.patch.object(self.service, '_restore_nginx'):
            job = self.run_job()
        self.assertEqual(job['state'], 'failed')
        self.assertEqual(self.snapshot(), before)

    def test_runtime_restoration_attempted_even_if_one_code_restore_fails(self):
        def failing(plugin):
            self.installer(plugin)
            return 1
        self.service = self.make_service(installer=failing)
        original = self.service._atomic_write
        def write(path, data, **kwargs):
            if path == self.plugin / 'index.html' and data == b'# old managed code\n':
                raise OSError('SECRET restore detail')
            return original(path, data, **kwargs)
        with mock.patch.object(self.service, '_atomic_write', side_effect=write), mock.patch.object(self.service, '_restore_nginx'):
            job = self.run_job()
        self.assertEqual(job['rollback']['state'], 'failed')
        self.assertEqual((self.runtime / 'init.lua').read_bytes(), b'old runtime\n')
        self.assertEqual((self.plugin / 'free_waf_main.py').read_bytes(), b'# old managed code\n')
        self.assertNotIn('SECRET', json.dumps(job))

    def test_status_write_failure_cannot_prevent_runtime_or_code_rollback(self):
        def failing(plugin):
            self.installer(plugin)
            return 1
        self.service = self.make_service(installer=failing)
        before = self.snapshot()
        save = self.service._save
        def broken(path, data):
            if path.name == 'job.json' and data.get('stage') == 'rollback':
                raise OSError('SECRET status failure')
            return save(path, data)
        with mock.patch.object(self.service, '_save', side_effect=broken), mock.patch.object(self.service, '_restore_nginx'):
            job = self.run_job()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(job['state'], 'failed')
        self.assertEqual(job['rollback']['state'], 'restored')

    def test_stale_installer_report_cannot_authorize_runtime_rollback(self):
        self.write(self.plugin / 'install-status.json', json.dumps({
            'status': 'success', 'version': '0.1', 'waf_active': False, 'runtime_changed': False,
        }).encode())
        def failing(plugin):
            self.write(self.runtime / 'init.lua', (plugin / 'init.lua').read_bytes())
            raise RuntimeError('secret')
        self.service = self.make_service(installer=failing)
        before = self.snapshot()
        with mock.patch.object(self.service, '_restore_nginx') as restore:
            job = self.run_job()
        self.assertEqual(job['state'], 'failed')
        self.assertEqual((self.runtime / 'init.lua').read_bytes(), b'new runtime\n')
        self.assertIn('runtime', job['rollback']['conflicts'])
        after = self.snapshot()
        runtime = str((self.runtime / 'init.lua').relative_to(self.root))
        self.assertEqual({k: v for k, v in after.items() if k != runtime},
                         {k: v for k, v in before.items() if k != runtime})
        restore.assert_not_called()

    def test_concurrent_unapplied_code_and_runtime_edits_are_preserved_without_installer(self):
        write = self.service._atomic_write
        external = b'external administrator repair\n'
        def concurrent(path, data, **kwargs):
            result = write(path, data, **kwargs)
            if path == self.plugin / 'info.json' and b'0.1.1' in data:
                self.write(self.plugin / 'index.html', external)
                self.write(self.runtime / 'init.lua', external)
            return result
        with mock.patch.object(self.service, '_atomic_write', side_effect=concurrent), mock.patch.object(self.service, '_restore_nginx') as reload:
            job = self.run_job()
        self.assertFalse(self.install_calls)
        self.assertEqual((self.plugin / 'index.html').read_bytes(), external)
        self.assertEqual((self.runtime / 'init.lua').read_bytes(), external)
        self.assertEqual(job['rollback']['state'], 'failed')
        self.assertIn('index.html', job['rollback']['conflicts'])
        reload.assert_not_called()
        self.assertFalse(self.service.start('v0.1.1')['status'])

    def test_concurrent_edits_of_applied_code_and_runtime_are_not_rolled_back(self):
        external = b'external administrator repair\n'
        def concurrent(plugin):
            self.installer(plugin)
            self.write(plugin / 'index.html', external)
            self.write(self.runtime / 'init.lua', external)
            return 1
        self.service = self.make_service(installer=concurrent)
        with mock.patch.object(self.service, '_restore_nginx') as reload:
            job = self.run_job()
        self.assertEqual((self.plugin / 'index.html').read_bytes(), external)
        self.assertEqual((self.runtime / 'init.lua').read_bytes(), external)
        self.assertEqual(job['rollback']['state'], 'failed')
        self.assertEqual(set(job['rollback']['conflicts']), {'index.html', 'runtime'})
        self.assertEqual((self.plugin / 'free_waf_main.py').read_bytes(), b'# old managed code\n')
        reload.assert_not_called()

    def test_new_managed_file_created_externally_before_apply_is_not_overwritten(self):
        external = b'external module\n'
        write = self.service._atomic_write
        def concurrent(path, data, **kwargs):
            result = write(path, data, **kwargs)
            if path == self.plugin / 'info.json' and b'0.1.1' in data:
                self.write(self.plugin / 'website_statistics.py', external)
            return result
        with mock.patch.object(self.service, '_atomic_write', side_effect=concurrent):
            job = self.run_job()
        self.assertEqual((self.plugin / 'website_statistics.py').read_bytes(), external)
        self.assertEqual(job['rollback']['state'], 'failed')
        self.assertIn('website_statistics.py', job['rollback']['conflicts'])
        self.assertFalse(self.install_calls)

    def test_real_http_response_drip_feed_obeys_total_body_deadline(self):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        stop = threading.Event()
        def drip():
            try:
                server.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n')
                for _ in range(32):
                    if stop.wait(0.03):
                        break
                    server.sendall(b'x')
            except OSError:
                pass
        thread = threading.Thread(target=drip)
        thread.start()
        response = http.client.HTTPResponse(client)
        response.begin()
        response.url = DOWNLOAD + ASSET
        opener = mock.Mock()
        opener.open.return_value = response
        started = time.monotonic()
        try:
            with mock.patch.object(updater.urllib.request, 'build_opener', return_value=opener):
                with self.assertRaises((TimeoutError, updater.UpdateError)):
                    updater._transport(DOWNLOAD + ASSET, timeout=0.15, max_bytes=64)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.5, 'continuous bytes must not reset the total deadline')
        finally:
            stop.set()
            thread.join(2)

    def test_normal_chunked_github_response_is_supported(self):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        server.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n')
        response = http.client.HTTPResponse(client)
        response.begin()
        response.url = DOWNLOAD + ASSET
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(updater.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(updater._transport(DOWNLOAD + ASSET, timeout=1, max_bytes=256), b'x')

    def test_default_network_transport_uses_a_separately_timed_process(self):
        self.assertTrue(callable(getattr(updater, '_isolated_transport', None)))
        service = updater.UpdateService(self.plugin, test_mode=True)
        self.assertIs(service._transport, updater._isolated_transport)

    def local_network_process(self, prefix, suffix, delay, timeout):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        stop = threading.Event()

        def serve():
            try:
                with listener.accept()[0] as peer:
                    peer.sendall(prefix)
                    for byte in suffix:
                        if stop.wait(delay):
                            return
                        peer.sendall(bytes([byte]))
            except OSError:
                pass

        thread = threading.Thread(target=serve)
        thread.start()
        original_popen = subprocess.Popen
        processes = []
        script = (
            'import http.client,runpy,socket,sys,urllib.request; '
            'from unittest import mock; '
            'port=int(sys.argv.pop(1)); sys.argv=sys.argv[1:]; '
            'sock=socket.create_connection(("127.0.0.1",port),timeout=3); '
            'response=http.client.HTTPResponse(sock); '
            'opener=mock.Mock(); '
            '\ndef connect(*args,**kwargs):\n response.begin(); response.url=args[0].full_url; return response\n'
            'opener.open.side_effect=connect\n'
            'with mock.patch.object(urllib.request,"build_opener",return_value=opener):\n'
            ' runpy.run_path(sys.argv[0],run_name="__main__")\n'
        )

        def spawn(argv, **kwargs):
            self.assertEqual(argv[:2], [sys.executable, '-B'])
            process = original_popen([sys.executable, '-B', '-c', script,
                                      str(listener.getsockname()[1])] + argv[2:], **kwargs)
            processes.append(process)
            return process

        try:
            with mock.patch.object(updater.subprocess, 'Popen', side_effect=spawn):
                return updater._isolated_transport(DOWNLOAD + ASSET, timeout=timeout, max_bytes=256)
        finally:
            stop.set()
            listener.close()
            thread.join(4)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(processes[0].returncode, 'download process must be reaped')

    def test_real_download_process_supports_normal_chunked_responses(self):
        self.assertEqual(self.local_network_process(
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n',
            b'1\r\nx\r\n0\r\n\r\n', 0, 3), b'x')

    def test_real_download_process_bounds_slow_headers_chunks_and_body(self):
        for prefix, suffix in (
            (b'HTTP/1.1 200 OK\r\nX-Slow: ', b'a' * 80 + b'\r\nContent-Length: 1\r\n\r\nx'),
            (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n',
             b'1;' + b'a' * 80 + b'\r\nx\r\n0\r\n\r\n'),
            (b'HTTP/1.1 200 OK\r\nContent-Length: 80\r\n\r\n', b'x' * 80),
        ):
            with self.subTest(prefix=prefix):
                started = time.monotonic()
                with self.assertRaises(updater.UpdateError):
                    self.local_network_process(prefix, suffix, 0.03, 0.4)
                self.assertLess(time.monotonic() - started, 2, 'network timeout must cover protocol framing')

    def test_network_worker_rejects_untrusted_urls_before_spawning(self):
        with mock.patch.object(updater.subprocess, 'Popen') as spawn:
            with self.assertRaises(updater.UpdateError):
                updater._isolated_transport('https://untrusted.invalid/', timeout=1, max_bytes=256)
            spawn.assert_not_called()

    def test_success_changes_code_mtime_for_backend_reload(self):
        target = self.plugin / 'free_waf_main.py'
        os.utime(target, (100000, 100000))
        old = target.stat().st_mtime_ns
        self.assertEqual(self.run_job()['state'], 'succeeded')
        self.assertGreater(target.stat().st_mtime_ns, old)

    def test_installer_failure_preserves_fixed_diagnostics_before_rollback(self):
        def failing(plugin):
            report = dict(operation='install', version='0.1.1', plugin_name='free_waf',
                          status='failed', stage='preflight', waf_active=False,
                          runtime_changed=False, task_id=self.service._install_owner['task_id'],
                          diagnostic_code='missing_resource',
                          diagnostic_resource='site.json', message='SECRET raw installer output')
            self.write(plugin / 'install-status.json', json.dumps(report).encode())
            return 1
        self.service = self.make_service(installer=failing)
        before = self.snapshot()
        job = self.run_job()
        self.assertEqual(job['state'], 'failed')
        self.assertEqual(job['rollback']['state'], 'restored')
        self.assertEqual(self.snapshot(), before)
        detail = job.get('installer', {})
        self.assertEqual(detail.get('exit_code'), 1)
        self.assertEqual(detail.get('stage'), 'preflight')
        self.assertEqual(detail.get('diagnostic_code'), 'missing_resource')
        self.assertEqual(detail.get('resource'), 'site.json')
        self.assertIn('缺失', detail.get('reason', ''))
        self.assertNotIn('SECRET', json.dumps(job))

    def test_inactive_success_is_not_reported_as_enabled_protection(self):
        def inactive(plugin):
            self.installer(plugin)
            report = json.loads((plugin / 'install-status.json').read_text())
            report['waf_active'] = False
            self.write(plugin / 'install-status.json', json.dumps(report).encode())
            return 0
        self.service = self.make_service(installer=inactive)
        job = self.run_job()
        self.assertEqual(job['state'], 'succeeded')
        self.assertIs(job.get('waf_active'), False)
        self.assertIs(job.get('installer', {}).get('waf_active'), False)
        self.assertIn('未启用', job['message'])
        self.assertIn('未重载', job['message'])
        self.assertFalse(self.reload_calls)

    def test_untrusted_installer_details_are_not_exposed(self):
        def failing(plugin):
            self.installer(plugin)
            report = json.loads((plugin / 'install-status.json').read_text())
            report.update(status='failed', stage='SECRET_STAGE',
                          diagnostic_code='SECRET_CODE', diagnostic_resource='SECRET_FILE',
                          reason='SECRET_REASON', message='SECRET_MESSAGE', waf_active='false')
            self.write(plugin / 'install-status.json', json.dumps(report).encode())
            return 7
        self.service = self.make_service(installer=failing)
        job = self.run_job()
        self.assertEqual(job['state'], 'failed')
        self.assertEqual(job.get('installer', {}).get('exit_code'), 7)
        self.assertNotIn('SECRET', json.dumps(job))
        self.assertNotIn('waf_active', job.get('installer', {}))

    def test_stale_installer_report_is_not_reused_as_failure_diagnostics(self):
        path = self.plugin / 'install-status.json'
        self.write(path, json.dumps({'status': 'failed', 'stage': 'nginx_reload',
            'version': '0.1.1', 'plugin_name': 'free_waf', 'operation': 'install',
            'diagnostic_code': 'missing_resource', 'diagnostic_resource': 'site.json'}).encode())
        self.service = self.make_service(installer=lambda plugin: 1)
        job = self.run_job()
        self.assertEqual(job['state'], 'failed')
        self.assertNotIn('diagnostic_code', job.get('installer', {}))
        self.assertNotIn('stage', job.get('installer', {}))

    def test_new_status_enriches_old_updater_success_only_with_matching_report(self):
        job = self.run_job()
        path = self.plugin / 'install-status.json'
        report = json.loads(path.read_text())
        report['waf_active'] = False
        self.write(path, json.dumps(report).encode())
        os.utime(path, (self.now, self.now))
        saved_path = self.plugin / 'data/updates/job.json'
        saved = json.loads(saved_path.read_text())
        saved.pop('installer', None)
        self.service._save(saved_path, saved)
        enriched = self.service.status()['job']
        self.assertIs(enriched.get('installer', {}).get('waf_active'), False)
        self.assertIs(enriched.get('waf_active'), False)
        self.assertNotIn('exit_code', enriched['installer'])
        os.utime(path, (self.now - 1, self.now - 1))
        stale = self.service.status()['job']
        self.assertNotIn('installer', stale)
        self.assertNotIn('waf_active', stale)
        os.utime(path, (self.now + 0.5, self.now + 0.5))
        later = self.service.status()['job']
        self.assertNotIn('installer', later)
        self.assertNotIn('waf_active', later)

    def test_public_job_drops_unknown_or_private_installer_fields(self):
        job = self.run_job()
        saved_path = self.plugin / 'data/updates/job.json'
        saved = json.loads(saved_path.read_text())
        saved['installer'] = dict(stage=['SECRET'], exit_code=True,
            diagnostic_code={'SECRET': 1}, resource='SECRET_PATH',
            reason='SECRET_TEXT', waf_active='false', private='SECRET')
        self.service._save(saved_path, saved)
        result = self.service.status()
        self.assertTrue(result['status'])
        self.assertEqual(result['job']['installer'], {})
        self.assertNotIn('SECRET', json.dumps(result))

    def test_restore_reload_error_is_reported_without_hiding_file_restore(self):
        def failing(plugin):
            self.installer(plugin)
            raise RuntimeError('SECRET installer detail')
        self.service = self.make_service(installer=failing)
        before = self.snapshot()
        with mock.patch.object(self.service, '_restore_nginx', side_effect=RuntimeError('SECRET nginx')):
            job = self.run_job()
        self.assertEqual(job['rollback']['state'], 'failed')
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn('SECRET', json.dumps(job))

    def test_runtime_restore_failure_never_reloads_unrestored_candidate(self):
        def failing(plugin):
            self.installer(plugin)
            return 1
        self.service = self.make_service(installer=failing)
        write = self.service._atomic_write
        def broken(path, data, **kwargs):
            if path == self.runtime / 'init.lua' and data == b'old runtime\n':
                raise OSError('cannot restore runtime')
            return write(path, data, **kwargs)
        with mock.patch.object(self.service, '_atomic_write', side_effect=broken), mock.patch.object(self.service, '_restore_nginx') as reload:
            job = self.run_job()
        self.assertEqual(job['rollback']['state'], 'failed')
        self.assertIn('runtime', job['rollback']['errors'])
        reload.assert_not_called()
        self.assertFalse(self.service.start('v0.1.1')['status'])

    def test_bad_python_is_compiled_before_any_replacement(self):
        self.assert_rejected_package(self.archive({'free_waf_main.py': b'def broken(:\n'}))

    def test_checksums_and_optional_asset_digest_are_both_required_to_match(self):
        self.checksums = ('0' * 64 + '  ' + ASSET + '\n').encode()
        self.release['assets'][1]['size'] = len(self.checksums)
        self.assertEqual(self.run_job()['state'], 'failed')
        self.assertFalse(self.install_calls)

    def test_asset_digest_mismatch_is_rejected(self):
        self.release['assets'][0]['digest'] = 'sha256:' + '0' * 64
        self.assertEqual(self.run_job()['state'], 'failed')
        self.assertFalse(self.install_calls)

    def test_checksum_asset_own_digest_is_verified(self):
        self.release['assets'][1]['digest'] = 'sha256:' + '0' * 64
        self.assertEqual(self.run_job()['state'], 'failed')
        self.assertFalse(self.install_calls)

    def test_corrupt_status_blocks_start_instead_of_erasing_unknown_job(self):
        self.write(self.plugin / 'data/updates/job.json', b'{broken')
        self.assertFalse(self.service.status()['status'])
        self.assertFalse(self.service.start('v0.1.1')['status'])
        self.assertEqual((self.plugin / 'data/updates/job.json').read_bytes(), b'{broken')
        self.assertFalse(self.spawn_calls)

    def test_archive_rejection_is_terminal_not_a_worker_crash(self):
        self.payload = b'not a zip archive'
        self.configure_release()
        before = self.snapshot()
        job = self.run_job()
        self.assertEqual(job['state'], 'failed')
        self.assertEqual(self.snapshot(), before)

    def test_package_allowlist_matches_release_builder(self):
        import ast
        source = Path(updater.__file__).parent / 'tools/build_release.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        values = [ast.literal_eval(node.value) for node in tree.body
                  if isinstance(node, ast.Assign) and any(
                      isinstance(target, ast.Name) and target.id == 'PLUGIN_FILES' for target in node.targets)]
        self.assertEqual(set(values[0]), set(updater.MANAGED_FILES))

    def test_optional_digest_absence_is_supported_with_checksum(self):
        del self.release['assets'][0]['digest']
        self.assertEqual(self.run_job()['state'], 'succeeded')

    def test_asset_size_mismatch_fails_closed(self):
        self.release['assets'][0]['size'] += 1
        self.assertEqual(self.run_job()['state'], 'failed')
        self.assertFalse(self.install_calls)

    def test_wrong_asset_url_is_rejected_before_download(self):
        self.release['assets'][0]['browser_download_url'] = 'https://evil.invalid/' + ASSET
        self.assertFalse(self.service.start('v0.1.1')['status'])
        self.assertFalse(any(url.startswith('https://evil') for url, _, _ in self.requests))

    def test_archive_traversal_unknown_absolute_and_backslash_entries_are_rejected(self):
        for name in ('free_waf/../escape', '/tmp/escape', 'free_waf/data/state.json',
                     'free_waf/rule.json', 'free_waf\\index.html', 'free_waf/C:/escape'):
            with self.subTest(name=name):
                self.assert_rejected_package(self.archive(extra=[(name, b'bad')]))

    def test_archive_links_and_duplicates_are_rejected(self):
        link = zipfile.ZipInfo('free_waf/index.html')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        payload = self.archive()
        stream = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(payload)) as source, zipfile.ZipFile(stream, 'w') as destination:
            for entry in source.infolist():
                destination.writestr(link if entry.filename == link.filename else entry, source.read(entry))
        self.assert_rejected_package(stream.getvalue())

    def test_archive_duplicate_managed_entry_is_rejected(self):
        self.assert_rejected_package(self.archive(extra=[('free_waf/index.html', b'duplicate')]))

    def test_archive_encryption_flag_and_missing_managed_file_are_rejected(self):
        payload = bytearray(self.archive())
        offset = payload.find(b'PK\x01\x02')
        payload[offset + 8] |= 1
        self.assert_rejected_package(bytes(payload))
        stream = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(self.archive())) as source, zipfile.ZipFile(stream, 'w') as destination:
            for entry in source.infolist()[:-1]:
                destination.writestr(entry, source.read(entry))
        self.assert_rejected_package(stream.getvalue())

    def test_metadata_identity_or_version_mismatch_is_rejected(self):
        for info in ({'name': 'gpt_firewall', 'versions': '0.1.1'},
                     {'name': 'free_waf', 'versions': '9.0.0'}):
            with self.subTest(info=info):
                self.assert_rejected_package(self.archive({'info.json': json.dumps(info).encode()}))

    def test_archive_expansion_bomb_is_rejected(self):
        self.assert_rejected_package(self.archive({'index.html': b'A' * (1024 * 1024)}))

    def test_queued_job_blocks_other_instances_and_status_is_persistent(self):
        first = self.service.start('v0.1.1')
        self.assertTrue(first['status'])
        other = self.make_service()
        self.assertFalse(other.start('v0.1.1')['status'])
        self.assertEqual(other.status()['job']['id'], first['job_id'])
        self.assertEqual(len(self.spawn_calls), 1)

    def test_unknown_stale_job_is_reported_but_never_automatically_unblocked(self):
        first = self.service.start('v0.1.1')
        self.assertTrue(first['status'])
        self.now += updater.JOB_STALE_SECONDS + 1
        status = self.service.status()
        self.assertEqual(status['job']['state'], 'recovery_required')
        self.assertFalse(self.make_service().start('v0.1.1')['status'])
        self.assertEqual(len(self.spawn_calls), 1)

    def test_after_spawn_status_failure_never_marks_potentially_live_job_failed(self):
        save = self.service._save
        failed = []
        def broken(path, data):
            if path.name == 'job.json' and data.get('pid') and not failed:
                failed.append(True)
                raise OSError('secret status failure after process exists')
            return save(path, data)
        with mock.patch.object(self.service, '_save', side_effect=broken):
            result = self.service.start('v0.1.1')
        self.assertFalse(result['status'])
        job = self.service.status()['job']
        self.assertEqual(job['state'], 'queued')
        self.assertFalse(self.make_service().start('v0.1.1')['status'])

    @unittest.skipIf(os.name == 'nt', 'fcntl lock contention requires POSIX')
    def test_other_process_cannot_obtain_global_update_lock(self):
        script = (
            'import sys; from update_service import UpdateService, UpdateError; '
            'service=UpdateService(sys.argv[1], test_mode=True); '
            '\ntry:\n with service._lock(): pass\nexcept UpdateError: sys.exit(23)\n'
        )
        with self.service._lock():
            process = subprocess.run([sys.executable, '-B', '-c', script, str(self.plugin)],
                                     cwd=str(Path(updater.__file__).parent), capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 23, process.stderr)

    def test_two_workers_cannot_apply_the_same_queued_job(self):
        first = self.service.start('v0.1.1')
        entered, release = threading.Event(), threading.Event()
        def delayed(plugin):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('test synchronization timed out')
            return self.installer(plugin)
        self.service._installer = delayed
        thread = threading.Thread(target=self.service.run_job, args=(first['job_id'],))
        thread.start()
        try:
            self.assertTrue(entered.wait(5))
            contender = self.make_service()
            self.assertFalse(contender.start('v0.1.1')['status'])
        finally:
            release.set()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        result = self.make_service().run_job(first['job_id'])
        self.assertFalse(result['status'])
        self.assertEqual(len(self.install_calls), 1)

    def test_production_installer_uses_only_fixed_bash_argv(self):
        with self.service._install_lock('a' * 32), mock.patch.object(self.service, '_test_mode', False), \
                mock.patch.object(self.service, '_production'), \
                mock.patch.object(self.service, '_command', return_value=(0, b'')) as command:
            self.assertEqual(self.service._run_installer(self.plugin), 0)
        self.assertEqual(command.call_args.args[0], ['/bin/bash', str(self.plugin / 'install.sh'), 'install'])

    def test_future_upgrade_executes_new_package_installer_not_old_version(self):
        self.write(self.plugin / 'info.json', json.dumps({'name': 'free_waf', 'versions': '0.1.1'}).encode())
        candidate_installer = b'#!/bin/bash\n# new package version 0.1.2\nexit 0\n'
        payload = self.archive({
            'info.json': json.dumps({'name': 'free_waf', 'versions': '0.1.2'}).encode(),
            'install.sh': candidate_installer,
        })
        self.payload = payload
        self.configure_release()
        release = json.loads(json.dumps(self.release).replace('0.1.1', '0.1.2'))
        checksum = (hashlib.sha256(payload).hexdigest() + '  ' + ASSET.replace('0.1.1', '0.1.2') + '\n').encode()
        release['assets'][1]['size'] = len(checksum)
        urls = {API + '?per_page=100': json.dumps([release]).encode(),
                API + '/tags/v0.1.2': json.dumps(release).encode(),
                DOWNLOAD.replace('0.1.1', '0.1.2') + ASSET.replace('0.1.1', '0.1.2'): payload,
                DOWNLOAD.replace('0.1.1', '0.1.2') + 'SHA256SUMS': checksum}
        def transport(url, **kwargs):
            return urls[url]
        def installer(plugin):
            self.assertEqual((plugin / 'install.sh').read_bytes(), candidate_installer)
            self.installer(plugin)
            report = json.loads((plugin / 'install-status.json').read_text())
            report['version'] = '0.1.2'
            self.write(plugin / 'install-status.json', json.dumps(report).encode())
            return 0
        service = self.make_service(transport=transport, installer=installer)
        job = service.start('v0.1.2')
        self.assertTrue(job['status'], job)
        self.assertTrue(service.run_job(job['job_id'])['status'])
        self.assertEqual(service.status()['job']['target_version'], '0.1.2')

    def test_runtime_restore_uses_only_panel_nginx_and_active_hooks(self):
        nginx = self.root / 'www/server/nginx/sbin/nginx'
        config = self.root / 'www/server/nginx/conf/nginx.conf'
        self.write(nginx, b'fake executable')
        self.write(config, b'http {}')
        calls = []
        def command(arguments, **kwargs):
            calls.append(arguments)
            return 0, b'init_by_lua_file /www/server/free_waf/init.lua;\n'
        with mock.patch.object(self.service, '_command', side_effect=command):
            self.service._restore_nginx()
        self.assertEqual([call[1] for call in calls], ['-t', '-T', '-s'])
        self.assertTrue(all(call[0] == str(nginx) for call in calls))
        self.assertEqual(calls[-1][1:3], ['-s', 'reload'])
        calls.clear()
        with mock.patch.object(self.service, '_command', side_effect=lambda args, **kwargs: (calls.append(args) or 0, b'# init_by_lua_file /www/server/free_waf/init.lua;\n')):
            self.service._restore_nginx()
        self.assertFalse(any(call[1] == '-s' for call in calls))

    def test_spawn_failure_is_persisted_and_does_not_change_code(self):
        def broken(*args, **kwargs):
            raise OSError('SECRET executable')
        self.service = self.make_service(spawn=broken)
        before = self.snapshot()
        self.assertFalse(self.service.start('v0.1.1')['status'])
        job = self.service.status()['job']
        self.assertEqual(job['state'], 'failed')
        self.assertNotIn('SECRET', json.dumps(job))
        self.assertEqual(self.snapshot(), before)

    def test_without_fcntl_production_mutations_fail_closed(self):
        with mock.patch.object(updater, 'fcntl', None):
            service = self.make_service(test_mode=False)
            self.assertFalse(service.start('v0.1.1')['status'])
        self.assertFalse(self.spawn_calls)

    def test_symlinked_code_parent_or_update_directory_is_rejected(self):
        if os.name == 'nt':
            self.skipTest('symlink creation needs Windows privilege')
        outside = self.root / 'outside'
        outside.mkdir()
        docs = self.plugin / 'docs'
        import shutil
        shutil.rmtree(docs)
        docs.symlink_to(outside, target_is_directory=True)
        before = self.snapshot()
        self.assertEqual(self.run_job()['state'], 'failed')
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(list(outside.iterdir()))

    @unittest.skipIf(os.name == 'nt', 'symlink creation needs Windows privilege')
    def test_symlinked_update_store_is_rejected_before_any_request(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.plugin / 'data/updates').symlink_to(outside, target_is_directory=True)
        self.assertFalse(self.service.check()['status'])
        self.assertFalse(self.service.start('v0.1.1')['status'])
        self.assertFalse(self.requests)
        self.assertFalse(list(outside.iterdir()))

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink and file mode checks')
    def test_symlinked_runtime_is_rejected_and_managed_modes_are_preserved(self):
        target = self.plugin / 'free_waf_main.py'
        target.chmod(0o640)
        self.assertEqual(self.run_job()['state'], 'succeeded')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((self.plugin / 'data/updates/job.json').stat().st_mode), 0o600)

    def test_redirect_to_allowed_asset_host_remains_https_and_deadline_bounded(self):
        request = urllib.request.Request(DOWNLOAD + ASSET)
        request.timeout = 10
        handler = updater.ReleaseRedirectHandler()
        handler.deadline = 100.0
        with mock.patch.object(updater.time, 'monotonic', return_value=95.0):
            redirected = handler.redirect_request(request, None, 302, '', {},
                'https://release-assets.githubusercontent.com/github-production-release-asset/1/fixture?token=test')
        self.assertLessEqual(request.timeout, 5.0)
        self.assertTrue(redirected.full_url.startswith('https://release-assets.githubusercontent.com/'))

    def test_production_command_timeout_kills_process_group_and_waits(self):
        process = mock.Mock(pid=4321, returncode=-9)
        process.communicate.side_effect = [subprocess.TimeoutExpired('installer', 1), (b'', b'')]
        with mock.patch.object(updater.subprocess, 'Popen', return_value=process), mock.patch.object(updater.os, 'name', 'posix'), mock.patch.object(updater.os, 'killpg', create=True) as kill, mock.patch.object(updater.signal, 'SIGKILL', 9, create=True):
            with self.assertRaises(subprocess.TimeoutExpired):
                updater.UpdateService._command(['/fixed/executable'], timeout=1)
        kill.assert_called_once_with(4321, 9)
        self.assertEqual(process.communicate.call_count, 2)

    def test_redirect_policy_never_accepts_arbitrary_hosts_or_http(self):
        policy = updater.ReleaseRedirectHandler()
        request = urllib.request.Request(DOWNLOAD + ASSET)
        for url in ('http://release-assets.githubusercontent.com/x', 'https://evil.invalid/x',
                    'https://github.com/other/repo/releases/download/v1/a.zip',
                    'https://release-assets.githubusercontent.com.evil.invalid/x'):
            with self.subTest(url=url):
                with self.assertRaises(updater.UpdateError):
                    policy.redirect_request(request, None, 302, '', {}, url)


if __name__ == '__main__':
    unittest.main()
