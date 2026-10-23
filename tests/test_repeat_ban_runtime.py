"""Opt-in real Nginx test, using only a disposable loopback configuration."""
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

from update_service import IntegrationRepairService


@unittest.skipUnless(os.environ.get('GPT_FIREWALL_TEST_NGINX'), 'requires explicitly selected Lua-enabled Nginx')
class RepeatBanRuntimeTest(unittest.TestCase):
    def test_cc_escalation_is_durable_site_only_and_revocable(self):
        binary = os.environ['GPT_FIREWALL_TEST_NGINX']
        with tempfile.TemporaryDirectory(prefix='gpt-firewall-repeat-isolated-') as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            (root / 'logs').mkdir()
            runtime = root / 'runtime'
            runtime.mkdir(mode=0o777)
            runtime.chmod(0o777)  # The disposable Nginx worker must write only its fixture snapshot.
            (runtime / 'rule').mkdir()
            (runtime / 'html').mkdir()
            config = {'open': True, 'log': False,
                      'cc': {'open': True, 'cycle': 1, 'endtime': 1, 'limit': 1, 'status': 403},
                      'retry': 6, 'retry_cycle': 60, 'retry_time': 60,
                      'reqfile_path': str(runtime / 'html'),
                      'scan': {'open': False, 'status': 403}, 'drop_abroad': {'open': False, 'status': 403}}
            for key in ('get', 'post', 'cookie', 'user-agent', 'other'):
                config[key] = {'open': False, 'reqfile': 'fixture.html', 'status': 403}
            (runtime / 'html/fixture.html').write_text('fixture rejection')
            (runtime / 'config.json').write_text(json.dumps(config))
            site = {'open': True, 'cc': dict(config['cc']), 'retry': 6, 'retry_cycle': 60, 'retry_time': 60,
                    'disable_php_path': [], 'disable_path': [], 'disable_ext': [], 'disable_upload_ext': [],
                    'url_rule': [], 'url_tell': []}
            policy = dict(enabled=True, window_seconds=86400,
                          tiers=[dict(threshold=5, ban_seconds=604800), dict(threshold=10, ban_seconds=2592000)])
            sites = {'fixture.example': dict(site, repeat_ban_policy=policy), 'other.example': dict(site)}
            sites['other.example']['cc'] = dict(config['cc'], open=False)
            (runtime / 'site.json').write_text(json.dumps(sites))
            (runtime / 'rule/scan_black.json').write_text(json.dumps({'cookie': [], 'header': [], 'args': []}))
            (runtime / 'rule/cn.json').write_text('[]')
            (runtime / 'rule/ip_white.json').write_text('[]')
            static = root / 'static'
            static.mkdir(mode=0o755)
            (static / 'fixture.txt').write_text('normal access completed')
            source = (Path(__file__).resolve().parents[1] / 'init.lua').read_text(encoding='utf-8')
            (root / 'init.lua').write_text(source.replace('local cpath = "/www/server/free_waf/"',
                                                        'local cpath = ' + json.dumps(str(runtime) + '/')))
            (root / 'access.lua').write_text('run_btwaf()\n')
            with socket.socket() as selected:
                selected.bind(('127.0.0.1', 0))
                port = selected.getsockname()[1]
            library = Path(binary).resolve().parents[1] / 'lib/lua'
            lua_path = ('lua_package_path "' + str(library) + '/?.lua;;";\n') if library.is_dir() else ''
            managed = IntegrationRepairService.INCLUDE.decode().replace(
                '/www/server/free_waf/init.lua', str(root / 'init.lua')).replace(
                '/www/server/free_waf/waf.lua', str(root / 'access.lua')).replace(
                '/www/server/free_waf/.health-no-content', str(root / 'empty')).replace(
                '127.0.0.1:39091', '127.0.0.1:' + str(port))
            conf = root / 'nginx.conf'
            conf.write_text('pid ' + str(root / 'nginx.pid') + ';\nerror_log ' + str(root / 'error.log') + ' notice;\n'
                'worker_processes 2; events { worker_connections 32; } http {\n'
                'keepalive_timeout 0; keepalive_requests 1;\n' + lua_path + managed +
                'server { listen 127.0.0.1:' + str(port) + '; server_name fixture.example; access_log off;\n'
                'location / { root ' + str(static) + '; } }\n'
                'server { listen 127.0.0.1:' + str(port) + '; server_name other.example; access_log off;\n'
                'location / { root ' + str(static) + '; } } }\n')
            args = [binary, '-p', str(root) + '/', '-c', str(conf), '-g', 'daemon off;']
            diagnostic_stream = (root / 'startup.log').open('wb')
            self.addCleanup(diagnostic_stream.close)
            process = None

            def request(path='/fixture.txt', host='fixture.example'):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
                try:
                    connection.request('GET', path, headers={'Host': host})
                    response = connection.getresponse()
                    return response.status, response.read(4096), dict(response.getheaders())
                finally:
                    connection.close()

            def start():
                nonlocal process
                process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=diagnostic_stream)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and process.poll() is None:
                    try:
                        if request('/_gpt_firewall_health/' + 'a' * 32, 'gpt-firewall-health.invalid')[0] == 200:
                            return
                    except (OSError, http.client.HTTPException):
                        pass
                    time.sleep(0.05)
                diagnostic = (root / 'startup.log').read_text(errors='replace')
                if (root / 'error.log').exists():
                    diagnostic += (root / 'error.log').read_text(errors='replace')
                self.fail(diagnostic[-2000:])

            def stop():
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)

            try:
                start()
                for count in range(5):
                    if count:
                        time.sleep(1.15)
                    self.assertEqual(request()[0], 200)
                    self.assertEqual(request()[0], 403)
                snapshot_file = runtime / 'repeat_bans.json'
                snapshot = json.loads(snapshot_file.read_text())
                self.assertEqual(len(snapshot['bans']), 1)
                record = snapshot['bans'][0]
                self.assertEqual(record['site'], 'fixture.example')
                self.assertEqual(record['trigger_count'], 5)
                self.assertEqual(record['duration'], 604800)
                time.sleep(1.15)  # The unchanged, legacy global one-second CC ban has expired.
                self.assertEqual(request(host='other.example')[0], 200)
                for _ in range(20):
                    status, body, _ = request()
                    self.assertEqual(status, 403)
                    self.assertIn(b'fixture rejection', body)
                self.assertEqual(json.loads(snapshot_file.read_text()), snapshot)
                import fcntl
                lock_path = runtime / '.repeat-bans.lock'
                self.assertTrue(lock_path.is_file(), 'runtime must use a fixed file lock')
                self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
                with lock_path.open('rb') as held:
                    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    before = time.monotonic()
                    status, body, _ = request('/remove_repeat_ban?site=fixture.example&ip=127.0.0.1')
                    self.assertLess(time.monotonic() - before, 1, 'lock contention must not block a worker')
                    self.assertEqual(status, 200)
                    self.assertFalse(json.loads(body)['status'])
                    self.assertEqual(json.loads(snapshot_file.read_text()), snapshot)
                stop()
                start()
                self.assertEqual(request()[0], 403)
                self.assertEqual(request(host='other.example')[0], 200)
                status, body, _ = request('/remove_repeat_ban?site=fixture.example&ip=127.0.0.1')
                self.assertEqual(status, 200)
                self.assertTrue(json.loads(body)['status'])
                self.assertEqual(json.loads(snapshot_file.read_text())['bans'], [])
                self.assertEqual(request()[0], 200)
            finally:
                stop()


if __name__ == '__main__':
    unittest.main()
