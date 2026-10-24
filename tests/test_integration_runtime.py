"""Optional real Nginx fixture; never loads or edits production configuration."""
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

from update_service import IntegrationRepairService, PLUGIN_VERSION


@unittest.skipUnless(os.environ.get('GPT_FIREWALL_TEST_NGINX'), 'requires explicitly selected Lua-enabled Nginx')
class RealIntegrationRuntimeTest(unittest.TestCase):
    def test_real_access_handler_answers_nonce_only_on_local_health_server(self):
        binary = os.environ['GPT_FIREWALL_TEST_NGINX']
        with tempfile.TemporaryDirectory(prefix='gpt-firewall-isolated-nginx-') as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            (root / 'logs').mkdir()
            runtime = root / 'runtime'
            runtime.mkdir(mode=0o755)
            (runtime / 'rule').mkdir()
            (runtime / 'html').mkdir()
            config = {'open': True, 'cc': {'cycle': 60, 'endtime': 60, 'limit': 100, 'open': False, 'status': 403},
                      'retry': 6, 'retry_time': 60, 'retry_cycle': 60, 'reqfile_path': str(runtime / 'html'),
                      'scan': {'open': False, 'status': 403}, 'drop_abroad': {'open': False, 'status': 403}}
            for key in ('get', 'post', 'cookie', 'user-agent', 'other'):
                config[key] = {'reqfile': 'fixture.html', 'status': 403, 'open': False}
            (runtime / 'html/fixture.html').write_text('fixture')
            (runtime / 'config.json').write_text(json.dumps(config))
            (runtime / 'site.json').write_text(json.dumps({'example.invalid': {'open': True,
                'cc': dict(config['cc']), 'retry': 6, 'retry_time': 60, 'retry_cycle': 60,
                'disable_php_path': [], 'disable_path': [], 'disable_ext': [],
                'disable_upload_ext': [], 'url_rule': [['^/fixture-post$', 'forbidden-fixture']],
                'url_tell': []}}))
            (runtime / 'rule/scan_black.json').write_text(json.dumps({'cookie': [], 'header': [], 'args': []}))
            (runtime / 'rule/cn.json').write_text('[]')
            static = root / 'static'
            static.mkdir(mode=0o755)
            (static / 'fixture.txt').write_text('normal access handler completed')
            source = (Path(__file__).resolve().parents[1] / 'init.lua').read_text(encoding='utf-8')
            (root / 'init.lua').write_text(source.replace('local cpath = "/www/server/free_waf/"',
                                                        'local cpath = ' + json.dumps(str(runtime) + '/')))
            (root / 'access.lua').write_text('run_btwaf()\n')
            with socket.socket() as selected:
                selected.bind(('127.0.0.1', 0))
                port = selected.getsockname()[1]
            conf = root / 'nginx.conf'
            lua_library = Path(binary).resolve().parents[1] / 'lib/lua'
            lua_path = ('lua_package_path "' + str(lua_library) + '/?.lua;;";\n') if lua_library.is_dir() else ''
            managed = IntegrationRepairService.INCLUDE.decode().replace(
                '/www/server/free_waf/init.lua', str(root / 'init.lua')).replace(
                '/www/server/free_waf/waf.lua', str(root / 'access.lua')).replace(
                '/www/server/free_waf/.health-no-content', str(root / 'empty')).replace(
                '127.0.0.1:39091', '127.0.0.1:' + str(port))
            conf.write_text('pid ' + str(root / 'nginx.pid') + ';\nerror_log ' + str(root / 'error.log') + ' notice;\n'
                'worker_processes 1; events { worker_connections 32; } http {\n'
                'keepalive_timeout 0; keepalive_requests 1;\n' + lua_path + managed +
                'server { listen 127.0.0.1:' + str(port) + '; server_name example.invalid; access_log off;\n'
                'location / { root ' + str(static) + '; }\n'
                'location = /fixture-post { content_by_lua_block { ngx.say("normal post completed") } } } }\n')
            args = [binary, '-p', str(root) + '/', '-c', str(conf)]
            diagnostics = (root / 'startup.log').open('wb')
            self.addCleanup(diagnostics.close)
            process = subprocess.Popen(args + ['-g', 'daemon off;'], stdout=subprocess.DEVNULL, stderr=diagnostics)
            try:
                nonce = 'a' * 32
                result = None
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and process.poll() is None:
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=0.5)
                    try:
                        connection.request('GET', '/_gpt_firewall_health/' + nonce)
                        response = connection.getresponse()
                        payload = response.read(4096)
                        if response.status == 200:
                            result = json.loads(payload)
                            break
                    except (OSError, ValueError, http.client.HTTPException):
                        pass
                    finally:
                        connection.close()
                    time.sleep(0.05)
                diagnostic = (root / 'error.log').read_text() if (root / 'error.log').exists() else ''
                diagnostic += (root / 'startup.log').read_text()
                self.assertIsNotNone(result, diagnostic[-1800:])
                self.assertEqual(result['nonce'], nonce)
                self.assertEqual(result['version'], PLUGIN_VERSION)
                self.assertEqual(result['product'], 'aapanel GPT Firewall')
                self.assertIs(type(result['worker_pid']), int)
                _, started = IntegrationRepairService._process_identity(process.pid, Path(binary), b'master process')
                proof = IntegrationRepairService._probe_loop(Path(binary), str(process.pid) + ':' + started, port)
                self.assertTrue(proof['execution_verified'])
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
                try:
                    connection.request('GET', '/fixture.txt', headers={'Host': 'example.invalid'})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b'normal access handler completed')
                finally:
                    connection.close()
                for kind in ('no-length', 'chunked', 'json'):
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
                    try:
                        if kind == 'no-length':
                            connection.putrequest('POST', '/fixture-post', skip_host=True)
                            connection.putheader('Host', 'example.invalid')
                            connection.putheader('Content-Type', 'application/x-www-form-urlencoded')
                            connection.endheaders()
                        elif kind == 'chunked':
                            connection.request('POST', '/fixture-post', body=iter([b'normal=1']),
                                               headers={'Host': 'example.invalid',
                                                        'Content-Type': 'application/x-www-form-urlencoded'},
                                               encode_chunked=True)
                        else:
                            connection.request('POST', '/fixture-post', body=b'{"normal":1}',
                                               headers={'Host': 'example.invalid', 'Content-Type': 'application/json'})
                        response = connection.getresponse()
                        diagnostics = (root / 'error.log').read_text(errors='replace')[-4000:]
                        self.assertEqual(response.status, 200, kind + '\n' + diagnostics)
                        self.assertEqual(response.read().strip(), b'normal post completed', kind)
                    finally:
                        connection.close()
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
                try:
                    connection.request('GET', '/_gpt_firewall_health/invalid')
                    response = connection.getresponse()
                    self.assertEqual(response.status, 404)
                    self.assertNotIn(b'worker_pid', response.read())
                finally:
                    connection.close()
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)


if __name__ == '__main__':
    unittest.main()
