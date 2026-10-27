"""Opt-in real proxy tests; only synthetic requests and loopback listeners."""
import concurrent.futures
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BodyDigestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.connection.settimeout(3)
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            chunks = []
            total = 0
            while True:
                length = int(self.rfile.readline(128).split(b';', 1)[0], 16)
                if not length:
                    while self.rfile.readline(8192).strip():
                        pass
                    break
                total += length
                if total > 1024 * 1024:
                    raise ValueError('fixture body limit exceeded')
                chunks.append(self.rfile.read(length))
                if self.rfile.read(2) != b'\r\n':
                    raise ValueError('invalid fixture chunk terminator')
            body = b''.join(chunks)
        else:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 <= length <= 1024 * 1024:
                raise ValueError('fixture body limit exceeded')
            body = self.rfile.read(length)
        payload = json.dumps(dict(length=len(body), sha256=hashlib.sha256(body).hexdigest(),
                                  content_type=self.headers.get('Content-Type', ''),
                                  content_types=self.headers.get_all('Content-Type', []))).encode('ascii')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class DigestServerMixin:
    def read_report(self, response):
        payload = response.read()
        self.assertEqual(response.status, 200, payload[:300])
        worker = response.getheader('X-Fixture-Worker')
        if worker and hasattr(self, 'worker_pids'):
            with self.worker_lock:
                self.worker_pids.add(worker)
        return json.loads(payload)

    def post_with_content_types(self, connection, body, content_types, path='/buffer/form'):
        connection.putrequest('POST', path, skip_host=True, skip_accept_encoding=True)
        connection.putheader('Host', 'fixture.example')
        connection.putheader('Content-Length', str(len(body)))
        for content_type in content_types:
            connection.putheader('Content-Type', content_type)
        connection.endheaders(body)
        return connection.getresponse()

    def start_digest_server(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), BodyDigestHandler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(3)

        self.addCleanup(stop)
        return server.server_port

    def assert_forwarded(self, connection, body, content_type, chunked=False, path='/buffer/form'):
        headers = {'Host': 'fixture.example', 'Content-Type': content_type}
        supplied = iter([body[i:i + 257] for i in range(0, len(body), 257)]) if chunked else body
        connection.request('POST', path, body=supplied, headers=headers, encode_chunked=chunked)
        response = connection.getresponse()
        report = self.read_report(response)
        self.assertEqual(report['length'], len(body))
        self.assertEqual(report['sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(report['content_type'], content_type)
        return report


class DigestFixtureTest(DigestServerMixin, unittest.TestCase):
    def test_upstream_measures_real_bytes_for_fixed_length_and_chunked_requests(self):
        port = self.start_digest_server()
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        try:
            first = self.assert_forwarded(connection, b'field=first&field=second', 'application/x-www-form-urlencoded')
            second = self.assert_forwarded(connection, b'field=changed', 'application/x-www-form-urlencoded', chunked=True)
            self.assertNotEqual(first['sha256'], second['sha256'])
        finally:
            connection.close()

    def test_raw_fixture_preserves_repeated_content_type_headers(self):
        port = self.start_digest_server()
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        try:
            types = ['application/octet-stream', 'application/x-www-form-urlencoded']
            body = b'field=synthetic'
            response = self.post_with_content_types(connection, body, types)
            report = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual(report['content_types'], types)
            self.assertEqual(report['length'], len(body))
            self.assertEqual(report['sha256'], hashlib.sha256(body).hexdigest())
        finally:
            connection.close()


@unittest.skipUnless(os.environ.get('GPT_FIREWALL_TEST_NGINX'), 'requires explicitly selected Lua-enabled Nginx')
class RealPostForwardingRuntimeTest(DigestServerMixin, unittest.TestCase):
    def start_php(self, root, binary):
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            port = available.getsockname()[1]
        (root / 'endpoint.php').write_text('''<?php
$raw = file_get_contents('php://input');
$files = array();
foreach ($_FILES as $key => $file) {
    $files[$key] = array('name' => $file['name'], 'error' => $file['error'],
        'size' => $file['size'], 'sha256' => $file['error'] === 0 ? hash_file('sha256', $file['tmp_name']) : null);
}
header('Content-Type: application/json');
echo json_encode(array('length' => strlen($raw), 'sha256' => hash('sha256', $raw),
    'content_type' => isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '',
    'post' => $_POST, 'files' => $files));
''', encoding='ascii')
        conf = root / 'php-fpm.conf'
        conf.write_text('[global]\nerror_log = ' + str(root / 'php-error.log') + '\ndaemonize = no\n'
                        '[fixture]\nuser = www\ngroup = www\nlisten = 127.0.0.1:' + str(port) + '\n'
                        'pm = static\npm.max_children = 2\nclear_env = yes\n'
                        'php_admin_value[post_max_size] = 2M\nphp_admin_value[upload_max_filesize] = 1M\n'
                        'php_admin_value[max_input_vars] = 2000\nphp_admin_flag[file_uploads] = on\n'
                        'php_admin_value[upload_tmp_dir] = ' + str(root / 'bodies') + '\n', encoding='ascii')
        diagnostics = (root / 'php-startup.log').open('wb')
        self.addCleanup(diagnostics.close)
        process = subprocess.Popen([binary, '-n', '-F', '-y', str(conf)],
                                   stdout=subprocess.DEVNULL, stderr=diagnostics)

        def stop():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)

        self.addCleanup(stop)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and process.poll() is None:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    return port
            except OSError:
                time.sleep(0.05)
        self.fail((root / 'php-startup.log').read_text(errors='replace')[-2000:])

    def assert_php_form(self, connection, value, chunked=False, path='/php/form'):
        body = ('field=' + value + '&repeated=first&repeated=second').encode('ascii')
        report = self.assert_forwarded(connection, body, 'application/x-www-form-urlencoded',
                                       chunked=chunked, path=path)
        self.assertEqual(report['post'], {'field': value, 'repeated': 'second'})
        self.assertFalse(report['files'])

    def assert_php_upload(self, connection, value, chunked=False, path='/php/form'):
        boundary = 'fixture-upload-boundary'
        file_body = ('synthetic-' + value + '-$_POST-blocked-post-fixture-blocked-url-fixture').encode('ascii')
        body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="field"\r\n\r\n' + value +
                '\r\n--' + boundary + '\r\nContent-Disposition: form-data; name="file"; '
                'filename="reference-PHP-photo.png"\r\nContent-Type: image/png\r\n\r\n').encode('ascii')
        body += file_body + ('\r\n--' + boundary + '--\r\n').encode('ascii')
        supplied = iter([body[:77], body[77:]]) if chunked else body
        connection.request('POST', path, body=supplied, encode_chunked=chunked,
                           headers={'Host': 'fixture.example', 'Content-Type': 'multipart/form-data; boundary=' + boundary})
        report = self.read_report(connection.getresponse())
        self.assertEqual(report['post'], {'field': value})
        self.assertEqual(report['files'], {'file': {'name': 'reference-PHP-photo.png', 'error': 0,
                                                    'size': len(file_body),
                                                    'sha256': hashlib.sha256(file_body).hexdigest()}})

    def test_forms_json_uploads_chunked_disk_keepalive_and_concurrent_bodies_reach_upstream(self):
        binary = os.environ['GPT_FIREWALL_TEST_NGINX']
        workers = int(os.environ.get('GPT_FIREWALL_POST_WORKERS', '1'))
        soak_seconds = int(os.environ.get('GPT_FIREWALL_POST_SOAK_SECONDS', '0'))
        self.assertTrue(1 <= workers <= 4 and 0 <= soak_seconds <= 300)
        self.worker_pids = set()
        self.worker_lock = threading.Lock()
        php_binary = os.environ.get('GPT_FIREWALL_TEST_PHP_FPM')
        upstream = self.start_digest_server()
        with tempfile.TemporaryDirectory(prefix='gpt-post-forwarding-') as directory:
            root = Path(directory)
            root.chmod(0o755)
            runtime = root / 'runtime'
            (runtime / 'rule').mkdir(parents=True)
            (runtime / 'html').mkdir()
            (root / 'logs').mkdir()
            body_temp = root / 'bodies'
            body_temp.mkdir(mode=0o777)
            body_temp.chmod(0o777)
            config = dict(open=True, log=False, retry=100, retry_time=60, retry_cycle=60,
                          reqfile_path=(runtime / 'html').as_posix(),
                          cc=dict(open=False, cycle=60, endtime=60, limit=100, status=403),
                          scan=dict(open=False, status=403), drop_abroad=dict(open=False, status=403))
            for name in ('get', 'post', 'cookie', 'user-agent', 'other'):
                config[name] = dict(open=name == 'post', status=403, reqfile='fixture.html')
            site = dict(open=True, post=True, log=False, cc=dict(config['cc']), retry=100,
                        retry_time=60, retry_cycle=60, disable_php_path=[], disable_path=[], disable_ext=[],
                        disable_upload_ext=[], url_tell=[],
                        url_rule=[['^/(?:buffer|memory|php)/form$', 'blocked-url-fixture']])
            (runtime / 'config.json').write_text(json.dumps(config), encoding='utf-8')
            (runtime / 'site.json').write_text(json.dumps({'fixture.example': site}), encoding='utf-8')
            (runtime / 'total.json').write_text('{"total":0,"rules":{},"sites":{}}', encoding='utf-8')
            (runtime / 'html/fixture.html').write_text('blocked fixture', encoding='utf-8')
            (runtime / 'rule/cn.json').write_text('[]', encoding='utf-8')
            (runtime / 'rule/post.json').write_text('[[1,"blocked-post-fixture"]]', encoding='utf-8')
            source = (ROOT / 'init.lua').read_text(encoding='utf-8')
            source = source.replace('local cpath = "/www/server/free_waf/"',
                                    'local cpath = ' + json.dumps(runtime.as_posix() + '/'))
            (root / 'init.lua').write_text(source, encoding='utf-8')
            (root / 'access.lua').write_text('run_btwaf()\n', encoding='utf-8')
            with socket.socket() as available:
                available.bind(('127.0.0.1', 0))
                port = available.getsockname()[1]
            library = Path(binary).resolve().parents[1] / 'lib/lua'
            lua_path = 'lua_package_path "' + library.as_posix() + '/?.lua;;";\n' if library.is_dir() else ''
            proxy = ('proxy_http_version 1.1; proxy_set_header Connection ""; proxy_request_buffering on; '
                     'proxy_pass http://127.0.0.1:' + str(upstream) + ';')
            php_location = ''
            if php_binary:
                php_port = self.start_php(root, php_binary)
                fastcgi = ('fastcgi_request_buffering on; fastcgi_pass 127.0.0.1:' + str(php_port) + '; '
                           'fastcgi_param SCRIPT_FILENAME "' + (root / 'endpoint.php').as_posix() + '"; '
                           'fastcgi_param REQUEST_METHOD $request_method; fastcgi_param QUERY_STRING $query_string; '
                           'fastcgi_param CONTENT_TYPE $content_type; fastcgi_param CONTENT_LENGTH $content_length; '
                           'fastcgi_param SERVER_PROTOCOL $server_protocol; fastcgi_param REQUEST_URI $request_uri; '
                           'fastcgi_param SERVER_NAME $server_name; fastcgi_param REDIRECT_STATUS 200;')
                php_location = ('location /php/ { client_body_buffer_size 128k; ' + fastcgi + ' }\n'
                                'location /php/disk/ { client_body_in_file_only clean; ' + fastcgi + ' }\n')
            conf = ('worker_processes ' + str(workers) + '; pid "' + (root / 'nginx.pid').as_posix() + '";\n'
                    'error_log "' + (root / 'error.log').as_posix() + '" notice;\n'
                    'events { worker_connections 128; } http {\n' + lua_path +
                    'access_log off; add_header X-Fixture-Worker $pid always; '
                    'client_max_body_size 1m; client_body_buffer_size 8k; '
                    'client_body_temp_path "' + body_temp.as_posix() + '";\n'
                    'lua_shared_dict free_waf 2m; lua_shared_dict free_waf_drop_ip 1m; '
                    'lua_shared_dict free_waf_drop_sum 1m; lua_shared_dict free_waf_cc 1m;\n'
                    'init_by_lua_file "' + (root / 'init.lua').as_posix() + '";\n'
                    'server { listen 127.0.0.1:' + str(port) + '; server_name fixture.example; '
                    'keepalive_timeout 10; keepalive_requests 1000; '
                    'access_by_lua_file "' + (root / 'access.lua').as_posix() + '";\n'
                    'location /buffer/ { ' + proxy + ' }\n'
                    'location /memory/ { client_body_buffer_size 128k; ' + proxy + ' }\n'
                    'location /disk/ { client_body_in_file_only clean; ' + proxy + ' }\n' + php_location + '} }\n')
            config_path = root / 'nginx.conf'
            config_path.write_text(conf, encoding='utf-8')
            args = [binary, '-p', root.as_posix() + '/', '-c', config_path.as_posix()]
            with (root / 'startup.log').open('wb') as diagnostics:
                process = subprocess.Popen(args + ['-g', 'daemon off;'], stdout=subprocess.DEVNULL, stderr=diagnostics)
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and process.poll() is None:
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                                break
                        except OSError:
                            time.sleep(0.05)
                    self.assertIsNone(process.poll(), (root / 'startup.log').read_text(errors='replace')[-2000:])
                    boundary = 'fixture-boundary'
                    multipart = ('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; '
                                 'filename="reference-PHP-photo.png"\r\nContent-Type: image/png\r\n\r\n'
                                 'field=blocked-post-fixture&other=blocked-url-fixture&literal=$_POST\r\n--'
                                 + boundary + '--\r\n').encode('ascii')
                    cases = [('form', b'username=fixture&password=synthetic&field=one&field=two',
                              'application/x-www-form-urlencoded', False),
                             ('json', b'{"username":"fixture","value":"<literal>"}', 'application/json', False),
                             ('multipart', multipart, 'multipart/form-data; boundary=' + boundary, False),
                             ('large-form', b'field=' + b'x' * 70000, 'application/x-www-form-urlencoded', False),
                             ('chunked-form', b'field=chunked', 'application/x-www-form-urlencoded', True),
                             ('chunked-large', b'field=' + b'y' * 70000, 'application/x-www-form-urlencoded', True),
                             ('binary', bytes(range(256)), 'application/octet-stream', False),
                             ('binary-with-form-marker', b'field=blocked-post-fixture&other=blocked-url-fixture',
                              'application/octet-stream', False),
                             ('plain-with-form-marker', b'field=blocked-post-fixture&other=blocked-url-fixture',
                              'text/plain', False),
                             ('mixed-case-form', b'field=normal', 'Application/X-WWW-Form-Urlencoded; charset=UTF-8', False),
                             ('empty', b'', 'application/x-www-form-urlencoded', False)]
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
                    try:
                        for name, body, content_type, chunked in cases:
                            with self.subTest(case=name):
                                self.assert_forwarded(connection, body, content_type, chunked=chunked)
                        self.assert_forwarded(connection, b'field=disk', 'application/x-www-form-urlencoded', path='/disk/form')
                        for marker in (b'blocked-post-fixture', b'blocked-url-fixture'):
                            with self.subTest(blocked_by=marker):
                                connection.request('POST', '/buffer/form', body=b'field=' + marker,
                                                   headers={'Host': 'fixture.example',
                                                            'Content-Type': 'application/x-www-form-urlencoded'})
                                blocked = connection.getresponse()
                                payload = blocked.read()
                                self.assertEqual(blocked.status, 403, payload[:300])
                        prefix = b'field=blocked-url-fixture&padding='
                        exact_limit = prefix + b'x' * (65536 - len(prefix))
                        for chunked in (False, True):
                            with self.subTest(exact_64k=True, chunked=chunked):
                                body = iter([exact_limit]) if chunked else exact_limit
                                connection.request('POST', '/memory/form', body=body, encode_chunked=chunked,
                                                   headers={'Host': 'fixture.example',
                                                            'Content-Type': 'application/x-www-form-urlencoded'})
                                blocked = connection.getresponse()
                                payload = blocked.read()
                                self.assertEqual(blocked.status, 403, payload[:300])
                        self.assert_forwarded(connection, b'field=normal-after-block', 'application/x-www-form-urlencoded')
                    finally:
                        connection.close()

                    form = 'application/x-www-form-urlencoded'
                    binary_type = 'application/octet-stream'
                    multipart_type = 'multipart/form-data; boundary=fixture'
                    for types in ([binary_type, form], [form, binary_type],
                                  [multipart_type, form], [form, multipart_type]):
                        for marker in (b'blocked-post-fixture', b'blocked-url-fixture'):
                            with self.subTest(repeated_content_types=types, marker=marker):
                                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
                                try:
                                    blocked = self.post_with_content_types(connection, b'field=' + marker, types)
                                    payload = blocked.read()
                                    # Nginx may reject ambiguous headers before the Lua access handler.
                                    self.assertIn(blocked.status, (400, 403), payload[:300])
                                finally:
                                    connection.close()

                    def request(index):
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
                        try:
                            self.assert_forwarded(connection, ('field=concurrent-%d' % index).encode('ascii'),
                                                  'application/x-www-form-urlencoded')
                        finally:
                            connection.close()

                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                        list(executor.map(request, range(80)))
                    if php_binary:
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                        try:
                            for chunked in (False, True):
                                for path in ('/php/form', '/php/disk/form'):
                                    with self.subTest(php='form', chunked=chunked, path=path):
                                        self.assert_php_form(connection, 'synthetic-php', chunked=chunked, path=path)
                                    with self.subTest(php='upload', chunked=chunked, path=path):
                                        self.assert_php_upload(connection, 'synthetic-upload', chunked=chunked, path=path)
                            for name, body, content_type, chunked in cases:
                                if name == 'multipart':
                                    continue
                                with self.subTest(php=name):
                                    self.assert_forwarded(connection, body, content_type, chunked=chunked, path='/php/form')
                        finally:
                            connection.close()
                    summary = dict(php_checked=bool(php_binary), workers=workers, concurrent_requests=80,
                                   soak_seconds=soak_seconds, reloads=0, soak_requests=0)
                    if os.environ.get('GPT_FIREWALL_POST_IDLE_CONTROL') == '1':
                        summary['idle_reload_control'] = self.exercise_idle_reload(port, args, root)
                    if soak_seconds:
                        summary.update(self.exercise_soak(port, args, soak_seconds, bool(php_binary)))
                        if summary['reloads']:
                            self.assertGreater(len(self.worker_pids), workers, 'reload did not serve requests with new workers')
                    summary['worker_pids'] = sorted(self.worker_pids)
                    diagnostics = (root / 'error.log').read_text(errors='replace')
                    for level in ('[error]', '[alert]', '[crit]', '[emerg]'):
                        self.assertNotIn(level, diagnostics, diagnostics[-4000:])
                    print('post_runtime_summary=' + json.dumps(summary, sort_keys=True), flush=True)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                    evidence = os.environ.get('GPT_FIREWALL_POST_EVIDENCE')
                    if evidence:
                        destination = Path(evidence) / root.name
                        destination.mkdir(parents=True, exist_ok=False)
                        for name in ('error.log', 'startup.log', 'php-error.log', 'php-startup.log'):
                            if (root / name).is_file():
                                shutil.copyfile(root / name, destination / name)

    def exercise_soak(self, port, args, seconds, php):
        started = time.monotonic()
        deadline = started + seconds
        reloads = int(os.environ.get('GPT_FIREWALL_POST_RELOADS', '0'))
        self.assertIn(reloads, (0, 2))

        def requests(client):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            counts = dict(http=0, php_form=0, php_upload=0)
            index = 0
            try:
                while time.monotonic() < deadline:
                    value = 'client-%d-request-%d' % (client, index)
                    chunked = index % 2 == 0
                    if php and index % 4 == 0:
                        self.assert_php_form(connection, value, chunked=chunked)
                        counts['php_form'] += 1
                    elif php and index % 4 == 1:
                        self.assert_php_upload(connection, value, chunked=chunked, path='/php/disk/form')
                        counts['php_upload'] += 1
                    else:
                        body = ('field=' + value + '&padding=').encode('ascii') + b'x' * (70000 if index % 3 == 0 else 17)
                        self.assert_forwarded(connection, body, 'application/x-www-form-urlencoded',
                                              chunked=chunked, path='/buffer/form')
                        counts['http'] += 1
                    # Reload availability uses new connections, not blind POST retries on stale sockets.
                    if reloads:
                        connection.close()
                    index += 1
                    time.sleep(0.005)
            finally:
                connection.close()
            return counts

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(requests, client) for client in range(8)]
            for moment in ((seconds / 3, seconds * 2 / 3) if reloads else ()):
                time.sleep(max(0, started + moment - time.monotonic()))
                result = subprocess.run(args + ['-s', 'reload'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stdout)
            reports = [future.result() for future in futures]
        counts = {kind: sum(report[kind] for report in reports) for kind in ('http', 'php_form', 'php_upload')}
        self.assertGreater(sum(counts.values()), 80)
        return dict(soak_requests=sum(counts.values()), soak_counts=counts, reloads=reloads,
                    elapsed_seconds=round(time.monotonic() - started, 2))

    def exercise_idle_reload(self, port, args, root):
        results = {}
        try:
            for enabled in (True, False):
                (root / 'access.lua').write_text('run_btwaf()\n' if enabled else '-- control: no WAF handler\n')
                result = subprocess.run(args + ['-s', 'reload'], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                time.sleep(0.3)
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
                try:
                    connection.request('POST', '/buffer/form', body=b'field=before-idle-reload',
                                       headers={'Host': 'fixture.example', 'Content-Type': 'application/x-www-form-urlencoded'})
                    response = connection.getresponse()
                    old_pid = response.getheader('X-Fixture-Worker')
                    self.read_report(response)
                    self.assertTrue(old_pid and old_pid.isdigit())
                    result = subprocess.run(args + ['-s', 'reload'], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    deadline = time.monotonic() + 5
                    while Path('/proc/' + old_pid).exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertFalse(Path('/proc/' + old_pid).exists(), 'old idle worker did not drain')
                    with self.assertRaises((BrokenPipeError, ConnectionResetError, http.client.RemoteDisconnected)) as caught:
                        self.assert_forwarded(connection, b'field=stale-connection-not-retried',
                                              'application/x-www-form-urlencoded')
                    results['waf_on' if enabled else 'waf_off'] = type(caught.exception).__name__
                finally:
                    connection.close()
                fresh = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
                try:
                    self.assert_forwarded(fresh, b'field=fresh-connection-after-reload', 'application/x-www-form-urlencoded')
                finally:
                    fresh.close()
        finally:
            (root / 'access.lua').write_text('run_btwaf()\n')
            result = subprocess.run(args + ['-s', 'reload'], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            time.sleep(0.3)
        return results


if __name__ == '__main__':
    unittest.main()
