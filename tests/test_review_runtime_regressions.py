import json
import os
import re
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ban_store import BanStore
from report_store import BackgroundReports, REPORT_STORE_VERSION, fcntl


def real_runtime_lua(directory):
    from tests.test_lua_state_regressions import lua_string
    source = (ROOT / 'init.lua').read_text(encoding='utf-8')
    names = ('runtime_file_stat', 'runtime_lock_metadata', 'repeat_ban_lock', 'repeat_ban_unlock',
             'read_file', 'read_file_body', 'runtime_atomic_write', 'with_ip_black_lock', 'add_ip_black_exact')
    chunks = [match.group() for name in names
              if (match := re.search(r'^function ' + name + r'\(.*?^end', source, re.M | re.S))]
    return '\n'.join((
        'local cpath=' + lua_string(str(directory) + '/'), 'local jpath=cpath',
        "local json=require 'cjson'; local repeat_ban_cache={}",
        'AUTO_BAN_SECONDS=28800; MAX_AUTO_BAN_SECONDS=28800; ip_black_rules={}',
        "ngx={now=os.clock,worker={pid=function() return 7 end},md5=function() return string.rep('a',32) end}",
        'function is_ipaddr() return true end',
        "function arrip(ip) local t={}; for n in ip:gmatch('%d+') do t[#t+1]=tonumber(n) end; return t end",
        "function encode_json_array(rows) return #rows==0 and '[]' or json.encode(rows) end", *chunks))


class RuntimePermissionsReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != 'posix':
            raise unittest.SkipTest('requires Linux file ownership')
        cls.lua = os.environ.get('FREE_WAF_LUAJIT') or shutil.which('luajit')
        if not cls.lua:
            raise unittest.SkipTest('requires real LuaJIT')

    def www(self):
        if os.geteuid() != 0:
            self.skipTest('requires root to switch to the real www identity')
        import pwd
        try:
            return pwd.getpwnam('www')
        except KeyError:
            self.skipTest('requires a www account')

    def run_lua(self, directory, tail, identity=None):
        kwargs = {}
        if identity:
            kwargs.update(user=identity.pw_uid, group=identity.pw_gid, extra_groups=[identity.pw_gid])
        return subprocess.run([self.lua, '-'], input=real_runtime_lua(directory) + '\n' + tail,
                              text=True, capture_output=True, timeout=5, **kwargs)

    def test_root_created_lock_retains_group_writers_and_inode(self):
        identity = self.www()
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            os.chown(root, 0, identity.pw_gid)
            root.chmod(0o770)
            path = root / 'ip_black.json'
            path.write_text('[]')
            os.chown(path, 0, identity.pw_gid)
            path.chmod(0o660)
            store = BanStore(path)
            store.save_rules([])
            lock = path.with_name(path.name + '.lock')
            before = lock.stat()
            self.assertEqual(stat.S_IMODE(before.st_mode), 0o660)
            self.assertEqual((before.st_uid, before.st_gid), (0, identity.pw_gid))
            result = self.run_lua(root, 'local ok,value=with_ip_black_lock(function() return true end); assert(ok and value)', identity)
            self.assertEqual(result.returncode, 0, result.stderr)
            with store._transaction():
                self.assertEqual(lock.stat().st_ino, before.st_ino)
            self.assertEqual(path.stat().st_mode & 0o777, 0o660)

    def test_real_www_atomic_write_preserves_owner_group_and_restrictive_mode(self):
        identity = self.www()
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            os.chown(root, identity.pw_uid, identity.pw_gid)
            root.chmod(0o750)
            path = root / 'ip_black.json'
            path.write_text('[]')
            os.chown(path, identity.pw_uid, identity.pw_gid)
            path.chmod(0o640)
            before = path.stat()
            result = self.run_lua(root, "assert(add_ip_black_exact('192.0.2.1',60))", identity)
            self.assertEqual(result.returncode, 0, result.stderr)
            after = path.stat()
            self.assertEqual((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
                             (before.st_uid, before.st_gid, 0o640))
            self.assertEqual(len(json.loads(path.read_text())), 1)

    def test_www_cannot_publish_when_original_root_owner_cannot_be_preserved(self):
        identity = self.www()
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            os.chown(root, 0, identity.pw_gid)
            root.chmod(0o770)
            path = root / 'ip_black.json'
            path.write_text('[]')
            os.chown(path, 0, identity.pw_gid)
            path.chmod(0o660)
            # Group writers can acquire the lock, but cannot chown a new inode to root.
            lock = path.with_name(path.name + '.lock')
            lock.touch()
            os.chown(lock, 0, identity.pw_gid)
            lock.chmod(0o660)
            before = path.stat()
            result = self.run_lua(root, "assert(add_ip_black_exact('192.0.2.1',60)==false)", identity)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.read_text(), '[]')
            self.assertEqual(path.stat().st_ino, before.st_ino)
            self.assertEqual(list(root.glob('*.tmp')), [])


@unittest.skipUnless(os.environ.get('GPT_FIREWALL_TEST_NGINX'), 'requires explicitly selected Lua-enabled Nginx')
class StatisticsReloadRuntimeTest(unittest.TestCase):
    def test_new_worker_flushes_pending_statistics_without_another_hit(self):
        self.assert_reload_takeover(worker_hook=True)

    def test_first_ordinary_request_adopts_pending_without_a_worker_hook(self):
        self.assert_reload_takeover(worker_hook=False)

    def test_migrated_statistics_flushes_beneath_read_only_runtime_directory(self):
        self.assert_reload_takeover(worker_hook=False, migrated=True)

    def test_corrupt_migrated_statistics_retains_pending_without_legacy_fallback(self):
        self.assert_reload_takeover(worker_hook=False, migrated=True, corrupted=True)

    def assert_reload_takeover(self, worker_hook, migrated=False, corrupted=False):
        import http.client
        binary = os.environ['GPT_FIREWALL_TEST_NGINX']
        with tempfile.TemporaryDirectory(prefix='gpt-statistics-reload-') as directory:
            root = Path(directory)
            root.chmod(0o755)
            runtime = root / 'runtime'
            runtime.mkdir(mode=0o777)
            runtime.chmod(0o777)
            (runtime / 'rule').mkdir()
            (root / 'logs').mkdir()
            config = {'open': False, 'log': False, 'retry': 6, 'retry_cycle': 60, 'retry_time': 60,
                      'cc': {'cycle': 60, 'endtime': 60, 'limit': 10}, 'reqfile_path': str(root)}
            for name in ('get', 'post', 'cookie', 'user-agent', 'other'):
                config[name] = {'reqfile': 'fixture.html', 'status': 403, 'open': False}
            (root / 'fixture.html').write_text('fixture')
            (runtime / 'config.json').write_text(json.dumps(config))
            (runtime / 'site.json').write_text('{}')
            (runtime / 'rule/cn.json').write_text('[]')
            legacy = runtime / 'total.json'
            legacy_body = json.dumps({'total': 5, 'rules': {}, 'sites': {}})
            data = runtime / '.statistics' if migrated else runtime
            if migrated:
                data.mkdir(mode=0o700)
                legacy.write_text(legacy_body)
                legacy.chmod(0o666)
                runtime.chmod(0o755)
            total = data / 'total.json'
            total_body = json.dumps({'total': 80, 'rules': {}, 'sites': {}})
            total.write_text('{broken' if corrupted else total_body)
            if os.geteuid() == 0:
                import pwd
                identity = pwd.getpwnam('www')
                os.chown(total, identity.pw_uid, identity.pw_gid)
                if migrated:
                    os.chown(data, identity.pw_uid, identity.pw_gid)
            total.chmod(0o640)
            source = (ROOT / 'init.lua').read_text(encoding='utf-8')
            (root / 'init.lua').write_text(source.replace('local cpath = "/www/server/free_waf/"',
                                                        'local cpath = ' + json.dumps(str(runtime) + '/')))
            library = Path(binary).resolve().parents[1] / 'lib/lua'
            lua_path = ('lua_package_path "' + str(library) + '/?.lua;;";\n') if library.is_dir() else ''
            with socket.socket() as selected:
                selected.bind(('127.0.0.1', 0))
                port = selected.getsockname()[1]
            conf = root / 'nginx.conf'
            hook = ('init_worker_by_lua_block { total_log_worker_init() }\n') if worker_hook else ''
            conf.write_text(('user www;\n' if os.geteuid() == 0 else '') +
                'pid ' + str(root / 'nginx.pid') + '; error_log ' + str(root / 'error.log') + ' notice;\n'
                'worker_processes 1; events { worker_connections 32; } http {\n' + lua_path +
                'lua_shared_dict free_waf 1m; lua_shared_dict free_waf_drop_ip 1m;\n'
                'init_by_lua_file ' + str(root / 'init.lua') + ';\n' + hook +
                'server { listen 127.0.0.1:' + str(port) + '; server_name fixture; access_log off;\n'
                'location = /ordinary { access_by_lua_block { run_btwaf() } '
                'content_by_lua_block { ngx.say("ordinary request completed") } }\n'
                'location = /pending { content_by_lua_block { local count=0; '
                'for _,key in ipairs(ngx.shared.free_waf:get_keys(0)) do '
                'if key:sub(1,20)=="statistics:v1:count:" then count=count+(ngx.shared.free_waf:get(key) or 0) end end; '
                'ngx.say(ngx.worker.pid(),":",count) } }\n'
                'location = /hit { content_by_lua_block { server_name="fixture"; '
                'assert(inc_log("post","regular")); ngx.say("counted") } } } }\n')
            process = subprocess.Popen([binary, '-p', str(root) + '/', '-c', str(conf), '-g', 'daemon off;'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

            def request(path):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
                try:
                    connection.request('GET', path)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    return response.read().decode().strip()
                finally:
                    connection.close()

            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        old_pid = int(request('/pending').split(':')[0])
                        break
                    except (OSError, http.client.HTTPException):
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail((root / 'error.log').read_text(errors='replace')[-4000:])
                        time.sleep(0.02)
                lock = total.with_name(total.name + '.lock')
                lock.touch()
                if os.geteuid() == 0:
                    os.chown(lock, identity.pw_uid, identity.pw_gid)
                import fcntl as real_fcntl
                with lock.open('rb') as held:
                    real_fcntl.flock(held, real_fcntl.LOCK_EX)
                    self.assertEqual(request('/hit'), 'counted')
                    process.send_signal(signal.SIGHUP)
                    deadline = time.monotonic() + 5
                    while True:
                        pid, pending = map(int, request('/pending').split(':'))
                        if pid != old_pid:
                            self.assertEqual(pending, 1)
                            break
                        self.assertLess(time.monotonic(), deadline, 'replacement worker did not start')
                        time.sleep(0.02)
                if not worker_hook:
                    time.sleep(1.2)
                    self.assertEqual(total.read_text(), '{broken' if corrupted else total_body,
                                     'fixture must leave pending until an ordinary request without a hook')
                    self.assertEqual(request('/pending').split(':')[1], '1')
                    self.assertEqual(request('/ordinary'), 'ordinary request completed')
                if corrupted:
                    time.sleep(1.2)
                    self.assertEqual(total.read_text(), '{broken')
                    self.assertEqual(legacy.read_text(), legacy_body)
                    self.assertFalse(legacy.with_name(legacy.name + '.lock').exists())
                    self.assertEqual(request('/pending').split(':')[1], '1')
                    total.write_text(total_body)
                deadline = time.monotonic() + 4
                while json.loads(total.read_text())['total'] != 81 and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(json.loads(total.read_text())['total'], 81,
                                 'new worker did not take over pending counters without a new hit')
                self.assertEqual(request('/pending').split(':')[1], '0')
                self.assertEqual(total.stat().st_mode & 0o777, 0o640)
                if migrated:
                    self.assertEqual(legacy.read_text(), legacy_body)
                    self.assertFalse(legacy.with_name(legacy.name + '.lock').exists())
                    self.assertEqual(runtime.stat().st_mode & 0o777, 0o755)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                process.stderr.close()


def competing_ban(path, ip, paused):
    store = BanStore(path)
    original = store.load_rules

    def paused_read():
        rules = original()
        print("ready", flush=True)
        if paused and sys.stdin.readline().strip() != "release":
            raise RuntimeError("fixture was not released")
        return rules

    store.load_rules = paused_read
    print("started", flush=True)
    print("result:" + json.dumps(store.add_temp_ban(ip, 60)), flush=True)


class BanRuntimeReviewTest(unittest.TestCase):
    def test_generic_mutator_reads_under_lock_and_returns_committed_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ip_black.json"
            path.write_text("[]")
            store = BanStore(path)
            expected = [[[198, 51, 100, 0], [198, 51, 100, 255]]]

            def mutate(rules):
                self.assertEqual(rules, [])
                self.assertTrue(path.with_name(path.name + ".lock").exists())
                if fcntl is not None:
                    with path.with_name(path.name + ".lock").open("a+b") as stream:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return expected

            self.assertEqual(store.mutate_rules(mutate), expected)
            self.assertEqual(store.load_rules(), expected)
            with self.assertRaises(ValueError):
                store.mutate_rules(lambda rules: {})
            self.assertEqual(store.load_rules(), expected)

    @unittest.skipIf(fcntl is None, "requires POSIX flock")
    def test_real_luajit_and_python_share_the_blacklist_lock(self):
        executable = os.environ.get("FREE_WAF_LUAJIT") or shutil.which("luajit")
        if not executable:
            self.skipTest("requires real Linux LuaJIT")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ip_black.json"
            path.write_text("[]")
            setup = real_runtime_lua(directory)

            def lua(tail):
                return subprocess.run([executable, "-"], input=setup + "\n" + tail,
                                      text=True, capture_output=True, timeout=5)

            store = BanStore(path)
            with store._transaction():
                blocked = lua("assert(add_ip_black_exact('192.0.2.2',60)==false)")
                self.assertEqual(blocked.returncode, 0, blocked.stderr)
                self.assertEqual(path.read_text(), "[]")
            inode = path.with_name(path.name + ".lock").stat().st_ino
            added = lua("assert(add_ip_black_exact('192.0.2.2',60))")
            self.assertEqual(added.returncode, 0, added.stderr)
            self.assertTrue(store.add_temp_ban("192.0.2.1", 60))
            self.assertEqual(set(store.active_exact_ips()), {"192.0.2.1", "192.0.2.2"})
            self.assertEqual(path.with_name(path.name + ".lock").stat().st_ino, inode)

    def test_processes_lock_the_complete_read_modify_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ip_black.json"
            path.write_text("[]")
            workers = []

            def start(ip, paused):
                started, ready, lines = threading.Event(), threading.Event(), []
                process = subprocess.Popen([sys.executable, "-B", str(Path(__file__)), "--ban-worker",
                                            str(path), ip, str(int(paused))],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True)

                def read_output():
                    for line in process.stdout:
                        lines.append(line.strip())
                        if line.strip() == "started":
                            started.set()
                        if line.strip() == "ready":
                            ready.set()

                reader = threading.Thread(target=read_output, daemon=True)
                reader.start()
                workers.append((process, reader, lines))
                self.assertTrue(started.wait(10), "standalone fixture worker did not start")
                return process, ready

            first = None
            try:
                first, first_read = start("192.0.2.1", True)
                self.assertTrue(first_read.wait(10))
                second, second_read = start("192.0.2.2", False)
                self.assertFalse(second_read.wait(0.4), "second process read an unlocked old snapshot")
            finally:
                if first is not None and first.poll() is None:
                    first.stdin.write("release\n")
                    first.stdin.flush()
                for process, reader, lines in workers:
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                    reader.join(2)
                    error = process.stderr.read()
                    process.stdin.close()
                    process.stdout.close()
                    process.stderr.close()
                    self.assertEqual(process.returncode, 0, error)
                    self.assertIn("result:true", lines)
            self.assertEqual(set(BanStore(path).active_exact_ips()), {"192.0.2.1", "192.0.2.2"})

    def test_atomic_replace_failure_preserves_existing_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ip_black.json"
            original = "[[[198,51,100,0],[198,51,100,255]]]"
            path.write_text(original)
            with patch("ban_store.os.replace", side_effect=OSError("fixture rename failure")):
                with self.assertRaises(OSError):
                    BanStore(path).add_temp_ban("192.0.2.1", 60)
            self.assertEqual(path.read_text(), original)
            self.assertEqual(set(p.name for p in path.parent.iterdir()), {path.name, path.name + ".lock"})

    def test_corrupt_rules_are_not_replaced_or_unlocked_by_unlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ip_black.json"
            path.write_text("{bad")
            with self.assertRaises(ValueError):
                BanStore(path).clear_exact_ips()
            self.assertEqual(path.read_text(), "{bad")
            self.assertTrue(path.with_name(path.name + ".lock").exists())

    def test_every_mutator_holds_the_same_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ip_black.json"
            store = BanStore(path, now_fn=lambda: 100)
            methods = (lambda: store.save_rules([]), lambda: store.add_temp_ban("192.0.2.1", 60),
                       lambda: store.remove_exact_ip("192.0.2.1"), store.clear_exact_ips,
                       store.prune_and_migrate)
            for method in methods:
                path.write_text("[[[192,0,2,1],[192,0,2,1]]]" )
                observed = []
                original_read, original_replace = store.load_rules, os.replace

                def check_lock():
                    lock_path = path.with_name(path.name + ".lock")
                    self.assertTrue(lock_path.exists(), "mutator has no persistent lock inode")
                    if fcntl is not None:
                        with lock_path.open("a+b") as stream:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    observed.append(True)

                def read():
                    check_lock()
                    return original_read()

                def replace(*args):
                    check_lock()
                    return original_replace(*args)

                with patch.object(store, "load_rules", side_effect=read), patch("ban_store.os.replace", side_effect=replace):
                    method()
                self.assertTrue(observed)


class ReportRuntimeReviewTest(unittest.TestCase):
    def test_runtime_module_version_rejects_the_cached_v2_implementation(self):
        self.assertEqual(REPORT_STORE_VERSION, 4)

    def test_same_revision_never_rebuilds_when_snapshot_reread_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = BackgroundReports(directory)
            calls = []

            def build():
                calls.append(1)
                if len(calls) > 1:
                    raise AssertionError("snapshot reread retriggered the same revision")
                return {"summary": {"total_requests": 7}}

            try:
                with patch.object(reports, "_load", return_value=None), patch("report_store.logging.getLogger"):
                    reports.request("all", build, force=True)
                    reports.close()
                self.assertEqual(calls, [1])
                self.assertFalse(reports._pending)
            finally:
                reports.close()

    def test_invalid_build_start_metadata_is_a_cache_miss(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = BackgroundReports(directory)
            try:
                reports._save(reports._path("all"), {"version": 1, "generated_at": 1000,
                                                     "started_at": "broken", "report": {}})
                with patch.object(reports._executor, "submit"):
                    result = reports.request("all", lambda: {})
                self.assertFalse(result["cached"])
                self.assertTrue(result["loading"])
            finally:
                reports.close()

    def test_clock_rollback_does_not_rebuild_until_request_time_catches_up(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = BackgroundReports(directory)
            calls = []

            def build():
                calls.append(1)
                if len(calls) > 1:
                    raise AssertionError("clock rollback retriggered the same refresh identity")
                return {"summary": {"total_requests": 7}}

            try:
                with patch("report_store.time.time", side_effect=[2000] + [1000] * 50):
                    reports.request("all", build, force=True)
                    with patch("report_store.logging.getLogger"):
                        reports.close()
                self.assertEqual(calls, [1])
                self.assertFalse(reports._pending)
            finally:
                reports.close()

    def test_future_refresh_marker_does_not_rebuild_the_same_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = BackgroundReports(directory)
            calls = []
            reports._save(reports._path("all").with_suffix(".refresh"),
                          {"requested_at": 9000, "revision": "future-revision"})

            def build():
                calls.append(1)
                if len(calls) > 1:
                    raise AssertionError("future marker retriggered the same refresh identity")
                return {"summary": {"total_requests": 7}}

            try:
                with patch("report_store.time.time", return_value=1000):
                    reports.request("all", build)
                    with patch("report_store.logging.getLogger"):
                        reports.close()
                self.assertEqual(calls, [1])
                self.assertFalse(reports._pending)
            finally:
                reports.close()

    def test_cache_age_is_measured_from_build_start(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = BackgroundReports(directory, ttl=300)
            clock = [1000]
            calls = []

            def build():
                calls.append(1)
                clock[0] = 1299
                return {"summary": {"total_requests": 1}}

            try:
                with patch("report_store.time.time", side_effect=lambda: clock[0]):
                    reports.request("all", build)
                    reports._executor.shutdown(wait=True)
                    snapshot = reports._load(reports._path("all"))
                    self.assertEqual(snapshot["started_at"], 1000)
                    self.assertEqual(snapshot["generated_at"], 1299)
                    clock[0] = 1301
                    with patch.object(reports._executor, "submit") as submit:
                        self.assertTrue(reports.request("all", build)["loading"])
                        submit.assert_called_once()
            finally:
                reports.close()

    def exercise_force_during_build(self, other_worker=False, frozen_clock=False):
        with tempfile.TemporaryDirectory() as directory:
            reports = BackgroundReports(directory)
            other = BackgroundReports(directory) if other_worker else reports
            sampled, release = threading.Event(), threading.Event()
            calls = []
            value = [1]

            def build():
                sampled_value = value[0]
                calls.append(sampled_value)
                if len(calls) == 1:
                    sampled.set()
                    if not release.wait(5):
                        raise RuntimeError("fixture timeout")
                return {"summary": {"total_requests": sampled_value}}

            clock_patch = patch("report_store.time.time", return_value=1000) if frozen_clock else patch("report_store.time.time", wraps=time.time)
            with clock_patch:
                try:
                    reports.request("all", build)
                    self.assertTrue(sampled.wait(2))
                    value[0] = 2
                    for _ in range(3):
                        self.assertTrue(other.request("all", build, force=True)["loading"])
                    release.set()
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        result = other.request("all", build)
                        if not result["loading"] and not reports.request("all", build)["loading"]:
                            break
                        time.sleep(0.005)
                    self.assertEqual(calls, [1, 2], "in-flight invalidation must cause exactly one additional sample")
                    self.assertEqual(result["summary"]["total_requests"], 2)
                    self.assertFalse(result["loading"])
                finally:
                    release.set()
                    reports.close()
                    if other is not reports:
                        other.close()

    def test_force_during_build_queues_a_second_sample(self):
        self.exercise_force_during_build()

    def test_force_identity_does_not_depend_on_clock_resolution(self):
        self.exercise_force_during_build(frozen_clock=True)

    @unittest.skipIf(fcntl is None, "requires POSIX flock")
    def test_another_worker_force_during_build_queues_a_second_sample(self):
        self.exercise_force_during_build(other_worker=True)


class LuaRuntimeReviewTest(unittest.TestCase):
    def test_runtime_review_fixture(self):
        source = (ROOT / "init.lua").read_text(encoding="utf-8")
        fixture = (ROOT / "tests" / "test_review_runtime_regressions.lua").read_text(encoding="utf-8")
        executable = os.environ.get("FREE_WAF_LUAJIT") or shutil.which("luajit")
        if executable:
            from tests.test_lua_state_regressions import lua_string
            result = subprocess.run([executable, "-"], input="WAF_RUNTIME_SOURCE=" + lua_string(source) + "\n" + fixture,
                                    text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            print(result.stdout.strip())
        else:
            try:
                from lupa.luajit21 import LuaRuntime
            except ImportError:
                self.skipTest("requires LuaJIT or optional lupa.luajit21")
            runtime = LuaRuntime(unpack_returned_tuples=True)
            runtime.globals().WAF_RUNTIME_SOURCE = source
            try:
                runtime.execute(fixture)
            except Exception as error:
                self.fail(str(error))


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--ban-worker":
        competing_ban(sys.argv[2], sys.argv[3], sys.argv[4] == "1")
    else:
        unittest.main()
