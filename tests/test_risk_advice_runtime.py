"""Read-only manual ban snapshots and opt-in, isolated two-vhost Nginx proof."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from update_service import IntegrationRepairService


SOURCE = Path(__file__).resolve().parents[1] / 'init.lua'


def entry(site='fixture.example', ip='127.0.0.1', seconds=86400, now=None):
    now = int(time.time()) if now is None else now
    return dict(site=site, ip=ip, started_at=now, expires_at=now + seconds,
                duration=seconds, reason='risk_advice', evidence_hash='a' * 64)


def snapshot(entries=None, revision='1' * 32):
    return dict(version=1, revision=revision, entries=[] if entries is None else entries)


class ManualSiteBanLuaTest(unittest.TestCase):
    def setUp(self):
        try:
            from lupa.luajit21 import LuaRuntime, lua_type
        except ImportError:
            self.skipTest('optional embedded LuaJIT unavailable')
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.source = SOURCE.read_text(encoding='utf-8')
        null = self.lua.eval('newproxy()')

        def to_lua(value):
            if value is None:
                return null
            if isinstance(value, dict):
                return self.lua.table_from({key: to_lua(item) for key, item in value.items()})
            if isinstance(value, list):
                return self.lua.table_from([to_lua(item) for item in value])
            return value

        def from_lua(value):
            kind = lua_type(value)
            if kind == 'userdata':
                return None
            if kind != 'table':
                return value
            keys = list(value.keys())
            if keys and set(keys) == set(range(1, len(keys) + 1)):
                return [from_lua(value[index]) for index in range(1, len(keys) + 1)]
            return {key: from_lua(item) for key, item in value.items()}

        self.lua.globals().fixture_decode = lambda body: to_lua(json.loads(body))
        self.lua.globals().fixture_encode = lambda value: json.dumps(from_lua(value), separators=(',', ':'))
        self.lua.globals().fixture_null = null
        self.lua.execute('''
            json={decode=function(body) return fixture_decode(body) end,
                  encode=function(value) return fixture_encode(value) end, null=fixture_null}
            manual_site_ban_state={}
            ngx={header={},time=function() return 1000 end,
                 say=function(body) response_body=body end,
                 exit=function(code) response_status=code end,
                 var={remote_addr='127.0.0.1',server_name='fixture.example'}}
            write_log=function() error('manual retries must not log or count') end
            repeat_ban_event=function() error('manual retries must not count') end
        ''')
        for name in ('is_runtime_ban_ipv4', 'is_runtime_ban_ip', 'endpoint_normalize_ip',
                     'encode_json_array', 'manual_site_ban_normalize_ip', 'manual_site_ban_valid_record',
                     'manual_site_ban_decode', 'manual_site_ban_load',
                     'manual_site_ban_guard', 'get_manual_site_bans', 'manual_site_ban_response'):
            found = re.search(r'(?m)^function ' + name + r'\(.*?\nend', self.source, re.S)
            self.assertIsNotNone(found, 'missing runtime manual-site-ban function: ' + name)
            self.lua.execute(found.group(0))

    def decode(self, value):
        body = value if isinstance(value, str) else json.dumps(value)
        result = self.lua.globals().manual_site_ban_decode(body)
        return result[0] if isinstance(result, tuple) else result

    def load(self, value, error=None):
        self.lua.globals().fixture_body = json.dumps(value) if isinstance(value, dict) else value
        self.lua.globals().fixture_read_error = error
        self.lua.execute('''
            read_count=0
            manual_site_ban_read=function()
                read_count=read_count+1
                return fixture_body,fixture_read_error
            end
            manual_site_ban_load(string.rep('b',32))
        ''')

    def test_snapshot_accepts_only_exact_finite_canonical_rows(self):
        valid = snapshot([entry(now=1000), entry(ip='2001:db8::1', now=1000, seconds=315360000)])
        self.assertIsNotNone(self.decode(valid))
        changes = [dict(duration=59), dict(duration=315360001), dict(duration=True),
                   dict(duration=86400.0), dict(started_at=1000.0),
                   dict(expires_at=1000), dict(started_at=-1), dict(ip='127.000.0.1'),
                   dict(ip='2001:0DB8::1'), dict(ip='::ffff:192.0.2.1'), dict(site='../fixture'),
                   dict(reason='cc'), dict(evidence_hash='a' * 63), dict(unexpected=True)]
        for change in changes:
            with self.subTest(change=change):
                row = entry(now=1000)
                row.update(change)
                self.assertIsNone(self.decode(snapshot([row])))

    def test_snapshot_rejects_duplicate_fields_and_object_array_confusion(self):
        for body in (
                '{"version":1,"revision":"' + '1' * 32 + '","entries":{}}',
                '{"version":1,"version":1,"revision":"' + '1' * 32 + '","entries":[]}',
                '{"version":1,"\\u0076ersion":1,"revision":"' + '1' * 32 + '","entries":[]}',
                json.dumps(snapshot([entry(now=1000)])).replace('"risk_advice"', '"risk_advice","reason":"risk_advice"'),
                json.dumps(snapshot([entry(now=1000), entry(now=1000)])),
                json.dumps(dict(snapshot(), extra=1)),
                json.dumps(dict(snapshot(), revision='G' * 32)),
                json.dumps(dict(snapshot(), version=True)),
                json.dumps(dict(snapshot(), version=1.0)),
                json.dumps(snapshot([entry(now=1000)])).replace('86400', '864e2'),
                json.dumps(snapshot()) + ' trailing',
                ' ' * 1048577):
            with self.subTest(body=body[:120]):
                self.assertIsNone(self.decode(body))
        self.assertIsNotNone(self.decode(snapshot()))
        self.assertIsNone(self.decode(snapshot([entry(site='fixture-' + str(i), now=1000) for i in range(4097)])))

    def test_snapshot_byte_and_row_limits_are_inclusive(self):
        body = json.dumps(snapshot())
        self.assertIsNotNone(self.decode(body + ' ' * (1048576 - len(body))))
        self.assertIsNone(self.decode(body + ' ' * (1048577 - len(body))))
        value = snapshot([entry(site='fixture-' + str(i), now=1000) for i in range(4096)])
        self.assertIsNotNone(self.decode(value))
        self.assertIsNotNone(self.decode(snapshot([entry(now=1000, seconds=60)])))
        self.assertIsNotNone(self.decode(snapshot([entry(now=9007198939380991, seconds=315360000)])))
        self.assertIsNone(self.decode(snapshot([entry(now=9007198939380992, seconds=315360000)])))

    def test_guard_is_site_only_expires_and_does_not_reread_or_count(self):
        self.load(snapshot([entry(ip='2001:db8::1', now=990, seconds=60)]))
        self.lua.execute('''
            server_name='fixture.example'; ip='2001:0DB8:0:0:0:0:0:1'
            assert(manual_site_ban_guard()==true and response_status==403)
            assert(ngx.header['Retry-After']=='50')
            assert(not string.find(response_body,'aaPanel',1,true))
            assert(not string.find(response_body,'risk_advice',1,true))
            for _=1,20 do assert(manual_site_ban_guard()==true) end
            assert(read_count==1,'requests must use loaded memory only')
            server_name='other.example'; response_status=nil
            assert(manual_site_ban_guard()==false and response_status==nil)
            server_name='fixture.example'; ngx.time=function() return 1050 end
            assert(manual_site_ban_guard()==false and response_status==nil)
        ''')

    def _assert_mapped_peer_matches_ipv4_ban(self, peer):
        self.load(snapshot([entry(ip='192.0.2.17', now=1000)]))
        self.lua.globals().ip = peer
        self.lua.execute("server_name='fixture.example'")
        self.assertTrue(self.lua.globals().manual_site_ban_guard(), peer)
        self.assertEqual(self.lua.globals().response_status, 403)
        self.assertEqual(self.lua.globals().read_count, 1)
        self.lua.execute('''
            server_name='other.example'; response_status=nil
            assert(manual_site_ban_guard()==false and response_status==nil)
        ''')

    def test_guard_matches_dotted_ipv4_mapped_peer_to_ipv4_ban(self):
        self._assert_mapped_peer_matches_ipv4_ban('::ffff:192.0.2.17')

    def test_guard_matches_hex_ipv4_mapped_peer_to_ipv4_ban(self):
        self._assert_mapped_peer_matches_ipv4_ban('::ffff:c000:211')

    def test_guard_matches_expanded_ipv4_mapped_peers_without_changing_legacy_identity(self):
        for peer in ('0:0:0:0:0:FFFF:C000:0211', '0:0:0:0:0:ffff:192.0.2.17'):
            with self.subTest(peer=peer):
                self._assert_mapped_peer_matches_ipv4_ban(peer)
                self.assertEqual(self.lua.globals().endpoint_normalize_ip(peer), '::ffff:c000:211')

    def test_snapshot_rejects_mapped_ipv6_keys_not_written_by_python(self):
        for peer in ('::ffff:192.0.2.17', '::ffff:c000:211', '0:0:0:0:0:FFFF:C000:0211',
                     '::ffff:0:0', '::ffff:ffff:ffff'):
            with self.subTest(peer=peer):
                self.assertIsNone(self.decode(snapshot([entry(ip=peer, now=1000)])))

    def test_native_ipv6_and_unrelated_ipv4_peers_do_not_match_ipv4_ban(self):
        self.load(snapshot([entry(ip='192.0.2.17', now=1000)]))
        self.lua.execute("server_name='fixture.example'")
        for peer in ('192.0.2.18', '::ffff:192.0.2.18', '::ffff:c000:212',
                     '::192.0.2.17', '64:ff9b::c000:211', '::ffff:0:c000:211', '2001:db8::1'):
            with self.subTest(peer=peer):
                self.lua.globals().ip = peer
                self.assertFalse(self.lua.globals().manual_site_ban_guard())
        for canonical, peer in (('::c000:211', '::192.0.2.17'),
                                ('64:ff9b::c000:211', '64:ff9b:0:0:0:0:c000:0211')):
            with self.subTest(canonical=canonical):
                self.load(snapshot([entry(ip=canonical, now=1000)]))
                self.lua.globals().ip = peer
                self.assertTrue(self.lua.globals().manual_site_ban_guard())

    def test_missing_is_valid_empty_but_corrupt_never_is(self):
        self.load(None, 'missing')
        self.lua.execute('''
            local result=get_manual_site_bans()
            assert(result.status==true and result.valid==true)
            assert(result.revision==string.rep('0',32) and #result.entries==0)
            manual_site_ban_response()
        ''')
        self.assertEqual(json.loads(self.lua.globals().response_body)['entries'], [])
        for body, error in (('not JSON', None), (None, 'read_failed'), (None, 'unsafe_directory')):
            self.load(body, error)
            self.lua.execute('''
                local result=get_manual_site_bans()
                assert(result.status==false and result.valid==false)
                assert(result.revision==json.null and result.entries==json.null)
                server_name='fixture.example'; ip='127.0.0.1'
                assert(manual_site_ban_guard()==false)
                manual_site_ban_response()
            ''')
            result = json.loads(self.lua.globals().response_body)
            self.assertIsNone(result['entries'])
            self.assertFalse(result['valid'])

    def test_proof_reports_loaded_not_changed_disk_and_keeps_expired_rows(self):
        self.load(snapshot([entry(now=900, seconds=60)]))
        self.lua.globals().fixture_body = json.dumps(snapshot([], revision='2' * 32))
        self.lua.execute('''
            manual_site_ban_response()
            assert(read_count==1,'proof must never force-read disk')
        ''')
        result = json.loads(self.lua.globals().response_body)
        self.assertEqual(result['revision'], '1' * 32)
        self.assertEqual(result['policy_signature'], 'b' * 32)
        self.assertEqual(len(result['entries']), 1)

    def test_reader_requires_safe_metadata_uses_nofollow_and_never_writes(self):
        found = re.search(r'(?m)^function manual_site_ban_read\(.*?\nend', self.source, re.S)
        self.assertIsNotNone(found)
        self.lua.execute('''
            cpath='/www/server/free_waf/'
            fake={descriptors={},next_fd=10,body='snapshot',errno=2,opened=0,closed=0}
            local C={}
            local function descriptor(kind)
                local fd=fake.next_fd; fake.next_fd=fd+1
                fake.descriptors[fd]={kind=kind,offset=0}; fake.opened=fake.opened+1
                return fd
            end
            function C.gpt_fw_manual_open(path,flags)
                assert(path=='/' and flags==720896,'root must be opened as nofollow directory')
                return descriptor('directory')
            end
            function C.gpt_fw_manual_openat(parent,path,flags)
                assert(fake.descriptors[parent].kind=='directory','all paths must be pinned to open parent')
                if path=='manual_site_bans.json' then
                    assert(flags==657408,'snapshot must be read-only, nonblocking, nofollow')
                    if fake.open_error then fake.errno=fake.open_error; return -1 end
                    return descriptor('file')
                end
                assert(flags==720896,'directory components must be nofollow')
                if fake.bad_component then fake.errno=40; return -1 end
                return descriptor('directory')
            end
            function C.gpt_fw_manual_fstat(fd,buffer)
                local current=assert(fake.descriptors[fd])
                local file=current.kind=='file'
                buffer[0]={mode=file and (fake.file_mode or 33188) or (fake.parent_mode or 16877),
                           uid=(file and fake.file_uid or fake.parent_uid) or 0,nlink=fake.nlink or 1}
                return 0
            end
            function C.gpt_fw_manual_read(fd,buffer,count)
                local current=assert(fake.descriptors[fd]); assert(current.kind=='file')
                assert(count<=1048577,'read must be bounded')
                local body=string.sub(fake.body,current.offset+1,current.offset+count)
                current.offset=current.offset+#body
                buffer.root.body=(buffer.root.body or '')..body
                return #body
            end
            function C.gpt_fw_manual_close(fd)
                assert(fake.descriptors[fd]); fake.descriptors[fd]=nil; fake.closed=fake.closed+1; return 0
            end
            local ffi={os='Linux',arch='x64',C=C,cdef=function() end,errno=function() return fake.errno end}
            function ffi.new(kind)
                if kind=='struct gpt_fw_manual_stat[1]' then return {[0]={}} end
                assert(kind=='char[?]')
                local value={}; value.root=value
                return setmetatable(value,{__add=function(left,offset) return {root=left.root,offset=offset} end})
            end
            function ffi.string(buffer,size) return string.sub(buffer.body or '',1,size) end
            require=function(name) assert(name=='ffi'); return ffi end
        ''')
        self.lua.execute(found.group(0))
        self.lua.execute('''
            local body,err=manual_site_ban_read()
            assert(body=='snapshot' and err==nil)
            assert(fake.opened==fake.closed and next(fake.descriptors)==nil)
            for _,changes in ipairs({
                {open_error=2,expected='missing'},
                {open_error=40,expected='read_failed'},
                {bad_component=true,expected='unsafe_directory'},
                {parent_mode=16895,expected='unsafe_directory'},
                {parent_uid=33,expected='unsafe_directory'},
                {file_uid=33,expected='unsafe_file'},
                {file_mode=33206,expected='unsafe_file'},
                {file_mode=33204,expected='unsafe_file'},
                {file_mode=4516,expected='unsafe_file'},
                {nlink=2,expected='unsafe_file'},
                {body=string.rep('x',1048577),expected='size_limit'}
            }) do
                fake={descriptors={},next_fd=10,body='snapshot',errno=2,opened=0,closed=0}
                for key,value in pairs(changes) do fake[key]=value end
                local result,code=manual_site_ban_read()
                assert(result==nil and code==changes.expected,'unexpected unsafe read result: '..tostring(code))
                assert(fake.opened==fake.closed and next(fake.descriptors)==nil,'descriptor leak')
            end
        ''')

    def test_hook_is_after_whitelist_and_before_auto_guard_and_health_404(self):
        run = re.search(r'(?m)^function run_btwaf\(\).*?\nend', self.source, re.S).group(0)
        self.assertLess(run.index("if not config['open']"), run.index('manual_site_ban_guard()'))
        self.assertLess(run.index('if ip_white() then return true end'), run.index('manual_site_ban_guard()'))
        self.assertLess(run.index('manual_site_ban_guard()'), run.index('repeat_ban_guard()'))
        route = re.search(r'(?m)^function min_route\(\).*?\nend', self.source, re.S).group(0)
        self.assertLess(route.index("remote_addr ~= '127.0.0.1'"), route.index("'/get_manual_site_bans'"))
        self.assertLess(route.index("'/get_manual_site_bans'"), route.index("server_name == 'gpt-firewall-health.invalid'"))
        self.assertIn('manual_site_ban_load(ngx.md5(', self.source.split('\nend')[-1])

    def test_route_is_loopback_only_and_works_on_health_host_with_open_switch_off(self):
        for name in ('min_route',):
            found = re.search(r'(?m)^function ' + name + r'\(.*?\nend', self.source, re.S)
            self.assertIsNotNone(found)
            self.lua.execute(found.group(0))
        self.load(snapshot([entry(now=1000)]))
        self.lua.execute('''
            uri='/get_manual_site_bans'
            ngx.var.server_name='gpt-firewall-health.invalid'
            min_route()
            assert(response_status==200)
            response_status=nil; response_body=nil
            ngx.var.remote_addr='192.0.2.1'
            assert(min_route()==false and response_status==nil and response_body==nil)
        ''')


class _IsolatedManualBanNginx:
    def __init__(self, case):
        self.case = case
        self.binary = os.environ['GPT_FIREWALL_TEST_NGINX']
        self.temporary = tempfile.TemporaryDirectory(prefix='gpt-firewall-manual-isolated-')
        case.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o755)
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir(mode=0o755)
        (self.root / 'logs').mkdir()
        (self.runtime / 'rule').mkdir()
        (self.runtime / 'html').mkdir()
        self.config = dict(open=True, log=False, retry=6, retry_cycle=60, retry_time=60,
                           cc=dict(open=False, cycle=60, endtime=60, limit=100, status=403),
                           scan=dict(open=False, status=403), drop_abroad=dict(open=False, status=403),
                           reqfile_path=str(self.runtime / 'html'), compatibility_profile='bt-free-waf-8.4',
                           site_aliases={'alias.example': 'fixture.example'})
        for key in ('get', 'post', 'cookie', 'user-agent', 'other'):
            self.config[key] = dict(open=False, reqfile='fixture.html', status=403)
        (self.runtime / 'html/fixture.html').write_text('unrelated rejection')
        base = dict(open=True, cc=dict(self.config['cc']), retry=6, retry_cycle=60, retry_time=60,
                    disable_php_path=[], disable_path=[], disable_ext=[], disable_upload_ext=[],
                    url_rule=[], url_tell=[], repeat_ban_policy=dict(enabled=False, window_seconds=86400,
                        tiers=[dict(threshold=5, ban_seconds=604800)]))
        self.sites = {'fixture.example': dict(base), 'other.example': dict(base)}
        self.save_policy()
        (self.runtime / 'rule/scan_black.json').write_text(json.dumps(dict(cookie=[], header=[], args=[])))
        (self.runtime / 'rule/cn.json').write_text('[]')
        (self.runtime / 'rule/ip_white.json').write_text('[]')
        self.auto = self.runtime / 'repeat_bans.json'
        self.auto.write_text('{"version":1,"revision":"' + 'e' * 32 + '","bans":[]}')
        self.auto_before = self.auto.read_bytes()
        self.static = self.root / 'static'
        self.static.mkdir(mode=0o755)
        (self.static / 'fixture.txt').write_text('normal access completed')
        (self.root / 'init.lua').write_text(SOURCE.read_text(encoding='utf-8').replace(
            'local cpath = "/www/server/free_waf/"', 'local cpath = ' + json.dumps(str(self.runtime) + '/')))
        (self.root / 'access.lua').write_text('run_btwaf()\n')
        with socket.socket() as selected:
            selected.bind(('127.0.0.1', 0))
            self.port = selected.getsockname()[1]
        self.ipv6 = False
        try:
            with socket.socket(socket.AF_INET6) as selected:
                selected.bind(('::1', self.port))
            self.ipv6 = True
        except OSError:
            pass
        library = Path(self.binary).resolve().parents[1] / 'lib/lua'
        lua_path = ('lua_package_path "' + str(library) + '/?.lua;;";\n') if library.is_dir() else ''
        managed = IntegrationRepairService.INCLUDE.decode().replace(
            '/www/server/free_waf/init.lua', str(self.root / 'init.lua')).replace(
            '/www/server/free_waf/waf.lua', str(self.root / 'access.lua')).replace(
            '/www/server/free_waf/.health-no-content', str(self.root / 'empty')).replace(
            '127.0.0.1:39091', '127.0.0.1:' + str(self.port))
        self.conf = self.root / 'nginx.conf'
        extra = 'listen [::1]:' + str(self.port) + ';' if self.ipv6 else ''
        self.conf.write_text('pid ' + str(self.root / 'nginx.pid') + ';\nerror_log ' + str(self.root / 'error.log') + ' notice;\n'
            'worker_processes 2; events { worker_connections 32; } http {\n'
            'keepalive_timeout 0; keepalive_requests 1;\n' + lua_path + managed +
            'server { listen 127.0.0.1:' + str(self.port) + '; ' + extra + ' server_name alias.example; access_log off;\n'
            'location / { root ' + str(self.static) + '; } }\n'
            'server { listen 127.0.0.1:' + str(self.port) + '; server_name other.example; access_log off;\n'
            'location / { root ' + str(self.static) + '; } } }\n')
        self.args = [self.binary, '-p', str(self.root) + '/', '-c', str(self.conf)]
        self.process = None
        self.diagnostic = (self.root / 'startup.log').open('wb')
        case.addCleanup(self.diagnostic.close)
        case.addCleanup(self.stop)

    def save_policy(self):
        (self.runtime / 'config.json').write_text(json.dumps(self.config))
        (self.runtime / 'site.json').write_text(json.dumps(self.sites))

    def signature(self):
        paths = ('config.json', 'site.json', 'rule/ip_white.json')
        return hashlib.md5(b'\0'.join((self.runtime / path).read_bytes() for path in paths)).hexdigest()

    def save_snapshot(self, value):
        path = self.runtime / 'manual_site_bans.json'
        temporary = self.runtime / '.fixture-manual.tmp'
        temporary.write_text(value if isinstance(value, str) else json.dumps(value))
        temporary.chmod(0o644)
        os.replace(str(temporary), str(path))

    def request(self, path='/fixture.txt', host='alias.example', address='127.0.0.1', source=None):
        connection = http.client.HTTPConnection(address, self.port, timeout=2, source_address=source)
        try:
            connection.request('GET', path, headers={'Host': host})
            response = connection.getresponse()
            return response.status, response.read(1048577), dict(response.getheaders())
        finally:
            connection.close()

    def proof(self):
        status, body, _ = self.request('/get_manual_site_bans', host='gpt-firewall-health.invalid')
        self.case.assertEqual(status, 200)
        return json.loads(body)

    def wait_proof(self, expected_revision, signature=None):
        deadline = time.monotonic() + 5
        result = None
        while time.monotonic() < deadline and self.process.poll() is None:
            try:
                result = self.proof()
                if result['revision'] == expected_revision and result['policy_signature'] == (signature or self.signature()):
                    return result
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        self.case.fail('loaded manual snapshot never observed: ' + repr(result) + '\n' + self.diagnostics())

    def diagnostics(self):
        result = (self.root / 'startup.log').read_text(errors='replace')
        if (self.root / 'error.log').exists():
            result += (self.root / 'error.log').read_text(errors='replace')
        return result[-3000:]

    def start(self):
        checked = subprocess.run(self.args + ['-t'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.case.assertEqual(checked.returncode, 0, checked.stderr.decode(errors='replace'))
        self.process = subprocess.Popen(self.args + ['-g', 'daemon off;'], stdout=subprocess.DEVNULL, stderr=self.diagnostic)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self.process.poll() is None:
            try:
                if self.request('/_gpt_firewall_health/' + 'a' * 32, 'gpt-firewall-health.invalid')[0] == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        self.case.fail(self.diagnostics())

    def worker_pids(self):
        pid = str(self.process.pid)
        return set((Path('/proc') / pid / 'task' / pid / 'children').read_text().split())

    def reload(self):
        previous = self.worker_pids()
        checked = subprocess.run(self.args + ['-t'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.case.assertEqual(checked.returncode, 0, checked.stderr.decode(errors='replace'))
        reloaded = subprocess.run(self.args + ['-s', 'reload'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.case.assertEqual(reloaded.returncode, 0, reloaded.stderr.decode(errors='replace'))
        # One new-worker proof does not exclude an old worker still serving requests.
        deadline = time.monotonic() + 5
        while self.process.poll() is None:
            if not previous.intersection(self.worker_pids()):
                return
            self.case.assertLess(time.monotonic(), deadline, 'previous test workers did not drain')
            time.sleep(0.05)
        self.case.fail('test Nginx exited during reload')

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)


class ManualBanReloadFixtureTest(unittest.TestCase):
    def test_reload_waits_until_both_previous_workers_have_drained(self):
        lab = _IsolatedManualBanNginx.__new__(_IsolatedManualBanNginx)
        lab.case, lab.args = self, ['nginx-fixture']
        lab.process = Mock()
        lab.process.poll.return_value = None
        lab.worker_pids = Mock(side_effect=[{'41', '42'}, {'41'}, {'42'}, set()])
        with patch('subprocess.run', return_value=Mock(returncode=0, stderr=b'')), \
                patch('time.sleep') as sleep:
            lab.reload()
        self.assertEqual(lab.worker_pids.call_count, 4)
        self.assertEqual(sleep.call_count, 2)

    def test_reload_fails_instead_of_waiting_forever_for_old_workers(self):
        lab = _IsolatedManualBanNginx.__new__(_IsolatedManualBanNginx)
        lab.case, lab.args = self, ['nginx-fixture']
        lab.process = Mock()
        lab.process.poll.return_value = None
        lab.worker_pids = Mock(return_value={'41'})
        with patch('subprocess.run', return_value=Mock(returncode=0, stderr=b'')), \
                patch('time.monotonic', side_effect=[0, 6]), patch('time.sleep'):
            with self.assertRaisesRegex(self.failureException, 'did not drain'):
                lab.reload()


@unittest.skipUnless(os.environ.get('GPT_FIREWALL_TEST_NGINX'), 'requires explicitly selected Lua-enabled Nginx')
class ManualSiteBanNginxTest(unittest.TestCase):
    def fixture(self):
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            self.skipTest('root-owned read-only runtime snapshot proof requires root in disposable Linux namespace')
        return _IsolatedManualBanNginx(self)

    def test_scope_alias_restart_reload_unban_and_automatic_history_unchanged(self):
        lab = self.fixture()
        value = snapshot([entry()])
        lab.save_snapshot(value)
        before = (lab.runtime / 'manual_site_bans.json').read_bytes()
        lab.start()
        loaded = lab.wait_proof(value['revision'])
        self.assertTrue(loaded['valid'])
        self.assertEqual(loaded['entries'], value['entries'])
        for _ in range(20):
            status, body, headers = lab.request()
            self.assertEqual(status, 403)
            self.assertGreater(int(headers['Retry-After']), 0)
            self.assertNotIn(b'aaPanel', body)
            self.assertNotIn(b'risk_advice', body)
            self.assertEqual(lab.request(host='other.example')[0], 200)
        self.assertEqual(lab.auto.read_bytes(), lab.auto_before)
        self.assertEqual((lab.runtime / 'manual_site_bans.json').read_bytes(), before)
        self.assertFalse((lab.runtime / 'drop_ip.log').exists())
        self.assertFalse((lab.runtime / '.repeat-bans.lock').exists())
        lab.stop()
        lab.start()
        self.assertEqual(lab.request()[0], 403)
        empty = snapshot([], revision='2' * 32)
        lab.save_snapshot(empty)
        for _ in range(5):
            self.assertEqual(lab.proof()['revision'], value['revision'], 'proof must not reread disk before reload')
            self.assertEqual(lab.request()[0], 403)
        lab.reload()
        self.assertEqual(lab.wait_proof(empty['revision'])['entries'], [])
        self.assertEqual(lab.request()[0], 200)
        self.assertEqual(lab.request(host='other.example')[0], 200)
        self.assertEqual(lab.auto.read_bytes(), lab.auto_before)

    def test_expiry_requires_no_file_write_or_reload(self):
        lab = self.fixture()
        now = int(time.time())
        value = snapshot([entry(seconds=60, now=now - 57)])
        lab.save_snapshot(value)
        before = (lab.runtime / 'manual_site_bans.json').read_bytes()
        lab.start()
        lab.wait_proof(value['revision'])
        self.assertEqual(lab.request()[0], 403)
        time.sleep(max(0, value['entries'][0]['expires_at'] - time.time() + 0.1))
        self.assertEqual(lab.request()[0], 200)
        self.assertEqual(lab.proof()['entries'], value['entries'], 'proof is exact loaded snapshot, including expiry')
        self.assertEqual((lab.runtime / 'manual_site_bans.json').read_bytes(), before)

    def test_global_site_switches_and_ip_whitelist_override_manual_ban(self):
        lab = self.fixture()
        value = snapshot([entry()])
        lab.save_snapshot(value)
        lab.config['open'] = False
        lab.save_policy()
        lab.start()
        lab.wait_proof(value['revision'])
        self.assertEqual(lab.request()[0], 200)
        lab.config['open'] = True
        lab.sites['fixture.example']['open'] = False
        lab.save_policy()
        previous = lab.proof()['policy_signature']
        self.assertNotEqual(previous, lab.signature())
        self.assertEqual(lab.proof()['policy_signature'], previous)
        lab.reload()
        lab.wait_proof(value['revision'])
        self.assertEqual(lab.request()[0], 200)
        lab.sites['fixture.example']['open'] = True
        lab.save_policy()
        (lab.runtime / 'rule/ip_white.json').write_text('[[[127,0,0,1],[127,0,0,1]]]')
        lab.reload()
        lab.wait_proof(value['revision'])
        self.assertEqual(lab.request()[0], 200)
        (lab.runtime / 'rule/ip_white.json').write_text('[]')
        lab.reload()
        lab.wait_proof(value['revision'])
        self.assertEqual(lab.request()[0], 403)

    def test_missing_corrupt_oversized_and_unsafe_files_are_not_false_valid_empty(self):
        lab = self.fixture()
        lab.start()
        self.assertEqual(lab.wait_proof('0' * 32)['entries'], [])
        self.assertTrue(lab.proof()['valid'])
        for value in ('not JSON', ' ' * 1048577, dict(snapshot(), entries={} )):
            lab.stop()
            lab.save_snapshot(value)
            lab.start()
            proof = lab.proof()
            self.assertFalse(proof['status'])
            self.assertFalse(proof['valid'])
            self.assertIsNone(proof['entries'])
            self.assertIsNone(proof['revision'])
            self.assertEqual(lab.request()[0], 200)
        for mode in (0o666, 0o664):
            lab.stop()
            lab.save_snapshot(snapshot([entry()]))
            (lab.runtime / 'manual_site_bans.json').chmod(mode)
            lab.start()
            self.assertFalse(lab.proof()['valid'])
            self.assertEqual(lab.request()[0], 200)
        lab.stop()
        lab.save_snapshot(snapshot([entry()]))
        (lab.runtime / 'manual_site_bans.json').unlink()
        (lab.runtime / 'manual_site_bans.json').symlink_to(lab.auto)
        lab.start()
        self.assertFalse(lab.proof()['valid'])
        self.assertEqual(lab.auto.read_bytes(), lab.auto_before)

    def test_remote_route_cannot_disclose_snapshot_and_ipv6_is_canonical(self):
        lab = self.fixture()
        lab.save_snapshot(snapshot([entry(ip='::1')]))
        lab.start()
        self.assertEqual(lab.request('/get_manual_site_bans', source=('127.0.0.2', 0))[0], 404)
        status, body, _ = lab.request('/get_manual_site_bans', host='gpt-firewall-health.invalid', source=('127.0.0.2', 0))
        self.assertNotEqual(status, 200)
        self.assertNotIn(b'evidence_hash', body)
        self.assertEqual(lab.request()[0], 200)
        if lab.ipv6:
            self.assertEqual(lab.request(address='::1')[0], 403)
        self.assertEqual(lab.auto.read_bytes(), lab.auto_before)


if __name__ == '__main__':
    unittest.main()
