"""Synthetic LuaJIT identity/scanner regression tests; no host IO or network."""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'init.lua'


def function_body(source, name):
    match = re.search(r'(?m)^function ' + re.escape(name) + r'\(.*?\nend', source, re.S)
    if not match:
        raise AssertionError('missing runtime function: ' + name)
    return match.group(0)


def lua_string(value):
    delimiter = '='
    while ']' + delimiter + ']' in value:
        delimiter += '='
    return '[' + delimiter + '[' + value + ']' + delimiter + ']'


NATIVE_PLATFORM = r'''
-- cjson is already part of the repository's native LuaJIT test environment.
local fixture_json=require('cjson')
fixture_encode=fixture_json.encode
fixture_decode=fixture_json.decode
function fixture_md5(value)
    -- Stable synthetic identity only, as in audit_runtime_routes.lua; not a crypto test.
    local hash=5381
    for i=1,#value do hash=(hash*33+value:byte(i))%2147483647 end
    return string.format('%032x',hash)
end
function fixture_match(value,pattern)
    if value==nil then return nil end
    value,pattern=string.lower(value),string.lower(pattern)
    -- Only the literal, anchor, character-class and single-alternation patterns
    -- used by this synthetic fixture. Unsupported regexes fail, never silently miss.
    local function simple(expression)
        assert(not expression:find('[?{}|()]'),'unsupported fixture regex: '..pattern)
        expression=expression:gsub('%%','%%%%'):gsub('%-','%%-'):gsub('\\%.','%%.')
        assert(not expression:find('\\',1,true),'unsupported fixture escape: '..pattern)
        return value:find(expression)
    end
    local prefix,choices,suffix=pattern:match('^([^()]*)%(([^()]*)%)([^()]*)$')
    if not choices then return simple(pattern) end
    local first
    for choice in choices:gmatch('[^|]+') do
        local found=simple(prefix..choice..suffix)
        if found and (not first or found<first) then first=found end
    end
    return first
end
'''


FIXTURE = r'''
now=1000
function dictionary()
    local values,expires={},{}
    local d={writes=0}
    function d:get(k)
        if expires[k] and expires[k]<=now then return nil end
        return values[k]
    end
    function d:set(k,v,ttl)
        self.writes=self.writes+1
        values[k],expires[k]=v,ttl and now+ttl
        return true
    end
    function d:safe_set(k,v,ttl)
        if self.full then return nil,'no memory' end
        return self:set(k,v,ttl)
    end
    function d:safe_add(k,v,ttl)
        if self:get(k)~=nil then return nil,'exists' end
        return self:safe_set(k,v,ttl)
    end
    function d:incr(k,v)
        if self:get(k)==nil then return nil,'not found' end
        values[k]=values[k]+v
        return values[k]
    end
    function d:delete(k) values[k],expires[k]=nil,nil end
    function d:ttl(k) return self:get(k)~=nil and expires[k] and expires[k]-now end
    function d:get_keys()
        local keys={}
        for k in pairs(values) do if self:get(k)~=nil then keys[#keys+1]=k end end
        return keys
    end
    return d
end
config={open=true,log=false,retry=6,retry_time=60,retry_cycle=60,
    cc={open=false,status=403,limit=100,cycle=60,endtime=60}}
site_config={}
for _,name in ipairs({'a.example','b.example'}) do
    site_config[name]={open=true,cdn=false,cdn_header={'x-forwarded-for'},url_white={},
        cc={open=false,increase=false,limit=100,cycle=60,endtime=60},
        retry=6,retry_time=60,retry_cycle=60}
end
headers={}
ngx={var={server_name='a.example',remote_addr='192.0.2.1',uri='/.env',request_uri='/.env',status=404},
    ctx={},header={},shared={free_waf=dictionary(),free_waf_drop_ip=dictionary(),free_waf_drop_sum=dictionary()},
    time=function() return now end,md5=function(v) return fixture_md5(v) end,
    re={find=function(v,p) return fixture_match(v,p) end,match=function(v,p) return fixture_match(v,p) end},
    unescape_uri=function(v) return v end,
    req={get_headers=function() return headers end,get_method=function() return 'GET' end,
        get_uri_args=function() return uri_request_args end},
    say=function() assert(phase~='log','log hook must not render a response') end,
    exit=function(status)
        assert(phase~='log','log hook must not exit a response')
        error({status=status},0)
    end,log=function() end,WARN=4}
ngx_match=ngx.re.find
json={encode=function(v) return fixture_encode(v) end,decode=function(v) return fixture_decode(v) end}
os={time=function() return now end}
ip_black_rules={}; ip_white_rules={}; url_white_rules={}; user_agent_white_rules={}
manual_site_ban_state={valid=true,by_site={}}
repeat_ban_cache={by_site={}}
snapshot={version=1,revision='fixture',bans={}}
events={}; drop_logs={}; global_writes=0; repeat_writes=0
cpath='fixture/'; jpath='fixture/rule/'; other_html='fixture blocked'
AUTO_BAN_SECONDS=28800; MAX_AUTO_BAN_SECONDS=28800
uri_request_args={}; retry=6
'''


BOUNDARIES = r'''
-- Only platform/file boundaries are substituted; guards, keys, counting and
-- repeat history execute the production Lua functions in the same environment.
function repeat_ban_lock() return {} end
function repeat_ban_unlock() end
function repeat_ban_snapshot()
    repeat_ban_cache.by_site={}
    for _,row in ipairs(snapshot.bans) do
        repeat_ban_cache.by_site[row.site]=repeat_ban_cache.by_site[row.site] or {}
        repeat_ban_cache.by_site[row.site][row.ip]=row
    end
    return snapshot
end
function repeat_ban_write(bans)
    repeat_writes=repeat_writes+1
    snapshot.bans=bans
    return true
end
local event=repeat_ban_event
function repeat_ban_event(site,address,seconds,reason,path)
    events[#events+1]={site=site,ip=address,seconds=seconds,reason=reason}
    return event(site,address,seconds,reason,path)
end
function write_drop_ip_entry(address,site,path,seconds,reason)
    drop_logs[#drop_logs+1]={ip=address,site=site,seconds=seconds,reason=reason}
    return true
end
function with_ip_black_lock(fn) return true,fn({}) end
function read_file(name) assert(name=='ip_black'); return ip_black_rules end
function runtime_atomic_write(path,body)
    assert(path==jpath..'ip_black.json')
    global_writes=global_writes+1
    ip_black_rules=json.decode(body)
    return true
end
function write_log() end
fixture_real_post=post
for _,name in ipairs({'total_log_worker_init','registration_guard','url_black','drop_abroad',
    'user_agent','header_rule','url','args','cookie','scan_black','post','php_path',
    'url_path','url_ext','url_rule_ex','url_tell','post_data'}) do
    _G[name]=function() return false end
end
function response(fn)
    local ok,result=pcall(fn)
    if ok then return 200,result end
    if type(result)~='table' or not result.status then error(result) end
    return result.status
end
function identify()
    server_name=ngx.var.server_name; request_header=headers
    ip=get_client_ip(); ipn=arrip(ip); request_uri=ngx.var.request_uri; uri=ngx.var.uri
end
function scan(count)
    local saved=capture_context()
    local saved_status=ngx.status
    local saved_headers={}
    for name,value in pairs(ngx.header) do saved_headers[name]=value end
    phase='log'
    for _=1,count or 1 do
        ban_404_accumulate()
        assert_context(saved)
        assert(ngx.status==saved_status,'log hook changed response status')
        for name,value in pairs(ngx.header) do
            assert(saved_headers[name]==value,'log hook changed response header: '..name)
        end
        for name,value in pairs(saved_headers) do
            assert(ngx.header[name]==value,'log hook removed response header: '..name)
        end
    end
    phase=nil
end
function ban_key(site,address) return cc_state_key('ban',site or 'a.example',address or '192.0.2.1') end
function counter_key(site,address)
    return 'cc:v3:scan404:'..#site..':'..site..':'..endpoint_normalize_ip(address)
end
function count_for(site,address) return ngx.shared.free_waf:get(counter_key(site,address)) end
function assert_quiet()
    assert(#events==0 and #drop_logs==0 and global_writes==0,'unexpected automatic side effect')
    assert(#ngx.shared.free_waf_drop_ip:get_keys()==0,'unexpected short ban')
end
function trust(mode)
    local s=site_config['a.example']; s.cdn=true; s.cdn_trust_mode=mode
    s.cdn_trusted_proxy={{{198,51,100,10},{198,51,100,20}}}
    ngx.var.remote_addr='198.51.100.10'; headers['x-forwarded-for']='192.0.2.1'
end
function enable_repeat()
    site_config['a.example'].repeat_ban_policy={enabled=true,window_seconds=86400,
        tiers={{threshold=2,ban_seconds=604800}}}
end
context_fields={'server_name','request_header','ip','ipn','request_uri','uri','retry',
    'error_rule','url_data','n','iparr','count','method','uri_request_args','cycle','endtime','limit',
    'retry_time','retry_cycle','site_cc'}
function capture_context()
    local saved={}
    for _,name in ipairs(context_fields) do saved[name]=_G[name] end
    return saved
end
function assert_context(saved)
    for _,name in ipairs(context_fields) do
        assert(_G[name]==saved[name],'log hook leaked access global: '..name)
    end
end
function seed_access_context()
    server_name='a.example'; ip='203.0.113.99'; ipn=arrip(ip)
    request_header={['user-agent']='request-a'}
    request_uri='/request-a?original=1'; uri='/request-a'; retry=19
    error_rule='request-a-rule'; url_data={original=true}; n=991; count=992
    return capture_context()
end
identify()
'''


class RuntimeIdentitySourceTest(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text(encoding='utf-8')

    def test_strict_mode_is_an_explicit_runtime_opt_in(self):
        self.assertIn("site_conf['cdn_trust_mode']", function_body(self.source, 'is_trusted_cdn_proxy'))

    def test_scanner_never_writes_the_global_blacklist_or_old_counter(self):
        body = function_body(self.source, 'ban_404_accumulate')
        self.assertNotIn('add_ip_black_exact', body)
        self.assertNotIn('client_ip .. "_404"', body)
        self.assertIn("cc_state_key('ban'", body)
        self.assertIn("cc_state_key('scan404'", body)

    def test_existing_hooks_are_not_newly_installed_or_called_from_access(self):
        self.assertNotIn('ban_404_accumulate()', function_body(self.source, 'run_btwaf'))
        self.assertEqual(self.source.count('ban_404_accumulate()'), 1)

    def test_health_reports_v012_runtime(self):
        body = function_body(self.source, 'min_route')
        self.assertIn("version='0.1.12'", body)
        self.assertNotIn("version='0.1.11'", body)

    def test_every_yielding_body_read_uses_the_request_context_guard(self):
        self.assertEqual(self.source.count('ngx.req.read_body'), 1)
        self.assertIn('pcall(ngx.req.read_body)', function_body(self.source, 'read_request_body'))
        for name, calls in (('post', 1), ('post_data', 1), ('url_rule_ex', 2)):
            self.assertEqual(function_body(self.source, name).count('read_request_body()'), calls)


class RuntimeIdentityRunnerTest(unittest.TestCase):
    def run_without_lupa(self, environment, executable, process_result):
        result = unittest.TestResult()
        case = RuntimeIdentityLuaTest('test_log_hook_cannot_change_suspended_real_post_site_or_identity')
        with patch.dict(os.environ, environment, clear=True), \
                patch.dict(sys.modules, {'lupa': None, 'lupa.luajit21': None}), \
                patch('shutil.which', return_value=executable), \
                patch('subprocess.run', return_value=process_result) as run:
            case.run(result)
        return result, run

    def test_explicit_native_luajit_runs_behavior_without_lupa(self):
        result, run = self.run_without_lupa(
            {'FREE_WAF_LUAJIT': 'fixture-luajit'}, None,
            subprocess.CompletedProcess([], 0, 'runtime_identity_case=true\n', ''))
        self.assertEqual(result.skipped, [], 'native CI must execute behavior, not skip it')
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertEqual(run.call_args[0][0], ['fixture-luajit', '-'])
        self.assertIn('B log hook bypassed A POST rule', run.call_args[1]['input'])

    def test_path_native_luajit_runs_behavior_without_lupa(self):
        result, run = self.run_without_lupa(
            {}, 'path-luajit', subprocess.CompletedProcess([], 0, 'runtime_identity_case=true\n', ''))
        self.assertEqual(result.skipped, [])
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertEqual(run.call_args[0][0], ['path-luajit', '-'])

    def test_missing_runtime_is_an_error_not_a_successful_skip(self):
        result, run = self.run_without_lupa({}, None, None)
        self.assertFalse(result.wasSuccessful(), 'missing interpreter silently hid behavioral coverage')
        self.assertEqual(result.skipped, [])
        self.assertIn('FREE_WAF_LUAJIT', result.errors[0][1])
        run.assert_not_called()

    def test_native_nonzero_exit_cannot_pass_or_fall_back(self):
        result, run = self.run_without_lupa(
            {'FREE_WAF_LUAJIT': 'fixture-luajit'}, None,
            subprocess.CompletedProcess([], 1, '', 'synthetic Lua assertion failed'))
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(result.skipped, [])
        self.assertIn('synthetic Lua assertion failed', result.failures[0][1])
        run.assert_called_once()

    def test_native_success_requires_fixture_completion_marker(self):
        result, run = self.run_without_lupa(
            {'FREE_WAF_LUAJIT': 'fixture-luajit'}, None,
            subprocess.CompletedProcess([], 0, '', ''))
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(result.skipped, [])
        run.assert_called_once()


class RuntimeIdentityLuaTest(unittest.TestCase):
    def setUp(self):
        source = SOURCE.read_text(encoding='utf-8')
        functions = re.findall(r'(?m)^function [A-Za-z0-9_]+\(.*?\nend', source, re.S)
        executable = os.environ.get('FREE_WAF_LUAJIT') or shutil.which('luajit')
        self.native_command = [executable, '-'] if executable else None
        if self.native_command:
            self.native_fixture = '\n'.join([
                'fixture_source=' + lua_string(source),
                "assert(loadstring(fixture_source, '@init.lua'))",
                NATIVE_PLATFORM, FIXTURE, *functions, BOUNDARIES,
            ])
            return
        try:
            from lupa.luajit21 import LuaRuntime, lua_type
        except ImportError as error:
            raise RuntimeError(
                'Runtime identity behavior requires FREE_WAF_LUAJIT, luajit on PATH, '
                'or existing lupa.luajit21; refusing to skip runtime coverage'
            ) from error
        import hashlib
        self.lua = LuaRuntime(unpack_returned_tuples=True)

        def to_lua(value):
            if isinstance(value, dict):
                return self.lua.table_from({key: to_lua(item) for key, item in value.items()})
            if isinstance(value, list):
                return self.lua.table_from([to_lua(item) for item in value])
            return value

        def from_lua(value):
            if lua_type(value) != 'table':
                return value
            keys = list(value.keys())
            if keys and set(keys) == set(range(1, len(keys) + 1)):
                return [from_lua(value[index]) for index in range(1, len(keys) + 1)]
            return {key: from_lua(item) for key, item in value.items()}

        def match(value, pattern):
            if value is None:
                return None
            found = re.search(pattern, value, re.I | re.S)
            return found.start() + 1 if found else None

        globals_ = self.lua.globals()
        globals_.fixture_encode = lambda value: json.dumps(from_lua(value), sort_keys=True, separators=(',', ':'))
        globals_.fixture_decode = lambda value: to_lua(json.loads(value))
        globals_.fixture_match = match
        globals_.fixture_md5 = lambda value: hashlib.md5(value.encode()).hexdigest()
        globals_.fixture_source = source
        self.lua.execute("assert(loadstring(fixture_source, '@init.lua'))")
        self.lua.execute(FIXTURE)
        for function in functions:
            self.lua.execute(function)
        self.lua.execute(BOUNDARIES)

    def check(self, body):
        if self.native_command:
            result = subprocess.run(
                self.native_command,
                input=self.native_fixture + '\n' + body + "\nprint('runtime_identity_case=true')\n",
                encoding='utf-8', capture_output=True, timeout=45, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('runtime_identity_case=true', result.stdout)
            return
        try:
            self.lua.execute(body)
        except Exception as error:
            self.fail(str(error))

    def test_strict_empty_or_absent_ranges_ignore_spoofed_headers(self):
        self.check('''
            trust('strict')
            for _,ranges in ipairs({{},false}) do
                site_config['a.example'].cdn_trusted_proxy=ranges or nil
                identify()
                assert(ip==ngx.var.remote_addr,'strict empty ranges trusted a forwarded identity')
            end
        ''')

    def test_synthetic_regex_boundary_agrees_for_all_scanner_patterns(self):
        source = SOURCE.read_text(encoding='utf-8')
        scanner = function_body(source, 'ban_404_accumulate')
        scan_path = function_body(source, 'is_scan_like_404_path')
        patterns = [
            json.loads('"' + re.search(r'local pattern = "([^"]+)"', scan_path).group(1) + '"'),
            json.loads('"' + re.search(r'ngx_match\(current_uri,"([^"]+)"', scanner).group(1) + '"'),
            '^/[.]env$', r'/\.\./', 'trusted-fixture', 'synthetic-attack',
        ]
        values = ['/.env', '/ordinary', '/wp-admin/logo.PNG', '/SHELL', '/vendor/x',
                  '/pma/', '/cgi-bin/test', '/phpmyadmin', '/shell/../', 'trusted-fixture',
                  'synthetic-attack', 'trustedXfixture', 'wp-includes\n/.git']
        assertions = []
        for pattern in patterns:
            for value in values:
                found = re.search(pattern, value, re.I | re.S)
                expected = str(found.start() + 1) if found else 'nil'
                assertions.append('assert(fixture_match({}, {})=={}, {})'.format(
                    lua_string(value), lua_string(pattern), expected,
                    lua_string('synthetic regex boundary mismatch: ' + pattern + ' / ' + value)))
        self.check('\n'.join(assertions))

    def test_strict_untrusted_private_peers_are_not_implicitly_trusted(self):
        self.check('''
            trust('strict')
            for _,peer in ipairs({'203.0.113.1','10.0.0.1','172.16.0.1','192.168.0.1','127.0.0.1','::1'}) do
                ngx.var.remote_addr=peer; identify()
                assert(ip==peer,'unlisted peer became trusted: '..peer)
            end
        ''')

    def test_trusted_ipv4_ranges_keep_first_last_header_direction(self):
        self.check('''
            trust('strict')
            headers['x-forwarded-for']={'invalid, 192.0.2.1, 203.0.113.2','192.0.2.99'}
            identify(); assert(ip=='192.0.2.1')
            site_config['a.example'].cdn_header_order='last'
            identify(); assert(ip=='203.0.113.2')
            ngx.var.remote_addr='198.51.100.20'; identify(); assert(ip=='203.0.113.2')
            ngx.var.remote_addr='198.51.100.21'; identify(); assert(ip=='198.51.100.21')
        ''')

    def test_absent_mode_keeps_legacy_empty_range_behavior(self):
        self.check('''
            trust(nil); site_config['a.example'].cdn_trusted_proxy=nil
            identify(); assert(ip=='192.0.2.1','legacy identity selection changed')
            site_config['a.example'].cdn_trusted_proxy={}
            identify(); assert(ip=='192.0.2.1')
            site_config['a.example'].cdn=false; identify(); assert(ip==ngx.var.remote_addr)
        ''')

    def test_strict_does_not_claim_ipv6_forwarding_or_trust_malformed_ranges(self):
        self.check('''
            trust('strict'); headers['x-forwarded-for']='2001:db8::1'
            identify(); assert(ip==ngx.var.remote_addr)
            headers['x-forwarded-for']='192.0.2.1'
            site_config['a.example'].cdn_trusted_proxy={{{'bad'},{}}}
            identify(); assert(ip==ngx.var.remote_addr,'malformed range trusted a peer')
        ''')

    def test_strict_rejects_sparse_or_non_numeric_range_bounds_without_error(self):
        self.check('''
            trust('strict')
            for _,ranges in ipairs({{{{198,nil,100,10},{198,51,100,20}}},
                {{{198,51,100,10},{198,51,100,false}}},'198.51.100.10/24',
                {{{198,51,100,10},{198,51,100,20.5}}}}) do
                site_config['a.example'].cdn_trusted_proxy=ranges
                identify(); assert(ip==ngx.var.remote_addr)
            end
        ''')

    def test_scanner_is_site_scoped_and_keeps_eight_hour_expiry(self):
        self.check('''
            scan(80); assert_quiet(); assert(count_for('a.example','192.0.2.1')==80)
            scan(); local key=ban_key()
            assert(ngx.shared.free_waf_drop_ip:ttl(key)==28800,'scanner duration is not eight hours')
            assert(global_writes==0 and ngx.shared.free_waf_drop_ip:get('192.0.2.1')==nil)
            assert(#events==1 and events[1].site=='a.example' and events[1].seconds==28800)
            assert(count_for('a.example','192.0.2.1')==nil)
            ngx.var.uri='/ordinary'; assert(response(run_btwaf)==403)
            now=1061; assert(response(run_btwaf)==403,'scanner was capped by the CC 60-second limit')
            ngx.var.server_name='b.example'; assert(response(run_btwaf)==200,'scanner ban leaked sites')
            ngx.var.server_name='a.example'; now=29800; assert(response(run_btwaf)==200)
        ''')

    def test_scanner_counts_do_not_mix_sites_or_clients(self):
        self.check('''
            scan(40); ngx.var.server_name='b.example'; scan(41)
            assert_quiet()
            ngx.var.server_name='a.example'; ngx.var.remote_addr='192.0.2.2'; scan(41)
            assert_quiet(); ngx.var.remote_addr='192.0.2.1'; scan(41)
            assert(ngx.shared.free_waf_drop_ip:get(ban_key()))
            assert(not ngx.shared.free_waf_drop_ip:get(ban_key('b.example')))
            assert(count_for('a.example','192.0.2.2')==41)
        ''')

    def test_domestic_alias_uses_canonical_site_config_and_identity(self):
        self.check('''
            config.compatibility_profile='bt-free-waf-8.4'
            config.site_aliases={['alias.example']='a.example'}
            ngx.var.server_name='alias.example'; trust('strict')
            scan(40); ngx.var.server_name='a.example'; scan(41)
            assert(ngx.shared.free_waf_drop_ip:get(ban_key()))
            assert(#events==1 and events[1].site=='a.example' and events[1].ip=='192.0.2.1')
            assert(not ngx.shared.free_waf_drop_ip:get(ban_key('alias.example')))
            ngx.var.server_name='alias.example'; assert(response(run_btwaf)==403)
        ''')

    def test_domestic_disabled_canonical_site_cannot_be_bypassed_by_alias(self):
        self.check('''
            config.compatibility_profile='bt-free-waf-8.4'
            config.site_aliases={['alias.example']='a.example'}
            site_config['a.example'].open=false; ngx.var.server_name='alias.example'
            scan(90); assert_quiet()
        ''')

    def test_standalone_log_hook_rebuilds_identity_not_stale_globals(self):
        self.check('''
            server_name='b.example'; ip='203.0.113.99'; ipn=arrip(ip)
            request_header={['x-forwarded-for']='203.0.113.99'}
            request_uri='/stale'; uri='/stale'
            trust('strict'); scan(81)
            assert(ngx.shared.free_waf_drop_ip:get(ban_key()),'log hook trusted stale access globals')
            assert(#events==1 and events[1].ip=='192.0.2.1' and events[1].site=='a.example')
        ''')

    def test_log_hook_cannot_change_suspended_real_post_site_or_identity(self):
        self.check('''
            post=fixture_real_post
            config.post={open=true,status=403}
            site_config['a.example'].post=true
            site_config['b.example'].post=true
            site_config['a.example'].disable_rule={post={}}
            site_config['b.example'].disable_rule={post={0}}
            post_rules={'synthetic-attack'}
            local a_vars={server_name='a.example',remote_addr='192.0.2.1',
                uri='/submit',request_uri='/submit',status=200}
            local a_headers={['content-type']='application/x-www-form-urlencoded'}
            ngx.var=a_vars; headers=a_headers; identify(); method='POST'
            ngx.req.read_body=function() coroutine.yield('read_body') end
            ngx.req.get_body_file=function() return nil end
            ngx.req.get_body_data=function() return 'probe=synthetic-attack' end
            ngx.req.get_post_args=function() return {probe='synthetic-attack'} end
            local logged,post_status
            write_log=function() logged={site=server_name,ip=ip,path=request_uri} end
            local a=coroutine.create(function() post_status=response(post) end)
            local ok,where=coroutine.resume(a)
            assert(ok and where=='read_body' and coroutine.status(a)=='suspended')
            local saved=capture_context()
            ngx.var={server_name='b.example',remote_addr='192.0.2.2',
                uri='/.env',request_uri='/.env',status=404}
            headers={['user-agent']='request-b'}
            scan(1)
            assert(count_for('b.example','192.0.2.2')==1,'B log hook did not execute')
            local after_scan=capture_context()
            -- Nginx resumes A's ngx request view, not worker-global Lua variables.
            ngx.var=a_vars; headers=a_headers
            ok,where=coroutine.resume(a)
            assert(ok,where)
            assert(post_status==403,'B log hook bypassed A POST rule; status='..tostring(post_status))
            assert(logged.site=='a.example' and logged.ip=='192.0.2.1' and logged.path=='/submit')
            for _,name in ipairs(context_fields) do
                assert(after_scan[name]==saved[name],'suspended A global changed: '..name)
            end
        ''')

    def test_slow_form_keeps_its_site_and_identity_across_another_access(self):
        for exempt in (False, True):
            with self.subTest(other_site_exempt=exempt):
                self.setUp()
                self.check('''
                    post=fixture_real_post
                    config.post={open=true,status=403}
                    site_config['a.example'].post=true
                    site_config['b.example'].post=true
                    site_config['a.example'].disable_rule={post={}}
                    site_config['b.example'].disable_rule={post=%s}
                    post_rules={'fixture-marker'}
                    local a_vars={server_name='a.example',remote_addr='192.0.2.1',
                        uri='/submit',request_uri='/submit',status=200}
                    local a_headers={['content-type']='application/x-www-form-urlencoded'}
                    ngx.var=a_vars; headers=a_headers; identify(); method='POST'
                    ngx.req.read_body=function() coroutine.yield('read_body') end
                    ngx.req.get_body_file=function() return nil end
                    ngx.req.get_body_data=function() return 'probe=fixture-marker' end
                    ngx.req.get_post_args=function() return {probe='fixture-marker'} end
                    local logged,post_status
                    write_log=function() logged={site=server_name,ip=ip,path=request_uri} end
                    local a=coroutine.create(function() post_status=response(post) end)
                    local ok,where=coroutine.resume(a)
                    assert(ok and where=='read_body')
                    ngx.var={server_name='b.example',remote_addr='192.0.2.2',
                        uri='/normal',request_uri='/normal',status=200}
                    headers={['user-agent']='request-b'}
                    assert(response(run_btwaf)==200)
                    assert(server_name=='b.example','second access did not run')
                    ngx.var=a_vars; headers=a_headers
                    ok,where=coroutine.resume(a)
                    assert(ok,where)
                    assert(post_status==403,'form used another site policy')
                    assert(logged.site=='a.example' and logged.ip=='192.0.2.1' and logged.path=='/submit',
                        'form event attributed to another request')
                ''' % ('{0}' if exempt else '{}'))

    def test_body_reader_restores_request_fields_when_reading_raises(self):
        self.check('''
            local names={'server_name','request_header','ip','ipn','request_uri','uri','retry',
                'method','uri_request_args','cycle','endtime','limit','retry_time','retry_cycle',
                'site_cc','request_cookie','error_rule','url_data','iparr','n','count'}
            for _,name in ipairs(names) do _G[name]=nil end
            method=false; request_header={fixture=true}
            local saved={}; for _,name in ipairs(names) do saved[name]=_G[name] end
            local failure={fixture='read-body-failure'}
            ngx.req.read_body=function()
                for _,name in ipairs(names) do _G[name]='other-request' end
                error(failure,0)
            end
            local ok,err=pcall(read_request_body)
            assert(not ok and err==failure,'body error must retain its original value')
            for _,name in ipairs(names) do assert(_G[name]==saved[name],'body reader changed '..name) end
        ''')

    def test_two_suspended_body_readers_each_resume_their_own_context(self):
        self.check('''
            ngx.req.read_body=function() coroutine.yield('waiting'); return 'read' end
            local seen={}
            local function request(site,address,path)
                server_name=site; ip=address; uri=path; request_uri=path
                request_header={site=site}; method='POST'; uri_request_args={site=site}
                assert(read_request_body()=='read')
                seen[site]={server_name,ip,uri,request_uri,request_header.site,method,uri_request_args.site}
            end
            local a=coroutine.create(function() request('a.example','192.0.2.1','/a') end)
            local b=coroutine.create(function() request('b.example','192.0.2.2','/b') end)
            assert(coroutine.resume(a)); assert(coroutine.resume(b))
            assert(coroutine.resume(a)); assert(coroutine.resume(b))
            for _,site in ipairs({'a.example','b.example'}) do
                local row=seen[site]
                assert(row[1]==site and row[5]==site and row[6]=='POST' and row[7]==site)
            end
            assert(seen['a.example'][2]=='192.0.2.1' and seen['a.example'][3]=='/a')
            assert(seen['b.example'][2]=='192.0.2.2' and seen['b.example'][4]=='/b')
        ''')

    def test_log_hook_restores_context_on_count_ban_and_existing_ban(self):
        self.check('''
            ngx.var.server_name='b.example'
            local saved=seed_access_context()
            scan(1); assert_context(saved)
            assert(count_for('b.example','192.0.2.1')==1)
            scan(80); assert_context(saved)
            assert(#events==1 and events[1].site=='b.example')
            scan(1); assert_context(saved)
            assert(#events==1)
        ''')

    def test_log_hook_restores_context_on_allowlist_helper_side_effects(self):
        self.check('''
            ngx.var.server_name='b.example'
            local saved=seed_access_context()
            ip_white_rules={{{192,0,2,1},{192,0,2,1}}}
            scan(); assert_context(saved); ip_white_rules={}
            headers={['user-agent']='trusted-fixture'}
            user_agent_white_rules={'trusted-fixture'}
            scan(); assert_context(saved); user_agent_white_rules={}
            url_white_rules={'^/[.]env$'}
            scan(); assert_context(saved); url_white_rules={}
            site_config['b.example'].url_white={'^/[.]env$'}
            scan(); assert_context(saved)
            assert_quiet()
        ''')

    def test_log_hook_restores_context_on_invalid_identity_proxy_and_storage_returns(self):
        self.check('''
            local saved=seed_access_context()
            ngx.var.remote_addr='not-an-ip'; scan(); assert_context(saved)
            trust('strict'); headers['x-forwarded-for']='198.51.100.10'
            scan(); assert_context(saved)
            headers['x-forwarded-for']='198.51.100.11'
            scan(); assert_context(saved)
            ngx.var.remote_addr='198.51.100.21'; scan(); assert_context(saved)
            site_config['a.example'].cdn=false; ngx.var.remote_addr='192.0.2.1'
            ngx.shared.free_waf.full=true; scan(); assert_context(saved)
            ngx.shared.free_waf.full=false; scan(80); assert_context(saved)
            ngx.shared.free_waf_drop_ip.full=true; scan(); assert_context(saved)
            assert_quiet()
        ''')

    def test_log_hook_restores_nil_and_false_context(self):
        self.check('''
            for _,name in ipairs(context_fields) do _G[name]=nil end
            scan(); assert_context({})
            for _,name in ipairs(context_fields) do _G[name]=false end
            local saved=capture_context()
            scan(); assert_context(saved)
        ''')

    def test_log_hook_restores_context_and_rethrows_original_errors(self):
        self.check('''
            local saved=seed_access_context()
            local failure={message='synthetic boundary failure'}
            for _,name in ipairs({'get_client_ip','user_agent_white','url_white',
                'manual_site_ban_guard','repeat_ban_guard','drop','ip_black','write_drop_ip_entry'}) do
                local original=_G[name]
                ngx.shared.free_waf:set(counter_key('a.example','192.0.2.1'),80,3600)
                _G[name]=function() error(failure,0) end
                local ok,err=pcall(scan,1)
                phase=nil; _G[name]=original
                assert_context(saved)
                assert(not ok and err==failure,'scanner swallowed or replaced boundary error: '..name)
                ngx.shared.free_waf_drop_ip:delete(ban_key())
            end
        ''')

    def test_log_hook_does_not_replace_any_worker_globals(self):
        self.check('''
            trust('strict'); seed_access_context()
            local saved={}
            for name,value in pairs(_G) do saved[name]=value end
            scan()
            for name,value in pairs(_G) do
                assert(saved[name]==value,'scanner replaced a worker global: '..name)
            end
            for name,value in pairs(saved) do
                assert(_G[name]==value,'scanner removed a worker global: '..name)
            end
            assert(count_for('a.example','192.0.2.1')==1)
        ''')

    def test_legacy_cdn_without_explicit_verified_proxy_skips_scanner(self):
        self.check('''
            trust(nil); site_config['a.example'].cdn_trusted_proxy={}
            scan(81); assert_quiet()
            trust(nil); ngx.var.remote_addr='10.0.0.1'
            scan(81); assert_quiet()
            assert(#ngx.shared.free_waf:get_keys()==0,'uncertain proxy accumulated scanner state')
        ''')

    def test_trusted_cdn_uses_selected_forwarded_identity_not_gateway(self):
        self.check('''
            trust(nil); site_config['a.example'].cdn_header_order='last'
            headers['x-forwarded-for']='203.0.113.2, 192.0.2.1'
            scan(81)
            assert(ngx.shared.free_waf_drop_ip:get(ban_key()))
            assert(not ngx.shared.free_waf_drop_ip:get(ban_key('a.example',ngx.var.remote_addr)))
            assert(global_writes==0)
        ''')

    def test_cdn_missing_invalid_or_gateway_only_header_never_bans_gateway(self):
        self.check('''
            trust('strict')
            for _,value in ipairs({'','garbage','2001:db8::1','198.51.100.10'}) do
                headers['x-forwarded-for']=value; scan(81); assert_quiet()
            end
            headers={}; scan(81); assert_quiet()
            site_config['a.example'].cdn_trusted_proxy={}; scan(81); assert_quiet()
        ''')

    def test_cdn_selected_header_cannot_ban_another_configured_proxy(self):
        self.check('''
            trust('strict'); headers['x-forwarded-for']='198.51.100.11'
            scan(81); assert_quiet()
        ''')

    def test_direct_ipv6_spellings_use_one_normalized_identity(self):
        self.check('''
            ngx.var.remote_addr='2001:0DB8:0:0:0:0:0:1'; scan(40)
            ngx.var.remote_addr='2001:db8::1'; scan(41)
            local key=ban_key('a.example','2001:db8::1')
            assert(ngx.shared.free_waf_drop_ip:get(key),'direct IPv6 identity not normalized')
            assert(events[1].ip=='2001:db8::1')
        ''')

    def test_global_site_open_and_all_allowlists_prevent_new_state(self):
        self.check('''
            config.open=false; scan(81); assert_quiet(); config.open=true
            site_config['a.example'].open=false; scan(81); assert_quiet(); site_config['a.example'].open=true
            ip_white_rules={{{192,0,2,1},{192,0,2,1}}}; scan(81); assert_quiet(); ip_white_rules={}
            url_white_rules={'^/[.]env$'}; scan(81); assert_quiet(); url_white_rules={}
            site_config['a.example'].url_white={'^/[.]env$'}; scan(81); assert_quiet()
            site_config['a.example'].url_white={}
            user_agent_white_rules={'trusted-fixture'}; headers['user-agent']='trusted-fixture'
            scan(81); assert_quiet()
            assert(#ngx.shared.free_waf:get_keys()==0,'bypassed requests counted')
        ''')

    def test_non_scanning_404_static_files_and_other_statuses_do_not_count(self):
        self.check('''
            for _,path in ipairs({'/ordinary','/missing.txt','/wp-admin/logo.png','/.env.css'}) do
                ngx.var.uri=path; scan(81); assert_quiet()
            end
            ngx.var.uri='/.env'; ngx.var.status=200; scan(81); assert_quiet()
            assert(#ngx.shared.free_waf:get_keys()==0)
        ''')

    def test_counter_window_does_not_slide_or_reuse_old_global_404(self):
        self.check('''
            ngx.shared.free_waf:set('192.0.2.1_404',80,777)
            scan(40); now=2000; scan(40)
            assert(ngx.shared.free_waf:ttl(counter_key('a.example','192.0.2.1'))==2600)
            now=4600; scan(); assert_quiet()
            assert(count_for('a.example','192.0.2.1')==1,'expired window reused')
        ''')

    def test_old_global_records_are_not_mutated_or_adopted(self):
        self.check('''
            ngx.shared.free_waf:set('192.0.2.1_404',79,4000)
            ngx.shared.free_waf_drop_ip:set('192.0.2.2',9,4000)
            ip_black_rules={{{192,0,2,3},{192,0,2,3},now+4000}}
            local before=json.encode(ip_black_rules)
            scan(81)
            assert(ngx.shared.free_waf:get('192.0.2.1_404')==79,'old global counter changed')
            assert(ngx.shared.free_waf_drop_ip:ttl('192.0.2.2')==4000)
            assert(json.encode(ip_black_rules)==before and global_writes==0,'global blacklist changed')
        ''')

    def test_active_scanner_ban_never_extends_or_inflates_repeat_history(self):
        self.check('''
            enable_repeat(); scan(81)
            local p=repeat_ban_policy('a.example')
            local key=repeat_ban_state_key('a.example','192.0.2.1',p)
            local raw=ngx.shared.free_waf:get(key)
            now=1010; scan(200)
            assert(#events==1,'active scanner ban generated another event')
            assert(ngx.shared.free_waf_drop_ip:ttl(ban_key())==28790,'active ban was extended')
            assert(ngx.shared.free_waf:get(key)==raw,'repeat history changed during ban')
            assert(count_for('a.example','192.0.2.1')==nil)
        ''')

    def test_active_manual_ban_with_404_status_cannot_create_scanner_state(self):
        self.check('''
            manual_site_ban_state.by_site['a.example']={['192.0.2.1']={started_at=900,expires_at=9000}}
            scan(90); assert_quiet()
            assert(#ngx.shared.free_waf:get_keys()==0)
        ''')

    def test_active_repeat_ban_with_404_status_cannot_create_scanner_state(self):
        self.check('''
            enable_repeat(); config.cc.status=404
            snapshot.bans={{site='a.example',ip='192.0.2.1',started_at=900,expires_at=9000}}
            scan(90); assert_quiet()
            assert(#ngx.shared.free_waf:get_keys()==0)
        ''')

    def test_active_cc_or_legacy_bans_do_not_get_scanner_extension(self):
        self.check('''
            ngx.shared.free_waf_drop_ip:set(ban_key(),7,60)
            scan(90)
            assert(ngx.shared.free_waf_drop_ip:ttl(ban_key())==60)
            assert(#events==0 and global_writes==0 and count_for('a.example','192.0.2.1')==nil)
            ngx.shared.free_waf_drop_ip:delete(ban_key())
            ngx.shared.free_waf_drop_ip:set('192.0.2.1',7,60); scan(90)
            assert(#events==0 and global_writes==0 and count_for('a.example','192.0.2.1')==nil)
        ''')

    def test_active_raw_ipv6_legacy_ban_still_guards_normalized_scanner(self):
        self.check('''
            ngx.var.remote_addr='2001:0DB8:0:0:0:0:0:1'
            ngx.shared.free_waf_drop_ip:set(ngx.var.remote_addr,7,60)
            scan(90)
            assert(#events==0 and #drop_logs==0,'raw legacy ban became a new automatic ban')
            assert(not ngx.shared.free_waf_drop_ip:get(ban_key('a.example','2001:db8::1')))
            assert(ngx.shared.free_waf_drop_ip:ttl(ngx.var.remote_addr)==60)
        ''')

    def test_active_global_blacklist_does_not_gain_site_ban_or_write(self):
        self.check('''
            ip_black_rules={{{192,0,2,1},{192,0,2,1},now+60}}
            scan(90); assert_quiet()
            assert(#ngx.shared.free_waf:get_keys()==0)
        ''')

    def test_storage_pressure_cannot_log_or_count_a_failed_ban(self):
        self.check('''
            ngx.shared.free_waf.full=true; scan(90); assert_quiet()
            ngx.shared.free_waf.full=false; ngx.shared.free_waf_drop_ip.full=true
            scan(90); assert_quiet()
            ngx.shared.free_waf_drop_ip.full=false; scan()
            assert(#events==1 and ngx.shared.free_waf_drop_ip:get(ban_key()))
        ''')

    def test_global_unban_clears_new_counters_but_not_other_clients_or_old_counter(self):
        self.check('''
            scan(81); ngx.var.server_name='b.example'; scan(80)
            ngx.var.remote_addr='192.0.2.2'; scan(20)
            ngx.shared.free_waf:set('192.0.2.1_404',55,3600)
            uri_request_args={ip='192.0.2.1'}
            assert(remove_btwaf_drop_ip().status)
            assert(not ngx.shared.free_waf_drop_ip:get(ban_key()))
            assert(count_for('b.example','192.0.2.1')==nil,'global unban left scanner counter')
            assert(count_for('b.example','192.0.2.2')==20)
            assert(ngx.shared.free_waf:get('192.0.2.1_404')==55)
        ''')

    def test_site_filtered_cc_cleanup_keeps_other_sites_and_global_bans(self):
        self.check('''
            scan(81); ngx.var.server_name='b.example'; scan(81)
            ngx.shared.free_waf_drop_ip:set('192.0.2.1',7,60)
            ngx.shared.free_waf:set(counter_key('a.example','192.0.2.1'),77,3600)
            ngx.shared.free_waf:set(counter_key('b.example','192.0.2.1'),66,3600)
            clear_cc_state({['192.0.2.1']=true},'a.example')
            assert(not ngx.shared.free_waf_drop_ip:get(ban_key()))
            assert(ngx.shared.free_waf_drop_ip:get(ban_key('b.example')),'site cleanup leaked to another site')
            assert(ngx.shared.free_waf_drop_ip:get('192.0.2.1')==7,'site cleanup removed global record')
            assert(count_for('a.example','192.0.2.1')==nil and count_for('b.example','192.0.2.1')==66)
        ''')

    def test_site_filtered_cleanup_canonicalizes_domestic_alias_without_widening_scope(self):
        self.check('''
            config.compatibility_profile='bt-free-waf-8.4'
            config.site_aliases={['alias.example']='a.example'}
            scan(81); ngx.var.server_name='b.example'; scan(81)
            clear_cc_state({['192.0.2.1']=true},'alias.example')
            assert(not ngx.shared.free_waf_drop_ip:get(ban_key()),'alias unban missed canonical short ban')
            assert(ngx.shared.free_waf_drop_ip:get(ban_key('b.example')))
        ''')

    def test_invalid_optional_site_filter_never_becomes_global_cleanup(self):
        self.check('''
            scan(81); ngx.var.server_name='b.example'; scan(81)
            for _,bad in ipairs({false,42,{},'',string.char(10)}) do
                assert(clear_cc_state({['192.0.2.1']=true},bad)==false,'invalid site filter accepted')
                assert(ngx.shared.free_waf_drop_ip:get(ban_key()))
                assert(ngx.shared.free_waf_drop_ip:get(ban_key('b.example')))
            end
        ''')

    def test_repeat_only_site_unban_preserves_scanner_short_ban(self):
        self.check('''
            enable_repeat(); scan(81)
            uri_request_args={site='a.example',ip='192.0.2.1',reset_counts='1'}
            assert(remove_repeat_ban().status)
            assert(ngx.shared.free_waf_drop_ip:get(ban_key()),'repeat-only unban removed independent short ban')
        ''')

    def test_global_clean_clears_counter_only_state_and_preserves_unknown_keys(self):
        self.check('''
            scan(20); ngx.var.server_name='b.example'; ngx.var.remote_addr='2001:db8::1'; scan(40)
            local bad='cc:v3:scan404:999:a.example:192.0.2.1'
            ngx.shared.free_waf:set(bad,9,3600); ngx.shared.free_waf:set('192.0.2.1_404',44,3600)
            assert(clean_btwaf_drop_ip().status)
            assert(count_for('a.example','192.0.2.1')==nil)
            assert(count_for('b.example','2001:db8::1')==nil)
            assert(ngx.shared.free_waf:get(bad)==9 and ngx.shared.free_waf:get('192.0.2.1_404')==44)
        ''')


if __name__ == '__main__':
    unittest.main()
