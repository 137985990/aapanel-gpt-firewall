-- Full-source integration: real cjson, memory-only files and dictionaries.
local source = assert(rawget(_G, 'WAF_RUNTIME_SOURCE'), 'inject the local init.lua source')
local json = require 'cjson'
local now = 1000
local root = '/www/server/free_waf/'

local function exact_rule(last)
    return {{192, 0, 2, last}, {192, 0, 2, last}, now + 60}
end

local function dictionary(values)
    local expiry = {}
    local dict = {}
    function dict:get(key)
        if expiry[key] and expiry[key] <= now then return nil end
        return values[key]
    end
    function dict:get_keys(limit)
        assert(limit == 0)
        local keys = {}
        for key in pairs(values) do keys[#keys + 1] = key end
        return keys
    end
    function dict:delete(key) values[key], expiry[key] = nil, nil end
    function dict:set(key, value, ttl)
        values[key], expiry[key] = value, ttl and now + ttl or nil
        return true
    end
    function dict:add(key, value, ttl)
        if self:get(key) ~= nil then return nil, 'exists' end
        return self:set(key, value, ttl)
    end
    function dict:incr(key, delta)
        if self:get(key) == nil then return nil, 'not found' end
        values[key] = values[key] + delta
        return values[key]
    end
    return dict
end

local function state_key(scope, ip, kind)
    return 'registration_guard:v2:' .. (kind and 'count' or 'ban') .. ':' .. #scope .. ':' .. scope .. ':' .. (kind and kind .. ':' or '') .. ip
end

local function fixture(rules, extra_scopes)
    local f = {files = {}, shared = {}, generic = {}, writes = 0, query = {}, post_args = {}}
    local config = {
        open = false, log = false, reqfile_path = 'fixture-html',
        cc = {cycle = 60, endtime = 60, limit = 2, status = 403},
        retry = 6, retry_time = 60, retry_cycle = 60,
    }
    for _, name in ipairs({'get', 'post', 'cookie', 'user-agent', 'other'}) do
        config[name] = {open = true, status = 403, reqfile = name .. '.html'}
        f.files['fixture-html/' .. name .. '.html'] = 'fixture-blocked'
    end
    f.files[root .. 'config.json'] = json.encode(config)
    local sites = {fixture = {
        post = true, disable_rule = {post = {1}},
        registration_guard = {
            open = true, scope = 'fixture:scope',
            register_paths = {'^/register$'}, verify_paths = {'^/verify$'},
            register_limit = 2, verify_limit = 2,
            register_window = 60, verify_window = 60, ban_seconds = 60,
        },
    }}
    for index, scope in ipairs(extra_scopes or {'other'}) do
        sites['scope' .. index] = {registration_guard = {open = false, scope = scope}}
    end
    f.files[root .. 'site.json'] = json.encode(sites)
    f.files[root .. '/rule/cn.json'] = '[]'
    f.files[root .. 'rule/ip_black.json'] = rules and json.encode(rules) or '[]'
    for _, name in ipairs({'post', 'user_agent_white'}) do
        f.files[root .. 'rule/' .. name .. '.json'] = json.encode({
            {0, 'inactive'}, {1, 'needle'}, {1, 'other'},
        })
    end
    local exit_marker = {}
    local ngx = {
        var = {remote_addr = '127.0.0.1', server_name = 'fixture'},
        header = {},
        shared = {free_waf = dictionary(f.shared), free_waf_drop_ip = dictionary(f.generic)},
        re = {find = function(value, pattern) return string.find(value, pattern) end},
        unescape_uri = function(value) return value end,
        say = function(body) f.output[#f.output + 1] = body end,
        exit = function(status) f.exit_status = status; error(exit_marker, 0) end,
        req = {
            get_headers = function() return {} end,
            get_method = function() return 'GET' end,
            get_uri_args = function() return f.query end,
            get_post_args = function() return f.post_args end,
            read_body = function() end,
        },
    }
    local env = setmetatable({
        ngx = ngx, os = {time = function() return now end},
        require = function(name) assert(name == 'cjson'); return json end,
        io = {open = function(path, mode)
            if mode == 'r' then
                if f.files[path] == nil then return nil end
                return {read = function() return f.files[path] end, close = function() end}
            end
            if mode == 'ab' and path == root .. 'drop_ip.log' then return nil end
            assert(mode == 'w' and path == root .. 'rule/ip_black.json', 'unexpected write: ' .. path)
            f.writes = f.writes + 1
            if f.fail_write then return nil end
            f.files[path] = ''
            local function stage_result(stage)
                if f.fail_stage == stage then return f.fail_result, 'fixture ' .. stage .. ' failure' end
                return true
            end
            return {
                write = function(_, body)
                    f.files[path] = f.fail_stage == 'write' and body:sub(1, 1) or body
                    return stage_result('write')
                end,
                flush = function() return stage_result('flush') end,
                close = function()
                    f.close_attempts = (f.close_attempts or 0) + 1
                    return stage_result('close')
                end,
            }
        end},
    }, {__index = _G})
    env._G = env
    local chunk = assert(loadstring(source, '@init.lua'))
    setfenv(chunk, env)
    chunk()
    f.env, f.ngx = env, ngx
    function f:request(path, query)
        self.output, self.exit_status, self.query = {}, nil, query or {}
        ngx.var.uri, ngx.var.request_uri = path, path
        local ok, message = pcall(env.run_btwaf)
        assert(not ok and message == exit_marker, 'route did not terminate normally: ' .. tostring(message))
        assert(self.exit_status == 200 and ngx.status == 200)
        assert(ngx.header.content_type == 'application/json;')
        assert(#self.output == 1, 'route must emit exactly one JSON document')
        local body = self.output[1]
        return json.decode(body), body
    end
    function f:assert_blocked(callback)
        self.output = {}
        local ok, message = pcall(callback)
        assert(not ok and message == exit_marker and self.exit_status == 403, 'expected request block')
    end
    return f
end

local tests = {}
function tests.empty_list_route_is_json_array_not_object_or_string()
    local f = fixture()
    assert(type(f.env.get_btwaf_drop_ip()) == 'table', 'helper must still return a Lua table')
    local decoded, body = f:request('/get_btwaf_drop_ip')
    assert(body == '[]', 'expected [] on the wire, got ' .. body)
    assert(type(decoded) == 'table' and #decoded == 0)
end

function tests.nonempty_route_merges_scopes_and_lexically_loaded_rules_once()
    local f = fixture({exact_rule(12)})
    f.generic['192.0.2.10'] = 7
    f.shared['registration_guard:ban:fixture:scope:192.0.2.10'] = 1
    f.shared['registration_guard:ban:other:192.0.2.11'] = 1
    local decoded, body = f:request('/get_btwaf_drop_ip')
    assert(body:sub(1, 1) == '[' and type(decoded) == 'table', 'double-encoded IP list')
    assert(#decoded == 3, 'cached persistent rules or scoped bans missing')
    local seen = {}
    for _, ip in ipairs(decoded) do seen[ip] = (seen[ip] or 0) + 1 end
    for _, ip in ipairs({'192.0.2.10', '192.0.2.11', '192.0.2.12'}) do assert(seen[ip] == 1) end
end

function tests.explicit_unban_route_preserves_object_and_resets_real_guard_closure()
    local f = fixture()
    f.generic['192.0.2.10'] = 7
    f.shared['registration_guard:ban:fixture:scope:192.0.2.10'] = 1
    f.shared['registration_guard:count:fixture:scope:register:192.0.2.10'] = 99
    f.shared['registration_guard:count:other:verify:192.0.2.10'] = 99
    f.shared['registration_guard:count:other:verify:192.0.2.100'] = 5
    local decoded, body = f:request('/remove_btwaf_drop_ip', {ip = '192.0.2.10'})
    assert(decoded.status == true and body:sub(1, 1) == '{', 'status response must remain an object')
    assert(f.shared['registration_guard:count:other:verify:192.0.2.10'] == nil)
    assert(f.shared['registration_guard:count:other:verify:192.0.2.100'] == 5)
    local _, empty_body = f:request('/get_btwaf_drop_ip')
    assert(empty_body == '[]', 'unban verification requires an empty JSON array')
    assert(f.env.registration_guard('fixture', '192.0.2.10', 'POST', '/register', '/register') == false)
    assert(f.shared[state_key('fixture:scope', '192.0.2.10', 'register')] == 1)
end

function tests.clean_route_writes_real_json_and_refreshes_lexical_cache()
    local f = fixture({exact_rule(12)})
    f.generic['192.0.2.10'] = 7
    f.shared['registration_guard:ban:fixture:scope:192.0.2.11'] = 1
    f.shared['registration_guard:count:fixture:scope:verify:192.0.2.11'] = 99
    local decoded = f:request('/clean_btwaf_drop_ip')
    assert(decoded.status == true and f.writes == 1)
    assert(f.files[root .. 'rule/ip_black.json'] == '[]', 'persistent empty array must stay an array')
    assert(f.shared['registration_guard:count:fixture:scope:verify:192.0.2.11'] == nil)
    local _, body = f:request('/get_btwaf_drop_ip')
    assert(body == '[]', 'clean must empty the actual cached table and response')
end

function tests.backend_first_cleanup_refreshes_cache_without_rewriting()
    local f = fixture({exact_rule(12)})
    f.files[root .. 'rule/ip_black.json'] = '[]'
    assert(f:request('/clean_btwaf_drop_ip').status == true)
    assert(f.writes == 0)
    local _, body = f:request('/get_btwaf_drop_ip')
    assert(body == '[]', 'already-clean disk must refresh the captured rule cache')
end

function tests.real_write_open_failure_keeps_bans_and_cached_rules()
    local f = fixture({exact_rule(12)})
    f.shared['registration_guard:ban:fixture:scope:192.0.2.11'] = 1
    f.fail_write = true
    assert(f:request('/clean_btwaf_drop_ip').status == false)
    assert(f.shared['registration_guard:ban:fixture:scope:192.0.2.11'] == 1)
    assert(#f:request('/get_btwaf_drop_ip') == 2)
end

function tests.loaded_post_rules_and_site_exceptions_keep_original_indices()
    local f = fixture()
    f:request('/get_btwaf_drop_ip')
    f.env.method, f.env.request_header = 'POST', {}
    f.post_args = {value = 'needle inactive'}
    assert(f.env.post() == false, 'captured post/site rules shifted their indices')
    f.post_args = {value = 'other'}
    f:assert_blocked(function() f.env.post() end)
end

function tests.loaded_ua_whitelist_skips_inactive_placeholders()
    local f = fixture()
    f.env.request_header = {['user-agent'] = 'inactive'}
    assert(f.env.user_agent_white() == false)
    f.env.request_header['user-agent'] = 'needle'
    assert(f.env.user_agent_white() == true)
end

function tests.legacy_ipv6_and_dotted_tail_are_listed_without_ipv4_aliasing()
    local f = fixture()
    local ipv6 = '2001:db8::192.0.2.10'
    f.shared['registration_guard:ban:fixture:scope:' .. ipv6] = 1
    f.shared['registration_guard:count:fixture:scope:verify:' .. ipv6] = 99
    f.shared['registration_guard:ban:other:2001:db8::20'] = 1
    f.generic['2001:db8::30'] = 7
    f.generic['192.0.2.10'] = 7
    assert(f:request('/remove_btwaf_drop_ip', {ip = '192.0.2.10'}).status == true)
    assert(f.shared['registration_guard:ban:fixture:scope:' .. ipv6] == 1, 'IPv4 unban deleted IPv6 ban')
    assert(f.shared['registration_guard:count:fixture:scope:verify:' .. ipv6] == 99)
    local ips = f:request('/get_btwaf_drop_ip')
    assert(#ips == 3, 'IPv6 bans missing or IPv4 suffix leaked')
    local seen = {}
    for _, ip in ipairs(ips) do seen[ip] = true end
    assert(seen[ipv6] and seen['2001:db8::20'] and seen['2001:db8::30'] and not seen['192.0.2.10'])
    assert(f:request('/remove_btwaf_drop_ip', {ip = ipv6}).status == true)
    assert(f.shared['registration_guard:ban:fixture:scope:' .. ipv6] == nil)
    assert(f.shared['registration_guard:count:fixture:scope:verify:' .. ipv6] == nil)
    assert(f.shared['registration_guard:ban:other:2001:db8::20'] == 1)
end

function tests.v2_scope_lengths_preserve_mapped_ipv6_and_cross_scope_unban()
    local f = fixture()
    local ipv6 = '::ffff:192.0.2.10'
    for _, scope in ipairs({'fixture:scope', 'removed:scope:with:colons'}) do
        f.shared[state_key(scope, ipv6)] = 1
        f.shared[state_key(scope, ipv6, 'register')] = 99
        f.shared[state_key(scope, ipv6, 'verify')] = 99
    end
    f.shared[state_key('fixture:scope', '192.0.2.10')] = 1
    f.generic[ipv6] = 7
    local ips = f:request('/get_btwaf_drop_ip')
    assert(#ips == 2, 'mapped IPv6 and IPv4 must be distinct')
    assert(f:request('/remove_btwaf_drop_ip', {ip = ipv6}).status == true)
    assert(f.generic[ipv6] == nil)
    for _, scope in ipairs({'fixture:scope', 'removed:scope:with:colons'}) do
        assert(f.shared[state_key(scope, ipv6)] == nil)
        assert(f.shared[state_key(scope, ipv6, 'register')] == nil)
        assert(f.shared[state_key(scope, ipv6, 'verify')] == nil)
    end
    assert(f.shared[state_key('fixture:scope', '192.0.2.10')] == 1)
end

function tests.ambiguous_or_unknown_legacy_scope_is_never_guessed()
    local f = fixture(nil, {'other', 'fixture:scope:2001:db8:'})
    local keys = {
        'registration_guard:ban:fixture:scope:2001:db8::192.0.2.10',
        'registration_guard:ban:unconfigured:192.0.2.10',
        'registration_guard:count:unconfigured:register:192.0.2.10',
    }
    for _, key in ipairs(keys) do f.shared[key] = 1 end
    f.generic['192.0.2.10'] = 7
    f.shared['registration_guard:count:other:verify:192.0.2.10'] = 9
    assert(#f:request('/get_btwaf_drop_ip') == 1, 'ambiguous legacy key must not alias any address')
    for _, ip in ipairs({'192.0.2.10', '2001:db8::192.0.2.10'}) do
        assert(f:request('/remove_btwaf_drop_ip', {ip = ip}).status == false, 'ambiguous target must fail before mutation')
    end
    assert(f:request('/clean_btwaf_drop_ip').status == false, 'ambiguous active state must prevent clean success')
    assert(f.generic['192.0.2.10'] == 7 and f.writes == 0)
    assert(f.shared['registration_guard:count:other:verify:192.0.2.10'] == 9)
    for _, key in ipairs(keys) do assert(f.shared[key] == 1, 'unresolvable legacy key was deleted') end
    assert(f:request('/remove_btwaf_drop_ip', {ip = '192.0.2.99'}).status == true, 'unrelated IP must remain revocable')
end

function tests.unknown_scope_or_expired_ambiguity_does_not_block_current_unban()
    local f = fixture(nil, {'fixture:scope:2001:db8:'})
    local unknown = 'registration_guard:ban:unconfigured:192.0.2.10'
    local ambiguous = 'registration_guard:ban:fixture:scope:2001:db8::192.0.2.10'
    f.shared[unknown] = 1
    f.ngx.shared.free_waf:set(ambiguous, 1, -1)
    f.generic['192.0.2.10'] = 7
    assert(f:request('/remove_btwaf_drop_ip', {ip = '192.0.2.10'}).status == true)
    assert(f.generic['192.0.2.10'] == nil and f.shared[unknown] == 1)
    assert(f:request('/clean_btwaf_drop_ip').status == true)
end

function tests.ip_validation_accepts_whole_ipv6_and_rejects_malformed_literals()
    local f = fixture()
    local valid = {'0.0.0.0', '255.255.255.255', '::', '::1', '2001:DB8::1',
        '1:2:3:4:5:6:7:8', '1:2:3:4:5:6::', '::ffff:192.0.2.10', '1:2:3:4:5:6:192.0.2.10'}
    for _, ip in ipairs(valid) do
        assert(f:request('/remove_btwaf_drop_ip', {ip = ip}).status == true, 'valid IP rejected: ' .. ip)
    end
    local invalid = {'2001:db8::1%eth0', '[::1]', '::1/128', '::1\n', '2001:::1',
        '1::2::3', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7:8::',
        '12345::1', 'gggg::1', '1:2:3:4:5::192.0.2.999', '192.0.2.10::',
        '1:2:3:4:5:192.0.2.10', '::ffff:192.00.2.10', '192.00.2.10', ':1:2:3:4:5:6:7',
        '1:2:3:4:5:6:7:', '::ffff:192.0.2.10:1'}
    for _, ip in ipairs(invalid) do
        assert(f:request('/remove_btwaf_drop_ip', {ip = ip}).status == false, 'invalid IP accepted: ' .. ip)
    end
end

function tests.guard_writes_length_prefixed_ipv6_keys_and_enforces_legacy_bans()
    local f = fixture()
    f:request('/get_btwaf_drop_ip')
    local ipv6 = '2001:db8::192.0.2.10'
    local legacy = 'registration_guard:ban:fixture:scope:' .. ipv6
    f.shared[legacy] = 1
    f:assert_blocked(function() f.env.registration_guard('fixture', ipv6, 'GET', '/', '/') end)
    assert(f:request('/remove_btwaf_drop_ip', {ip = ipv6}).status == true)
    for _ = 1, 2 do
        assert(f.env.registration_guard('fixture', ipv6, 'POST', '/register', '/register') == false)
    end
    assert(f.shared[state_key('fixture:scope', ipv6, 'register')] == 2, 'new counter key is ambiguous')
    f:assert_blocked(function() f.env.registration_guard('fixture', ipv6, 'POST', '/register', '/register') end)
    assert(f.shared[state_key('fixture:scope', ipv6)] == 1, 'new ban key is ambiguous')
    assert(f.shared[legacy] == nil)
end

function tests.legacy_counter_window_survives_upgrade_without_resetting()
    local f = fixture()
    f:request('/get_btwaf_drop_ip')
    local key = 'registration_guard:count:fixture:scope:verify:2001:db8::1'
    f.shared[key] = 2
    f:assert_blocked(function() f.env.registration_guard('fixture', '2001:db8::1', 'POST', '/verify', '/verify') end)
    assert(f.shared[key] == nil)
    assert(f.shared[state_key('fixture:scope', '2001:db8::1')] == 1)
end

function tests.clean_all_includes_both_ipv6_key_protocols()
    local f = fixture()
    f.shared['registration_guard:ban:fixture:scope:2001:db8::1'] = 1
    f.shared['registration_guard:count:other:register:2001:db8::1'] = 9
    f.shared[state_key('scope:removed', '::ffff:192.0.2.10')] = 1
    f.shared[state_key('scope:removed', '::ffff:192.0.2.10', 'verify')] = 9
    f.generic['2001:db8::2'] = 7
    assert(f:request('/clean_btwaf_drop_ip').status == true)
    assert(next(f.shared) == nil and next(f.generic) == nil)
    local _, body = f:request('/get_btwaf_drop_ip')
    assert(body == '[]')
end

function tests.real_write_flush_close_failures_cannot_report_clean_success()
    for _, stage in ipairs({'write', 'flush', 'close'}) do
        for _, returns_false in ipairs({false, true}) do
            local f = fixture({exact_rule(12)})
            f.shared['registration_guard:ban:fixture:scope:192.0.2.11'] = 1
            f.shared['registration_guard:count:fixture:scope:verify:192.0.2.11'] = 9
            f.generic['192.0.2.10'] = 7
            f.fail_stage = stage
            if returns_false then f.fail_result = false end
            local response = f:request('/clean_btwaf_drop_ip')
            assert(response.status == false, stage .. ' failure incorrectly reported success')
            assert(f.close_attempts == 1, 'write failure must still close its file')
            assert(f.shared['registration_guard:ban:fixture:scope:192.0.2.11'] == 1)
            assert(f.shared['registration_guard:count:fixture:scope:verify:192.0.2.11'] == 9)
            assert(f.generic['192.0.2.10'] == 7)
            assert(#f:request('/get_btwaf_drop_ip') == 3, 'write failure changed captured rule cache')
        end
    end
end

function tests.expiry_equality_is_listed_enforced_and_cleanable()
    local rule = exact_rule(12)
    rule[3] = now
    local f = fixture({rule})
    assert(#f:request('/get_btwaf_drop_ip') == 1, 'active expiry boundary missing from list')
    f.env.ip, f.env.ipn = '192.0.2.12', {192, 0, 2, 12}
    f:assert_blocked(function() f.env.ip_black() end)
    assert(f:request('/clean_btwaf_drop_ip').status == true)
    assert(#f:request('/get_btwaf_drop_ip') == 0)
    rule[3] = now - 1
    local expired = fixture({rule})
    assert(#expired:request('/get_btwaf_drop_ip') == 0)
    expired.env.ip, expired.env.ipn = '192.0.2.12', {192, 0, 2, 12}
    assert(expired.env.ip_black() == false)
end

local failed, names = 0, {}
for name in pairs(tests) do names[#names + 1] = name end
table.sort(names)
for _, name in ipairs(names) do
    local ok, message = pcall(tests[name])
    if not ok then failed = failed + 1 end
    print((ok and 'PASS ' or 'FAIL ') .. name .. (ok and '' or ': ' .. tostring(message)))
end
print('runtime_routes: ' .. (#names - failed) .. '/' .. #names .. ' passed; isolated_fixture=true')
assert(failed == 0, tostring(failed) .. ' full-runtime regressions')
