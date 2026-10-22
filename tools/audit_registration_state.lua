-- Only extracted functions run; all dictionaries and persistence are fixtures.
local source = rawget(_G, 'WAF_RUNTIME_SOURCE')
if not source then
    local file = assert(io.open(arg[1] or 'init.lua', 'r'))
    source = file:read('*a')
    file:close()
end

local now = 1000
local function dictionary(values, expires)
    local dict = {}
    function dict:get(key)
        if expires[key] and expires[key] <= now then return nil end
        return values[key]
    end
    function dict:delete(key) values[key], expires[key] = nil, nil end
    function dict:get_keys(limit)
        assert(limit == 0, 'state enumeration must not truncate keys')
        local keys = {}
        -- Keep expired keys to exercise lazy expiration during enumeration.
        for key in pairs(values) do keys[#keys + 1] = key end
        return keys
    end
    function dict:set(key, value, ttl)
        values[key], expires[key] = value, ttl and now + ttl or nil
        return true
    end
    function dict:add(key, value, ttl)
        if self:get(key) ~= nil then return nil, 'exists' end
        return self:set(key, value, ttl)
    end
    function dict:incr(key, amount)
        local value = self:get(key)
        if value == nil then return nil, 'not found' end
        values[key] = value + amount
        return values[key]
    end
    return dict
end

local function fixture()
    local f = {shared = {}, generic = {}, shared_expiry = {}, generic_expiry = {}, rules = {}, writes = 0}
    local env = setmetatable({
        ngx = {shared = {
            free_waf = dictionary(f.shared, f.shared_expiry),
            free_waf_drop_ip = dictionary(f.generic, f.generic_expiry),
        }},
        os = {time = function() return now end},
        ip_black_rules = f.rules,
        config = {other = {status = 403}}, other_html = 'neutral',
        site_config = {},
        uri_request_args = {ip = '192.0.2.10'},
        guard = {
            scope = 'fixture', verify_paths = {'^/verify$'}, register_paths = {'^/register$'},
            verify_limit = 2, register_limit = 2, verify_window = 60, register_window = 60,
            ban_seconds = 60,
        },
        jpath = 'fixture/',
        read_file = function(name) assert(name == 'ip_black'); return f.rules end,
        write_file = function(path, body)
            assert(path == 'fixture/ip_black.json')
            f.writes = f.writes + 1
            f.written_rules = body
            if f.write_failure then return f.write_result end
            return true
        end,
        encode_json_array = function(value) return value end,
        ngx_match = function(value, pattern) return string.find(value, pattern) end,
        write_log = function() end,
        write_drop_ip_entry = function() return true end,
        return_html = function() error('fixture_blocked', 0) end,
    }, {__index = _G})
    env.get_registration_guard_config = function() return env.guard end
    for index, scope in ipairs({'fixture', 'fixture:child', '192.0.2.10:scope', 'other', 'other:scope'}) do
        env.site_config[index] = {registration_guard = {scope = scope}}
    end
    for _, name in ipairs({
        'split', 'arrlen', 'is_ipaddr', 'trim_string', 'get_return_state',
        'is_runtime_ban_ipv4', 'is_runtime_ban_ip', 'registration_guard_state_key',
        'registration_guard_scopes', 'registration_state_ip', 'registration_state_ambiguous', 'clear_registration_state',
        'get_btwaf_drop_ip', 'remove_btwaf_drop_ip', 'clean_btwaf_drop_ip',
        'registration_guard_path_matches', 'registration_guard',
    }) do
        local body = source:match('function ' .. name .. '%b()%s*.-\nend')
        if body then
            local compiled = assert(loadstring(body))
            setfenv(compiled, env)
            compiled()
        end
    end
    f.env = env
    return f
end

local function exact_rule(ip, expiry)
    return {{192, 0, 2, ip}, {192, 0, 2, ip}, expiry}
end

local function assert_ips(actual, expected)
    assert(#actual == #expected, 'IP list length: expected ' .. #expected .. ', got ' .. #actual)
    local wanted = {}
    for _, value in ipairs(expected) do wanted[value] = true end
    for _, value in ipairs(actual) do
        assert(type(value) == 'string' and wanted[value], 'unexpected or duplicate IP: ' .. tostring(value))
        wanted[value] = nil
    end
end

local tests = {}
function tests.registration_bans_are_listed()
    local f = fixture()
    f.shared['registration_guard:ban:fixture:192.0.2.10'] = 1
    assert_ips(f.env.get_btwaf_drop_ip(), {'192.0.2.10'})
end

function tests.all_sources_deduplicate_without_scope_leaks()
    local f = fixture()
    f.generic['192.0.2.10'] = 7
    f.shared['registration_guard:ban:fixture:192.0.2.10'] = 1
    f.shared['registration_guard:ban:other:scope:192.0.2.10'] = 1
    f.shared['registration_guard:ban:other:192.0.2.11'] = 1
    f.rules[1] = exact_rule(10, now + 1)
    f.rules[2] = exact_rule(12, now + 1)
    assert_ips(f.env.get_btwaf_drop_ip(), {'192.0.2.10', '192.0.2.11', '192.0.2.12'})
end

function tests.expired_and_non_ip_keys_are_not_listed()
    local f = fixture()
    f.generic['192.0.2.10'], f.generic_expiry['192.0.2.10'] = 7, now
    f.generic['retry_192.0.2.11'] = 3
    f.generic['999.0.2.11'] = 7
    f.shared['registration_guard:ban:fixture:192.0.2.12'] = 1
    f.shared_expiry['registration_guard:ban:fixture:192.0.2.12'] = now - 1
    f.shared['registration_guard:ban::192.0.2.13'] = 1
    f.shared['registration_guard:ban:fixture:192.0.2.14.extra'] = 1
    f.shared['registration_guard:ban:fixture:999.0.2.14'] = 1
    f.shared['registration_guard:count:fixture:register:192.0.2.15'] = 2
    f.rules[1] = exact_rule(16, now - 1)
    f.rules[2] = exact_rule(17, now - 1)
    f.rules[3] = {{192, 0, 2, 18}, {192, 0, 2, 20}, now + 1}
    f.rules[4] = exact_rule(21)
    assert_ips(f.env.get_btwaf_drop_ip(), {})
end

function tests.explicit_unban_removes_all_scopes_and_associated_counters()
    local f = fixture()
    f.generic['192.0.2.10'] = 7
    for _, scope in ipairs({'fixture', 'fixture:child', '192.0.2.10:scope'}) do
        f.shared['registration_guard:ban:' .. scope .. ':192.0.2.10'] = 1
        for _, kind in ipairs({'register', 'verify'}) do
            f.shared['registration_guard:count:' .. scope .. ':' .. kind .. ':192.0.2.10'] = 99
        end
    end
    assert(f.env.remove_btwaf_drop_ip().status == true)
    assert(next(f.generic) == nil, 'generic ban remains')
    assert(next(f.shared) == nil, 'scoped ban or rate counter remains')
end

function tests.explicit_unban_preserves_other_ips_scopes_and_counter_names()
    local f = fixture()
    local keys = {
        'registration_guard:ban:fixture:192.0.2.100',
        'registration_guard:ban:fixture:192.0.2.10:192.0.2.11',
        'registration_guard:count:fixture:verify:192.0.2.100',
        'registration_guard:count:fixture:unknown:192.0.2.10',
        'registration_guard:ban::192.0.2.10',
        'other:registration_guard:ban:fixture:192.0.2.10',
        'retry_192.0.2.10', '192.0.2.10_404', 'unrelated',
    }
    for _, key in ipairs(keys) do f.shared[key] = 9 end
    f.generic['192.0.2.100'] = 7
    assert(f.env.remove_btwaf_drop_ip().status == true)
    for _, key in ipairs(keys) do assert(f.shared[key] == 9, 'unrelated key deleted: ' .. key) end
    assert(f.generic['192.0.2.100'] == 7, 'IP prefix collision')
end

function tests.invalid_unban_returns_false_without_mutation()
    local invalid = {'', 'unknown', '999.0.2.10', '192.0.2.10.extra', '192.0.2.10.1',
        '192..0.2.10', '192.0.2.-1', '192.0.2.1e1', ' 192.0.2.10', '192.0.2.10\n',
        '2001:db8:::1', false, 123, {}, true}
    for _, value in ipairs(invalid) do
        local f = fixture()
        f.shared['registration_guard:ban:fixture:192.0.2.10'] = 1
        f.generic['192.0.2.10'] = 7
        f.env.uri_request_args.ip = value
        local ok, result = pcall(f.env.remove_btwaf_drop_ip)
        assert(ok and result.status == false, 'invalid IP must return status=false: ' .. tostring(value))
        assert(f.generic['192.0.2.10'] == 7 and next(f.shared) ~= nil, 'invalid unban changed state')
    end
    local f = fixture()
    f.env.uri_request_args.ip = nil
    assert(f.env.remove_btwaf_drop_ip().status == false, 'missing IP must fail')
end

function tests.unban_allows_fresh_registration_window()
    for _, kind in ipairs({'register', 'verify'}) do
        local f = fixture()
        f.shared['registration_guard:ban:fixture:192.0.2.10'] = 1
        f.shared['registration_guard:count:fixture:' .. kind .. ':192.0.2.10'] = 99
        assert(f.env.remove_btwaf_drop_ip().status == true)
        local ok, result = pcall(f.env.registration_guard, 'fixture', '192.0.2.10', 'POST', '/' .. kind, '/' .. kind)
        assert(ok and result == false, 'unban must start a fresh registration window')
        assert(f.shared['registration_guard:v2:count:7:fixture:' .. kind .. ':192.0.2.10'] == 1)
    end
end

function tests.registration_threshold_still_enforces_new_abuse()
    local f = fixture()
    for _ = 1, 2 do
        assert(f.env.registration_guard('fixture', '192.0.2.10', 'POST', '/verify', '/verify') == false)
    end
    local ok, message = pcall(f.env.registration_guard, 'fixture', '192.0.2.10', 'POST', '/verify', '/verify')
    assert(not ok and message == 'fixture_blocked', 'fresh abuse must still be blocked')
end

function tests.clean_all_clears_registration_and_generic_bans()
    local f = fixture()
    f.shared['registration_guard:ban:fixture:192.0.2.10'] = 1
    f.shared['registration_guard:count:fixture:verify:192.0.2.10'] = 99
    f.shared['registration_guard:count:other:register:192.0.2.10'] = 99
    f.shared['registration_guard:count:fixture:verify:192.0.2.100'] = 1
    f.shared['other'] = 8
    f.generic['192.0.2.11'] = 7
    f.rules[1] = exact_rule(12, now + 1)
    f.rules[2] = {{192, 0, 2, 20}, {192, 0, 2, 30}, now + 1}
    f.rules[3] = exact_rule(40)
    assert(f.env.clean_btwaf_drop_ip().status == true)
    assert_ips(f.env.get_btwaf_drop_ip(), {})
    assert(f.shared['registration_guard:count:fixture:verify:192.0.2.10'] == nil, 'stale verify counter')
    assert(f.shared['registration_guard:count:other:register:192.0.2.10'] == nil, 'stale register counter')
    assert(f.shared['registration_guard:count:fixture:verify:192.0.2.100'] == 1)
    assert(f.shared.other == 8)
    assert(f.writes == 1 and #f.written_rules == 2, 'only the exact active persistent ban is removed')
end

function tests.clean_without_persistent_changes_skips_write()
    local f = fixture()
    f.generic['192.0.2.10'] = 7
    f.rules[1] = {{192, 0, 2, 20}, {192, 0, 2, 30}, now + 1}
    assert(f.env.clean_btwaf_drop_ip().status == true)
    assert(f.writes == 0, 'unchanged rule file must not be written')
    assert(f.generic['192.0.2.10'] == nil)
end

function tests.clean_refreshes_cache_after_backend_removed_persistent_rules()
    local f = fixture()
    f.env.ip_black_rules = {exact_rule(10, now + 1)}
    assert(f.env.clean_btwaf_drop_ip().status == true)
    assert(f.writes == 0 and #f.env.ip_black_rules == 0, 'already-clean persistence must refresh cache without a write')
end

local function write_failure(result)
    local f = fixture()
    f.rules[1] = exact_rule(10, now + 1)
    f.generic['192.0.2.10'] = 7
    f.shared['registration_guard:ban:fixture:192.0.2.10'] = 1
    f.shared['registration_guard:count:fixture:verify:192.0.2.10'] = 99
    f.write_failure, f.write_result = true, result
    assert(f.env.clean_btwaf_drop_ip().status == false, 'persistence failure must not report success')
    assert(f.writes == 1)
    assert(f.env.ip_black_rules == f.rules, 'failed write replaced cached rules')
    assert(f.generic['192.0.2.10'] == 7, 'failed write removed generic ban')
    assert(f.shared['registration_guard:ban:fixture:192.0.2.10'] == 1, 'failed write removed registration ban')
    assert(f.shared['registration_guard:count:fixture:verify:192.0.2.10'] == 99, 'failed write reset counters')
end
function tests.clean_write_false_returns_failure() write_failure(false) end
function tests.clean_write_nil_returns_failure() write_failure(nil) end

local failed, total = 0, 0
local names = {}
for name in pairs(tests) do names[#names + 1] = name end
table.sort(names)
for _, name in ipairs(names) do
    total = total + 1
    local ok, message = pcall(tests[name])
    if not ok then failed = failed + 1 end
    print((ok and 'PASS ' or 'FAIL ') .. name .. (ok and '' or ': ' .. tostring(message)))
end
print('registration_state: ' .. (total - failed) .. '/' .. total .. ' passed; isolated_fixture=true')
assert(failed == 0, tostring(failed) .. ' registration state regressions')
