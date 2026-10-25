-- Retired-policy regression and shared CC helpers; all state remains memory-only.
local source = assert(rawget(_G, 'WAF_RUNTIME_SOURCE'))
local json = require 'cjson'
local passed = 0
local function check(name, body)
    local ok, err = pcall(body)
    if not ok then error('FAIL ' .. name .. ': ' .. tostring(err)) end
    passed = passed + 1
end
local function dictionary()
    local values = {}
    local d = {}
    function d:get(key) return values[key] end
    function d:set(key, value) values[key] = value; return true end
    function d:safe_add(key, value)
        if values[key] ~= nil then return nil, 'exists' end
        values[key] = value; return true
    end
    function d:incr(key, delta)
        if values[key] == nil then return nil, 'not found' end
        values[key] = values[key] + delta; return values[key]
    end
    function d:delete(key) values[key] = nil end
    function d:get_keys() local keys = {}; for key in pairs(values) do keys[#keys + 1] = key end; return keys end
    return d
end
local function fixture()
    local f = {responses = {}, events = {}, checks = {}}
    local env = setmetatable({}, {__index = _G})
    local config = {open = true, cc = {open = true, cycle = 10, limit = 2, endtime = 60, status = 403},
        retry = 6, retry_time = 60, retry_cycle = 60}
    local site = {open = true, cc = {increase = true, cycle = 10, limit = 2, endtime = 60},
        retry = 6, retry_time = 60, retry_cycle = 60,
        endpoint_limits = {{id = string.rep('a',32), name = 'Legacy login', enabled = true, action = 'ban', path = '/login', match = 'exact',
            method = 'POST', max_requests = 1, window_seconds = 3600, ban_seconds = 28800}}}
    env.config, env.site_config, env.json = config, {['fixture.example'] = site}, json
    env.ngx = {var = {uri = '/login', request_uri = '/login?token=secret', server_name = 'fixture.example'},
        req = {get_headers = function() return {} end, get_method = function() return 'POST' end,
            get_uri_args = function() return {} end},
        shared = {free_waf = dictionary(), free_waf_drop_ip = dictionary(), free_waf_drop_sum = dictionary()},
        header = {}, unescape_uri = function(value) return value end,
        md5 = function(value) return value end, time = function() return 1000 end,
        say = function(value) f.responses[#f.responses + 1] = value end,
        exit = function(status) error({status = status}) end}
    env.ngx_match = function() return false end
    env.get_client_ip = function() return '192.0.2.1' end
    env.arrip = function() return {192, 0, 2, 1} end
    env.is_site_config = function(name) return site[name] end
    env.ip_white, env.user_agent_white, env.url_white = function() return false end, function() return false end, function() return false end
    env.write_log = function() end
    env.write_drop_ip = function() end
    env.repeat_ban_event = function(...) f.events[#f.events + 1] = {...} end
    for _,name in ipairs({'min_route', 'total_log_worker_init', 'repeat_ban_guard', 'registration_guard',
        'drop', 'ip_black', 'ban_empty_ua', 'url_black', 'drop_abroad', 'user_agent', 'header_rule',
        'url', 'args', 'cookie', 'scan_black', 'post', 'php_path', 'url_path', 'url_ext',
        'url_rule_ex', 'url_tell', 'post_data'}) do
        local key = name
        env[key] = function() f.checks[key] = (f.checks[key] or 0) + 1 end
    end
    for _,name in ipairs({'is_runtime_ban_ipv4', 'is_runtime_ban_ip', 'endpoint_normalize_ip', 'endpoint_state_ip', 'clear_endpoint_state',
        'rate_limit_response', 'cc_counter_key', 'cc', 'cc2', 'security_verification', 'run_btwaf'}) do
        local text = assert(source:match('\nfunction ' .. name .. '%(.-\nend'), name)
        local chunk = assert(loadstring('local config,site_config,json=config,site_config,json\n' .. text, '@' .. name))
        setfenv(chunk, env); chunk()
    end
    f.env, f.site = env, site
    env.ip, env.server_name, env.method = '192.0.2.1', 'fixture.example', 'POST'
    env.uri, env.request_uri, env.request_header = '/login', '/login', {}
    env.cycle, env.limit, env.endtime, env.retry, env.site_cc = 10, 2, 60, 6, true
    function f:request()
        local ok, value = pcall(env.run_btwaf)
        if not ok and type(value) ~= 'table' then error(value) end
        return not ok and value.status or 200
    end
    return f
end
local function legacy_key(kind, address)
    return 'endpoint:v1:' .. kind .. ':15:fixture.example:' .. string.rep('a',32) .. '.' .. string.rep('b',32) .. ':' .. address
end

check('old enabled policies and malformed policy data cannot throttle requests', function()
    for _,legacy in ipairs({false, 'malformed', {enabled = true}, {}}) do
        local f = fixture()
        if legacy ~= false then f.site.endpoint_limits = legacy end
        f.env.cc, f.env.cc2 = function() return false end, function() return false end
        f.env.ngx.shared.free_waf:safe_add(legacy_key('ban', '192.0.2.1'), 9999)
        for _=1,10 do assert(f:request() == 200) end
        assert(#f.responses == 0 and #f.events == 0)
        assert(f.checks.registration_guard == 10 and f.checks.post == 10)
    end
end)
check('normal CC still enforces despite retained retired configuration', function()
    local f = fixture(); f.env.cc2 = function() return false end
    assert(f:request() == 200 and f:request() == 200 and f:request() == 403)
    assert(#f.events == 1 and f.events[1][4] == 'cc')
end)
check('ordinary CC separates sites and paths but ignores query strings', function()
    local f = fixture(); local env = f.env
    for n=1,2 do env.request_uri = '/login?attempt=' .. n; assert(not env.cc()) end
    env.server_name = 'other.example'; assert(not env.cc())
    env.server_name = 'fixture.example'; env.ngx.var.uri = '/other'; assert(not env.cc())
    env.ngx.var.uri = '/login'
    local ok, value = pcall(env.cc)
    assert(not ok and type(value) == 'table' and value.status == 403)
end)
check('enhanced CC still enforces its fingerprint threshold', function()
    local f = fixture(); f.env.cc = function() return false end
    for _=1,6 do assert(f:request() == 200) end
    assert(f:request() == 429)
end)
check('enhanced CC aggregates fingerprints but keeps site and path boundaries', function()
    local f = fixture(); local env = f.env
    env.site_config['other.example'] = {cc = {increase = true}}
    for n=1,6 do env.ip = '192.0.2.' .. n; assert(not env.cc2()) end
    env.ip = '192.0.2.8'; env.server_name = 'other.example'; assert(not env.cc2())
    env.server_name = 'fixture.example'; env.ngx.var.uri = '/other'; assert(not env.cc2())
    env.ngx.var.uri = '/login'
    local ok, value = pcall(env.cc2)
    assert(not ok and type(value) == 'table' and value.status == 429)
end)
check('CC allocation does not evict existing security state', function()
    local f = fixture(); local shared = f.env.ngx.shared.free_waf
    shared:set('existing-ban', 9999)
    shared.add = function(self) self:delete('existing-ban'); return nil, 'no memory' end
    assert(not f.env.cc())
    assert(shared:get('existing-ban') == 9999)
end)
check('enhanced CC first increment remains atomic under contention', function()
    local f = fixture(); local shared = f.env.ngx.shared.free_waf
    local original, injected = shared.safe_add, false
    shared.safe_add = function(self, key, value, ttl)
        if not injected and key:sub(-4) == '_cc2' then
            injected = true; self:set(key, 1)
        end
        return original(self, key, value, ttl)
    end
    assert(not f.env.cc2() and injected)
    for _,key in ipairs(shared:get_keys()) do
        if key:sub(-4) == '_cc2' then assert(shared:get(key) == 2) end
    end
end)
check('IP and URL allowlists retain priority over ordinary CC', function()
    for _,name in ipairs({'ip_white', 'url_white'}) do
        local f = fixture(); f.env[name] = function() return true end
        for _=1,10 do assert(f:request() == 200) end
        assert(#f.events == 0)
    end
end)
check('precise legacy cleanup never removes another clients state', function()
    local f = fixture(); local shared = f.env.ngx.shared.free_waf
    for _,kind in ipairs({'count', 'event', 'ban'}) do
        shared:safe_add(legacy_key(kind, '192.0.2.1'), 9999)
        shared:safe_add(legacy_key(kind, '192.0.2.2'), 9999)
    end
    shared:safe_add('unrelated', true)
    f.env.clear_endpoint_state({['192.0.2.1'] = true})
    for _,kind in ipairs({'count', 'event', 'ban'}) do
        assert(shared:get(legacy_key(kind, '192.0.2.1')) == nil)
        assert(shared:get(legacy_key(kind, '192.0.2.2')) == 9999)
    end
    assert(shared:get('unrelated'))
end)
check('shared IP normalization and malformed legacy keys remain safe', function()
    local f = fixture()
    assert(f.env.endpoint_normalize_ip('2001:0DB8:0:0:0:0:0:1') == '2001:db8::1')
    assert(f.env.endpoint_normalize_ip('::ffff:192.0.2.1') == '::ffff:c000:201')
    assert(f.env.endpoint_normalize_ip('192.0.2.1.evil') == nil)
    assert(f.env.endpoint_state_ip('endpoint:v1:ban:999:x:y:192.0.2.1', true) == nil)
end)
check('legacy challenge still returns a safe rate limit response', function()
    local f = fixture()
    f.env.request_uri = "/login?q=';alert(1);//"
    local ok, value = pcall(f.env.security_verification)
    assert(not ok and type(value) == 'table' and value.status == 429)
    assert(f.env.ngx.header['Retry-After'] == '10')
    assert(not f.responses[1]:find('alert',1,true))
    assert(json.decode(f.responses[1]).error.type == 'rate_limit_exceeded')
end)
print('retired_endpoint_policy=' .. passed .. '/' .. passed .. ' isolated_fixture=true')
