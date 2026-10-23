-- Real production helpers; storage, clock and responses remain memory-only.
local source = assert(rawget(_G, 'WAF_RUNTIME_SOURCE'))
local json = require 'cjson'
local now = 1000
local passed = 0
local function check(name, body)
    local ok, err = pcall(body)
    if not ok then error('FAIL ' .. name .. ': ' .. tostring(err)) end
    passed = passed + 1
end
local function dictionary()
    local values, deadlines = {}, {}
    local d = {}
    function d:get(k)
        if deadlines[k] and deadlines[k] <= now then values[k] = nil end
        return values[k]
    end
    function d:set(k, v, ttl) values[k], deadlines[k] = v, ttl and now + ttl; return true end
    function d:add(k, v, ttl)
        if self:get(k) ~= nil then return nil, 'exists' end
        return self:set(k, v, ttl)
    end
    function d:safe_set(k,v,ttl) values[k],deadlines[k]=v,ttl and now+ttl; return true end
    function d:safe_add(k,v,ttl)
        if self:get(k)~=nil then return nil,'exists' end
        return self:safe_set(k,v,ttl)
    end
    function d:incr(k, delta)
        if self:get(k) == nil then return nil, 'not found' end
        values[k] = values[k] + delta; return values[k]
    end
    function d:delete(k) values[k], deadlines[k] = nil, nil end
    function d:get_keys() local keys = {}; for k in pairs(values) do keys[#keys + 1] = k end; return keys end
    return d
end
local function fixture(overrides)
    local rule = {id = string.rep('a', 32), name = 'fixture', enabled = true, action = 'reject',
        match = 'exact', path = '/login', method = 'POST', window_seconds = 10, max_requests = 2, ban_seconds = 30}
    for k,v in pairs(overrides or {}) do rule[k] = v end
    local env = setmetatable({}, {__index = _G})
    local f = {rule = rule, events = {}, drops = {}, writes = 0}
    local sites = {['example.org'] = {endpoint_limits = {rule}}, ['other.example'] = {endpoint_limits = {rule}}}
    local ngx = {var = {uri = '/login', server_name = 'example.org'}, header = {},
        shared = {free_waf = dictionary(), free_waf_drop_ip = dictionary(), free_waf_drop_sum = dictionary()},
        time = function() return now end, today = function() return '2026-10-23' end,
        localtime = function() return '2026-10-23 10:00:00' end,
        md5 = function(s) local h=5381; for i=1,#s do h=(h*33+s:byte(i))%2147483647 end; return string.format('%032x',h) end,
        say = function(s) f.response = s end,
        exit = function(status) error({status = status}) end}
    local config = {open = true, log = true, logs_path = 'fixture', cc = {open = true, status = 403}}
    env.ngx, env.ip, env.server_name, env.method = ngx, '192.0.2.1', 'example.org', 'POST'
    env.ip_black_rules, env.request_header = {}, {}
    env.ngx_match = function() return false end
    env.retry, env.cycle, env.limit, env.endtime, env.site_cc = 6, 10, 2, 60, true
    env.request_uri, env.uri, env.uri_request_args = '/login', '/login', {}
    env.json, env.config, env.site_config = json, config, sites
    env.write_log = function() error('legacy retry/attack counter changed') end
    env.read_file=function() return {} end
    env.write_file=function() return true end
    env.jpath='fixture/'
    env.write_drop_ip = function() f.drops[#f.drops + 1] = true end
    env.write_drop_ip_entry = function(...) f.drops[#f.drops + 1] = {...}; return true end
    env.io = {open = function(path, mode)
        assert(path == 'fixture/endpoint_2026-10-23.jsonl' and mode == 'ab')
        return {write = function(_, data) f.writes = f.writes + 1; f.events[#f.events + 1] = json.decode(data); return true end,
            close = function() return true end, flush = function() return true end}
    end}
    local helpers = {'is_runtime_ban_ipv4', 'is_runtime_ban_ip', 'endpoint_normalize_ip',
        'endpoint_state_key', 'endpoint_state_ip', 'endpoint_valid_rule', 'endpoint_path_matches',
        'endpoint_record_event', 'endpoint_limit_response', 'endpoint_policy_guard',
        'clear_endpoint_state', 'cc_counter_key', 'cc', 'cc2', 'security_verification', 'registration_guard_scopes',
        'registration_state_ip', 'registration_state_ambiguous', 'clear_registration_state',
        'get_return_state', 'encode_json_array', 'get_btwaf_drop_ip', 'clean_btwaf_drop_ip'}
    for _,name in ipairs(helpers) do
        local start = source:find('function ' .. name .. '%(')
        assert(start, 'missing production helper: ' .. name)
        local finish = source:find('\nfunction ', start + 1)
        local text = source:sub(start, finish and finish - 1 or #source)
        assert(loadstring(text, '@' .. name))
        local fn = assert(loadstring('local config, site_config, json = config, site_config, json\n' .. text, '@' .. name))
        setfenv(fn, env); fn()
    end
    f.env, f.ngx, f.sites = env, ngx, sites
    function f:request(path, method, site, ip)
        ngx.header, self.response = {}, nil
        ngx.var.uri = path or '/login'; env.uri = ngx.var.uri
        env.server_name = site or 'example.org'; ngx.var.server_name = env.server_name
        env.method, env.ip = method or 'POST', ip or '192.0.2.1'
        local ok, value = pcall(env.endpoint_policy_guard)
        if ok then return false end
        if type(value) == 'table' then return value.status end
        error(value)
    end
    return f
end
check('missing rules are inert', function()
    local f = fixture(); f.sites['example.org'].endpoint_limits = nil
    for i=1,4 do assert(not f:request()) end
    assert(f.writes == 0 and #f.ngx.shared.free_waf:get_keys() == 0)
end)
check('disabled and invalid rules are inert', function()
    for _,change in ipairs({{enabled=false},{action='unknown'},{window_seconds=0},{max_requests=0},{id='bad'},{ban_seconds=28801}}) do
        local f = fixture(change); for i=1,4 do assert(not f:request()) end
        assert(f.writes == 0)
    end
end)
check('exact path and method', function()
    local f = fixture()
    for i=1,4 do assert(not f:request('/login-more')); assert(not f:request('/login','GET')) end
    assert(not f:request()); assert(not f:request()); assert(f:request()==429)
    assert(f.ngx.header['Retry-After'] == '10')
    assert(json.decode(f.response).error.type == 'rate_limit_exceeded')
end)
check('prefix is segment aware', function()
    local f = fixture({match='prefix',path='/api'})
    for i=1,4 do assert(not f:request('/apiculture')) end
    assert(not f:request('/api/login')); assert(not f:request('/api/search')); assert(f:request('/api')==429)
end)
check('site and ip counters isolated', function()
    local f = fixture(); assert(not f:request()); assert(not f:request())
    assert(not f:request(nil,nil,'other.example')); assert(not f:request(nil,nil,nil,'192.0.2.2'))
    assert(f:request()==429)
end)
check('observe never bans or calls legacy counters', function()
    local f=fixture({action='observe'})
    for i=1,8 do assert(not f:request()) end
    assert(f.writes==1 and f.events[1].action=='observe' and #f.drops==0)
    assert(#f.ngx.shared.free_waf_drop_ip:get_keys()==0)
    assert(f.events[1].path=='/login' and f.events[1].rule_id==f.rule.id)
end)
check('counter window expires', function()
    local f=fixture(); assert(not f:request()); assert(not f:request()); assert(f:request()==429)
    now=now+11; assert(not f:request())
end)
check('ban scoped to endpoint and site', function()
    local f=fixture({action='ban'}); assert(not f:request()); assert(not f:request()); assert(f:request()==429)
    assert(f:request()==429 and f.ngx.header['Retry-After']=='30')
    assert(not f:request('/home')); assert(not f:request(nil,nil,'other.example'))
    assert(#f.ngx.shared.free_waf_drop_ip:get_keys()==0 and #f.drops==1)
    now=now+31; assert(not f:request())
end)
check('policy edits do not inherit old counter or ban', function()
    local f=fixture({action='ban'}); f:request(); f:request(); assert(f:request()==429)
    f.rule.max_requests=20; assert(not f:request())
end)
check('shared storage exhaustion fails open', function()
    local f=fixture(); f.ngx.shared.free_waf.safe_add=function() return nil,'no memory' end
    f.ngx.shared.free_waf.incr=function() return nil,'not found' end
    for i=1,4 do assert(not f:request()) end
    assert(f.writes==0)
end)
check('endpoint allocations cannot evict unrelated security state', function()
    for _,action in ipairs({'observe','reject','ban'}) do
        local f=fixture({action=action}); local shared=f.ngx.shared.free_waf
        shared:safe_set('legacy-retry',5,3600)
        shared.add=function(self,...) self:delete('legacy-retry'); return nil,'no memory' end
        shared.set=shared.add
        for i=1,4 do f:request() end
        assert(shared:get('legacy-retry')==5)
    end
end)
check('ban enumeration hides edited disabled and deleted policy revisions', function()
    for _,change in ipairs({'edit','disable','delete'}) do
        local f=fixture({action='ban'}); for i=1,3 do f:request() end
        assert(#f.env.get_btwaf_drop_ip()==1)
        if change=='edit' then f.rule.action='observe'
        elseif change=='disable' then f.rule.enabled=false
        else f.sites['example.org'].endpoint_limits={} end
        assert(not f:request())
        assert(#f.env.get_btwaf_drop_ip()==0)
        f.env.clear_endpoint_state({['192.0.2.1']=true})
        for _,key in ipairs(f.ngx.shared.free_waf:get_keys()) do assert(not f.env.endpoint_state_ip(key,true)) end
    end
end)
check('bulk unban removes hidden endpoint revisions and counters', function()
    for _,change in ipairs({'edit','disable','delete'}) do
        local f=fixture({action='ban'}); for i=1,3 do f:request() end
        if change=='edit' then f.rule.action='observe'
        elseif change=='disable' then f.rule.enabled=false
        else f.sites['example.org'].endpoint_limits={} end
        assert(#f.env.get_btwaf_drop_ip()==0)
        assert(f.env.clean_btwaf_drop_ip().status==true)
        f.rule.action,f.rule.enabled='ban',true
        f.sites['example.org'].endpoint_limits={f.rule}
        assert(not f:request())
        assert(#f.env.get_btwaf_drop_ip()==0)
    end
end)
check('enhanced cc aggregates fingerprint across clients but not sites or paths', function()
    local f=fixture(); f.sites['example.org'].cc={increase=true}; f.sites['other.example'].cc={increase=true}
    for i=1,6 do f.env.ip='192.0.2.'..i; assert(not f.env.cc2()) end
    f.env.ip='192.0.2.8'
    f.env.server_name='other.example'; assert(not f.env.cc2())
    f.env.server_name='example.org'; f.ngx.var.uri='/other'; assert(not f.env.cc2())
    f.ngx.var.uri='/login'
    local ok,e=pcall(f.env.cc2); assert(not ok and type(e)=='table' and e.status==429)
end)
check('ordinary cc initialization does not evict existing security state', function()
    local f=fixture(); local shared=f.ngx.shared.free_waf
    shared:safe_set('existing-ban',100,60)
    shared.add=function(self,...) self:delete('existing-ban'); return nil,'no memory' end
    f.env.write_log=function() end
    assert(not f.env.cc())
    assert(shared:get('existing-ban')==100)
end)
check('enhanced cc increments the first counter atomically', function()
    local f=fixture(); f.sites['example.org'].cc={increase=true}
    local shared=f.ngx.shared.free_waf
    local original_get, original_set=shared.get,shared.safe_set
    local original_add=shared.safe_add
    local injected=false
    shared.get=function(self,key)
        local value=original_get(self,key)
        if not injected and key:sub(-4)=='_cc2' and value==nil then
            injected=true; original_set(self,key,1,10)
        end
        return value
    end
    shared.safe_add=function(self,key,value,ttl)
        if not injected and key:sub(-4)=='_cc2' then
            injected=true; original_set(self,key,1,10)
        end
        return original_add(self,key,value,ttl)
    end
    assert(not f.env.cc2())
    for _,key in ipairs(shared:get_keys()) do
        if key:sub(-4)=='_cc2' then assert(original_get(shared,key)==2) end
    end
    assert(injected)
end)
check('evidence excludes secrets and limits repeated events', function()
    local f=fixture(); f.env.request_uri='/login?token=secret'; f.env.request_header={authorization='secret'}
    for i=1,10 do f:request() end
    assert(f.writes==1 and not json.encode(f.events):find('secret',1,true))
end)
check('scoped bans visible and precise unban clears all state for one ip', function()
    local f=fixture({action='ban'}); for i=1,3 do f:request() end
    assert(f.env.get_btwaf_drop_ip()[1]=='192.0.2.1')
    for i=1,3 do f:request(nil,nil,nil,'192.0.2.2') end
    f.env.clear_endpoint_state({['192.0.2.1']=true})
    assert(not f:request()); assert(f:request(nil,nil,nil,'192.0.2.2')==429)
end)
check('ipv6 canonicalization and malformed keys', function()
    local f=fixture()
    assert(f.env.endpoint_normalize_ip('2001:0DB8:0:0:0:0:0:1')=='2001:db8::1')
    assert(f.env.endpoint_normalize_ip('::ffff:192.0.2.1')=='::ffff:c000:201')
    assert(f.env.endpoint_normalize_ip('192.0.2.1.evil')==nil)
    for _,key in ipairs({'endpoint:v1:ban:1:x:bad:192.0.2.1','endpoint:v1:ban:999:x:y:192.0.2.1'}) do
        assert(f.env.endpoint_state_ip(key,true)==nil)
    end
end)
check('legacy cc site dimension and query independent key', function()
    local f=fixture(); f.env.write_log=function() end
    for i=1,2 do f.env.request_uri='/login?x='..i; assert(not f.env.cc()) end
    f.env.server_name='other.example'; assert(not f.env.cc())
    f.env.server_name='example.org'
    local ok,e=pcall(f.env.cc); assert(not ok and type(e)=='table' and e.status==403)
end)
check('legacy arithmetic challenge cannot reflect a request or grant a bypass', function()
    local f=fixture()
    f.env.request_uri="/login?q=';alert(1);//"
    f.env.uri_request_args={btwaf='40'}
    local ok,e=pcall(f.env.security_verification)
    assert(not ok and type(e)=='table' and e.status==429)
    assert(not f.response:find('alert',1,true) and not f.response:find('<script',1,true))
    assert(f.ngx.shared.free_waf:get('192.0.2.1')==nil)
end)
print('endpoint_policy=' .. passed .. '/' .. passed .. ' isolated_fixture=true')
