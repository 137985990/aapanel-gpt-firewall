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
    dict.safe_add,dict.safe_set = dict.add,dict.set
    return dict
end

local function state_key(scope, ip, kind)
    return 'registration_guard:v2:' .. (kind and 'count' or 'ban') .. ':' .. #scope .. ':' .. scope .. ':' .. (kind and kind .. ':' or '') .. ip
end

local function fixture(rules, extra_scopes, options)
    options = options or {}
    local f = {files = {}, shared = {}, generic = {}, writes = 0, query = {}, post_args = {}, headers = {},
        lock_files = {}, descriptors = {}, locked = {}, metadata = {}, next_fd = 10, next_inode = 1}
    local config = {
        open = false, log = false, reqfile_path = 'fixture-html',
        cc = {cycle = 60, endtime = 60, limit = 2, status = 403},
        retry = 6, retry_time = 60, retry_cycle = 60,
    }
    for _, name in ipairs({'get', 'post', 'cookie', 'user-agent', 'other'}) do
        config[name] = {open = true, status = 403, reqfile = name .. '.html'}
        f.files['fixture-html/' .. name .. '.html'] = 'fixture-blocked'
    end
    for key, value in pairs(options.config or {}) do config[key] = value end
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
    f.files[root .. 'site.json'] = json.encode(options.sites or sites)
    f.files[root .. '/rule/cn.json'] = '[]'
    f.files[root .. 'rule/ip_black.json'] = rules and json.encode(rules) or '[]'
    for _, name in ipairs({'post', 'user_agent_white'}) do
        f.files[root .. 'rule/' .. name .. '.json'] = json.encode({
            {0, 'inactive'}, {1, 'needle'}, {1, 'other'},
        })
    end
    if options.args_rules then
        f.files[root .. 'rule/args.json'] = json.encode(options.args_rules)
    end
    local exit_marker = {}
    local ngx = {
        var = {remote_addr = '127.0.0.1', server_name = 'fixture'},
        header = {},
        shared = {free_waf = dictionary(f.shared), free_waf_drop_ip = dictionary(f.generic),
            free_waf_drop_sum = dictionary({})},
        re = {find = function(value, pattern) return string.find(value, pattern) end},
        unescape_uri = function(value) return value end,
        md5 = function(value)
            local hash = 5381
            for i = 1, #value do hash = (hash * 33 + value:byte(i)) % 2147483647 end
            return string.format('%032x', hash)
        end,
        say = function(body) f.output[#f.output + 1] = body end,
        exit = function(status) f.exit_status = status; error(exit_marker, 0) end,
        req = {
            get_headers = function() return f.headers end,
            get_method = function() return 'GET' end,
            get_uri_args = function() return f.query end,
            get_post_args = function() return f.post_args end,
            read_body = function() end,
            get_body_file = function() return nil end,
            get_body_data = function() return nil end,
        },
    }
    local lock_path = root .. 'rule/ip_black.json.lock'
    local function assert_locked()
        assert(f.locked[lock_path], 'blacklist IO must hold the transaction lock')
    end
    local function metadata(path)
        if not f.metadata[path] then
            f.metadata[path] = {dev=1,ino=f.next_inode,nlink=1,mode=32768+384,uid=1000,gid=1000}
            f.next_inode = f.next_inode + 1
        end
        return f.metadata[path]
    end
    local ffi = {os = 'Linux', arch = 'x64', C = {}, cdef = function() end,
        errno = function() return f.errno or 2 end,
        new = function(kind, value) if kind=='struct gpt_fw_stat[1]' then return {[0]={}} end; return value end}
    function ffi.C.open(path, flags, mode)
        if flags == 655426 then
            assert(path == lock_path and mode == 384, 'unexpected lock protocol')
            f.lock_files[path] = f.lock_files[path] or {}
        elseif flags == 657408 then
            if not f.lock_files[path] and f.files[path] == nil then f.errno=2; return -1 end
        else
            assert(flags == 655553 and mode == 384 and path:match('%.tmp$'), 'unexpected temporary protocol')
            assert_locked()
            f.writes = f.writes + 1
            if f.fail_write then return -1 end
            if f.files[path] ~= nil then f.errno=17; return -1 end
            f.files[path] = ''
        end
        local fd = f.next_fd
        f.next_fd = fd + 1
        metadata(path)
        f.descriptors[fd] = path
        return fd
    end
    function ffi.C.gpt_fw_fstat(fd, buffer)
        for key,value in pairs(metadata(assert(f.descriptors[fd]))) do buffer[0][key]=value end
        return 0
    end
    function ffi.C.gpt_fw_fchmod(fd, mode) metadata(assert(f.descriptors[fd])).mode=32768+mode; return 0 end
    function ffi.C.gpt_fw_fchown(fd, uid, gid)
        local row=metadata(assert(f.descriptors[fd])); row.uid,row.gid=uid,gid; return 0
    end
    local function stage_result(stage)
        if f.fail_stage ~= stage then return 0 end
        if f.fail_result == false then return -1 end
        error('fixture ' .. stage .. ' failure')
    end
    function ffi.C.gpt_fw_write(fd, body, size)
        local path=assert(f.descriptors[fd])
        f.files[path]=f.fail_stage=='write' and body:sub(1,1) or body
        return stage_result('write') == 0 and size or -1
    end
    function ffi.C.gpt_fw_fsync(fd) return stage_result('flush') end
    function ffi.C.flock(fd, operation)
        assert(operation == 6, 'request locks must be nonblocking')
        local path = assert(f.descriptors[fd])
        if f.lock_busy or f.locked[path] then return -1 end
        f.locked[path] = fd
        return 0
    end
    function ffi.C.close(fd)
        local path = assert(f.descriptors[fd])
        if f.locked[path] == fd then f.locked[path] = nil end
        f.descriptors[fd] = nil
        if path:match('%.tmp$') then
            f.close_attempts = (f.close_attempts or 0) + 1
            return stage_result('close')
        end
        return 0
    end
    local function assert_temporary(path)
        local prefix = root .. 'rule/ip_black.json.'
        assert(path:sub(1, #prefix) == prefix and path:sub(-4) == '.tmp', 'unexpected temporary path: ' .. path)
    end
    local env = setmetatable({
        ngx = ngx, os = {time = function() return now end,
            rename = function(temporary, path)
                assert_temporary(temporary); assert_locked()
                assert(path == root .. 'rule/ip_black.json' and f.files[temporary] ~= nil)
                if f.fail_rename then return nil, 'fixture rename failure' end
                f.files[path], f.files[temporary] = f.files[temporary], nil
                f.metadata[path], f.metadata[temporary] = f.metadata[temporary], nil
                f.renames = (f.renames or 0) + 1
                return true
            end,
            remove = function(path)
                assert_temporary(path); assert_locked()
                f.files[path] = nil
                f.metadata[path] = nil
                return true
            end},
        require = function(name)
            if name == 'cjson' then return json end
            assert(name == 'ffi', 'unexpected module: ' .. name)
            return ffi
        end,
        io = {open = function(path, mode)
            if mode == 'r' or mode == 'rb' then
                if f.loaded and path == root .. 'rule/ip_black.json' then assert_locked() end
                if f.files[path] == nil then return nil, 'missing', 2 end
                local body = f.files[path]
                return {read = function() return body end, close = function() return true end}
            end
            if mode == 'ab' and path == root .. 'drop_ip.log' then return nil end
            assert(mode == 'wb', 'unexpected write mode: ' .. tostring(mode))
            assert_temporary(path); assert_locked()
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
    ngx.time,ngx.now = function() return now end,function() return now+0.01 end
    ngx.worker = {pid=function() return 123 end}
    env._G = env
    local chunk = assert(loadstring(source, '@init.lua'))
    setfenv(chunk, env)
    chunk()
    f.loaded = true
    f.env, f.ngx = env, ngx
    function f:request(path, query)
        self.output, self.exit_status, self.query = {}, nil, query or {}
        ngx.var.uri, ngx.var.request_uri = path, path
        local ok, message = pcall(env.run_btwaf)
        assert(not ok and message == exit_marker, 'route did not terminate normally: ' .. tostring(message))
        assert(self.exit_status == 200 and ngx.status == 200)
        assert(ngx.header.content_type == 'application/json;')
        assert(#self.output == 1, 'route must emit exactly one JSON document')
        assert(next(self.descriptors) == nil and next(self.locked) == nil, 'route leaked a lock descriptor')
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

function tests.scoped_cc_enforcement_and_unban_use_the_full_loaded_runtime()
    local f=fixture(nil,nil,{config={cc={open=true,cycle=10,endtime=60,limit=1,status=403}}})
    local env=f.env
    env.server_name,env.ip,env.uri,env.site_cc='fixture','192.0.2.10','/a',true
    env.cycle,env.endtime,env.limit,env.retry=10,60,1,6
    f.ngx.var.uri='/a'
    assert(env.cc()==false)
    f:assert_blocked(env.cc)
    f.ngx.var.uri='/b'
    f:assert_blocked(env.drop)
    env.server_name='other'
    assert(env.drop()==false,'CC ban crossed the site boundary')
    local rows=f:request('/get_btwaf_drop_ip')
    assert(#rows==1 and rows[1]=='192.0.2.10','scoped ban missing from real route')
    assert(f:request('/remove_btwaf_drop_ip',{ip='192.0.2.10'}).status==true)
    env.server_name,env.ip='fixture','192.0.2.10'
    assert(env.drop()==false,'real unban route left scoped CC state')
end

function tests.failed_bulk_cleanup_preserves_scoped_cc_bans_and_history()
    local f=fixture({exact_rule(10)})
    local ban=f.env.cc_state_key('ban','fixture','192.0.2.10')
    local history=f.env.cc_state_key('history','fixture','192.0.2.10')
    f.ngx.shared.free_waf_drop_ip:set(ban,7,60)
    f.ngx.shared.free_waf_drop_sum:set(history,3,86400)
    f.fail_write=true
    assert(f:request('/clean_btwaf_drop_ip').status==false)
    assert(f.ngx.shared.free_waf_drop_ip:get(ban)==7,'failed cleanup removed scoped ban')
    assert(f.ngx.shared.free_waf_drop_sum:get(history)==3,'failed cleanup removed CC history')
    f.fail_write=false
    assert(f:request('/clean_btwaf_drop_ip').status==true)
    assert(f.ngx.shared.free_waf_drop_ip:get(ban)==nil)
    assert(f.ngx.shared.free_waf_drop_sum:get(history)==nil)
end

local function cdn_fixture(order, overrides, config)
    local site = {
        cdn = true, cdn_header = {'x-forwarded-for', 'x-real-ip'}, cdn_header_order = order,
        cdn_trusted_proxy = {{{198, 51, 100, 20}, {198, 51, 100, 20}}},
    }
    for key, value in pairs(overrides or {}) do site[key] = value end
    local f = fixture(nil, nil, {config = config, sites = {fixture = site}})
    f.ngx.var.remote_addr = '198.51.100.20'
    f.headers['x-forwarded-for'] = '192.0.2.10, 192.0.2.30'
    return f
end

local function assert_identity(f, site, ip)
    f.output, f.exit_status = {}, nil
    f.ngx.var.uri, f.ngx.var.request_uri = '/ordinary', '/ordinary'
    local ok, result = pcall(f.env.run_btwaf)
    assert(ok and result == false, 'identity request failed: ' .. tostring(result))
    assert(f.env.server_name == site, 'expected site ' .. site .. ', got ' .. tostring(f.env.server_name))
    assert(f.env.ip == ip, 'expected client IP ' .. ip .. ', got ' .. tostring(f.env.ip))
    assert(f.writes == 0, 'identity lookup must not write files')
end

function tests.cn_alias_maps_once_before_cdn_lookup_and_resets_each_request()
    local f = fixture(nil, nil, {
        config = {compatibility_profile = 'bt-free-waf-8.4',
            site_aliases = {fixture = 'canonical', canonical = 'other'}},
        sites = {
            fixture = {cdn = true, cdn_header = {'x-forwarded-for'}},
            canonical = {cdn = true, cdn_header = {'x-forwarded-for'}, cdn_header_order = 'last',
                cdn_trusted_proxy = {{{198, 51, 100, 20}, {198, 51, 100, 20}}}},
            other = {},
        },
    })
    f.ngx.var.remote_addr = '198.51.100.20'
    f.headers['x-forwarded-for'] = '192.0.2.10, 192.0.2.30'
    assert_identity(f, 'canonical', '192.0.2.30')
    assert(f.ngx.var.server_name == 'fixture', 'must not rewrite the Nginx server name')
    f.ngx.var.remote_addr = '198.51.100.21'
    assert_identity(f, 'canonical', '198.51.100.21')
    f.ngx.var.server_name = 'new-alias'
    f.headers.host = 'fixture'
    assert_identity(f, 'new-alias', '198.51.100.21')
    f.ngx.var.server_name = '_'
    assert_identity(f, '_', '198.51.100.21')
end

function tests.cn_alias_requires_the_exact_profile_and_preserves_aapanel()
    local profiles = {false, true, 84, {}, json.null, 'bt-free-waf-8.4 ',
        'BT-free-waf-8.4', 'bt-free-waf-8.5', 'aapanel-free-waf-5.0'}
    for index = 0, #profiles do
        local f = fixture(nil, nil, {
            config = {compatibility_profile = profiles[index], site_aliases = {fixture = 'canonical'}},
            sites = {fixture = {}, canonical = {}},
        })
        assert_identity(f, 'fixture', '127.0.0.1')
    end
end

function tests.cn_alias_ignores_unknown_map_and_target_types()
    local invalid = {false, true, 84, 'canonical', json.null, {{fixture = 'canonical'}}}
    for index = 0, #invalid do
        local f = fixture(nil, nil, {
            config = {compatibility_profile = 'bt-free-waf-8.4', site_aliases = invalid[index]},
            sites = {fixture = {}, canonical = {}},
        })
        assert_identity(f, 'fixture', '127.0.0.1')
    end
    for _, target in ipairs({false, true, 84, {}, json.null, '', 'missing', ' canonical '}) do
        local f = fixture(nil, nil, {
            config = {compatibility_profile = 'bt-free-waf-8.4', site_aliases = {fixture = target}},
            sites = {fixture = {}, canonical = {}},
        })
        assert_identity(f, 'fixture', '127.0.0.1')
    end
end

function tests.cn_alias_stale_or_non_site_target_keeps_the_original_scope()
    for _, site in ipairs({false, true, 84, 'not-a-site', json.null}) do
        local f = fixture(nil, nil, {
            config = {compatibility_profile = 'bt-free-waf-8.4', site_aliases = {fixture = 'removed'}},
            sites = {fixture = {}, removed = site},
        })
        assert_identity(f, 'fixture', '127.0.0.1')
    end
end

function tests.cdn_explicit_first_and_last_follow_both_header_orders()
    for _, order in ipairs({'first', 'last'}) do
        local f = cdn_fixture(order, {cdn_baidu = order == 'last'})
        local expected = order == 'last' and '192.0.2.30' or '192.0.2.10'
        assert_identity(f, 'fixture', expected)
        f.headers['x-forwarded-for'] = '192.0.2.30, 192.0.2.10'
        expected = order == 'last' and '192.0.2.10' or '192.0.2.30'
        assert_identity(f, 'fixture', expected)
    end
end

function tests.cdn_missing_or_invalid_order_keeps_first_even_in_cn_profile()
    local invalid = {false, true, 1, {}, json.null, 'LAST', 'last ', ''}
    for index = 0, #invalid do
        local f = cdn_fixture(invalid[index], {cdn_baidu = true}, {compatibility_profile = 'bt-free-waf-8.4'})
        assert_identity(f, 'fixture', '192.0.2.10')
    end
    assert_identity(cdn_fixture(), 'fixture', '192.0.2.10')
end

function tests.cdn_scans_past_invalid_and_loopback_ips_in_the_selected_direction()
    for _, order in ipairs({'first', 'last'}) do
        local f = cdn_fixture(order)
        f.headers['x-forwarded-for'] = 'bad, 999.0.0.1, 127.0.0.1, 192.0.2.10, 192.0.2.30, 127.0.0.1, bad'
        assert_identity(f, 'fixture', order == 'last' and '192.0.2.30' or '192.0.2.10')
        f.headers['x-forwarded-for'] = 'bad, 999.0.0.1, 127.0.0.1'
        assert_identity(f, 'fixture', '198.51.100.20')
        f.headers['x-real-ip'] = '192.0.2.40'
        assert_identity(f, 'fixture', '192.0.2.40')
    end
end

function tests.cdn_rejects_malformed_ipv4_tokens_not_just_bad_octet_ranges()
    for _, order in ipairs({'first', 'last'}) do
        for _, invalid in ipairs({'192.0.2.1.9', '192.0.2.1:80', '192.0.2.-1', '192.0.2.1e1'}) do
            local f = cdn_fixture(order)
            f.headers['x-forwarded-for'] = invalid .. ', 192.0.2.10, ' .. invalid
            assert_identity(f, 'fixture', '192.0.2.10')
        end
    end
end

function tests.cdn_ignores_non_string_headers_and_preserves_repeated_header_semantics()
    for _, order in ipairs({'first', 'last'}) do
        for _, value in ipairs({false, true, 84, json.null, {}, {true}, {{'192.0.2.10'}}}) do
            local f = cdn_fixture(order)
            f.headers['x-forwarded-for'] = value
            assert_identity(f, 'fixture', '198.51.100.20')
        end
        local f = cdn_fixture(order)
        f.headers['x-forwarded-for'] = {'192.0.2.10, 192.0.2.30', '192.0.2.99'}
        assert_identity(f, 'fixture', order == 'last' and '192.0.2.30' or '192.0.2.10')
    end
end

function tests.cdn_order_never_bypasses_proxy_trust_or_the_site_cdn_switch()
    for _, order in ipairs({'first', 'last'}) do
        local f = cdn_fixture(order)
        f.ngx.var.remote_addr = '198.51.100.21'
        assert_identity(f, 'fixture', '198.51.100.21')
        f.ngx.var.remote_addr = nil
        assert_identity(f, 'fixture', 'unknown')
        assert_identity(cdn_fixture(order, {cdn = false}), 'fixture', '198.51.100.20')
        f = cdn_fixture(order, {cdn_trusted_proxy = {}})
        assert_identity(f, 'fixture', order == 'last' and '192.0.2.30' or '192.0.2.10')
    end
end

local function args_fixture(args_disabled, post_disabled)
    local f = fixture(nil, nil, {
        config = {open = true, scan = {open = false}, drop_abroad = {open = false}},
        args_rules = {{0, 'inactive'}, {1, 'needle'}, {1, 'other'}},
        sites = {fixture = {
            open = true, log = false, cdn = false, get = true, post = false, cookie = false,
            ['user-agent'] = false, cc = {open = false}, retry = 6, retry_time = 60, retry_cycle = 60,
            disable_rule = {args = args_disabled or {}, post = post_disabled or {}},
            url_white = {}, disable_php_path = {}, disable_path = {}, disable_ext = {},
            url_rule = {}, url_tell = {},
        }},
    })
    f.ngx.var.remote_addr = '198.51.100.20'
    f.ngx.var.uri, f.ngx.var.request_uri = '/ordinary', '/ordinary?a=clean&a=needle'
    f.headers['user-agent'] = 'fixture-client'
    f.query = {a = {'clean', 'needle'}}
    return f
end

function tests.repeated_get_values_block_on_either_array_position()
    for _, values in ipairs({{'clean', 'needle'}, {'needle', 'clean'}}) do
        local f = args_fixture()
        f.query = {a = values}
        f:assert_blocked(f.env.run_btwaf)
        assert(f.ngx.status == 403 and f.output[1] == 'fixture-blocked')
        assert(f.env.error_rule == 'needle >> a:needle', 'block must come from the repeated GET value')
    end
end

function tests.repeated_get_values_keep_raw_args_exception_offsets()
    local f = args_fixture({1})
    assert(f.env.run_btwaf() == nil and f.exit_status == nil, 'args exception must permit the repeated value')
    f = args_fixture({0})
    f:assert_blocked(f.env.run_btwaf)
    assert(f.env.error_rule == 'needle >> a:needle', 'disabled global rows must not compact exception offsets')
end

function tests.repeated_get_values_do_not_use_post_exceptions()
    local f = args_fixture({}, {1})
    f:assert_blocked(f.env.run_btwaf)
    assert(f.env.error_rule == 'needle >> a:needle', 'POST exceptions must not disable GET rules')
end

function tests.repeated_get_values_ignore_non_strings_without_skipping_later_strings()
    local f = args_fixture()
    f.query = {flag = true, a = {true, false, 84, json.null, {}, {'needle'}, 'needle'}}
    f:assert_blocked(f.env.run_btwaf)
    assert(f.env.error_rule == 'needle >> a:needle')
end

function tests.repeated_get_values_expand_only_one_array_level()
    local f = args_fixture()
    f.query = {flag = true, a = {true, false, 84, json.null, {'needle'}, {named = 'needle'}}}
    assert(f.env.run_btwaf() == nil and f.exit_status == nil, 'nested/non-string values must not crash or recurse')
    for _, value in ipairs({true, false, 84, json.null}) do
        local ok, matched = pcall(f.env.is_ngx_match, {'needle'}, value, 'args')
        assert(ok and matched == false, 'non-table/non-string input must be ignored safely')
    end
end

function tests.repeated_get_values_preserve_scalar_key_and_other_family_semantics()
    local f = args_fixture()
    local match = f.env.is_ngx_match
    assert(match({'needle'}, {a = 'needle'}, 'args'), 'scalar values must still match')
    assert(match({'needle'}, {needle = true}, 'args'), 'boolean parameter keys must still match')
    assert(not match({'needle'}, {needle = false}, 'args'), 'false-valued keys must retain existing behavior')
    assert(not match({'needle'}, {content = {'needle'}}, 'args'), 'excluded parameter keys must stay excluded')
    assert(match({'needle'}, {a = {'clean', 'needle'}}, 'post'), 'repeated POST values must be inspected')
    assert(match({'needle'}, {a = {'clean', 'needle'}}, 'header'), 'repeated header values must be inspected')
    assert(not match({'needle'}, {a = {{'needle'},false,84}}, 'post'), 'POST arrays must not recurse')
    assert(not match({'needle'}, {a = {{'needle'},false,84}}, 'header'), 'header arrays must not recurse')
end

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
    assert(f.renames == 1 and f.lock_files[root .. 'rule/ip_black.json.lock'], 'publish must keep the fixed lock inode')
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

function tests.blacklist_lock_contention_cannot_clear_bans_or_publish()
    local f = fixture({exact_rule(12)})
    local path = root .. 'rule/ip_black.json'
    local original = f.files[path]
    f.generic['192.0.2.10'] = 7
    f.lock_busy = true
    assert(f:request('/clean_btwaf_drop_ip').status == false)
    assert(f.files[path] == original and f.writes == 0)
    assert(f.generic['192.0.2.10'] == 7 and #f:request('/get_btwaf_drop_ip') == 2)
    local inode = f.lock_files[path .. '.lock']
    f.lock_busy = false
    assert(f:request('/clean_btwaf_drop_ip').status == true)
    assert(f.lock_files[path .. '.lock'] == inode, 'lock inode was replaced after contention')
end

function tests.atomic_rename_failure_keeps_original_json_and_runtime_bans()
    local f = fixture({exact_rule(12)})
    local path = root .. 'rule/ip_black.json'
    local original = f.files[path]
    f.generic['192.0.2.10'] = 7
    f.fail_rename = true
    assert(f:request('/clean_btwaf_drop_ip').status == false)
    assert(f.files[path] == original and f.renames == nil)
    assert(f.generic['192.0.2.10'] == 7 and #f:request('/get_btwaf_drop_ip') == 2)
    for name in pairs(f.files) do assert(name:sub(-4) ~= '.tmp', 'failed publish leaked a temporary file') end
    local inode = f.lock_files[path .. '.lock']
    f.fail_rename = false
    assert(f:request('/clean_btwaf_drop_ip').status == true)
    assert(f.lock_files[path .. '.lock'] == inode)
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
    for key in pairs(f.shared) do assert(key == 'repeat:v1:revision', 'security state survived cleanup: '..key) end
    assert(next(f.generic) == nil)
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
            local path = root .. 'rule/ip_black.json'
            local original = f.files[path]
            local response = f:request('/clean_btwaf_drop_ip')
            assert(response.status == false, stage .. ' failure incorrectly reported success')
            assert(f.close_attempts == 1, 'write failure must still close its file')
            assert(f.files[path] == original, 'failed staged write changed committed JSON')
            for name in pairs(f.files) do assert(name:sub(-4) ~= '.tmp', 'failed write leaked a temporary file') end
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
