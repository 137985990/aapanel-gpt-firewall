-- Real production helpers; all filesystem, FFI and Nginx state is in memory.
local source = assert(WAF_RUNTIME_SOURCE)
assert(loadstring(source, '@init.lua'))
local checks, failures = 0, {}
local function check(name, run)
    local ok, err = pcall(run)
    checks = checks + 1
    if not ok then failures[#failures+1] = name .. ': ' .. tostring(err) end
end

-- Token codec avoids requiring a separately installed cjson in embedded LuaJIT.
local objects, serial = {}, 0
local function copy(value)
    if type(value) ~= 'table' then return value end
    local out = {}; for k,v in pairs(value) do out[k] = copy(v) end; return out
end
local json = {}
function json.encode(value)
    serial = serial + 1
    local token = type(value)=='table' and #value==2 and type(value[1])=='string' and type(value[2])=='string'
        and ('fixture-identity:'..value[1]..':'..value[2]) or ('fixture-json-' .. serial)
    objects[token] = copy(value)
    return token
end
function json.decode(token)
    if token == '[]' then return {} end
    assert(objects[token], 'invalid fixture JSON')
    return copy(objects[token])
end
local function dictionary()
    local values, d = {}, {}
    function d:get(key) return values[key] end
    function d:safe_add(key, value)
        if values[key] ~= nil then return nil, 'exists' end
        if self.full then return nil, 'no memory' end
        values[key] = value; return true
    end
    function d:safe_set(key, value)
        if self.full then return nil, 'no memory' end
        values[key] = value; return true
    end
    function d:incr(key, delta)
        if values[key] == nil then return nil, 'not found' end
        values[key] = values[key] + delta; return values[key]
    end
    function d:delete(key) values[key] = nil end
    function d:get_keys()
        local keys = {}; for key in pairs(values) do keys[#keys+1] = key end; return keys
    end
    d.add, d.set = d.safe_add, d.safe_set
    return d
end
local function fixture(kernel)
    kernel = kernel or {files={}, locks={}, descriptors={}, metadata={}, next_fd=10, next_inode=1}
    local f = {kernel=kernel, reads=0, writes=0, timers={}, cache={}, total_state={}, now=1000}
    local env = setmetatable({}, {__index=_G})
    env.cpath, env.jpath, env.json = '/fixture/', '/fixture/rule/', json
    env.repeat_ban_cache, env.total_log_state = f.cache, f.total_state
    env.site_config = {fixture={url_rule={}}}
    env.config, env.server_name, env.uri = {other={status=403}}, 'fixture', '/form'
    env.method, env.request_header, env.uri_request_args = 'POST', {}, {}
    env.ip_black_rules = {}
    env.AUTO_BAN_SECONDS, env.MAX_AUTO_BAN_SECONDS = 28800, 28800
    env.ngx_match = function() return true end
    env.is_ngx_match = function() return false end
    env.is_json_request = function() return f.is_json or false end
    env.write_log, env.return_html = function() end, function() f.blocked = true end
    env.write_to_file, env.is_site_config = function() return true end, function() return true end
    env.ip, env.request_uri, env.retry_cycle = '192.0.2.1', '/form', 60
    env.repeat_ban_clear = function() return true end
    env.registration_state_ambiguous = function() return false end
    env.repeat_ban_rows, env.get_btwaf_drop_ip = function() return {} end, function() return {} end
    env.repeat_ban_state_identity, env.endpoint_state_ip = function() end, function() end
    env.clear_registration_state = function() f.registration_cleared=true end
    env.clear_endpoint_state = function() f.endpoint_cleared=true end
    env.get_return_state = function(status, msg) return {status=status, msg=msg} end
    env.is_ipaddr = function() return true end
    env.arrip = function(ip)
        local out = {}; for n in ip:gmatch('%d+') do out[#out+1] = tonumber(n) end; return out
    end
    env.encode_json_array = function(rows) return #rows == 0 and '[]' or json.encode(rows) end
    env.ngx = {shared={free_waf=dictionary(), free_waf_drop_ip=dictionary()}, WARN=4, worker={pid=function() return 7 end},
        var={http_user_agent='fixture'}, localtime=function() return 'fixture-time' end,
        time=function() return f.now end, now=function() return f.now end,
        md5=function() serial=serial+1; return string.format('%032x', serial) end,
        log=function() end, timer={at=function(_, callback)
            if f.timer_failure then return nil, 'timer unavailable' end
            f.timers[#f.timers+1] = callback; return true
        end}, req={get_method=function() return env.method end,
            read_body=function() f.body_reads=(f.body_reads or 0)+1 end,
            get_body_data=function() return f.body end,
            get_body_file=function() return f.body_file end,
            get_post_args=function() f.form_reads=(f.form_reads or 0)+1; return {field='needle'} end}}
    local function metadata(path)
        if not kernel.metadata[path] then
            kernel.metadata[path]={dev=1,ino=kernel.next_inode,nlink=1,mode=32768+384,uid=1000,gid=1000}
            kernel.next_inode=kernel.next_inode+1
        end
        return kernel.metadata[path]
    end
    local ffi = {os='Linux', arch='x64', C={}, cdef=function() end,
        errno=function() return f.errno or 2 end,
        new=function(kind,v) if kind=='struct gpt_fw_stat[1]' then return {[0]={}} end; return v end}
    function ffi.C.open(path, flags, mode)
        if flags==655426 then
            assert(mode==384 and path:match('%.lock$'), 'must reuse repeat_bans open protocol')
            if f.lock_failure then return -1 end
            kernel.files[path]=kernel.files[path] or ''
        elseif flags==657408 then
            if kernel.files[path]==nil then f.errno=2; return -1 end
        else
            assert(flags==655553 and mode==384 and path:match('%.tmp$'), 'temporary must be exclusive and private')
            if f.write_failure then return -1 end
            if kernel.files[path]~=nil then f.errno=17; return -1 end
            f.writes=f.writes+1; kernel.files[path]=''
        end
        metadata(path)
        local fd = kernel.next_fd; kernel.next_fd = fd+1
        kernel.descriptors[fd] = path; return fd
    end
    function ffi.C.gpt_fw_fstat(fd,buffer)
        local row=metadata(assert(kernel.descriptors[fd]))
        for key,value in pairs(row) do buffer[0][key]=value end
        return 0
    end
    function ffi.C.gpt_fw_fchmod(fd,mode)
        if f.metadata_failure then return -1 end
        metadata(assert(kernel.descriptors[fd])).mode=32768+mode; return 0
    end
    function ffi.C.gpt_fw_fchown(fd,uid,gid)
        if f.metadata_failure then return -1 end
        local row=metadata(assert(kernel.descriptors[fd])); row.uid,row.gid=uid,gid; return 0
    end
    function ffi.C.gpt_fw_write(fd,body,size)
        local path=assert(kernel.descriptors[fd])
        if f.write_stage=='write' then return -1 end
        local count=f.partial_write and math.min(3,size) or size
        kernel.files[path]=kernel.files[path]..body:sub(1,count); return count
    end
    function ffi.C.gpt_fw_fsync(fd) return f.write_stage=='flush' and -1 or 0 end
    function ffi.C.flock(fd, operation)
        assert(operation == 6, 'request locks must not block')
        local path = assert(kernel.descriptors[fd])
        if kernel.locks[path] then return -1 end
        kernel.locks[path] = fd; return 0
    end
    function ffi.C.close(fd)
        local path = assert(kernel.descriptors[fd])
        if kernel.locks[path] == fd then kernel.locks[path] = nil end
        kernel.descriptors[fd] = nil
        return path:match('%.tmp$') and f.write_stage=='close' and -1 or 0
    end
    env.require = function(name) assert(name=='ffi'); return ffi end
    env.io = {open=function(path, mode)
        if mode == 'r' or mode == 'rb' then
            f.reads=f.reads+1
            if (f.read_failure and path=='/fixture/total.json') or path==f.denied_path then
                return nil, 'fixture read failure', 13
            end
            local body=kernel.files[path]
            if body == nil then return nil, 'missing', 2 end
            if f.on_read then f.on_read(path) end
            return {read=function() return body end, close=function() return true end}
        end
        f.writes=f.writes+1
        if f.write_failure then return nil, 'disk full' end
        kernel.files[path]=''
        return {write=function(_,body)
            kernel.files[path]=body
            if f.write_stage=='write' then return nil end
            return true
        end, flush=function() return f.write_stage~='flush' end,
            close=function() return f.write_stage~='close' end}
    end}
    env.os = {time=function() return f.now end, rename=function(a,b)
        if f.on_rename then f.on_rename(a,b) end
        if f.rename_failure then return nil end
        kernel.metadata[b],kernel.metadata[a]=kernel.metadata[a],nil
        kernel.files[b],kernel.files[a]=kernel.files[a],nil; return true
    end, remove=function(path)
        assert(not path:match('%.lock$'), 'never unlink lock inode')
        kernel.files[path],kernel.metadata[path]=nil,nil; return true
    end}
    local helpers = {'read_file','read_file_body','write_file','runtime_file_stat','runtime_lock_metadata','repeat_ban_lock','repeat_ban_unlock',
        'runtime_atomic_write','with_ip_black_lock','total_log_path','total_log_warning','total_log_schedule',
        'total_log_flush','total_log_worker_init','inc_log','write_log','url_rule_ex','add_ip_black_exact',
        'remove_permanent_ban_ip','clean_btwaf_drop_ip'}
    for _,name in ipairs(helpers) do
        local start = source:find('function '..name..'%(')
        if start then
            local finish = assert(source:find('\nend', start+1))
            local fn = assert(loadstring('local cpath,jpath,json,config,site_config,repeat_ban_cache,total_log_state=cpath,jpath,json,config,site_config,repeat_ban_cache,total_log_state\n' .. source:sub(start,finish+3), '@'..name))
            setfenv(fn,env); fn()
        end
    end
    f.env=env
    function f:flush()
        local pending=self.timers; self.timers={}
        for _,callback in ipairs(pending) do callback(false) end
    end
    return f
end

check('R03 empty rules never read a chunked POST', function()
    local f=fixture()
    assert(f.env.url_rule_ex()==false)
    assert(not f.body_reads and not f.form_reads)
end)
check('R03 bounded unknown-length form remains inspectable', function()
    local f=fixture(); f.env.site_config.fixture.url_rule={{'.*','needle'}}
    f.body='field=needle'
    assert(f.env.url_rule_ex()==false)
    assert(f.form_reads==1)
end)
check('R03 enabled form rules still block bounded POST bodies', function()
    for _,length in ipairs({'missing','12'}) do
        local f=fixture(); f.env.site_config.fixture.url_rule={{'.*','needle'}}
        f.body='field=needle'
        if length~='missing' then f.env.request_header['content-length']=length end
        f.env.is_ngx_match=function(_,_,kind) return kind=='post' end
        assert(f.env.url_rule_ex()==true and f.blocked)
    end
end)
check('R03 JSON and disk-backed unknown body skip form parsing', function()
    for _,kind in ipairs({'json','disk','large','malformed-length'}) do
        local f=fixture(); f.env.site_config.fixture.url_rule={{'.*','needle'}}
        if kind=='json' then f.is_json=true; f.env.request_header['content-type']='application/json'
        elseif kind=='disk' then f.body_file='/fixture/body'
        elseif kind=='large' then f.body=string.rep('x',65536)
        else f.env.request_header['content-length']='invalid' end
        assert(f.env.url_rule_ex()==false)
        assert(not f.form_reads, 'unsafe form parsing: '..kind)
    end
end)
check('R07 competing Lua writer cannot read an old ban snapshot', function()
    local a=fixture(); local b=fixture(a.kernel)
    a.kernel.files['/fixture/rule/ip_black.json']='[]'
    local competing
    a.on_read=function(path)
        if path=='/fixture/rule/ip_black.json' then a.on_read=nil; competing=b.env.add_ip_black_exact('192.0.2.2',60) end
    end
    assert(a.env.add_ip_black_exact('192.0.2.1',60))
    assert(competing==false, 'competing writer was not excluded')
    assert(b.env.add_ip_black_exact('192.0.2.2',60))
    assert(#json.decode(a.kernel.files['/fixture/rule/ip_black.json'])==2)
end)
check('R07 every atomic write failure leaves blacklist and cache intact', function()
    for _,stage in ipairs({'open','write','flush','close','rename'}) do
        local f=fixture(); f.kernel.files['/fixture/rule/ip_black.json']='[]'
        if stage=='open' then f.write_failure=true
        elseif stage=='rename' then f.rename_failure=true
        else f.write_stage=stage end
        assert(f.env.add_ip_black_exact('192.0.2.1',60)==false, stage..' reported success')
        assert(f.kernel.files['/fixture/rule/ip_black.json']=='[]', stage..' destroyed durable rules')
        assert(#f.env.ip_black_rules==0)
        assert(next(f.kernel.locks)==nil and next(f.kernel.descriptors)==nil)
    end
end)
check('R07 metadata failure cannot replace or expose a private file', function()
    local f=fixture(); f.kernel.files['/fixture/rule/ip_black.json']='[]'
    local owner=assert(f.env.repeat_ban_lock('/fixture/rule/ip_black.json.lock'))
    f.metadata_failure=true
    assert(f.env.runtime_atomic_write('/fixture/rule/ip_black.json','changed',owner)==false)
    f.env.repeat_ban_unlock(owner)
    assert(f.kernel.files['/fixture/rule/ip_black.json']=='[]')
    assert(next(f.kernel.descriptors)==nil)
end)
check('R07 partial syscalls are accumulated before atomic publication', function()
    local f=fixture(); f.kernel.files['/fixture/rule/ip_black.json']='[]'; f.partial_write=true
    assert(f.env.add_ip_black_exact('192.0.2.1',60))
    assert(#json.decode(f.kernel.files['/fixture/rule/ip_black.json'])==1)
end)
check('R07 unban failure cannot report success', function()
    local f=fixture(); local ip={192,0,2,1}
    local old=json.encode({{ip,ip,1060}})
    f.kernel.files['/fixture/rule/ip_black.json']=old
    f.env.uri_request_args.ip='192.0.2.1'; f.rename_failure=true
    assert(f.env.remove_permanent_ban_ip().status==false)
    assert(f.kernel.files['/fixture/rule/ip_black.json']==old)
end)
check('R07 bulk clean persists under the same lock and retains ranges', function()
    local f=fixture(); local b=fixture(f.kernel); local ip={192,0,2,1}
    local range={{198,51,100,0},{198,51,100,255}}
    f.kernel.files['/fixture/rule/ip_black.json']=json.encode({{ip,ip,1060},range})
    f.env.get_btwaf_drop_ip=function() return {'192.0.2.1'} end
    f.on_read=function(path)
        if path=='/fixture/rule/ip_black.json' then
            f.on_read=nil
            assert(b.env.add_ip_black_exact('192.0.2.2',60)==false)
        end
    end
    assert(f.env.clean_btwaf_drop_ip().status==true)
    local rows=json.decode(f.kernel.files['/fixture/rule/ip_black.json'])
    assert(#rows==1 and rows[1][1][1]==198 and f.registration_cleared and f.endpoint_cleared)
end)
check('R07 failed bulk save never clears runtime bans', function()
    local f=fixture(); local ip={192,0,2,1}
    local old=json.encode({{ip,ip,1060}})
    f.kernel.files['/fixture/rule/ip_black.json']=old; f.rename_failure=true
    f.env.get_btwaf_drop_ip=function() return {'192.0.2.1'} end
    assert(f.env.clean_btwaf_drop_ip().status==false)
    assert(f.kernel.files['/fixture/rule/ip_black.json']==old)
    assert(not f.registration_cleared and not f.endpoint_cleared)
end)
check('R08 request counting has no disk IO and folds simultaneous workers', function()
    local a=fixture(); local b=fixture(a.kernel)
    b.env.ngx.shared.free_waf=a.env.ngx.shared.free_waf
    a.kernel.files['/fixture/total.json']=json.encode({total=5,sites={},rules={}})
    a.env.inc_log('post','regular'); b.env.inc_log('post','regular')
    assert(a.reads==0 and b.reads==0 and a.writes==0 and b.writes==0, 'request performed statistics IO')
    a:flush(); b:flush()
    local total=json.decode(a.kernel.files['/fixture/total.json'])
    assert(total.total==7 and total.sites.fixture.post==2 and total.rules.post==2)
    assert(#a.timers==0 and #b.timers==0, 'idle workers must stop statistics timers')
end)
check('R08 migrated statistics uses only the dedicated data file and lock', function()
    local f=fixture(); local legacy='/fixture/total.json'; local path='/fixture/.statistics/total.json'
    local original=json.encode({total=5,sites={},rules={}})
    f.kernel.files[legacy]=original
    f.kernel.files[path]=json.encode({total=80,sites={},rules={}})
    f.env.inc_log('post','regular'); f:flush()
    assert(json.decode(f.kernel.files[path]).total==81, 'new statistics path was not used')
    assert(f.kernel.files[legacy]==original, 'legacy statistics must not be dual-written')
    assert(f.kernel.files[path..'.lock'] and not f.kernel.files[legacy..'.lock'], 'wrong statistics lock')
end)
check('R08 corrupt migrated statistics never falls back and retains pending', function()
    local f=fixture(); local legacy='/fixture/total.json'; local path='/fixture/.statistics/total.json'
    local original=json.encode({total=5,sites={},rules={}})
    f.kernel.files[legacy]=original; f.kernel.files[path]='{broken'
    assert(f.env.inc_log('post','regular')); f:flush()
    assert(f.kernel.files[path]=='{broken' and f.kernel.files[legacy]==original, 'corruption fell back or overwrote data')
    f.kernel.files[path]=json.encode({total=80,sites={},rules={}}); f:flush()
    assert(json.decode(f.kernel.files[path]).total==81, 'pending increment was lost')
    assert(f.kernel.files[legacy]==original and not f.kernel.files[legacy..'.lock'])
end)
check('R08 unreadable migrated statistics is not treated as missing', function()
    local f=fixture(); local legacy='/fixture/total.json'; local path='/fixture/.statistics/total.json'
    local original=json.encode({total=5,sites={},rules={}})
    f.kernel.files[legacy]=original
    f.kernel.files[path]=json.encode({total=80,sites={},rules={}}); f.denied_path=path
    f.env.inc_log('post','regular'); f:flush()
    assert(f.kernel.files[legacy]==original and not f.kernel.files[legacy..'.lock'], 'read denial used legacy path')
    f.denied_path=nil; f:flush()
    assert(json.decode(f.kernel.files[path]).total==81)
end)
check('R08 missing migrated statistics keeps legacy compatibility', function()
    local f=fixture(); local path='/fixture/total.json'
    f.kernel.files[path]=json.encode({total=5,sites={},rules={}})
    f.env.inc_log('post','regular'); f:flush()
    assert(json.decode(f.kernel.files[path]).total==6 and f.kernel.files[path..'.lock'])
    assert(not f.kernel.files['/fixture/.statistics/total.json'], 'runtime must not migrate or dual-write')
end)
check('R08 malformed total cannot escape or discard pending increments', function()
    local f=fixture(); f.kernel.files['/fixture/total.json']='{broken'
    assert(pcall(f.env.inc_log,'post','regular'))
    assert(pcall(function() f:flush() end))
    assert(f.kernel.files['/fixture/total.json']=='{broken')
    f.kernel.files['/fixture/total.json']=json.encode({total=8,sites={},rules={}})
    f:flush()
    assert(json.decode(f.kernel.files['/fixture/total.json']).total==9)
end)
check('R08 new worker adopts premature timers without a new request', function()
    local old=fixture(); old.kernel.files['/fixture/total.json']=json.encode({total=80,sites={},rules={}})
    old.env.inc_log('post','regular')
    for _,callback in ipairs(old.timers) do callback(true) end
    local fresh=fixture(old.kernel)
    fresh.env.ngx.shared.free_waf=old.env.ngx.shared.free_waf
    assert(fresh.env.total_log_worker_init())
    assert(fresh.env.total_log_worker_init() and #fresh.timers==1, 'takeover must schedule only once per worker')
    fresh:flush()
    assert(json.decode(fresh.kernel.files['/fixture/total.json']).total==81)
    assert(#fresh.timers==0, 'idle takeover timer must stop')
    assert(fresh.env.total_log_worker_init() and #fresh.timers==0, 'ordinary requests must not restart idle timers')
end)
check('R08 failed worker takeover can retry without changing protection', function()
    local f=fixture(); f.timer_failure=true
    assert(f.env.total_log_worker_init()==false)
    f.timer_failure=false
    assert(f.env.total_log_worker_init() and #f.timers==1)
end)
check('R08 increments arriving during atomic commit survive subtraction', function()
    local f=fixture(); f.kernel.files['/fixture/total.json']=json.encode({total=0,sites={},rules={}})
    f.env.inc_log('post','regular')
    f.on_rename=function() f.on_rename=nil; f.env.inc_log('post','regular') end
    f:flush(); f:flush()
    assert(json.decode(f.kernel.files['/fixture/total.json']).total==2)
end)
check('R08 failed rename retries without double counting', function()
    local f=fixture(); local old=json.encode({total=4,sites={},rules={}})
    f.kernel.files['/fixture/total.json']=old; f.rename_failure=true
    f.env.inc_log('post','regular'); f:flush()
    assert(f.kernel.files['/fixture/total.json']==old)
    f.rename_failure=false; f:flush(); f:flush()
    assert(json.decode(f.kernel.files['/fixture/total.json']).total==5)
end)
check('R08 successful rename is not replayed if a later read fails', function()
    local f=fixture(); f.kernel.files['/fixture/total.json']=json.encode({total=4,sites={},rules={}})
    f.env.inc_log('post','regular')
    f.on_rename=function() f.on_rename=nil; f.read_failure=true end
    f:flush(); f.read_failure=false; f:flush()
    assert(json.decode(f.kernel.files['/fixture/total.json']).total==5, 'committed delta replayed')
end)
check('R08 shared memory and timer errors never escape into protection', function()
    for _,kind in ipairs({'full','timer','lock'}) do
        local f=fixture()
        f.env.ngx.shared.free_waf.full=kind=='full'
        f.timer_failure=kind=='timer'; f.lock_failure=kind=='lock'
        assert(pcall(f.env.inc_log,'post','regular'))
        assert(pcall(function() f:flush() end))
    end
end)
check('R08 actual write_log cannot prevent the configured blocking response', function()
    for _,failure in ipairs({'corrupt','full','timer'}) do
        local f=fixture(); f.env.config.log=true
        f.env.site_config.fixture.url_rule={{'.*','needle'}}
        f.env.is_ngx_match=function() return true end
        f.kernel.files['/fixture/total.json']='{broken'
        f.env.ngx.shared.free_waf.full=failure=='full'
        f.timer_failure=failure=='timer'
        local ok,result=pcall(f.env.url_rule_ex)
        assert(ok and result==true and f.blocked, failure..' changed protection result')
        assert(pcall(function() f:flush() end))
    end
end)
for _,message in ipairs(failures) do print('FAIL '..message) end
print('review_runtime_checks='..checks..' failures='..#failures..' isolated_fixture=true')
assert(#failures==0, table.concat(failures,'\n'))
