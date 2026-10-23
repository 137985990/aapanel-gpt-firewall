-- Production helpers with memory-only clock, storage and shared dictionaries.
local source = assert(rawget(_G, 'WAF_RUNTIME_SOURCE'))
local json = require 'cjson'
local now, passed, failures = 100000, 0, {}
local function check(name, fn)
    local ok, err = pcall(fn)
    if ok then passed = passed + 1
    else failures[#failures+1] = 'FAIL ' .. name .. ': ' .. tostring(err) end
end
local function dictionary()
    local values, deadlines = {}, {}
    local d = {}
    function d:get(k)
        if deadlines[k] and deadlines[k] <= now then values[k] = nil end
        return values[k]
    end
    function d:safe_set(k,v,ttl)
        if self.full then return nil,'no memory' end
        values[k],deadlines[k]=v,ttl and now+ttl
        return true
    end
    function d:safe_add(k,v,ttl)
        if self:get(k) ~= nil then return nil,'exists' end
        return self:safe_set(k,v,ttl)
    end
    d.set, d.add = d.safe_set, d.safe_add
    function d:incr(k,n)
        local value=self:get(k); if value==nil then return nil,'not found' end
        return self:safe_set(k,value+n) and value+n
    end
    function d:delete(k) values[k],deadlines[k]=nil,nil end
    function d:get_keys()
        local keys={}; for k in pairs(values) do if self:get(k)~=nil then keys[#keys+1]=k end end
        return keys
    end
    return d
end
local function fixture(kernel)
    now=100000
    local f={files={},drops={},logs={},reads=0,writes=0,cache={}}
    kernel=kernel or {next_fd=10,descriptors={},opens=0,closes=0}
    f.kernel=kernel
    local env=setmetatable({}, {__index=_G})
    env.config={open=true,cc={status=403}}
    env.site_config={['fixture.example']={open=true,repeat_ban_policy={enabled=true,window_seconds=86400,
        tiers={{threshold=5,ban_seconds=604800},{threshold=10,ban_seconds=2592000}}}},
        ['other.example']={open=true}}
    env.json, env.cpath, env.repeat_ban_cache=json,'/fixture/',f.cache
    env.ip,env.server_name,env.uri='192.0.2.1','fixture.example','/login'
    env.ngx={header={},shared={free_waf=dictionary(),free_waf_drop_ip=dictionary()},
        time=function() return now end,now=function() return now+0.01 end,
        worker={pid=function() return 123 end},WARN=4,
        log=function(_,msg) f.logs[#f.logs+1]=msg end,
        md5=function(s) local h=5381; for i=1,#s do h=(h*33+s:byte(i))%2147483647 end; return string.format('%032x',h) end}
    local ffi={os='Linux',arch='x64',C={}}
    f.ffi=ffi
    function ffi.cdef() if f.cdef_failure then error('ffi declaration unavailable') end end
    function ffi.new(_,value) return value end
    function ffi.C.open(path,flags,mode)
        assert(path==env.cpath..'.repeat-bans.lock','unexpected lock path')
        assert(flags==655426,'lock must use Linux O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC')
        assert(mode==384,'lock mode must be 0600')
        kernel.opens=kernel.opens+1
        if f.open_failure or f.symlink_lock then return -1 end
        local fd=kernel.next_fd; kernel.next_fd=fd+1; kernel.descriptors[fd]=true
        return fd
    end
    function ffi.C.flock(fd,operation)
        assert(kernel.descriptors[fd] and operation==6,'lock must be exclusive and nonblocking')
        if kernel.held or f.flock_failure then return -1 end
        kernel.held=fd; return 0
    end
    function ffi.C.close(fd)
        assert(kernel.descriptors[fd],'closing an unknown descriptor')
        kernel.descriptors[fd]=nil; kernel.closes=kernel.closes+1
        if kernel.held==fd then kernel.held=nil end
        return 0
    end
    env.require=function(name)
        assert(name=='ffi','unexpected module')
        if f.no_ffi then error('ffi unavailable') end
        return ffi
    end
    env.io={open=function(path,mode)
        if mode=='rb' then
            f.reads=f.reads+1
            if f.files[path]==nil then return nil,'missing',2 end
            return {read=function(_,size) return string.sub(f.files[path],1,size) end,close=function() return true end}
        end
        assert(mode=='wb','unexpected IO mode '..tostring(mode))
        f.writes=f.writes+1
        if f.write_failure then return nil,'disk full',28 end
        local content=''
        return {write=function(_,data) content=content..data; f.files[path]=content; return true end,
            flush=function() if f.flush_failure then return nil end; return true end,
            close=function() return true end}
    end}
    env.os={rename=function(a,b)
        if f.rename_failure then return nil,'rename failed' end
        f.files[b],f.files[a]=f.files[a],nil; return true
    end,remove=function(path)
        assert(path~=env.cpath..'.repeat-bans.lock','never unlink the fixed lock inode')
        f.files[path]=nil; return true
    end,time=function() return now end}
    env.write_drop_ip_entry=function(...) f.drops[#f.drops+1]={...}; return true end
    env.return_html=function() error({status=403}) end
    env.other_html='fixture'
    env.uri_request_args={}
    local helpers={'is_runtime_ban_ipv4','is_runtime_ban_ip','endpoint_normalize_ip','trim_string',
        'get_return_state','repeat_ban_policy','repeat_ban_state_key','repeat_ban_state_identity',
        'repeat_ban_valid_record','repeat_ban_snapshot','repeat_ban_lock','repeat_ban_unlock',
        'repeat_ban_write','repeat_ban_warning','repeat_ban_event','repeat_ban_rows',
        'repeat_ban_guard','repeat_ban_clear','remove_repeat_ban'}
    for _,name in ipairs(helpers) do
        local start=source:find('function '..name..'%(')
        assert(start,'missing production helper: '..name)
        local finish=source:find('\nfunction ',start+1)
        local chunk=source:sub(start,finish and finish-1 or #source)
        local fn=assert(loadstring('local config,site_config,json,cpath,repeat_ban_cache = config,site_config,json,cpath,repeat_ban_cache\n'..chunk,'@'..name))
        setfenv(fn,env); fn()
    end
    f.env=env
    function f:event(site,ip,seconds,reason)
        return env.repeat_ban_event(site or 'fixture.example',ip or '192.0.2.1',seconds or 60,reason or 'cc','/login')
    end
    function f:next_event() now=now+61; return self:event() end
    function f:rows(site) return env.repeat_ban_rows(site) end
    function f:restart()
        for key in pairs(f.cache) do f.cache[key]=nil end
        env.ngx.shared.free_waf=dictionary()
    end
    return f
end
check('policy absence and disabled never creates state or touches disk',function()
    local f=fixture(); f.env.site_config['fixture.example'].repeat_ban_policy=nil
    for _=1,30 do assert(not f:next_event()) end
    assert(f.reads==0 and f.writes==0 and #f.env.ngx.shared.free_waf:get_keys()==0)
end)
check('strict policy validation',function()
    local invalid={false,{enabled=true,window_seconds=86400,tiers={}},
        {enabled=true,window_seconds=0,tiers={{threshold=5,ban_seconds=604800}}},
        {enabled=true,window_seconds=86400,tiers={{threshold=10,ban_seconds=604800},{threshold=5,ban_seconds=2592000}}},
        {enabled=true,window_seconds=86400,tiers={{threshold=5,ban_seconds=2592000},{threshold=10,ban_seconds=604800}}}}
    for _,policy in ipairs(invalid) do
        local f=fixture(); f.env.site_config['fixture.example'].repeat_ban_policy=policy
        assert(not f:event()); assert(f.writes==0)
    end
end)
check('fifth distinct ban persists seven days only for that site',function()
    local f=fixture()
    for _=1,4 do assert(not f:next_event()) end
    assert(f:next_event())
    local rows=f:rows('fixture.example'); assert(#rows==1)
    assert(rows[1].duration==604800 and rows[1].expires_at==now+604800)
    assert(rows[1].threshold==5 and rows[1].trigger_count==5)
    assert(#f:rows('other.example')==0)
    assert(#f.drops==1 and f.drops[1][5]=='repeat_ban')
end)
check('non-ASCII path bytes are escaped before persisting evidence',function()
    for _,path in ipairs({'/login/'..string.char(255,128),'/login/'..string.char(194,133),'/login/'..string.char(228,184,173)}) do
        local f=fixture()
        for _=1,4 do f:next_event() end
        now=now+61
        assert(f.env.repeat_ban_event('fixture.example','192.0.2.1',60,'cc',path))
        local stored=f:rows()[1].path
        assert(not string.find(stored,'[\127-\255]'),'unsafe path bytes in snapshot')
        assert(string.find(stored,'%%'),'escaped evidence was lost')
        f:restart(); assert(f:rows()[1].path==stored)
    end
end)
check('oversized escaped paths are replaced with a safe root evidence path',function()
    local f=fixture(); for _=1,4 do f:next_event() end
    now=now+61
    assert(f.env.repeat_ban_event('fixture.example','192.0.2.1',60,'cc','/'..string.rep(string.char(255),180)))
    assert(f:rows()[1].path=='/')
end)
check('overlapping automatic bans and retries count once',function()
    local f=fixture()
    for _=1,100 do assert(not f:event()) end
    assert(#f:rows('fixture.example')==0)
    for _=1,3 do assert(not f:next_event()) end
    assert(f:next_event())
end)
check('deduplication outlives a rolling window shorter than the original ban',function()
    local f=fixture(); local first=now
    f.env.site_config['fixture.example'].repeat_ban_policy={enabled=true,window_seconds=60,
        tiers={{threshold=2,ban_seconds=604800}}}
    assert(not f:event(nil,nil,28800,'endpoint_limit'))
    now=first+61; assert(not f:event(nil,nil,1,'endpoint_limit'))
    now=first+63
    assert(not f:event(nil,nil,1,'endpoint_limit'),'overlapping bans were counted after history TTL expired')
    assert(#f:rows()==0)
    now=first+28800; assert(not f:event(nil,nil,1,'endpoint_limit'))
    now=now+2; assert(f:event(nil,nil,1,'endpoint_limit'),'distinct bans after exact expiry must count')
end)
check('a longer overlapping ban refreshes the deduplication TTL',function()
    local f=fixture(); local first=now
    local policy=f.env.site_config['fixture.example'].repeat_ban_policy
    policy.window_seconds=60
    assert(not f:event(nil,nil,1,'endpoint_limit'))
    assert(not f:event(nil,nil,28800,'endpoint_limit'))
    now=first+61; assert(not f:event(nil,nil,1,'endpoint_limit'))
    local key=f.env.repeat_ban_state_key('fixture.example','192.0.2.1',policy)
    local raw=assert(f.env.ngx.shared.free_waf:get(key),'deduplication state expired')
    local history=json.decode(raw)
    assert(#history.events==1 and history.events[1]==first,'overlap added an event')
end)
check('different sites never combine their histories',function()
    local f=fixture(); f.env.site_config['other.example'].repeat_ban_policy=f.env.site_config['fixture.example'].repeat_ban_policy
    for _=1,4 do now=now+61; assert(not f:event()); assert(not f:event('other.example')) end
    assert(#f:rows()==0); now=now+61; assert(f:event('other.example'))
    assert(#f:rows('fixture.example')==0 and #f:rows('other.example')==1)
end)
check('rolling window expires exact boundary rather than midnight',function()
    local f=fixture(); local first=now
    assert(not f:event()); for _=1,3 do assert(not f:next_event()) end
    now=first+86400; assert(not f:event())
    assert(#f:rows()==0)
    now=now+60; assert(f:event())
end)
check('highest matching configured tier takes precedence',function()
    local f=fixture()
    local policy=f.env.site_config['fixture.example'].repeat_ban_policy
    -- A higher threshold can be reached in a fresh configuration with no earlier tier.
    policy.tiers={{threshold=10,ban_seconds=2592000}}
    for _=1,9 do assert(not f:next_event()) end
    assert(f:next_event()); assert(f:rows()[1].duration==2592000)
end)
check('manual and ordinary rule hits never count',function()
    for _,reason in ipairs({'manual_temp','ip_black','args','empty_ua','observe','reject','repeat_ban','unknown'}) do
        local f=fixture()
        for _=1,20 do now=now+61; assert(not f:event(nil,nil,60,reason)) end
        assert(f.writes==0)
    end
end)
check('canonical IPv6 identities cannot split event counts',function()
    local f=fixture()
    for i=1,5 do now=now+61; local hit=f:event(nil,i%2==0 and '2001:db8::1' or '2001:0db8:0:0:0:0:0:1'); assert(hit==(i==5)) end
    assert(f:rows()[1].ip=='2001:db8::1')
end)
check('a policy change starts a new counter identity',function()
    local f=fixture(); for _=1,4 do assert(not f:next_event()) end
    f.env.site_config['fixture.example'].repeat_ban_policy.window_seconds=3600
    assert(not f:next_event()); assert(#f:rows()==0)
end)
check('a running long ban is never extended or counted again',function()
    local f=fixture(); for _=1,5 do f:next_event() end
    local expiry=f:rows()[1].expires_at
    for _=1,20 do now=now+61; assert(not f:event()) end
    assert(f:rows()[1].expires_at==expiry and #f.drops==1)
end)
check('long bans survive a full worker/shared-memory restart',function()
    local f=fixture(); for _=1,5 do f:next_event() end
    f:restart(); assert(#f:rows('fixture.example')==1)
    local ok,value=pcall(f.env.repeat_ban_guard)
    assert(not ok and type(value)=='table' and value.status==403)
end)
check('the request guard uses an indexed snapshot rather than listing every ban',function()
    local f=fixture(); for _=1,5 do f:next_event() end
    f.env.repeat_ban_rows=function() error('per-request list scan') end
    local ok,value=pcall(f.env.repeat_ban_guard)
    assert(not ok and type(value)=='table' and value.status==403)
end)
check('missing revision and full memory cause at most one snapshot read per ten seconds',function()
    local f=fixture(); for _=1,5 do f:next_event() end
    local shared=f.env.ngx.shared.free_waf
    shared:delete('repeat:v1:revision'); shared.full=true
    now=now+10
    local reads=f.reads
    for _=1,100 do pcall(f.env.repeat_ban_guard) end
    assert(f.reads-reads==1,'missing revision caused per-request snapshot reads: '..(f.reads-reads))
    now=now+9; pcall(f.env.repeat_ban_guard); assert(f.reads-reads==1)
    now=now+1; pcall(f.env.repeat_ban_guard); assert(f.reads-reads==2)
end)
check('successful writes update the local cache even without a revision hint',function()
    local f=fixture(); local shared=f.env.ngx.shared.free_waf
    local safe_set=shared.safe_set
    function shared:safe_set(key,...)
        if key=='repeat:v1:revision' then return nil,'no memory' end
        return safe_set(self,key,...)
    end
    function shared:safe_add(key,...)
        if key=='repeat:v1:revision' then return nil,'no memory' end
        if self:get(key)~=nil then return nil,'exists' end
        return self:safe_set(key,...)
    end
    for _=1,5 do f:next_event() end
    local reads=f.reads
    local ok,value=pcall(f.env.repeat_ban_guard)
    assert(not ok and type(value)=='table' and value.status==403)
    assert(f.reads==reads,'writer did not use its fresh local snapshot')
end)
check('disabled strategy stops enforcement without erasing its records',function()
    local f=fixture(); for _=1,5 do f:next_event() end
    f.env.site_config['fixture.example'].repeat_ban_policy.enabled=false
    assert(not f.env.repeat_ban_guard())
    assert(#f:rows('fixture.example')==1)
end)
check('expiry boundary is inactive and not renewed by a read',function()
    local f=fixture(); for _=1,5 do f:next_event() end
    now=f:rows()[1].expires_at
    assert(#f:rows()==0 and not f.env.repeat_ban_guard())
end)
check('disk write flush or rename failure cannot invent a long ban',function()
    for _,failure in ipairs({'write_failure','flush_failure','rename_failure'}) do
        local f=fixture(); f[failure]=true
        for _=1,5 do assert(not f:next_event()) end
        assert(#f:rows()==0 and #f.drops==0)
        assert(f.files['/fixture/repeat_bans.json']==nil)
    end
end)
check('corrupt and oversized snapshots never become new bans',function()
    for _,content in ipairs({'broken','[]',string.rep('x',1048577)}) do
        local f=fixture(); f.files['/fixture/repeat_bans.json']=content
        for _=1,5 do assert(not f:next_event()) end
        local rows=f:rows(); assert(rows==nil or #rows==0)
        assert(#f.drops==0 and f.writes==0)
    end
end)
check('busy or full shared memory cannot escalate or evict existing counters',function()
    local f=fixture(); local owner=assert(f.env.repeat_ban_lock())
    assert(not f:event()); assert(f.writes==0)
    f.env.repeat_ban_unlock(owner)
    f=fixture(); f.env.ngx.shared.free_waf.full=true
    for _=1,5 do assert(not f:next_event()) end
    assert(f.writes==0)
end)
check('writer exclusion survives shared-memory eviction until rename completes',function()
    local a=fixture(); local b=fixture(a.kernel)
    b.files=a.files; b.env.ngx.shared.free_waf=a.env.ngx.shared.free_waf
    b.env.ngx.worker.pid=function() return 456 end
    for _=1,5 do a:next_event() end
    for _=1,4 do now=now+61; a:event(nil,'192.0.2.2') end
    local rename=a.env.os.rename
    local competing_unban
    a.env.os.rename=function(from,to)
        -- Enter precisely after the old ownership check and before the commit.
        a.env.ngx.shared.free_waf:delete('repeat:v1:lock')
        now=now+31
        competing_unban=b.env.repeat_ban_clear({['192.0.2.1']=true})
        return rename(from,to)
    end
    now=now+61; assert(a:event(nil,'192.0.2.2'))
    assert(competing_unban==false,'a competing writer reported successful unban before the first rename')
    assert(b.env.repeat_ban_clear({['192.0.2.1']=true}))
    local rows=b:rows()
    assert(#rows==1 and rows[1].ip=='192.0.2.2','successful unban was overwritten')
end)
check('absent optional state does not require FFI to clear legacy bans',function()
    local f=fixture(); f.no_ffi=true
    f.env.site_config['fixture.example'].repeat_ban_policy=nil
    assert(f.env.repeat_ban_clear({['192.0.2.1']=true}))
    assert(f.kernel.opens==0 and f.writes==0 and f.cache.lock_ffi==nil)
    f.env.ngx.shared.free_waf.full=true
    assert(f.env.repeat_ban_clear({['192.0.2.1']=true},nil,true))
    assert(f.kernel.opens==0 and f.writes==0 and f.cache.lock_ffi==nil)
end)
check('disabled persisted state cannot be silently skipped when FFI is unavailable',function()
    local f=fixture(); for _=1,5 do f:next_event() end
    local snapshot=f.files['/fixture/repeat_bans.json']
    f.env.site_config['fixture.example'].repeat_ban_policy.enabled=false
    f:restart(); f.no_ffi=true
    assert(not f.env.repeat_ban_clear({['192.0.2.1']=true}))
    assert(f.files['/fixture/repeat_bans.json']==snapshot and #f:rows()==1)
    assert(#f.logs>0)
end)
check('disabled history-only state cannot be silently skipped when FFI is unavailable',function()
    local f=fixture(); assert(not f:next_event())
    local policy=f.env.site_config['fixture.example'].repeat_ban_policy
    local key=f.env.repeat_ban_state_key('fixture.example','192.0.2.1',policy)
    local history=assert(f.env.ngx.shared.free_waf:get(key))
    policy.enabled=false; f.no_ffi=true; f.cache.lock_ffi=nil
    assert(not f.env.repeat_ban_clear({['192.0.2.1']=true},nil,true))
    assert(f.env.ngx.shared.free_waf:get(key)==history and #f.logs>0)
end)
check('enabled empty state cannot bypass an in-flight writer lock',function()
    local writer=fixture(); local clearing=fixture(writer.kernel)
    clearing.files=writer.files
    clearing.env.ngx.shared.free_waf=writer.env.ngx.shared.free_waf
    clearing.no_ffi=true
    local owner=assert(writer.env.repeat_ban_lock())
    assert(not clearing.env.repeat_ban_clear({['192.0.2.1']=true}),
        'an enabled policy must not turn an uncommitted event into no-op success')
    assert(writer.kernel.held==owner.fd and writer.writes==0)
    writer.env.repeat_ban_unlock(owner)
end)
check('each acquisition has a new descriptor and failures close their descriptors',function()
    local f=fixture(); local first=assert(f.env.repeat_ban_lock())
    assert(not f.env.repeat_ban_lock(),'separate opens must contend within one worker')
    f.env.repeat_ban_unlock(first)
    local second=assert(f.env.repeat_ban_lock())
    f.env.repeat_ban_unlock(second)
    assert(f.kernel.opens==3 and f.kernel.closes==3 and next(f.kernel.descriptors)==nil)
    for _,failure in ipairs({'open_failure','flock_failure','no_ffi','cdef_failure'}) do
        f=fixture(); f[failure]=true
        assert(not f:event(),'optional lock failure must not create a ban')
        assert(f.writes==0 and next(f.kernel.descriptors)==nil and #f.logs>0)
    end
    for _,platform in ipairs({{'Windows','x64'},{'Linux','mips'}}) do
        f=fixture(); f.ffi.os,f.ffi.arch=platform[1],platform[2]
        assert(not f:event() and f.kernel.opens==0 and #f.logs>0)
    end
end)
check('lock symlinks are refused without writing a snapshot',function()
    local f=fixture(); f.symlink_lock=true
    assert(not f:event()); assert(f.writes==0 and #f.logs>0)
end)
check('record validation rejects UTF-8 C1 controls but permits non-control UTF-8',function()
    local f=fixture(); for _=1,5 do f:next_event() end
    local row=f:rows()[1]
    for code=128,159 do
        row.path='/'..string.char(194,code)
        assert(not f.env.repeat_ban_valid_record(row),'accepted C1 code point '..code)
    end
    row.path='/'..string.char(194,160)
    assert(f.env.repeat_ban_valid_record(row),'non-control UTF-8 was rejected')
end)
check('site-specific unban preserves the selected rolling count',function()
    local f=fixture(); f.env.site_config['other.example'].repeat_ban_policy=f.env.site_config['fixture.example'].repeat_ban_policy
    for _=1,5 do now=now+61; f:event(); f:event('other.example') end
    f.env.uri_request_args={site='fixture.example',ip='192.0.2.1'}
    assert(f.env.remove_repeat_ban().status==true)
    assert(#f:rows('fixture.example')==0 and #f:rows('other.example')==1)
    assert(f:next_event())
    assert(f:rows('fixture.example')[1].trigger_count==6)
end)
check('a tenth independent ban after early manual release selects thirty days',function()
    local f=fixture()
    for _=1,5 do f:next_event() end
    for count=6,10 do
        f.env.uri_request_args={site='fixture.example',ip='192.0.2.1'}
        assert(f.env.remove_repeat_ban().status)
        assert(f:next_event())
        local row=f:rows()[1]
        assert(row.trigger_count==count)
        assert(row.duration==(count==10 and 2592000 or 604800))
    end
end)
check('explicit unban and reset clears count as well as the long ban',function()
    local f=fixture(); for _=1,5 do f:next_event() end
    f.env.uri_request_args={site='fixture.example',ip='192.0.2.1',reset_counts='1'}
    assert(f.env.remove_repeat_ban().status)
    assert(#f:rows()==0 and not f:next_event())
end)
check('failed unban persistence reports failure and keeps the ban',function()
    local f=fixture(); for _=1,5 do f:next_event() end
    f.rename_failure=true; f.env.uri_request_args={site='fixture.example',ip='192.0.2.1'}
    assert(f.env.remove_repeat_ban().status==false)
    assert(#f:rows('fixture.example')==1)
end)
check('global unban clears all scopes including disabled records',function()
    local f=fixture(); f.env.site_config['other.example'].repeat_ban_policy=f.env.site_config['fixture.example'].repeat_ban_policy
    for _=1,5 do now=now+61; f:event(); f:event('other.example') end
    assert(f.env.repeat_ban_clear({['192.0.2.1']=true},nil,true))
    assert(#f:rows()==0 and not f:next_event())
end)
assert(#failures==0,table.concat(failures,'\n'))
io.write('repeat_ban_checks='..passed..' isolated_fixture=true\n')
