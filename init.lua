--[[
	免费WAF 功能比较少
	
]]--
local cpath = "/www/server/free_waf/"
local jpath = cpath .. "rule/"
local json = require "cjson"
local ngx_match = ngx.re.find
error_rule = nil
AUTO_BAN_SECONDS = 28800
MAX_AUTO_BAN_SECONDS = 28800

function read_file(name)
    fbody = read_file_body(jpath .. name .. '.json')
    if fbody == nil then
        return {}
    end
    return json.decode(fbody)
end

function read_file_body(filename)
	fp = io.open(filename,'r')
	if fp == nil then
        return nil
    end
	fbody = fp:read("*a")
    fp:close()
    if fbody == '' then
        return nil
    end
	return fbody
end

function write_file(filename,body)
	local fp = io.open(filename,'w')
	if fp == nil then
        return nil
    end
	local written = fp:write(body)
	local flushed = fp:flush()
	local closed = fp:close()
	return not not (written and flushed and closed)
end

local config_body = read_file_body(cpath .. 'config.json')
local site_body = read_file_body(cpath .. 'site.json')
local config = json.decode(config_body)
local site_config = json.decode(site_body)
local repeat_ban_cache = {}
local manual_site_ban_state = {}
local total_log_state = {}
local other_html

function manual_site_ban_normalize_ip(value)
	local address=endpoint_normalize_ip(value)
	if not address then return nil end
	-- Match the Python scoped store without changing legacy global key protocols.
	local high,low=string.match(address,'^::ffff:(%x+):(%x+)$')
	if not high then return address end
	high,low=tonumber(high,16),tonumber(low,16)
	return string.format('%d.%d.%d.%d',math.floor(high/256),high%256,math.floor(low/256),low%256)
end

function manual_site_ban_valid_record(row)
	if type(row) ~= 'table' then return false end
	local allowed = {site=true,ip=true,started_at=true,expires_at=true,duration=true,reason=true,evidence_hash=true}
	local count = 0
	for key in pairs(row) do if not allowed[key] then return false end; count=count+1 end
	if count ~= 7 then return false end
	if type(row.site) ~= 'string' or #row.site < 1 or #row.site > 253 or not string.match(row.site,'^[%w_-][%w_.-]*$') or string.find(row.site,'..',1,true) then return false end
	if type(row.ip) ~= 'string' or manual_site_ban_normalize_ip(row.ip) ~= row.ip then return false end
	for _,key in ipairs({'started_at','expires_at','duration'}) do
		local value = row[key]
		if type(value) ~= 'number' or value ~= value or value ~= math.floor(value) or value < 1 or value > 9007199254740991 then return false end
	end
	if row.duration < 60 or row.duration > 315360000 or row.expires_at-row.started_at ~= row.duration then return false end
	return row.reason == 'risk_advice' and type(row.evidence_hash) == 'string' and #row.evidence_hash == 64 and string.match(row.evidence_hash,'^[0-9a-f]+$') ~= nil
end

function manual_site_ban_decode(body)
	if type(body) ~= 'string' or #body > 1048576 then return nil,'size_limit' end
	local ok,value = pcall(json.decode,body)
	if not ok or type(value) ~= 'table' or value.version ~= 1 or type(value.revision) ~= 'string' or #value.revision ~= 32 or not string.match(value.revision,'^[0-9a-f]+$') or type(value.entries) ~= 'table' or #value.entries > 4096 then return nil,'invalid_snapshot' end
	local fields = 0
	for key in pairs(value) do if key ~= 'version' and key ~= 'revision' and key ~= 'entries' then return nil,'invalid_snapshot' end; fields=fields+1 end
	if fields ~= 3 then return nil,'invalid_snapshot' end
	-- cjson erases duplicate keys and the distinction between [] and {}. Check the
	-- bounded, shallow wire shape as well, including escaped duplicate field names.
	local position = 1
	local function skip() local _,last=string.find(body,'^%s*',position); position=(last or position-1)+1 end
	local function token(character)
		skip()
		if string.sub(body,position,position) ~= character then return false end
		position=position+1; return true
	end
	local function quoted()
		skip()
		if string.sub(body,position,position) ~= '"' then return nil end
		local start=position; position=position+1
		while position <= #body do
			local character=string.sub(body,position,position)
			if character == '\\' then position=position+2
			elseif character == '"' then
				position=position+1
				local valid,result=pcall(json.decode,string.sub(body,start,position-1))
				return valid and result or nil
			else position=position+1 end
		end
	end
	local function scalar(integer)
		skip()
		local character=string.sub(body,position,position)
		if character == '"' then return not integer and quoted() ~= nil end
		if character == '{' or character == '[' then return false end
		local start=position
		position=string.find(body,'[,%]}%s]',position) or (#body+1)
		return position > start and (not integer or string.match(string.sub(body,start,position-1),'^%d+$') ~= nil)
	end
	local object,array
	object=function(root)
		if not token('{') then return false end
		local seen={}
		skip()
		if token('}') then return true end
		while true do
			local key=quoted()
			if type(key) ~= 'string' or seen[key] or not token(':') then return false end
			seen[key]=true
			if root and key == 'entries' then
				if not array() then return false end
			elseif not scalar(root and key == 'version' or not root and (key == 'started_at' or key == 'expires_at' or key == 'duration')) then return false end
			if token('}') then return true end
			if not token(',') then return false end
		end
	end
	array=function()
		if not token('[') then return false end
		if token(']') then return true end
		local count=0
		while true do
			count=count+1
			if count > 4096 or not object(false) then return false end
			if token(']') then return true end
			if not token(',') then return false end
		end
	end
	if not object(true) then return nil,'invalid_shape' end
	skip()
	if position <= #body then return nil,'invalid_shape' end
	local seen,count={},0
	for key,row in pairs(value.entries) do
		if type(key) ~= 'number' or key < 1 or key > #value.entries or key ~= math.floor(key) or not manual_site_ban_valid_record(row) then return nil,'invalid_record' end
		local identity=row.site .. '\0' .. row.ip
		if seen[identity] then return nil,'duplicate_record' end
		seen[identity],count=true,count+1
	end
	if count ~= #value.entries then return nil,'invalid_snapshot' end
	return value
end

function manual_site_ban_read()
	local available,ffi=pcall(require,'ffi')
	if not available or ffi.os ~= 'Linux' or (ffi.arch ~= 'x64' and ffi.arch ~= 'arm64') then return nil,'read_unsupported' end
	local prefix=ffi.arch == 'x64'
		and 'unsigned long dev,ino,nlink; unsigned int mode,uid,gid;'
		or 'unsigned long dev,ino; unsigned int mode,nlink,uid,gid;'
	local declared=pcall(ffi.cdef,'struct gpt_fw_manual_stat { ' .. prefix .. [[ unsigned char tail[256]; };
		int gpt_fw_manual_open(const char *path, int flags, ...) __asm__("open");
		int gpt_fw_manual_openat(int dirfd, const char *path, int flags, ...) __asm__("openat");
		int gpt_fw_manual_fstat(int fd, void *buf) __asm__("fstat");
		long gpt_fw_manual_read(int fd, void *buf, unsigned long count) __asm__("read");
		int gpt_fw_manual_close(int fd) __asm__("close");
	]])
	if not declared then return nil,'read_unsupported' end
	local directory,descriptor
	local function close()
		if descriptor then ffi.C.gpt_fw_manual_close(descriptor); descriptor=nil end
		if directory then ffi.C.gpt_fw_manual_close(directory); directory=nil end
	end
	local checked,body,err=pcall(function()
		if string.sub(cpath,1,1) ~= '/' then return nil,'unsafe_directory' end
		-- Pin every path component; no links, worker-writable parent, or writable
		-- snapshot may supply a manual ban. Never create/chmod/chown anything here.
		directory=ffi.C.gpt_fw_manual_open('/',720896) -- O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC
		if directory < 0 then directory=nil; return nil,'read_failed' end
		for part in string.gmatch(cpath,'[^/]+') do
			if part == '.' or part == '..' then return nil,'unsafe_directory' end
			local child=ffi.C.gpt_fw_manual_openat(directory,part,720896)
			if child < 0 then return nil,'unsafe_directory' end
			ffi.C.gpt_fw_manual_close(directory); directory=child
		end
		local metadata=ffi.new('struct gpt_fw_manual_stat[1]')
		if ffi.C.gpt_fw_manual_fstat(directory,metadata) ~= 0 then return nil,'read_failed' end
		local parent=metadata[0]
		local function writable(mode) return math.floor(mode/16)%2 == 1 or math.floor(mode/2)%2 == 1 end
		if tonumber(parent.uid) ~= 0 or math.floor(tonumber(parent.mode)/4096) ~= 4 or writable(tonumber(parent.mode)) then return nil,'unsafe_directory' end
		descriptor=ffi.C.gpt_fw_manual_openat(directory,'manual_site_bans.json',657408) -- O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC
		if descriptor < 0 then
			descriptor=nil
			return nil,ffi.errno() == 2 and 'missing' or 'read_failed'
		end
		if ffi.C.gpt_fw_manual_fstat(descriptor,metadata) ~= 0 then return nil,'read_failed' end
		local file=metadata[0]
		if tonumber(file.uid) ~= 0 or tonumber(file.nlink) ~= 1 or math.floor(tonumber(file.mode)/4096) ~= 8 or writable(tonumber(file.mode)) then return nil,'unsafe_file' end
		local buffer=ffi.new('char[?]',1048577)
		local size=0
		while size <= 1048576 do
			local count=tonumber(ffi.C.gpt_fw_manual_read(descriptor,buffer+size,1048577-size))
			if count < 0 then return nil,'read_failed' end
			if count == 0 then return ffi.string(buffer,size) end
			size=size+count
		end
		return nil,'size_limit'
	end)
	close()
	if not checked then return nil,'read_failed' end
	return body,err
end

function manual_site_ban_load(policy_signature)
	local checked,body,err=pcall(manual_site_ban_read)
	local value
	if checked and err == 'missing' then
		value={version=1,revision=string.rep('0',32),entries={}}
	elseif checked and body then
		value,err=manual_site_ban_decode(body)
	end
	manual_site_ban_state={valid=value ~= nil,snapshot=value,by_site={},policy_signature=policy_signature}
	if not value then
		if ngx.log then ngx.log(ngx.WARN,'GPT Firewall manual site-ban snapshot unavailable: ' .. tostring(err or 'read_failed')) end
		return false
	end
	for _,row in ipairs(value.entries) do
		manual_site_ban_state.by_site[row.site]=manual_site_ban_state.by_site[row.site] or {}
		manual_site_ban_state.by_site[row.site][row.ip]=row
	end
	return true
end

function manual_site_ban_guard()
	if not manual_site_ban_state.valid then return false end
	local by_ip=manual_site_ban_state.by_site[server_name]
	local address=by_ip and manual_site_ban_normalize_ip(ip)
	local row=address and by_ip[address]
	local now=ngx.time()
	if not row or row.started_at > now or row.expires_at <= now then return false end
	ngx.header['Retry-After']=tostring(row.expires_at-now)
	ngx.header['Cache-Control']='no-store'
	ngx.header.content_type='text/plain; charset=utf-8'
	ngx.status=403
	ngx.say('Forbidden')
	ngx.exit(403)
	return true
end

function get_manual_site_bans()
	local state=manual_site_ban_state
	return {status=state.valid,valid=state.valid,policy_signature=state.policy_signature,
		revision=state.valid and state.snapshot.revision or json.null,
		entries=state.valid and state.snapshot.entries or json.null}
end

function manual_site_ban_response()
	local view=get_manual_site_bans()
	local entries=view.entries
	view.entries=nil
	local prefix=json.encode(view)
	ngx.header.content_type='application/json;'
	ngx.header['Cache-Control']='no-store'
	ngx.status=200
	ngx.say(string.sub(prefix,1,-2) .. ',"entries":' .. (view.valid and encode_json_array(entries) or 'null') .. '}')
	ngx.exit(200)
end

function repeat_ban_policy(site)
	local current = site_config[site]
	local policy = type(current) == 'table' and current.repeat_ban_policy
	if type(policy) ~= 'table' or policy.enabled ~= true then return nil end
	local policy_fields = 0
	for key in pairs(policy) do
		if key ~= 'enabled' and key ~= 'window_seconds' and key ~= 'tiers' then return nil end
		policy_fields = policy_fields+1
	end
	if policy_fields ~= 3 then return nil end
	local window = policy.window_seconds
	if type(window) ~= 'number' or window ~= math.floor(window) or window < 60 or window > 604800 then return nil end
	if type(policy.tiers) ~= 'table' or #policy.tiers < 1 or #policy.tiers > 8 then return nil end
	local tier_count = 0
	for key in pairs(policy.tiers) do
		if type(key) ~= 'number' or key ~= math.floor(key) or key < 1 or key > #policy.tiers then return nil end
		tier_count=tier_count+1
	end
	if tier_count ~= #policy.tiers then return nil end
	local previous_count, previous_seconds = 1, 0
	for _,tier in ipairs(policy.tiers) do
		if type(tier) ~= 'table' then return nil end
		local fields = 0
		for key in pairs(tier) do if key ~= 'threshold' and key ~= 'ban_seconds' then return nil end; fields=fields+1 end
		if fields ~= 2 then return nil end
		local count,seconds = tier.threshold,tier.ban_seconds
		if type(count) ~= 'number' or count ~= math.floor(count) or count <= previous_count or count > 1000 then return nil end
		if type(seconds) ~= 'number' or seconds ~= math.floor(seconds) or seconds < 60 or seconds <= previous_seconds or seconds > 31536000 then return nil end
		previous_count,previous_seconds = count,seconds
	end
	return policy
end

function repeat_ban_state_key(site, client_ip, policy)
	local identity = {policy.window_seconds}
	for _,tier in ipairs(policy.tiers) do identity[#identity+1] = {tier.threshold,tier.ban_seconds} end
	return 'repeat:v1:history:' .. #site .. ':' .. site .. ':' .. ngx.md5(json.encode(identity)) .. ':' .. client_ip
end

function repeat_ban_state_identity(key)
	if type(key) ~= 'string' then return nil end
	local length,rest = string.match(key,'^repeat:v1:history:(%d+):(.*)$')
	length = tonumber(length)
	if not length or length < 1 or length > 253 or string.sub(rest,length+1,length+1) ~= ':' then return nil end
	local site = string.sub(rest,1,length)
	local revision,client_ip = string.match(string.sub(rest,length+2),'^([0-9a-f]+):(.*)$')
	if not revision or #revision ~= 32 then return nil end
	client_ip = endpoint_normalize_ip(client_ip)
	if not client_ip then return nil end
	return site,client_ip
end

function repeat_ban_valid_record(row)
	if type(row) ~= 'table' then return false end
	local allowed = {site=true,ip=true,started_at=true,expires_at=true,duration=true,trigger_count=true,
		window_seconds=true,threshold=true,reason=true,path=true}
	local keys = 0
	for name in pairs(row) do if not allowed[name] then return false end; keys=keys+1 end
	if keys ~= 10 then return false end
	if type(row.site) ~= 'string' or #row.site < 1 or #row.site > 253 or not string.match(row.site,'^[%w_-][%w_.-]*$') or string.find(row.site,'..',1,true) then return false end
	if not endpoint_normalize_ip(row.ip) or endpoint_normalize_ip(row.ip) ~= row.ip then return false end
	for _,field in ipairs({'started_at','expires_at','duration','trigger_count','window_seconds','threshold'}) do
		local value = row[field]
		if type(value) ~= 'number' or value ~= value or value ~= math.floor(value) or value < 1 or value > 9007199254740991 then return false end
	end
	if row.duration < 60 or row.duration > 31536000 or row.expires_at-row.started_at ~= row.duration then return false end
	if row.window_seconds < 60 or row.window_seconds > 604800 or row.threshold < 2 or row.threshold > 1000 or row.trigger_count < row.threshold or row.trigger_count > 1000 then return false end
	local reasons = {cc=true,registration_abuse_verify=true,registration_abuse_register=true,endpoint_limit=true,['404_flood']=true}
	if not reasons[row.reason] then return false end
	if type(row.path) ~= 'string' or #row.path < 1 or #row.path > 512 or string.sub(row.path,1,1) ~= '/' or string.find(row.path,'[%c?#\\]') or string.find(row.path,'\194[\128-\159]') then return false end
	return true
end

function repeat_ban_snapshot(force)
	local shared,now = ngx.shared.free_waf,ngx.time()
	local revision = shared:get('repeat:v1:revision')
	if not force and repeat_ban_cache.snapshot and (revision == nil or revision == repeat_ban_cache.snapshot.revision) and now-(repeat_ban_cache.checked_at or 0) < 10 then
		return repeat_ban_cache.snapshot
	end
	local fp,err,code = io.open(cpath .. 'repeat_bans.json','rb')
	local snapshot
	if not fp then
		if code ~= 2 then return nil,'read_failed' end
		snapshot = {version=1,revision=string.rep('0',32),bans={}}
	else
		local body = fp:read(1048577)
		fp:close()
		if type(body) ~= 'string' or #body > 1048576 then return nil,'size_limit' end
		local ok,value = pcall(json.decode,body)
		if not ok or type(value) ~= 'table' or value.version ~= 1 or type(value.revision) ~= 'string' or #value.revision ~= 32 or not string.match(value.revision,'^[0-9a-f]+$') or type(value.bans) ~= 'table' or #value.bans > 4096 then return nil,'invalid_snapshot' end
		local fields = 0
		for key in pairs(value) do if key ~= 'version' and key ~= 'revision' and key ~= 'bans' then return nil,'invalid_snapshot' end; fields=fields+1 end
		if fields ~= 3 then return nil,'invalid_snapshot' end
		local seen,count = {},0
		for key,row in pairs(value.bans) do
			if type(key) ~= 'number' or key < 1 or key > #value.bans or key ~= math.floor(key) or not repeat_ban_valid_record(row) then return nil,'invalid_record' end
			local identity = row.site .. '\0' .. row.ip
			if seen[identity] then return nil,'duplicate_record' end
			seen[identity],count = true,count+1
		end
		if count ~= #value.bans then return nil,'invalid_snapshot' end
		snapshot = value
	end
	local by_site = {}
	for _,row in ipairs(snapshot.bans) do
		by_site[row.site] = by_site[row.site] or {}
		by_site[row.site][row.ip] = row
	end
	repeat_ban_cache.snapshot,repeat_ban_cache.checked_at,repeat_ban_cache.by_site = snapshot,now,by_site
	shared:safe_add('repeat:v1:revision',snapshot.revision)
	return snapshot
end

function runtime_file_stat(owner,path)
	local ffi = owner.ffi
	if not repeat_ban_cache.metadata_ready then
		-- Only the stable Linux x64/arm64 stat prefix is read; reserve its full tail.
		local prefix = ffi.arch == 'x64'
			and 'unsigned long dev,ino,nlink; unsigned int mode,uid,gid;'
			or 'unsigned long dev,ino; unsigned int mode,nlink,uid,gid;'
		local declared = pcall(ffi.cdef,'struct gpt_fw_stat { ' .. prefix .. [[ unsigned char tail[256]; };
			int gpt_fw_fstat(int fd, void *buf) __asm__("fstat");
			int gpt_fw_fchmod(int fd, unsigned int mode) __asm__("fchmod");
			int gpt_fw_fchown(int fd, unsigned int uid, unsigned int gid) __asm__("fchown");
			long gpt_fw_write(int fd, const void *buf, unsigned long count) __asm__("write");
			int gpt_fw_fsync(int fd) __asm__("fsync");
		]])
		if not declared then return nil end
		repeat_ban_cache.metadata_ready = true
	end
	local fd,opened = path,false
	if type(path) == 'string' then
		fd = ffi.C.open(path,657408) -- O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC
		if fd < 0 then return nil,ffi.errno() end
		opened = true
	end
	local buffer = ffi.new('struct gpt_fw_stat[1]')
	local ok = ffi.C.gpt_fw_fstat(fd,buffer) == 0
	if opened then ffi.C.close(fd) end
	if not ok or math.floor(tonumber(buffer[0].mode)/4096) ~= 8 then return nil end
	local row = buffer[0]
	return {dev=tostring(row.dev),ino=tostring(row.ino),nlink=tonumber(row.nlink),
		mode=tonumber(row.mode)%4096,uid=tonumber(row.uid),gid=tonumber(row.gid)}
end

function runtime_lock_metadata(owner,path)
	local metadata,err = runtime_file_stat(owner,path)
	if not metadata then return err == 2 end
	local current = runtime_file_stat(owner,owner.fd)
	if not current or current.nlink ~= 1 then return false end
	local mode = 384 + (math.floor(metadata.mode/16)%2 == 1 and 48 or 0)
		+ (math.floor(metadata.mode/2)%2 == 1 and 6 or 0)
	local c = owner.ffi.C
	if (current.uid ~= metadata.uid or current.gid ~= metadata.gid)
		and c.gpt_fw_fchown(owner.fd,metadata.uid,metadata.gid) ~= 0 then return false end
	if current.mode ~= mode and c.gpt_fw_fchmod(owner.fd,mode) ~= 0 then return false end
	local verified,named = runtime_file_stat(owner,owner.fd),runtime_file_stat(owner,path .. '.lock')
	return verified and named and verified.uid == metadata.uid and verified.gid == metadata.gid
		and verified.mode == mode and verified.dev == named.dev and verified.ino == named.ino
end

function repeat_ban_lock(path)
	local ffi = repeat_ban_cache.lock_ffi
	if ffi == nil then
		local available,module = pcall(require,'ffi')
		if available and module.os == 'Linux' and (module.arch == 'x64' or module.arch == 'arm64') then
			local declared = pcall(module.cdef,[[
				int open(const char *pathname, int flags, ...);
				int flock(int fd, int operation);
				int close(int fd);
			]])
			if declared then ffi = module end
		end
		repeat_ban_cache.lock_ffi = ffi or false
	end
	if not ffi then return nil,'lock_unsupported' end
	local fd
	local ok,locked = pcall(function()
		-- Linux x64/arm64: O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, mode 0600.
		-- Open after worker fork on every acquisition; never unlink this inode.
		fd = ffi.C.open(path or (cpath .. '.repeat-bans.lock'),655426,ffi.new('unsigned int',384))
		if fd < 0 then fd=nil; return false end
		return ffi.C.flock(fd,6) == 0 -- LOCK_EX|LOCK_NB
	end)
	if not ok or not locked then
		if fd then pcall(function() ffi.C.close(fd) end) end
		return nil,'lock_failed'
	end
	local owner = {fd=fd,ffi=ffi}
	if path then
		local checked,valid = pcall(runtime_lock_metadata,owner,string.sub(path,1,-6))
		if not checked or not valid then repeat_ban_unlock(owner); return nil,'lock_metadata' end
	end
	return owner
end

function repeat_ban_unlock(owner)
	if owner and owner.fd then
		pcall(function() owner.ffi.C.close(owner.fd) end)
		owner.fd=nil
	end
end

function runtime_atomic_write(path, body, owner)
	if type(owner) ~= 'table' or not owner.fd then return false end
	local temporary = path .. '.' .. ngx.md5(body .. tostring(ngx.now()) .. tostring(ngx.worker.pid())) .. '.tmp'
	local fd,created
	local verified,result = pcall(function()
		local metadata,err = runtime_file_stat(owner,path)
		if not metadata and err ~= 2 then return false end
		-- O_EXCL prevents following/reusing a stale or attacker-chosen temporary inode.
		fd = owner.ffi.C.open(temporary,655553,owner.ffi.new('unsigned int',384))
		if fd < 0 then fd=nil; return false end
		created = true
		local current = runtime_file_stat(owner,fd)
		if not current then return false end
		local c = owner.ffi.C
		if metadata then
			if (current.uid ~= metadata.uid or current.gid ~= metadata.gid)
				and c.gpt_fw_fchown(fd,metadata.uid,metadata.gid) ~= 0 then return false end
		end
		local offset = 0
		while offset < #body do
			local count = tonumber(c.gpt_fw_write(fd,string.sub(body,offset+1),#body-offset))
			if not count or count <= 0 then return false end
			offset = offset+count
		end
		if metadata then
			if c.gpt_fw_fchmod(fd,metadata.mode) ~= 0 then return false end
			current = runtime_file_stat(owner,fd)
			if not current or current.uid ~= metadata.uid or current.gid ~= metadata.gid or current.mode ~= metadata.mode then return false end
		end
		if c.gpt_fw_fsync(fd) ~= 0 then return false end
		local closing = fd; fd=nil
		if c.close(closing) ~= 0 then return false end
		if read_file_body(temporary) ~= body then return false end
		local latest = runtime_file_stat(owner,path)
		if metadata and (not latest or latest.dev ~= metadata.dev or latest.ino ~= metadata.ino
			or latest.mode ~= metadata.mode or latest.uid ~= metadata.uid or latest.gid ~= metadata.gid) then return false end
		if not metadata and latest then return false end
		return not not os.rename(temporary,path)
	end)
	if fd then pcall(function() owner.ffi.C.close(fd) end) end
	if not verified or not result then if created then os.remove(temporary) end; return false end
	return true
end

function with_ip_black_lock(action)
	-- Shared with BanStore: rule/ip_black.json.lock is never renamed/unlinked.
	local owner = repeat_ban_lock(jpath .. 'ip_black.json.lock')
	if not owner then return false end
	local ok,result = pcall(action,owner)
	repeat_ban_unlock(owner)
	return ok,result
end

function repeat_ban_write(bans, owner)
	if type(owner) ~= 'table' or not owner.fd then return false,'lock_required' end
	if #bans > 4096 then return false,'row_limit' end
	local snapshot = {version=1,revision=ngx.md5(json.encode(bans) .. tostring(ngx.now()) .. tostring(ngx.worker.pid())),bans=bans}
	local array = #bans == 0 and '[]' or json.encode(bans)
	local body = '{"version":1,"revision":"' .. snapshot.revision .. '","bans":' .. array .. '}'
	if #body > 1048576 then return false,'size_limit' end
	local path = cpath .. '.repeat_bans.' .. snapshot.revision .. '.tmp'
	local fp = io.open(path,'wb')
	if not fp then return false,'write_failed' end
	local written = fp:write(body)
	local flushed = fp:flush()
	local closed = fp:close()
	if not written or not flushed or not closed then
		os.remove(path)
		return false,'write_failed'
	end
	if not os.rename(path,cpath .. 'repeat_bans.json') then os.remove(path); return false,'rename_failed' end
	-- The durable file is authoritative; eviction of this hint cannot revoke a ban.
	ngx.shared.free_waf:delete('repeat:v1:revision')
	ngx.shared.free_waf:safe_set('repeat:v1:revision',snapshot.revision)
	local by_site = {}
	for _,row in ipairs(bans) do
		by_site[row.site] = by_site[row.site] or {}
		by_site[row.site][row.ip] = row
	end
	repeat_ban_cache.snapshot,repeat_ban_cache.checked_at,repeat_ban_cache.by_site = snapshot,ngx.time(),by_site
	return true
end

function repeat_ban_warning(code)
	if ngx.shared.free_waf:safe_add('repeat:v1:warning',true,60) then
		ngx.log(ngx.WARN,'GPT Firewall repeat-ban escalation skipped: ' .. tostring(code))
	end
end

function repeat_ban_event(site, client_ip, seconds, reason, path)
	local policy = repeat_ban_policy(site)
	local reasons = {cc=true,registration_abuse_verify=true,registration_abuse_register=true,['404_flood']=true}
	if not policy or not reasons[reason] then return false end
	client_ip = endpoint_normalize_ip(client_ip)
	if not client_ip or type(site) ~= 'string' or #site > 253 or type(seconds) ~= 'number' or seconds < 1 or seconds > 28800 then return false end
	local owner,lock_error = repeat_ban_lock()
	if not owner then repeat_ban_warning(lock_error); return false end
	local ok,result = pcall(function()
		local shared,now = ngx.shared.free_waf,ngx.time()
		local snapshot,err = repeat_ban_snapshot(true)
		if not snapshot then repeat_ban_warning(err); return false end
		for _,row in ipairs(snapshot.bans) do
			if row.site == site and row.ip == client_ip and row.expires_at > now then return false end
		end
		local key = repeat_ban_state_key(site,client_ip,policy)
		local raw = shared:get(key)
		local history = {events={},until_time=0}
		if raw then
			local valid,value = pcall(json.decode,raw)
			if not valid or type(value) ~= 'table' or type(value.events) ~= 'table' or #value.events > 1000 or type(value.until_time) ~= 'number' then return false end
			history = value
		end
		if history.until_time > now then
			-- Overlapping scopes are not distinct bans, even if the second lasts longer.
			history.until_time = math.max(history.until_time,now+seconds)
			shared:safe_set(key,json.encode(history),math.max(policy.window_seconds,history.until_time-now))
			return false
		end
		local events = {}
		for _,stamp in ipairs(history.events) do
			if type(stamp) ~= 'number' or stamp ~= math.floor(stamp) then return false end
			if stamp > now-policy.window_seconds and stamp <= now then events[#events+1] = stamp end
		end
		events[#events+1] = now
		while #events > 1000 do table.remove(events,1) end
		if not shared:safe_set(key,json.encode({events=events,until_time=now+seconds}),math.max(policy.window_seconds,seconds)) then return false end
		local selected
		for _,tier in ipairs(policy.tiers) do if #events >= tier.threshold then selected=tier end end
		if not selected then return false end
		local bans = {}
		for _,row in ipairs(snapshot.bans) do if row.expires_at > now then bans[#bans+1] = row end end
		if type(path) ~= 'string' or #path < 1 or #path > 512 or string.sub(path,1,1) ~= '/' or string.find(path,'[%c?#\\]') then path='/' end
		-- URI bytes need not be valid UTF-8; keep durable evidence valid JSON text.
		path = string.gsub(path,'[\127-\255]',function(byte) return string.format('%%%02X',string.byte(byte)) end)
		if #path > 512 then path='/' end
		local record = {site=site,ip=client_ip,started_at=now,expires_at=now+selected.ban_seconds,duration=selected.ban_seconds,
			trigger_count=#events,window_seconds=policy.window_seconds,threshold=selected.threshold,reason=reason,path=path}
		if not repeat_ban_valid_record(record) then return false end
		bans[#bans+1] = record
		local saved,error_code = repeat_ban_write(bans,owner)
		if not saved then repeat_ban_warning(error_code); return false end
		write_drop_ip_entry(client_ip,site,path,selected.ban_seconds,'repeat_ban')
		return true
	end)
	repeat_ban_unlock(owner)
	if not ok then repeat_ban_warning('state_error'); return false end
	return result
end

function repeat_ban_rows(site)
	local snapshot,err = repeat_ban_snapshot(false)
	if not snapshot then return nil,err end
	local rows,now = {},ngx.time()
	for _,row in ipairs(snapshot.bans) do
		if row.expires_at > now and (not site or row.site == site) then rows[#rows+1] = row end
	end
	return rows
end

function repeat_ban_guard()
	if not repeat_ban_policy(server_name) then return false end
	local client_ip = endpoint_normalize_ip(ip)
	if not client_ip then return false end
	local snapshot,err = repeat_ban_snapshot(false)
	if not snapshot then repeat_ban_warning(err); return false end
	local entries = repeat_ban_cache.by_site[server_name]
	local row = entries and entries[client_ip]
	if row and row.expires_at > ngx.time() then
		ngx.header['Retry-After'] = tostring(row.expires_at-ngx.time())
		return_html(config['cc']['status'],other_html)
		return true
	end
	return false
end

function repeat_ban_clear(target_ips, site, reset_counts)
	local normalized = {}
	for value in pairs(target_ips) do local address=endpoint_normalize_ip(value); if address then normalized[address]=true end end
	local enabled = false
	for name in pairs(site_config) do if repeat_ban_policy(name) then enabled=true; break end end
	if not enabled then
		local snapshot = repeat_ban_snapshot(true)
		if not snapshot then return false end
		local has_state = #snapshot.bans > 0
		if not has_state then
			for _,key in ipairs(ngx.shared.free_waf:get_keys(0)) do
				if repeat_ban_state_identity(key) then has_state=true; break end
			end
		end
		-- An unused optional feature must not make legacy unban depend on FFI.
		if not has_state then return true end
	end
	local owner,lock_error = repeat_ban_lock()
	if not owner then repeat_ban_warning(lock_error); return false end
	local ok,result = pcall(function()
		local snapshot = repeat_ban_snapshot(true)
		if not snapshot then return false end
		local bans,changed,now = {},false,ngx.time()
		for _,row in ipairs(snapshot.bans) do
			if normalized[row.ip] and (not site or row.site==site) then changed=true
			elseif row.expires_at>now then bans[#bans+1]=row
			else changed=true end
		end
		if changed and not repeat_ban_write(bans,owner) then return false end
		for _,key in ipairs(ngx.shared.free_waf:get_keys(0)) do
			local state_site,address = repeat_ban_state_identity(key)
			if address and normalized[address] and (not site or state_site==site) then
				if reset_counts then ngx.shared.free_waf:delete(key)
				else
					local valid,history = pcall(json.decode,ngx.shared.free_waf:get(key) or '')
					if valid and type(history)=='table' and type(history.events)=='table' then
						history.until_time=0
						local policy=repeat_ban_policy(state_site)
						if not ngx.shared.free_waf:safe_set(key,json.encode(history),policy and policy.window_seconds or 604800) then return false end
					else ngx.shared.free_waf:delete(key) end
				end
			end
		end
		return true
	end)
	repeat_ban_unlock(owner)
	return ok and result == true
end

function remove_repeat_ban()
	local site = uri_request_args.site
	local address = endpoint_normalize_ip(uri_request_args.ip)
	if type(site) ~= 'string' or type(site_config[site]) ~= 'table' or not address then return get_return_state(false,'站点或IP不正确') end
	local reset = uri_request_args.reset_counts
	if reset ~= nil and reset ~= '0' and reset ~= '1' then return get_return_state(false,'清零选项不正确，未解封') end
	if not repeat_ban_clear({[address]=true},site,reset=='1') then return get_return_state(false,'升级封禁清理未完成，可能已部分处理，请检查后重试') end
	return get_return_state(true,reset=='1' and '该站点的升级封禁及其计数已清除；其他独立封禁不受影响' or '该站点的升级封禁已解除，窗口内计数保留；其他独立封禁不受影响')
end

function is_ipaddr(client_ip)
	local cipn = split(client_ip,'.')
	if arrlen(cipn) < 4 then return false end
	for _,v in ipairs({1,2,3,4})
	do
		local ipv = tonumber(cipn[v])
		if ipv == nil then return false end
		if ipv > 255 or ipv < 0 then return false end
	end
	return true
end

function compare_ip_block(ips)
	if not ips then return false end
	if string.find(ips,':') then return false end
	ips = arrip(ips)
	if not is_max(ips,arrip("127.0.0.255")) then return false end
	if not is_min(ips,arrip("127.0.0.1")) then return false end
	return true
end

function trim_string(value)
	value = tostring(value or "")
	return string.gsub(value, "^%s*(.-)%s*$", "%1")
end

function first_client_ip_from_header(header_value, order)
	if type(header_value) == "table" then header_value = header_value[1] end
	if type(header_value) ~= 'string' or header_value == "" then return nil end
	local parts = split_bylog(header_value, ',')
	local first, last, step = 1, #parts, 1
	if order == 'last' then first, last, step = #parts, 1, -1 end
	for index = first, last, step
	do
		local candidate = trim_string(parts[index])
		if string.match(candidate, '^%d+%.%d+%.%d+%.%d+$') and is_ipaddr(candidate) and not compare_ip_block(candidate) then
			return candidate
		end
	end
	return nil
end

function is_ip_in_range(client_ip, ip_range)
	if not client_ip or not ip_range then return false end
	if not is_ipaddr(client_ip) then return false end
	if arrlen(ip_range) < 2 then return false end
	local client_ipn = arrip(client_ip)
	if not is_max(client_ipn, ip_range[2]) then return false end
	if not is_min(client_ipn, ip_range[1]) then return false end
	return true
end

function is_trusted_cdn_proxy(site_conf)
	if not site_conf then return false end
	local trusted_proxy = site_conf['cdn_trusted_proxy']
	if not trusted_proxy or arrlen(trusted_proxy) == 0 then return true end
	local remote_addr = ngx.var.remote_addr
	if not remote_addr or remote_addr == "" then return false end
	for _,ip_range in ipairs(trusted_proxy)
	do
		if is_ip_in_range(remote_addr, ip_range) then return true end
	end
	return false
end

function get_client_ip()
	local client_ip = "unknown"
	if site_config[server_name] then
		if site_config[server_name]['cdn'] then
			if not is_trusted_cdn_proxy(site_config[server_name]) then
				client_ip = ngx.var.remote_addr
				if client_ip == nil then client_ip = "unknown" end
				return client_ip
			end
			for _,v in ipairs(site_config[server_name]['cdn_header'])
			do
				if request_header[v] ~= nil and request_header[v] ~= "" then
					local header_tmp = request_header[v]
					local candidate = first_client_ip_from_header(header_tmp, site_config[server_name]['cdn_header_order'])
					if candidate then
						client_ip = candidate
						break
					end
				end
			end
		end
	end
	if type(client_ip) == 'table' then client_ip = "" end
	if (string.match(client_ip,"^%d+%.%d+%.%d+%.%d+$") == nil and string.match(client_ip,"^[%w:]+$") == nil) or client_ip == 'unknown'  then
		client_ip = ngx.var.remote_addr
		if client_ip == nil then
			client_ip = "unknown"
		end
	end
	return client_ip
end

function split_bylog( str,reps )
	local resultStrList = {}
	string.gsub(str,'[^'..reps..']+',function(w)
		table.insert(resultStrList,w)
	end)
	return resultStrList
end


function get_client_ip22()
	local client_ip = "unknown"
	if site_config[server_name] then
		if site_config[server_name]['cdn'] then
			for _,v in ipairs(site_config[server_name]['cdn_header'])
			do
				if request_header[v] ~= nil and request_header[v] ~= "" then
					client_ip = request_header[v]
					break;
				end
			end	
		end
	end
	if (string.match(client_ip,"^%d+%.%d+%.%d+%.%d+$") == nil and string.match(client_ip,"^[%w:]+$") == nil) or client_ip == 'unknown'  then
		client_ip = ngx.var.remote_addr
		if client_ip == nil then
			client_ip = "unknown"
		end
	end
	return client_ip
end

function split( str,reps )
    local resultStrList = {}
    string.gsub(str,'[^'..reps..']+',function(w)
        table.insert(resultStrList,w)
    end)
    return resultStrList
end

function arrip(ipstr)
    if string.find(ipstr,':') then return ipstr end
	if ipstr == 'unknown' then return {0,0,0,0} end
	iparr = split(ipstr,'.')
	iparr[1] = tonumber(iparr[1])
	iparr[2] = tonumber(iparr[2])
	iparr[3] = tonumber(iparr[3])
	iparr[4] = tonumber(iparr[4])
	return iparr
end

function join(arr,e)
	result = ''
	length = arrlen(arr)
	for k,v in ipairs(arr)
	do
		if length == k then e = '' end
		result = result .. v .. e
	end
	return result
end

function arrlen(arr)
	if not arr then return 0 end
	count = 0
	for _,v in ipairs(arr)
	do
		count = count + 1
	end
	return count
end

function select_rule(rules)
	if not rules then return {} end
	local new_rules = {}
	for i,v in ipairs(rules)
	do 
		-- Site exceptions refer to the original zero-based rule offsets.
		new_rules[i] = ""
		if v[1] == 1 then
			new_rules[i] = v[2]
		end
	end
	return new_rules
end

function is_site_config(cname)
	if site_config[server_name] ~= nil then
		if cname == 'cc' then
			return site_config[server_name][cname]['open']
		else
			return site_config[server_name][cname]
		end
	end
	return true
end

function get_boundary()
    local header = request_header["content-type"]
    if not header then return nil end
    if type(header) == "table" then
        header = header[1]
    end

    local m = string.match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end
    return string.match(header, ";%s*boundary=([^\",;]+)")
end

function is_json_request()
	if not request_header then return false end
	local header = request_header["content-type"] or request_header["Content-Type"]
	if not header then return false end
	if type(header) == "table" then header = header[1] end
	header = string.lower(tostring(header or ""))
	if string.find(header, "application/json", 1, true) then return true end
	if string.find(header, "+json", 1, true) then return true end
	return false
end

function is_form_request()
	if not request_header then return false end
	local header = request_header['content-type'] or request_header['Content-Type']
	-- Preserve legacy headerless forms; explicit non-form bodies need their own parser.
	if header == nil then return true end
	local values = type(header) == 'table' and header or {header}
	-- Do not let first/last-header differences hide a declared form from inspection.
	for _,value in ipairs(values) do
		if type(value) == 'string' then
			local media_type = string.match(value, '^([^;]*)')
			media_type = string.match(media_type, '^%s*(.-)%s*$')
			if string.lower(media_type) == 'application/x-www-form-urlencoded' then return true end
		end
	end
	return false
end

local get_html = read_file_body(config["reqfile_path"] .. '/' .. config["get"]["reqfile"])
local post_html = read_file_body(config["reqfile_path"] .. '/' .. config["post"]["reqfile"])
local cookie_html = read_file_body(config["reqfile_path"] .. '/' .. config["cookie"]["reqfile"])
local user_agent_html = read_file_body(config["reqfile_path"] .. '/' .. config["user-agent"]["reqfile"])
other_html = read_file_body(config["reqfile_path"] .. '/' .. config["other"]["reqfile"])
local cnlist = json.decode(read_file_body(cpath .. '/rule/cn.json'))
local scan_black_rules = read_file('scan_black')
local ip_black_rules = read_file('ip_black')
local ip_white_body = read_file_body(jpath .. 'ip_white.json')
local ip_white_rules = ip_white_body and json.decode(ip_white_body) or {}
local url_white_rules = read_file('url_white')
local url_black_rules = read_file('url_black')
local user_agent_white_rules = select_rule(read_file('user_agent_white'))
local user_agent_rules = select_rule(read_file('user_agent'))
local header_rules = select_rule(read_file('header'))
local post_rules = select_rule(read_file('post'))
local cookie_rules = select_rule(read_file('cookie'))
local args_rules = select_rule(read_file('args'))
local url_rules = select_rule(read_file('url'))
local head_white_rules = read_file('head_white')

function is_min(ip1,ip2)
	
	n = 0
	for _,v in ipairs({1,2,3,4})
	do
		if ip1[v] == ip2[v] then
			n = n + 1
		elseif ip1[v] > ip2[v] then
			break
		else
			return false
		end
	end
	return true
end

function is_max(ip1,ip2)
	n = 0
	for _,v in ipairs({1,2,3,4})
	do
		if ip1[v] == ip2[v] then
			n = n + 1
		elseif ip1[v] < ip2[v] then
			break
		else
			return false
		end
	end
	return true
end

function compare_ip(ips)
	if ip == 'unknown' then return true end
	if string.find(ip,':') then return false end
	if not is_max(ipn,ips[2]) then return false end
	if not is_min(ipn,ips[1]) then return false end
	return true
end

function write_log(name,rule)
	local retry_key = 'retry_' .. ip
	local count,_ = ngx.shared.free_waf:get(retry_key)
	if count then
		count = ngx.shared.free_waf:incr(retry_key,1)
	else
		ngx.shared.free_waf:set(retry_key,1,retry_cycle)
		count = 1
	end
	if config['log'] ~= true or is_site_config('log') ~= true then return false end
	local method = ngx.req.get_method()
	if error_rule then 
		rule = error_rule
		error_rule = nil
	end
	
	local logtmp = {ngx.localtime(),ip,method,request_uri,ngx.var.http_user_agent,name,rule}
	local logstr = json.encode(logtmp) .. "\n"
	write_to_file(logstr)
	inc_log(name,rule)
end

function write_drop_ip_entry(client_ip, site_name, request_path, drop_time, reason)
	local filename = cpath .. 'drop_ip.log'
	local fp = io.open(filename,'ab')
	if fp == nil then return false end
	local logtmp = {os.time(),client_ip,site_name or '',request_path or '',drop_time,reason or 'auto'}
	local logstr = json.encode(logtmp) .. "\n"
	fp:write(logstr)
	fp:flush()
	fp:close()
	return true
end

function write_drop_ip(is_drop,drop_time)
	return write_drop_ip_entry(ip,server_name,request_uri,drop_time,is_drop)
end

function get_registration_guard_config(current_server_name)
	local host = string.lower(tostring(current_server_name or ""))
	local direct = site_config[current_server_name]
	if type(direct) == "table" then
		local guard = direct['registration_guard']
		if type(guard) == "table" and guard['open'] == true then
			return guard
		end
	end
	for _,site in pairs(site_config)
	do
		if type(site) == "table" then
			local guard = site['registration_guard']
			if type(guard) == "table" and guard['open'] == true and type(guard['aliases']) == "table" then
				for _,alias in ipairs(guard['aliases'])
				do
					if string.lower(tostring(alias)) == host then
						return guard
					end
				end
			end
		end
	end
	return nil
end

function registration_guard_path_matches(paths, current_uri)
	if type(paths) ~= "table" then return false end
	for _,pattern in ipairs(paths)
	do
		if type(pattern) == "string" and pattern ~= "" and ngx_match(current_uri, pattern, "ijo") then
			return true
		end
	end
	return false
end

function registration_guard(current_server_name, client_ip, current_method, current_uri, current_request_uri)
	local guard = get_registration_guard_config(current_server_name)
	if not guard then return false end
	local scope = trim_string(guard['scope'])
	if scope == "" or not is_runtime_ban_ip(client_ip) then return false end
	local shared = ngx.shared.free_waf
	local ban_key = registration_guard_state_key('ban', scope, client_ip)
	local legacy_ban_key = 'registration_guard:ban:' .. scope .. ':' .. client_ip
	if shared:get(ban_key) or shared:get(legacy_ban_key) then
		return_html(config['other']['status'], other_html)
		return true
	end
	if current_method ~= "POST" then return false end

	local counter_type = nil
	local limit = nil
	local window_seconds = nil
	if registration_guard_path_matches(guard['verify_paths'], current_uri) then
		counter_type = 'verify'
		limit = tonumber(guard['verify_limit'])
		window_seconds = tonumber(guard['verify_window'])
	elseif registration_guard_path_matches(guard['register_paths'], current_uri) then
		counter_type = 'register'
		limit = tonumber(guard['register_limit'])
		window_seconds = tonumber(guard['register_window'])
	else
		return false
	end
	if not limit or limit < 1 or not window_seconds or window_seconds < 1 then return false end

	local counter_key = registration_guard_state_key('count', scope, client_ip, counter_type)
	local legacy_counter_key = 'registration_guard:count:' .. scope .. ':' .. counter_type .. ':' .. client_ip
	local legacy_count = nil
	if registration_state_ip(legacy_counter_key, true) == client_ip then
		legacy_count = shared:get(legacy_counter_key)
	end
	-- Finish an existing legacy window in place; write only v2 keys otherwise.
	if legacy_count then counter_key = legacy_counter_key end
	ngx.shared.free_waf:add(counter_key, 0, window_seconds)
	local count = ngx.shared.free_waf:incr(counter_key, 1)
	if not count or count <= limit then return false end

	local ban_seconds = tonumber(guard['ban_seconds']) or 28800
	if ban_seconds <= 0 then ban_seconds = 28800 end
	if ban_seconds > 28800 then ban_seconds = 28800 end
	local created = ngx.shared.free_waf:safe_add(ban_key, 1, ban_seconds)
	ngx.shared.free_waf:delete(counter_key)
	if created then
		write_log('registration_abuse', counter_type .. ' exceeds ' .. limit .. ' in ' .. window_seconds .. ' seconds; blocked for ' .. ban_seconds .. ' seconds')
		write_drop_ip_entry(client_ip, scope, current_request_uri, ban_seconds, 'registration_abuse_' .. counter_type)
		repeat_ban_event(current_server_name,client_ip,ban_seconds,'registration_abuse_' .. counter_type,current_uri)
	end
	return_html(config['other']['status'], other_html)
	return true
end

function total_log_path()
	local path = cpath .. '.statistics/total.json'
	local fp,err,code = io.open(path,'rb')
	if fp then fp:close(); return path end
	-- Only an absent migrated file/directory permits the legacy compatibility path.
	if code == 2 then return cpath .. 'total.json' end
	return nil
end

function total_log_warning()
	pcall(function()
		if ngx.shared.free_waf:safe_add('statistics:v1:warning',true,60) then
			ngx.log(ngx.WARN,'GPT Firewall statistics deferred; pending counters retained')
		end
	end)
end

function total_log_schedule()
	if total_log_state.scheduled then return true end
	local ok = ngx.timer.at(1,total_log_flush)
	total_log_state.scheduled = not not ok
	return not not ok
end

function total_log_worker_init()
	if total_log_state.worker_started then return true end
	-- Optional worker hook or first ordinary request adopts deltas left by reload.
	local ok,scheduled = pcall(total_log_schedule)
	if not ok or not scheduled then total_log_warning(); return false end
	total_log_state.worker_started = true
	return true
end

function total_log_flush(premature)
	total_log_state.scheduled = false
	if premature then return end
	local owner
	local ok,saved = pcall(function()
		local path = total_log_path()
		if not path then return false end
		owner = repeat_ban_lock(path .. '.lock')
		if not owner then return false end
		local shared,pending = ngx.shared.free_waf,{}
		for _,key in ipairs(shared:get_keys(0)) do
			if string.sub(key,1,20) == 'statistics:v1:count:' then
				local count = shared:get(key)
				if type(count) == 'number' and count > 0 then pending[#pending+1] = {key,count} end
			end
		end
		if #pending == 0 then return true end
		local fp,err,code = io.open(path,'rb')
		local total = {}
		if fp then
			local body = fp:read('*a')
			fp:close()
			total = json.decode(body)
		elseif code ~= 2 then return false end
		if type(total) ~= 'table' then return false end
		total.sites,total.rules = total.sites or {},total.rules or {}
		if type(total.sites) ~= 'table' or type(total.rules) ~= 'table' then return false end
		local function increment(value,delta)
			value = value or 0
			assert(type(value) == 'number' and value >= 0 and value < math.huge and value == math.floor(value))
			return value+delta
		end
		for _,entry in ipairs(pending) do
			local identity = json.decode(string.sub(entry[1],21))
			local site,name,count = identity[1],identity[2],entry[2]
			if type(site) ~= 'string' or type(name) ~= 'string' then return false end
			total.sites[site] = total.sites[site] or {}
			if type(total.sites[site]) ~= 'table' then return false end
			total.total = increment(total.total,count)
			total.rules[name] = increment(total.rules[name],count)
			total.sites[site][name] = increment(total.sites[site][name],count)
		end
		if not runtime_atomic_write(path,json.encode(total),owner) then return false end
		-- Subtract only the committed snapshot, preserving increments during IO.
		for _,entry in ipairs(pending) do shared:incr(entry[1],-entry[2]) end
		return true
	end)
	repeat_ban_unlock(owner)
	if not ok or not saved then total_log_warning() end
	-- Retry pending deltas without another request, but stop when idle.
	local checked = pcall(function()
		local shared = ngx.shared.free_waf
		for _,key in ipairs(shared:get_keys(0)) do
			if string.sub(key,1,20) == 'statistics:v1:count:' and (shared:get(key) or 0) > 0 then
				if not total_log_schedule() then total_log_warning() end
				break
			end
		end
	end)
	if not checked then total_log_warning() end
end

function inc_log(name,rule)
	local ok,result = pcall(function()
		local shared = ngx.shared.free_waf
		local key = 'statistics:v1:count:' .. json.encode({server_name,name})
		-- safe_add never evicts security state to make room for statistics.
		local added,err = shared:safe_add(key,0)
		if not added and err ~= 'exists' then return false end
		local count = shared:incr(key,1)
		if not count then return false end
		return total_log_schedule()
	end)
	if not ok or not result then total_log_warning(); return false end
	return true
end

function write_to_file(logstr)
	local filename = config["logs_path"] .. '/' .. server_name .. '_' .. ngx.today() .. '.log'
	local fp = io.open(filename,'ab')
	if fp == nil then return false end
	fp:write(logstr)
	fp:flush()
	fp:close()
	return true
end

function drop_abroad()
	if ip == 'unknown' then return false end
	if not config['drop_abroad']['open'] or not is_site_config('drop_abroad') then return false end	
	for _,v in ipairs(cnlist)
	do
		if compare_ip(v) then return false end
	end
	ngx.exit(config['drop_abroad']['status'])
	return true
end

function drop()
	local key = cc_state_key('ban',server_name,ip)
	if key and ngx.shared.free_waf_drop_ip:get(key) then
		ngx.exit(config['cc']['status'])
		return true
	end
	-- Existing IP-only bans retain their scope and expiry; never guess a site.
	local count,_ = ngx.shared.free_waf_drop_ip:get(ip)
	if not count then return false end
	if count > retry then
		ngx.exit(config['cc']['status'])
		return true
	end
	return false
end

function encode_json_array(data)
	if data == nil or #data == 0 then
		return '[]'
	end
	return json.encode(data)
end

function endpoint_normalize_ip(value)
	if not is_runtime_ban_ip(value) then return nil end
	if is_runtime_ban_ipv4(value) then return value end
	local address = string.lower(value)
	if string.find(address, '.', 1, true) then
		local prefix,a,b,c,d = string.match(address, '^(.*:)(%d+)%.(%d+)%.(%d+)%.(%d+)$')
		address = prefix .. string.format('%x:%x', tonumber(a)*256+tonumber(b), tonumber(c)*256+tonumber(d))
	end
	local left,right = string.match(address, '^(.-)::(.-)$')
	local groups = {}
	for item in string.gmatch(left or address, '[^:]+') do groups[#groups+1] = tonumber(item,16) end
	if left then
		local tail = {}
		for item in string.gmatch(right, '[^:]+') do tail[#tail+1] = tonumber(item,16) end
		for _=1,8-#groups-#tail do groups[#groups+1] = 0 end
		for _,item in ipairs(tail) do groups[#groups+1] = item end
	end
	local best_start,best_length,index = nil,1,1
	while index <= 8 do
		if groups[index] == 0 then
			local finish = index
			while finish <= 8 and groups[finish] == 0 do finish=finish+1 end
			if finish-index > best_length then best_start,best_length=index,finish-index end
			index=finish
		else index=index+1 end
	end
	local a,b = {},{}
	for i,item in ipairs(groups) do
		if not best_start or i < best_start then a[#a+1]=string.format('%x',item)
		elseif i >= best_start+best_length then b[#b+1]=string.format('%x',item) end
	end
	return table.concat(a,':') .. (best_start and '::' or '') .. table.concat(b,':')
end

-- Decode only retired keys so existing precise unban operations can clear them.
function endpoint_state_ip(key, include_counters)
	if type(key) ~= 'string' then return nil end
	local kind,length,rest = string.match(key, '^endpoint:v1:([^:]+):(%d+):(.*)$')
	if not length or (kind ~= 'ban' and (not include_counters or (kind ~= 'count' and kind ~= 'event'))) then return nil end
	length=tonumber(length)
	if length < 1 or length > 253 or string.sub(rest,length+1,length+1) ~= ':' then return nil end
	local identity,client_ip=string.match(string.sub(rest,length+2), '^([^:]+):(.*)$')
	if not identity or #identity ~= 65 or string.sub(identity,33,33) ~= '.' then return nil end
	if not string.match(string.sub(identity,1,32),'^[0-9a-f]+$') or not string.match(string.sub(identity,34),'^[0-9a-f]+$') then return nil end
	return endpoint_normalize_ip(client_ip)
end

function rate_limit_response(retry_after)
	ngx.header['Retry-After']=tostring(math.max(1,math.ceil(retry_after)))
	ngx.header.content_type='application/json; charset=utf-8'
	ngx.header['Cache-Control']='no-store'
	ngx.status=429
	ngx.say(json.encode({error={type='rate_limit_exceeded',message='请求过于频繁，请稍后重试。'}}))
	ngx.exit(429)
	return true
end

function clear_endpoint_state(target_ips)
	local normalized={}
	for value in pairs(target_ips) do local v=endpoint_normalize_ip(value); if v then normalized[v]=true end end
	local shared=ngx.shared.free_waf
	for _,key in ipairs(shared:get_keys(0)) do
		local client_ip=endpoint_state_ip(key,true)
		if client_ip and normalized[client_ip] then shared:delete(key) end
	end
end

function cc_counter_key()
	local path=ngx.var.uri or uri or '/'
	local site=tostring(server_name or '')
	return ngx.md5('cc:v2:' .. #site .. ':' .. site .. ':' .. tostring(endpoint_normalize_ip(ip) or ip) .. ':' .. path)
end

function cc_state_key(kind, site, client_ip)
	client_ip=endpoint_normalize_ip(client_ip)
	if (kind ~= 'ban' and kind ~= 'history') or type(site) ~= 'string' or #site < 1 or #site > 253 or string.find(site,'%c') or not client_ip then return nil end
	return 'cc:v3:' .. kind .. ':' .. #site .. ':' .. site .. ':' .. client_ip
end

function cc_state_identity(key, expected_kind)
	if type(key) ~= 'string' then return nil end
	local kind,length,rest=string.match(key,'^cc:v3:([^:]+):(%d+):(.*)$')
	if not length or (kind ~= 'ban' and kind ~= 'history') or (expected_kind and kind ~= expected_kind) then return nil end
	local size=tonumber(length)
	if size < 1 or size > 253 or tostring(size) ~= length or string.sub(rest,size+1,size+1) ~= ':' then return nil end
	local site,client_ip=string.sub(rest,1,size),endpoint_normalize_ip(string.sub(rest,size+2))
	if string.find(site,'%c') or not client_ip then return nil end
	return site,client_ip
end

function clear_cc_state(target_ips)
	local targets={}
	for value in pairs(target_ips or {}) do
		local address=endpoint_normalize_ip(value)
		if address then targets[address]=true end
	end
	for _,entry in ipairs({{ngx.shared.free_waf_drop_ip,'ban'},{ngx.shared.free_waf_drop_sum,'history'}}) do
		local shared,kind=entry[1],entry[2]
		for _,key in ipairs(shared:get_keys(0)) do
			local _,address=cc_state_identity(key,kind)
			if not address and kind == 'ban' then address=endpoint_normalize_ip(key) end
			if address and (not target_ips or targets[address]) then shared:delete(key) end
		end
	end
end

function cc()
	if not config['cc']['open'] or not site_cc then return false end
	local ban_key=cc_state_key('ban',server_name,ip)
	local history_key=cc_state_key('history',server_name,ip)
	if not ban_key then return false end
	local token = cc_counter_key()
	ngx.shared.free_waf:safe_add(token,0,cycle)
	local count = ngx.shared.free_waf:incr(token,1)
	if count then
		if count > limit then
			ngx.shared.free_waf_drop_sum:safe_add(history_key,0,86400)
			ngx.shared.free_waf_drop_sum:incr(history_key,1)
			local lock_time = tonumber(endtime) or 60
			if lock_time <= 0 then lock_time = 60 end
			if lock_time > 60 then lock_time = 60 end
			if ngx.shared.free_waf_drop_ip:safe_add(ban_key,retry+1,lock_time) then
				write_log('cc',cycle..'秒内累计超过'..limit..'次请求,封锁' .. lock_time .. '秒')
				write_drop_ip('cc',lock_time)
				repeat_ban_event(server_name,ip,lock_time,'cc',ngx.var.uri or uri)
			end
			ngx.exit(config['cc']['status'])
			return true
		end
	end
	return false
end

function cc2()
	if not config['cc']['open'] or not site_cc then return false end
	if not site_config[server_name] then return false end
	if not site_config[server_name]['cc']['increase'] then return false end
	local ban_key=cc_state_key('ban',server_name,ip)
	local history_key=cc_state_key('history',server_name,ip)
	if not ban_key then return false end
	if ngx_match(uri,"\\.(jpg|png|gif|css|js|swf|ts)$","isjo") then return false end
	local token2 = ngx.md5(method .. server_name .. tostring(request_header['user-agent']) .. tostring(request_header['host']) .. tostring(request_header['accept-language']) .. tostring(request_header['connection']) .. tostring(request_header['accept']) .. tostring(request_header['accept-encoding']) .. tostring(request_header['upgrade-insecure-requests']) .. tostring(request_header['cache-control'])) .. '_' .. 'cc2'
	local path=ngx.var.uri or uri or '/'
	local site=tostring(server_name or '')
	local client=endpoint_normalize_ip(ip)
	token2 = ngx.md5('cc2:v3:'..#site..':'..site..':'..#client..':'..client..':'..#path..':'..path..':'..token2)..'_cc2'
	local cc2_limit = limit * 3
	ngx.shared.free_waf:safe_add(token2,0,cycle)
	local count = ngx.shared.free_waf:incr(token2,1)
	if count then
		if count > cc2_limit then
			ngx.shared.free_waf_drop_sum:safe_add(history_key,0,86400)
			local safe_count=math.max(1,(ngx.shared.free_waf_drop_sum:incr(history_key,1) or 1)-1)
			if safe_count > retry then 
				local lock_time = tonumber(endtime) or 60
				if lock_time <= 0 then lock_time = 60 end
				if lock_time > 60 then lock_time = 60 end
				if ngx.shared.free_waf_drop_ip:safe_add(ban_key,retry+1,lock_time) then
					write_log('cc',cycle..'秒内累计超过'..limit..'次请求,封锁' .. lock_time .. '秒')
					write_drop_ip('cc',lock_time)
					repeat_ban_event(server_name,ip,lock_time,'cc',ngx.var.uri or uri)
				end
				ngx.exit(config['cc']['status'])
				return true
			end
			security_verification()
		end
	end
	return false
end

function security_verification()
	-- Retired predictable arithmetic/URL-script challenge; never grant an IP bypass.
	local wait=tonumber(cycle) or 60
	return rate_limit_response(math.max(1,math.min(wait,3600)))
end

function scan_black()
	if not config['scan']['open'] or not is_site_config('scan') then return false end
	if is_ngx_match(scan_black_rules['cookie'],request_header['cookie'],false) then
		write_log('scan','regular')
		ngx.exit(config['scan']['status'])
		return true
	end
	if is_ngx_match(scan_black_rules['args'],request_uri,false) then
		write_log('scan','regular')
		ngx.exit(config['scan']['status'])
		return true
	end
	for key,value in pairs(request_header)
	do
		if is_ngx_match(scan_black_rules['header'],key,false) then
			write_log('scan','regular')
			ngx.exit(config['scan']['status'])
			return true
		end
	end
	return false
end

function ip_black()
	local now = os.time()
	for _,rule in ipairs(ip_black_rules)
	do
		if rule[3] and now > rule[3] then
			-- skip expired entry
		elseif not rule[3] and rule[1] and rule[2] and rule[1][1] == rule[2][1] and rule[1][2] == rule[2][2] and rule[1][3] == rule[2][3] and rule[1][4] == rule[2][4] then
			-- skip legacy exact-IP entries without expiry; automatic bans must be temporary
		elseif compare_ip(rule) then 
			ngx.exit(config['cc']['status'])
			return true 
		end
	end
	return false
end

function add_ip_black_exact(client_ip, seconds)
	if not is_ipaddr(client_ip) then return false end
	seconds = tonumber(seconds) or AUTO_BAN_SECONDS
	if seconds > MAX_AUTO_BAN_SECONDS then seconds = MAX_AUTO_BAN_SECONDS end
	if seconds <= 0 then seconds = AUTO_BAN_SECONDS end
	local ok,result = with_ip_black_lock(function(owner)
	local ipn = arrip(client_ip)
	local current_rules = read_file('ip_black')
	local now = os.time()
	local new_rules = {}
	for _,rule in ipairs(current_rules)
	do
		if rule[3] and now > tonumber(rule[3]) then
			-- prune expired entry while writing
		elseif rule[1] and rule[2]
		   and rule[1][1] == ipn[1] and rule[1][2] == ipn[2]
		   and rule[1][3] == ipn[3] and rule[1][4] == ipn[4]
		   and rule[2][1] == ipn[1] and rule[2][2] == ipn[2]
		   and rule[2][3] == ipn[3] and rule[2][4] == ipn[4] then
			if rule[3] then
				return false
			end
			-- replace unsafe legacy no-expiry exact-IP entry with a temporary one
		else
			table.insert(new_rules, rule)
		end
	end
	table.insert(new_rules, 1, {ipn, ipn, now + seconds})
	if not runtime_atomic_write(jpath .. 'ip_black.json', encode_json_array(new_rules),owner) then return false end
	ip_black_rules = new_rules
	return true
	end)
	return ok and result or false
end

function ip_white()
	for _,rule in ipairs(ip_white_rules)
	do
		if compare_ip(rule) then 
			return true 
		end
	end
	return false
end

function split2(input, delimiter)
    input = tostring(input)
    delimiter = tostring(delimiter)
    if (delimiter=='') then return false end
    local pos,arr = 0, {}
    for st,sp in function() return string.find(input, delimiter, pos, true) end do
        table.insert(arr, string.sub(input, pos, st - 1))
        pos = sp + 1
    end
    table.insert(arr, string.sub(input, pos))
    return arr
end

function url_white()
	if ngx.var.document_root=='/www/server/phpmyadmin' then return true end
	if is_ngx_match(url_white_rules,request_uri,false) then
        url_data=split2(request_uri,'?')
        if not url_data then url_data=request_uri end
        if not url_data[1] then
            url_data=request_uri
        else
            url_data=url_data[1]
        end
        if ngx.re.match(url_data,'/\\.\\./') then return false end
		return true
	end
	if site_config[server_name] ~= nil then
		if is_ngx_match(site_config[server_name]['url_white'],request_uri,false) then
            url_data=split2(request_uri,'?')
            if not url_data then url_data=request_uri end
            if not url_data[1] then
                url_data=request_uri
            else
                url_data=url_data[1]
            end
            if ngx.re.match(url_data,'/\\.\\./') then return false end
    		return true
    	end
	end
	return false
end

function url_black()
	if is_ngx_match(url_black_rules,request_uri,false) then
		ngx.exit(config['get']['status'])
		return true
	end
	return false
end

function user_agent_white()
	if is_ngx_match(user_agent_white_rules,request_header['user-agent'],false) then
		return true
	end
	return false
end

function head()
	if method ~= 'HEAD' then return false end
	for _,v in ipairs(head_white_rules)
	do
		if ngx_match(uri,v,"isjo") then
			return false
		end
	end
	spiders = {'spider','bot'}
	for _,v in ipairs(spiders)
	do
		if ngx_match(request_header['user-agent'],v,"isjo") then
			return false
		end
	end
	write_log('head','禁止HEAD请求')
	ngx.shared.free_waf:set(ip,retry,endtime)
	write_drop_ip('head',endtime)
	ngx.exit(444)
end

function user_agent()
	if not config['user-agent']['open'] or not is_site_config('user-agent') then return false end	
	if is_ngx_match(user_agent_rules,request_header['user-agent'],'user_agent') then
		write_log('user_agent','regular')
		return_html(config['user-agent']['status'],user_agent_html)
		return true
	end
	return false
end

function header_rule()
	if is_ngx_match(header_rules,request_header,'header') then
		write_log('header','regular')
		return_html(config['get']['status'],get_html)
		return true
	end
	return false
end

function post()
	if not config['post']['open'] or not is_site_config('post') then return false end	
	if method ~= "POST" then return false end
	if not is_form_request() then return false end
	local content_length=tonumber(request_header['content-length'])
	local max_len = 64 * 1024
	if content_length and content_length > max_len then return false end
	ngx.req.read_body()
	if ngx.req.get_body_file() then return false end
	local body = ngx.req.get_body_data()
	if type(body) == 'string' and #body > max_len then return false end
	local request_args = ngx.req.get_post_args()
	if not request_args then
		return false
	end
	
	if is_ngx_match(post_rules,request_args,'post') then
		write_log('post','regular')
		return_html(config['post']['status'],post_html)
		return true
	end
	return false
end

function disable_upload_ext(ext)
	if not ext then return false end
	ext = string.lower(ext)
	if is_key(site_config[server_name]['disable_upload_ext'],ext) then
		write_log('upload_ext','上传扩展名黑名单')
		return_html(config['other']['status'],other_html)
		return true
	end
end

function post_data()
	if method ~= "POST" then return false end
	content_length=tonumber(request_header['content-length'])
	if not content_length then return false end
	max_len = 256 * 1024
	if content_length > max_len then return false end
	local boundary = get_boundary()
	if boundary then
		ngx.req.read_body()
		local data = ngx.req.get_body_data()
		if not data then return false end
		local tmp = ngx.re.match(data,[[filename=\"(.+)\.(.*)\"]])
		if not tmp then return false end
		if not tmp[2] then return false end
		disable_upload_ext(tmp[2])
	end
	return false
end

function cookie()
	if not config['cookie']['open'] or not is_site_config('cookie') then return false end
	if not request_header['cookie'] then return false end
	if type(request_header['cookie']) == "table" then return false end
	request_cookie = string.lower(request_header['cookie'])
	if is_ngx_match(cookie_rules,request_cookie,'cookie') then
		write_log('cookie','regular')
		return_html(config['cookie']['status'],cookie_html)
		return true
	end
	return false
end

function args()
	if not config['get']['open'] or not is_site_config('get') then return false end	
	if is_ngx_match(args_rules,uri_request_args,'args') then
		write_log('args','regular')
		return_html(config['get']['status'],get_html)
		return true
	end
	return false
end

function url()
	if not config['get']['open'] or not is_site_config('get') then return false end

	--正则--
	if is_ngx_match(url_rules,uri,'url') then
		write_log('url','regular')
		return_html(config['get']['status'],get_html)
		return true
	end
	return false
end

function php_path()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['disable_php_path'])
	do
		if type(rule) == 'string' and rule ~= '' then
			local separator = string.sub(rule,-1) == '/' and '' or '/'
			if ngx_match(uri,rule .. separator .. ".*\\.php$","isjo") then
				write_log('php_path','regular')
				return_html(config['other']['status'],other_html)
				return true
			end
		end
	end
	return false
end

function url_path()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]["disable_path"])
	do
		if ngx_match(uri,rule,"isjo") then
			write_log("url_path", "disable_path")
			return_html(config["other"]["status"],other_html)
			return true
		end
	end
	return false
end

function url_ext()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['disable_ext'])
	do
		if ngx_match(uri,"\\."..rule.."$","isjo") then
			write_log('url_ext','regular')
			return_html(config['other']['status'],other_html)
			return true
		end
	end
	return false
end

function url_rule_ex()
	if site_config[server_name] == nil then return false end
	local rules = site_config[server_name]['url_rule']
	if type(rules) ~= 'table' or #rules == 0 then return false end
	-- Form arguments belong to this invocation, never a prior worker request.
	local request_args
	local form_checked = false
	for _,rule in ipairs(rules)
	do
		if ngx_match(uri,rule[1],"isjo") then
			if is_ngx_match(rule[2],uri_request_args,false) then
				write_log('url_rule','regular')
				return_html(config['other']['status'],other_html)
				return true
			end
			
			if method == "POST" and not form_checked then
				form_checked = true
				if is_form_request() then
					local length_header = request_header['content-length']
					local content_length = tonumber(length_header)
					local max_len = 64 * 1024
					if content_length and content_length >= 0 and content_length <= max_len then
						ngx.req.read_body()
						if not ngx.req.get_body_file() then request_args = ngx.req.get_post_args() end
					elseif length_header == nil then
						ngx.req.read_body()
						local body = ngx.req.get_body_data()
						if type(body) == 'string' and #body <= max_len and not ngx.req.get_body_file() then
							request_args = ngx.req.get_post_args()
						end
					end
				end
			end

			if method == "POST" and request_args ~= nil then 
				if is_ngx_match(rule[2],request_args,'post') then
					write_log('post','regular')
					return_html(config['other']['status'],other_html)
					return true
				end
			end
		end
	end
	return false
end

function url_tell()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['url_tell'])
	do
		if ngx_match(uri,rule[1],"isjo") then
			if uri_request_args[rule[2]] ~= rule[3] then
				write_log('url_tell','regular')
				return_html(config['other']['status'],other_html)
				return true
			end
		end
	end
	return false
end

function continue_key(key)
	key = tostring(key)
	if string.len(key) > 64 then return false end;
	local keys = {"content","contents","body","msg",""}
	for _,k in ipairs(keys)
	do
		if k == key then return false end;
	end
	return true;
end

function is_ngx_match(rules,sbody,rule_name)
	if rules == nil or sbody == nil then return false end
	if type(sbody) == "string" then
		sbody = {sbody}
	end
	if type(sbody) ~= "table" then return false end
	
	if type(rules) == "string" then
		rules = {rules}
	end
	
	for k,body in pairs(sbody)
	do
		if rule_name == 'header' or continue_key(k) then
			local values = {body}
			-- Nginx exposes repeated parameters and headers as one-level value arrays.
			if (rule_name == 'args' or rule_name == 'post' or rule_name == 'header') and type(body) == 'table' then values = body end
			for i,rule in ipairs(rules)
			do
				if site_config[server_name] and rule_name then
					local n = i - 1
					local disabled_rules = {}
					if site_config[server_name]['disable_rule'] and site_config[server_name]['disable_rule'][rule_name] then
						disabled_rules = site_config[server_name]['disable_rule'][rule_name]
					end
					for _,j in ipairs(disabled_rules)
					do
						if n == j then
							rule = ""
						end
					end
				end
				
				if body and rule ~="" then
					for _,value in ipairs(values) do
						if type(value) == "string" and ngx_match(ngx.unescape_uri(value),rule,"isjo") then
							error_rule = rule .. ' >> ' .. k .. ':' .. value
							return true
						end
					end
					if type(k) == "string" then
						if ngx_match(ngx.unescape_uri(k),rule,"isjo") then
							error_rule = rule .. ' >> ' .. k
							return true
						end
					end
				end
			end
		end
	end
	return false
end

function is_key(keys,values)
	if keys == nil or values == nil then return false end
	if type(values) == "string" then
		values = {values}
	end
	
	if type(keys) == "string" then
		keys = {keys}
	end
	
	for _,value in pairs(values)
	do
		if type(value) == "boolean" or value == "" then return false end
		sval = ngx.unescape_uri(string.lower(ngx.unescape_uri(value)))
		for _,v in ipairs(keys)
        do
			if v == sval then
				return true
			end
        end
	end
	return false
end

function get_return_state(rstate,rmsg)
	result = {}
	result['status'] = rstate
	result['msg'] = rmsg
	return result
end

function is_runtime_ban_ipv4(client_ip)
	if type(client_ip) ~= 'string' then return false end
	local a,b,c,d = string.match(client_ip, '^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
	if not a then return false end
	for _,value in ipairs({a,b,c,d})
	do
		if #value > 3 or (#value > 1 and string.sub(value,1,1) == '0') or tonumber(value) > 255 then return false end
	end
	return true
end

function is_runtime_ban_ip(client_ip)
	if is_runtime_ban_ipv4(client_ip) then return true end
	if type(client_ip) ~= 'string' or #client_ip > 45 or not string.find(client_ip, ':', 1, true) or not string.match(client_ip, '^[%x:%.]+$') then return false end
	local address = client_ip
	if string.find(address, '.', 1, true) then
		local prefix,tail = string.match(address, '^(.*:)(%d+%.%d+%.%d+%.%d+)$')
		if not prefix or not is_runtime_ban_ipv4(tail) then return false end
		address = prefix .. '0:0'
	end
	local function groups(part)
		if part == '' then return 0 end
		if string.sub(part,1,1) == ':' or string.sub(part,-1) == ':' then return nil end
		local count = 0
		for group in string.gmatch(part, '[^:]+') do
			if #group > 4 or not string.match(group, '^%x+$') then return nil end
			count = count + 1
		end
		return count
	end
	local compressed = string.find(address, '::', 1, true)
	if compressed then
		if string.find(address, '::', compressed + 2, true) then return false end
		local left = groups(string.sub(address,1,compressed - 1))
		local right = groups(string.sub(address,compressed + 2))
		return left ~= nil and right ~= nil and left + right < 8
	end
	return groups(address) == 8
end

function registration_guard_state_key(kind, scope, client_ip, counter_type)
	return 'registration_guard:v2:' .. kind .. ':' .. #scope .. ':' .. scope .. ':' .. (counter_type and counter_type .. ':' or '') .. client_ip
end

function registration_guard_scopes()
	local scopes = {}
	for _,site in pairs(site_config) do
		if type(site) == 'table' and type(site['registration_guard']) == 'table' then
			local scope = trim_string(site['registration_guard']['scope'])
			if scope ~= '' then scopes[scope] = true end
		end
	end
	return scopes
end

function registration_state_ip(key, include_counters, scopes)
	if type(key) ~= 'string' then return nil end
	local function address(kind, suffix)
		if kind == 'count' then
			if not include_counters then return nil end
			local counter_type
			counter_type,suffix = string.match(suffix, '^([^:]+):(.*)$')
			if counter_type ~= 'register' and counter_type ~= 'verify' then return nil end
		end
		if is_runtime_ban_ip(suffix) then return suffix end
	end
	local kind,length,rest = string.match(key, '^registration_guard:v2:([^:]+):(%d+):(.*)$')
	if kind then
		if kind ~= 'ban' and kind ~= 'count' then return nil end
		length = tonumber(length)
		if length < 1 or length >= #rest or string.sub(rest,length + 1,length + 1) ~= ':' then return nil end
		return address(kind, string.sub(rest,length + 2))
	end
	kind,rest = string.match(key, '^registration_guard:([^:]+):(.*)$')
	if kind ~= 'ban' and kind ~= 'count' then return nil end
	local candidates,count,last_ip = {},0,nil
	for scope in pairs(scopes or registration_guard_scopes()) do
		local prefix = scope .. ':'
		if string.sub(rest,1,#prefix) == prefix then
			local client_ip = address(kind, string.sub(rest,#prefix + 1))
			if client_ip and not candidates[client_ip] then
				candidates[client_ip],count,last_ip = true,count + 1,client_ip
			end
		end
	end
	-- Unknown scopes cannot be recovered safely. Ambiguous legacy keys need TTL
	-- expiry or scoped diagnosis; never guess their address from the last colon.
	if count == 1 then return last_ip end
	if count > 1 then return nil,candidates end
	return nil
end

function registration_state_ambiguous(target_ip)
	local shared,scopes = ngx.shared.free_waf,registration_guard_scopes()
	for _,key in ipairs(shared:get_keys(0)) do
		if shared:get(key) then
			local _,candidates = registration_state_ip(key, true, scopes)
			if candidates and (not target_ip or candidates[target_ip]) then return true end
		end
	end
	return false
end

function clear_registration_state(target_ips)
	local shared = ngx.shared.free_waf
	local scopes = registration_guard_scopes()
	for _,key in ipairs(shared:get_keys(0))
	do
		local client_ip = registration_state_ip(key, true, scopes)
		if client_ip and target_ips[client_ip] then shared:delete(key) end
	end
end

function get_btwaf_drop_ip()
	local data,seen = {},{}
	local generic = ngx.shared.free_waf_drop_ip
	for _,key in ipairs(generic:get_keys(0))
	do
		local _,scoped_ip=cc_state_identity(key,'ban')
		local client_ip=scoped_ip or (is_runtime_ban_ip(key) and key)
		if client_ip and generic:get(key) and not seen[client_ip] then
			seen[client_ip] = true
			table.insert(data, client_ip)
		end
	end
	local shared = ngx.shared.free_waf
	local scopes = registration_guard_scopes()
	for _,key in ipairs(shared:get_keys(0))
	do
		local client_ip=registration_state_ip(key,false,scopes)
		if client_ip and shared:get(key) and not seen[client_ip] then
			seen[client_ip] = true
			table.insert(data, client_ip)
		end
	end
	local now = os.time()
	for _,rule in ipairs(ip_black_rules)
	do
		local expires = tonumber(rule[3])
		if rule[1] and rule[2] and expires and now <= expires and rule[1][1] == rule[2][1] and rule[1][2] == rule[2][2] and rule[1][3] == rule[2][3] and rule[1][4] == rule[2][4] then
			local ipstr = table.concat(rule[1],'.')
			if is_runtime_ban_ipv4(ipstr) and not seen[ipstr] then
				seen[ipstr] = true
				table.insert(data, ipstr)
			end
		end
	end
	local has_repeat_policy = false
	for site in pairs(site_config) do if repeat_ban_policy(site) then has_repeat_policy=true; break end end
	if has_repeat_policy then
		for _,row in ipairs(repeat_ban_rows() or {}) do
			if repeat_ban_policy(row.site) and not seen[row.ip] then seen[row.ip]=true; data[#data+1]=row.ip end
		end
	end
	return data
end

function remove_btwaf_drop_ip()
	local target_ip = uri_request_args['ip']
	if not is_runtime_ban_ip(target_ip) then return get_return_state(false,'IP格式错误') end
	if registration_state_ambiguous(target_ip) then return get_return_state(false,'旧版注册封禁归属不明确，未解封；请等待到期或按作用域排查') end
	if not repeat_ban_clear({[target_ip]=true}) then return get_return_state(false,'升级封禁清理失败，未确认解封') end
	ngx.shared.free_waf_drop_ip:delete(target_ip)
	clear_cc_state({[target_ip]=true})
	-- The legacy IP-only interface revokes this IP across every guard scope.
	clear_registration_state({[target_ip] = true})
	clear_endpoint_state({[target_ip] = true})
	return get_return_state(true,target_ip .. '已解封')
end

function clean_btwaf_drop_ip()
	local ok,result = with_ip_black_lock(function(owner)
	if registration_state_ambiguous() then return get_return_state(false,'旧版注册封禁归属不明确，未清理；请等待到期或按作用域排查') end
	local data = get_btwaf_drop_ip()
	local drop_map = {}
	for _,value in ipairs(data)
	do
		drop_map[value] = true
	end
	local repeat_rows = repeat_ban_rows()
	if not repeat_rows then return get_return_state(false,'无法读取升级封禁，未确认清理') end
	for _,row in ipairs(repeat_rows) do drop_map[row.ip]=true end
	for _,key in ipairs(ngx.shared.free_waf:get_keys(0)) do
		local _,address=repeat_ban_state_identity(key)
		if address then drop_map[address]=true end
	end
	local endpoint_map = {}
	for value in pairs(drop_map) do endpoint_map[value]=true end
	-- Cleanup includes old revisions hidden from the current enforcement view.
	for _,key in ipairs(ngx.shared.free_waf:get_keys(0)) do
		local client_ip=endpoint_state_ip(key,true)
		if client_ip then endpoint_map[client_ip]=true end
	end
	local rules = read_file('ip_black')
	local new_rules = {}
	local changed = false
	for _,rule in ipairs(rules)
	do
		local remove_rule = false
		if rule[1] and rule[2] then
			local ip_start = table.concat(rule[1],'.')
			local ip_end = table.concat(rule[2],'.')
			if ip_start == ip_end and drop_map[ip_start] then
				remove_rule = true
			end
		end
		if remove_rule then
			changed = true
		else
			table.insert(new_rules, rule)
		end
	end
	if changed and not runtime_atomic_write(jpath .. 'ip_black.json', encode_json_array(new_rules),owner) then
		return get_return_state(false,'写入IP黑名单失败，未清理运行时封禁')
	end
	if not repeat_ban_clear(drop_map,nil,true) then return get_return_state(false,'升级封禁清理失败，未确认清理运行时封禁') end
	ip_black_rules = new_rules
	for _,value in ipairs(data)
	do
		ngx.shared.free_waf_drop_ip:delete(value)
	end
	clear_cc_state()
	clear_registration_state(drop_map)
	clear_endpoint_state(endpoint_map)
	return get_return_state(true,'已解封所有封锁IP')
	end)
	if not ok then return get_return_state(false,'IP黑名单存储忙或不可用，未确认清理') end
	return result
end

function get_permanent_ban_ips()
	local rules = read_file('ip_black')
	local ips = {}
	local now = os.time()
	for _,rule in ipairs(rules)
	do
		if rule[1] and rule[2] and rule[3] and now <= tonumber(rule[3]) then
			local ip_start = table.concat(rule[1],'.')
			local ip_end = table.concat(rule[2],'.')
			if ip_start == ip_end then
				table.insert(ips, ip_start)
			else
				table.insert(ips, ip_start .. '-' .. ip_end)
			end
		end
	end
	return ips
end

function remove_permanent_ban_ip()
	local target_ip = uri_request_args['ip']
	if not target_ip or not is_ipaddr(target_ip) then
		return get_return_state(false, 'IP格式错误')
	end
	local ok,result = with_ip_black_lock(function(owner)
	local ipn = arrip(target_ip)
	local rules = read_file('ip_black')
	local new_rules = {}
	local found = false
	for _,rule in ipairs(rules)
	do
		if rule[1] and rule[2]
		   and rule[1][1] == ipn[1] and rule[1][2] == ipn[2]
		   and rule[1][3] == ipn[3] and rule[1][4] == ipn[4]
		   and rule[2][1] == ipn[1] and rule[2][2] == ipn[2]
		   and rule[2][3] == ipn[3] and rule[2][4] == ipn[4] then
			found = true
		else
			table.insert(new_rules, rule)
		end
	end
	if not found then
		return get_return_state(false, target_ip .. ' 不在封禁列表中')
	end
	if not repeat_ban_clear({[target_ip]=true}) then return get_return_state(false,'升级封禁清理失败，未确认解封') end
	if not runtime_atomic_write(jpath .. 'ip_black.json', encode_json_array(new_rules),owner) then
		return get_return_state(false,'写入IP黑名单失败，未确认解封')
	end
	ip_black_rules = new_rules
	ngx.shared.free_waf_drop_ip:delete(target_ip)
	clear_cc_state({[target_ip]=true})
	return get_return_state(true, target_ip .. ' 已从封禁列表移除')
	end)
	if not ok then return get_return_state(false,'IP黑名单存储忙或不可用，未确认解封') end
	return result
end

function min_route()
	if ngx.var.remote_addr ~= '127.0.0.1' then return false end
	if uri == '/get_manual_site_bans' then return manual_site_ban_response() end
	if ngx.var.server_name == 'gpt-firewall-health.invalid' then
		local nonce = string.match(uri or '', '^/_gpt_firewall_health/([0-9a-f]+)$')
		if nonce and #nonce == 32 then
			return_message(200, {product='aapanel GPT Firewall', version='0.1.11',
				nonce=nonce, worker_pid=ngx.worker.pid()})
		else
			ngx.exit(404)
		end
	end
	if uri == '/get_btwaf_drop_ip' then
		return_message(200,get_btwaf_drop_ip(),true)
	elseif uri == '/remove_btwaf_drop_ip' then
		return_message(200,remove_btwaf_drop_ip())
	elseif uri == '/clean_btwaf_drop_ip' then
		return_message(200,clean_btwaf_drop_ip())
	elseif uri == '/get_permanent_ban_ips' then
		return_message(200,get_permanent_ban_ips())
	elseif uri == '/remove_permanent_ban_ip' then
		return_message(200,remove_permanent_ban_ip())
	elseif uri == '/remove_repeat_ban' then
		return_message(200,remove_repeat_ban())
	end
end

function return_message(status,msg,is_array)
	ngx.header.content_type = "application/json;"
	ngx.status = status
	if is_array then
		ngx.say(encode_json_array(msg))
	else
		ngx.say(json.encode(msg))
	end
    ngx.exit(status)
end

function return_html(status,html)
	ngx.header.content_type = "text/html"
    ngx.status = status
    ngx.say(html)
    ngx.exit(status)
end



function ban_empty_ua()
	return false
end

function is_scan_like_404_path(current_uri)
	if not current_uri or current_uri == "" then return false end
	local pattern = "(wp-admin|wp-content|wp-includes|xmlrpc\\.php|phpmyadmin|pma/|\\.env|\\.git|/vendor/|/backup|/backup/|/admin/|/shell|/webshell|/filemanager|/wp_filemanager|/boaform|/cgi-bin/)"
	if ngx_match(current_uri, pattern, "isjo") then return true end
	return false
end

function ban_404_accumulate()
	local status = ngx.var.status
	if tostring(status) ~= "404" then return false end
	local site_name = ngx.var.server_name or server_name or ''
	if config['open'] ~= true then return false end
	if site_config[site_name] and site_config[site_name]['open'] ~= true then return false end
	local current_uri = ngx.var.uri or uri or ''
	if ngx_match(current_uri,"\\.(jpg|jpeg|png|gif|css|js|ico|woff|woff2|svg)$","isjo") then return false end
	if not is_scan_like_404_path(current_uri) then return false end
	local client_ip = ngx.var.remote_addr or ip
	if not client_ip or not is_ipaddr(client_ip) then return false end
	local key_404 = client_ip .. "_404"
	local cnt,_ = ngx.shared.free_waf:get(key_404)
	if cnt then
		if cnt >= 80 then
			add_ip_black_exact(client_ip, AUTO_BAN_SECONDS)
			if ngx.shared.free_waf_drop_ip:safe_add(client_ip, (config['retry'] or 6)+1, AUTO_BAN_SECONDS) then
				write_drop_ip_entry(client_ip, site_name, ngx.var.request_uri or current_uri, AUTO_BAN_SECONDS, "404_flood")
				repeat_ban_event(site_name,client_ip,AUTO_BAN_SECONDS,'404_flood',current_uri)
			end
			ngx.shared.free_waf:delete(key_404)
			return true
		end
		ngx.shared.free_waf:incr(key_404, 1)
	else
		ngx.shared.free_waf:set(key_404, 1, 3600)
	end
	return false
end

function run_btwaf()
	server_name = ngx.var.server_name
	if config['compatibility_profile'] == 'bt-free-waf-8.4' and type(config['site_aliases']) == 'table' then
		local canonical = config['site_aliases'][server_name]
		if type(canonical) == 'string' and canonical ~= '' and type(site_config[canonical]) == 'table' then
			server_name = canonical
		end
	end
	error_rule = nil
	request_header = ngx.req.get_headers()
	method = ngx.req.get_method()
	ip = get_client_ip()
	ipn = arrip(ip)
	request_uri = ngx.var.request_uri
	uri = ngx.unescape_uri(ngx.var.uri)
	uri_request_args = ngx.req.get_uri_args()
	cycle = config['cc']['cycle']
	endtime = config['cc']['endtime']
	limit = config['cc']['limit']
	retry = config['retry']
	retry_time = config['retry_time']
	retry_cycle = config['retry_cycle']
	min_route()
	total_log_worker_init()

	if not config['open'] or not is_site_config('open') then return false end
	site_cc = is_site_config('cc')
	if site_config[server_name] and site_cc then
		cycle = site_config[server_name]['cc']['cycle']
		endtime = site_config[server_name]['cc']['endtime']
		limit = site_config[server_name]['cc']['limit']
	end

	if site_config[server_name] then
		retry = site_config[server_name]['retry']
		retry_time = site_config[server_name]['retry_time']
		retry_cycle = site_config[server_name]['retry_cycle']
	end
	
	if ip_white() then return true end
	manual_site_ban_guard()
	repeat_ban_guard()
	registration_guard(server_name, ip, method, uri, request_uri)
	drop()
	ip_black()
	if user_agent_white() then return true end

	if url_white() then return true end
	ban_empty_ua()
	url_black()
	drop_abroad()
	cc()
	cc2()
	user_agent()
	header_rule()
	url()
	args()
	cookie()
	scan_black()
	post()
	if site_config[server_name] then
		php_path()
		url_path()
		url_ext()
		url_rule_ex()
		url_tell()
		post_data()
	end
end

-- Capture exactly the loaded configuration and snapshot before workers fork.
-- HTTP proof never rereads disk; changes require a checked smooth reload.
manual_site_ban_load(ngx.md5(config_body .. '\0' .. site_body .. '\0' .. (ip_white_body or '')))
