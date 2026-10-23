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

local config = json.decode(read_file_body(cpath .. 'config.json'))
local site_config = json.decode(read_file_body(cpath .. 'site.json'))

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

function first_client_ip_from_header(header_value)
	if type(header_value) == "table" then header_value = header_value[1] end
	if not header_value or header_value == "" then return nil end
	for _,part in ipairs(split_bylog(header_value, ','))
	do
		local candidate = trim_string(part)
		if is_ipaddr(candidate) and not compare_ip_block(candidate) then
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
					local candidate = first_client_ip_from_header(header_tmp)
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

local get_html = read_file_body(config["reqfile_path"] .. '/' .. config["get"]["reqfile"])
local post_html = read_file_body(config["reqfile_path"] .. '/' .. config["post"]["reqfile"])
local cookie_html = read_file_body(config["reqfile_path"] .. '/' .. config["cookie"]["reqfile"])
local user_agent_html = read_file_body(config["reqfile_path"] .. '/' .. config["user-agent"]["reqfile"])
local other_html = read_file_body(config["reqfile_path"] .. '/' .. config["other"]["reqfile"])
local cnlist = json.decode(read_file_body(cpath .. '/rule/cn.json'))
local scan_black_rules = read_file('scan_black')
local ip_black_rules = read_file('ip_black')
local ip_white_rules = read_file('ip_white')
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
	ngx.shared.free_waf:set(ban_key, 1, ban_seconds)
	ngx.shared.free_waf:delete(counter_key)
	write_log('registration_abuse', counter_type .. ' exceeds ' .. limit .. ' in ' .. window_seconds .. ' seconds; blocked for ' .. ban_seconds .. ' seconds')
	write_drop_ip_entry(client_ip, scope, current_request_uri, ban_seconds, 'registration_abuse_' .. counter_type)
	return_html(config['other']['status'], other_html)
	return true
end

function inc_log(name,rule)
	local total_path = cpath .. 'total.json'
	local tbody = read_file_body(total_path)
	if not tbody then return false end
	local total = json.decode(tbody)
	if not total['sites'] then total['sites'] = {} end
	if not total['sites'][server_name] then total['sites'][server_name] = {} end
	if not total['sites'][server_name][name] then total['sites'][server_name][name] = 0 end
	if not total['rules'] then total['rules'] = {} end
	if not total['rules'][name] then total['rules'][name] = 0 end
	if not total['total'] then total['total'] = 0 end
	total['total'] = total['total'] + 1
	total['sites'][server_name][name] = total['sites'][server_name][name] + 1
	total['rules'][name] = total['rules'][name] + 1
	local total_log = json.encode(total)
	if not total_log then return false end
	write_file(total_path,total_log)
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

function endpoint_state_key(kind, site, rule, client_ip)
	-- Policy revisions do not inherit counters or bans from an edited rule.
	local revision = ngx.md5(json.encode({rule.path,rule.match,rule.method,rule.action,rule.window_seconds,rule.max_requests,rule.ban_seconds}))
	return 'endpoint:v1:' .. kind .. ':' .. #site .. ':' .. site .. ':' .. rule.id .. '.' .. revision .. ':' .. client_ip
end

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

function endpoint_valid_rule(rule)
	if type(rule) ~= 'table' or rule.enabled ~= true then return false end
	if type(rule.id) ~= 'string' or #rule.id ~= 32 or not string.match(rule.id,'^[0-9a-f]+$') then return false end
	if rule.action ~= 'observe' and rule.action ~= 'reject' and rule.action ~= 'ban' then return false end
	if rule.match ~= 'exact' and rule.match ~= 'prefix' then return false end
	if type(rule.path) ~= 'string' or #rule.path < 1 or #rule.path > 512 or string.sub(rule.path,1,1) ~= '/' then return false end
	if string.find(rule.path,'[%c%%?#\\]') or string.find(rule.path,'//',1,true) then return false end
	for component in string.gmatch(rule.path,'[^/]+') do if component=='.' or component=='..' then return false end end
	local methods = {ALL=true,GET=true,POST=true,PUT=true,PATCH=true,DELETE=true,HEAD=true,OPTIONS=true}
	if not methods[rule.method] then return false end
	for _,item in ipairs({{'window_seconds',3600},{'max_requests',100000},{'ban_seconds',28800}}) do
		local n=rule[item[1]]
		if type(n)~='number' or n~=n or n<1 or n>item[2] or n~=math.floor(n) then return false end
	end
	return true
end

function endpoint_path_matches(rule, path, request_method)
	if rule.method ~= 'ALL' and rule.method ~= request_method then return false end
	if path==rule.path then return true end
	if rule.match~='prefix' then return false end
	if rule.path=='/' then return true end
	local prefix=rule.path
	if string.sub(prefix,-1)~='/' then prefix=prefix..'/' end
	return string.sub(path,1,#prefix)==prefix
end

function endpoint_record_event(rule, site, client_ip, path, count, retry_after)
	if config.log ~= true or (site_config[site] and site_config[site].log == false) then return false end
	local key=endpoint_state_key('event',site,rule,client_ip)
	if not ngx.shared.free_waf:safe_add(key,true,rule.window_seconds) then return false end
	local entry={timestamp=ngx.localtime(),site=site,ip=client_ip,path=string.sub(path,1,512),method=method,
		rule_id=rule.id,rule_name=string.sub(tostring(rule.name or ''),1,240),action=rule.action,
		count=count,limit=rule.max_requests,window_seconds=rule.window_seconds,retry_after=retry_after}
	local fp=io.open(config.logs_path..'/endpoint_'..ngx.today()..'.jsonl','ab')
	if not fp then return false end
	local written=fp:write(json.encode(entry)..'\n')
	fp:close()
	return not not written
end

function endpoint_limit_response(retry_after)
	ngx.header['Retry-After']=tostring(math.max(1,math.ceil(retry_after)))
	ngx.header.content_type='application/json; charset=utf-8'
	ngx.header['Cache-Control']='no-store'
	ngx.status=429
	ngx.say(json.encode({error={type='rate_limit_exceeded',message='请求过于频繁，请稍后重试。'}}))
	ngx.exit(429)
	return true
end

function endpoint_policy_guard()
	local site=site_config[server_name]
	if type(site)~='table' or type(site.endpoint_limits)~='table' then return false end
	if type(server_name)~='string' or #server_name>253 then return false end
	local client_ip=endpoint_normalize_ip(ip)
	local path=ngx.var.uri
	if not client_ip or type(path)~='string' then return false end
	local shared=ngx.shared.free_waf
	for index,rule in ipairs(site.endpoint_limits) do
		if index>50 then break end
		if endpoint_valid_rule(rule) and endpoint_path_matches(rule,path,method) then
			local now=ngx.time()
			local ban_key=endpoint_state_key('ban',server_name,rule,client_ip)
			local banned_until=shared:get(ban_key)
			if type(banned_until)=='number' and banned_until>now then return endpoint_limit_response(banned_until-now) end
			local count_key=endpoint_state_key('count',server_name,rule,client_ip)
			shared:safe_add(count_key,0,rule.window_seconds)
			local count=shared:incr(count_key,1)
			if count and count>rule.max_requests then
				local wait=rule.window_seconds
				if rule.action=='ban' then
					wait=rule.ban_seconds
					if not shared:safe_set(ban_key,now+wait,wait) then return false end
					write_drop_ip_entry(client_ip,server_name,path,wait,'endpoint_limit')
				end
				endpoint_record_event(rule,server_name,client_ip,path,count,wait)
				if rule.action~='observe' then return endpoint_limit_response(wait) end
			end
		end
	end
	return false
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
	return ngx.md5('cc:v2:' .. #site .. ':' .. site .. ':' .. tostring(ip) .. ':' .. path)
end

function cc()
	if not config['cc']['open'] or not site_cc then return false end
	local token = cc_counter_key()
	ngx.shared.free_waf:safe_add(token,0,cycle)
	local count = ngx.shared.free_waf:incr(token,1)
	if count then
		if count > limit then
			local safe_count,_ = ngx.shared.free_waf_drop_sum:get(ip)
			if not safe_count then
				ngx.shared.free_waf_drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.free_waf_drop_sum:incr(ip,1)
			end
			local lock_time = tonumber(endtime) or 60
			if lock_time <= 0 then lock_time = 60 end
			if lock_time > 60 then lock_time = 60 end
			ngx.shared.free_waf_drop_ip:set(ip,retry+1,lock_time)
			write_log('cc',cycle..'秒内累计超过'..limit..'次请求,封锁' .. lock_time .. '秒')
			write_drop_ip('cc',lock_time)
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
	if ngx_match(uri,"\\.(jpg|png|gif|css|js|swf|ts)$","isjo") then return false end
	local token2 = ngx.md5(method .. server_name .. tostring(request_header['user-agent']) .. tostring(request_header['host']) .. tostring(request_header['accept-language']) .. tostring(request_header['connection']) .. tostring(request_header['accept']) .. tostring(request_header['accept-encoding']) .. tostring(request_header['upgrade-insecure-requests']) .. tostring(request_header['cache-control'])) .. '_' .. 'cc2'
	local path=ngx.var.uri or uri or '/'
	local site=tostring(server_name or '')
	token2 = ngx.md5('cc2:v2:'..#site..':'..site..':'..#path..':'..path..':'..token2)..'_cc2'
	local cc2_limit = limit * 3
	ngx.shared.free_waf:safe_add(token2,0,cycle)
	local count = ngx.shared.free_waf:incr(token2,1)
	if count then
		if count > cc2_limit then
			local safe_count,_ = ngx.shared.free_waf_drop_sum:get(ip)
			if not safe_count then
				ngx.shared.free_waf_drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.free_waf_drop_sum:incr(ip,1)
			end
			if safe_count > retry then 
				local lock_time = tonumber(endtime) or 60
				if lock_time <= 0 then lock_time = 60 end
				if lock_time > 60 then lock_time = 60 end
				ngx.shared.free_waf_drop_ip:set(ip,retry+1,lock_time)
				write_log('cc',cycle..'秒内累计超过'..limit..'次请求,封锁' .. lock_time .. '秒')
				write_drop_ip('cc',lock_time)
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
	return endpoint_limit_response(math.max(1,math.min(wait,3600)))
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
	write_file(jpath .. 'ip_black.json', encode_json_array(new_rules))
	ip_black_rules = new_rules
	return true
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
	if is_json_request() then return false end
	content_length=tonumber(request_header['content-length'])
	max_len = 64 * 1024
	if content_length and content_length > max_len then return false end
	if get_boundary() then return false end
	ngx.req.read_body()
	request_args = ngx.req.get_post_args()
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
		if ngx_match(uri,rule .. "/.*\\.php$","isjo") then
			write_log('php_path','regular')
			return_html(config['other']['status'],other_html)
			return true
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
	if method == "POST" and not request_args then
		content_length=tonumber(request_header['content-length'])
		max_len = 64 * 1024
		request_args = nil
		if content_length < max_len then
			ngx.req.read_body()
			request_args = ngx.req.get_post_args()
		end
	end
	for _,rule in ipairs(site_config[server_name]['url_rule'])
	do
		if ngx_match(uri,rule[1],"isjo") then
			if is_ngx_match(rule[2],uri_request_args,false) then
				write_log('url_rule','regular')
				return_html(config['other']['status'],other_html)
				return true
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
	local keys = {"content","contents","body","msg","file","files","img",""}
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
	
	if type(rules) == "string" then
		rules = {rules}
	end
	
	for k,body in pairs(sbody)
	do
		if continue_key(k) then
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
					if type(body) == "string" then
						if ngx_match(ngx.unescape_uri(body),rule,"isjo") then
							error_rule = rule .. ' >> ' .. k .. ':' .. body
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
	for _,client_ip in ipairs(generic:get_keys(0))
	do
		if is_runtime_ban_ip(client_ip) and generic:get(client_ip) and not seen[client_ip] then
			seen[client_ip] = true
			table.insert(data, client_ip)
		end
	end
	local shared = ngx.shared.free_waf
	local scopes = registration_guard_scopes()
	for _,key in ipairs(shared:get_keys(0))
	do
		local client_ip = endpoint_state_ip(key, false)
		if client_ip then
			local length,rest=string.match(key,'^endpoint:v1:ban:(%d+):(.*)$')
			local site=string.sub(rest,1,tonumber(length))
			local current=site_config[site]
			local active=false
			local deadline=shared:get(key)
			if type(deadline)=='number' and deadline>ngx.time() and type(current)=='table' and type(current.endpoint_limits)=='table' then
				for index,rule in ipairs(current.endpoint_limits) do
					if index>50 then break end
					if endpoint_valid_rule(rule) and rule.action=='ban' and key==endpoint_state_key('ban',site,rule,client_ip) then active=true; break end
				end
			end
			if not active then client_ip=nil end
		else client_ip=registration_state_ip(key,false,scopes) end
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
	return data
end

function remove_btwaf_drop_ip()
	local target_ip = uri_request_args['ip']
	if not is_runtime_ban_ip(target_ip) then return get_return_state(false,'IP格式错误') end
	if registration_state_ambiguous(target_ip) then return get_return_state(false,'旧版注册封禁归属不明确，未解封；请等待到期或按作用域排查') end
	ngx.shared.free_waf_drop_ip:delete(target_ip)
	-- The legacy IP-only interface revokes this IP across every guard scope.
	clear_registration_state({[target_ip] = true})
	clear_endpoint_state({[target_ip] = true})
	return get_return_state(true,target_ip .. '已解封')
end

function clean_btwaf_drop_ip()
	if registration_state_ambiguous() then return get_return_state(false,'旧版注册封禁归属不明确，未清理；请等待到期或按作用域排查') end
	local data = get_btwaf_drop_ip()
	local drop_map = {}
	for _,value in ipairs(data)
	do
		drop_map[value] = true
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
	if changed and not write_file(jpath .. 'ip_black.json', encode_json_array(new_rules)) then
		return get_return_state(false,'写入IP黑名单失败，未清理运行时封禁')
	end
	ip_black_rules = new_rules
	for _,value in ipairs(data)
	do
		ngx.shared.free_waf_drop_ip:delete(value)
	end
	clear_registration_state(drop_map)
	clear_endpoint_state(endpoint_map)
	return get_return_state(true,'已解封所有封锁IP')
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
	write_file(jpath .. 'ip_black.json', encode_json_array(new_rules))
	ip_black_rules = new_rules
	ngx.shared.free_waf_drop_ip:delete(target_ip)
	return get_return_state(true, target_ip .. ' 已从封禁列表移除')
end

function min_route()
	if ngx.var.remote_addr ~= '127.0.0.1' then return false end
	if ngx.var.server_name == 'gpt-firewall-health.invalid' then
		local nonce = string.match(uri or '', '^/_gpt_firewall_health/([0-9a-f]+)$')
		if nonce and #nonce == 32 then
			return_message(200, {product='aapanel GPT Firewall', version='0.1.5',
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
			ngx.shared.free_waf_drop_ip:set(client_ip, (config['retry'] or 6)+1, AUTO_BAN_SECONDS)
			write_drop_ip_entry(client_ip, site_name, ngx.var.request_uri or current_uri, AUTO_BAN_SECONDS, "404_flood")
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
	registration_guard(server_name, ip, method, uri, request_uri)
	drop()
	ip_black()
	if user_agent_white() then return true end

	if url_white() then return true end
	endpoint_policy_guard()
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
