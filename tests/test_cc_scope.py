import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CCScopeTest(unittest.TestCase):
    def setUp(self):
        try:
            from lupa.luajit21 import LuaRuntime
        except ImportError:
            self.skipTest('optional embedded LuaJIT unavailable')
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.lua.execute('''
            now = 1000
            function dictionary()
                local values, expires = {}, {}
                local d = {}
                function d:get(k)
                    if expires[k] and expires[k] <= now then return nil end
                    return values[k]
                end
                function d:set(k,v,ttl) values[k]=v; expires[k]=ttl and now+ttl; return true end
                function d:safe_add(k,v,ttl)
                    if self:get(k) ~= nil then return nil,'exists' end
                    return self:set(k,v,ttl)
                end
                function d:incr(k,v)
                    if self:get(k)==nil then return nil,'not found' end
                    values[k]=values[k]+v; return values[k]
                end
                function d:delete(k) values[k],expires[k]=nil,nil end
                function d:get_keys() local keys={}; for k in pairs(values) do keys[#keys+1]=k end; return keys end
                function d:ttl(k) return expires[k] and expires[k]-now end
                return d
            end
            ngx={shared={free_waf=dictionary(),free_waf_drop_ip=dictionary(),free_waf_drop_sum=dictionary()},
                var={uri='/a'},header={},md5=function(v) return v end,
                exit=function(status) error({status=status}) end,say=function() end}
            json={encode=function(v) return v end}
            config={cc={open=true,status=403}}
            site_config={['a.example']={cc={increase=true}},['b.example']={cc={increase=true}}}
            ip='192.0.2.1'; server_name='a.example'; uri='/a'; method='GET'; request_header={}
            retry=1; limit=1; cycle=10; endtime=60; site_cc=true
            ip_black_rules={}; events=0; uri_request_args={ip=ip}; jpath='fixture/'
            ngx_match=function() return false end
            trim_string=function(v) return type(v)=='string' and v or '' end
            write_log=function() end; write_drop_ip=function() end
            repeat_ban_event=function() events=events+1 end
            repeat_ban_policy=function() return nil end; repeat_ban_rows=function() return {} end
            repeat_ban_clear=function() return true end
            with_ip_black_lock=function(body) return true,body({}) end
            read_file=function() return ip_black_rules end
            runtime_atomic_write=function() return true end
            encode_json_array=function(v) return v end
            function response(fn)
                local ok,value=pcall(fn)
                if ok then return 200 end
                if type(value)~='table' then error(value) end
                return value.status
            end
        ''')
        source = (ROOT / 'init.lua').read_text(encoding='utf-8')
        names = (
            'is_runtime_ban_ipv4', 'is_runtime_ban_ip', 'endpoint_normalize_ip',
            'endpoint_state_ip', 'clear_endpoint_state', 'cc_state_key', 'cc_state_identity',
            'clear_cc_state', 'registration_guard_scopes', 'registration_state_ip',
            'registration_state_ambiguous', 'clear_registration_state', 'get_return_state',
            'repeat_ban_state_identity', 'get_btwaf_drop_ip', 'remove_btwaf_drop_ip',
            'clean_btwaf_drop_ip', 'rate_limit_response', 'cc_counter_key', 'drop', 'cc', 'cc2',
            'security_verification',
        )
        for name in names:
            match = re.search(r'\nfunction ' + name + r'\(.*?\nend', source, re.S)
            if match:
                self.lua.execute(match.group(0))

    def run_lua(self, body):
        from lupa.luajit21 import LuaError
        try:
            self.lua.execute(body)
        except LuaError as exc:
            self.fail(str(exc))

    def test_cc_ban_blocks_all_paths_of_one_site_not_other_sites(self):
        self.run_lua('''
            assert(response(cc)==200 and response(cc)==403)
            ngx.var.uri='/another'; assert(response(drop)==403)
            server_name='b.example'; assert(response(drop)==200,'CC ban leaked to another site')
            assert(events==1)
        ''')

    def test_enhanced_history_does_not_spill_between_sites(self):
        self.run_lua('''
            endtime=1; limit=0
            assert(response(cc)==403); now=1002; assert(response(cc)==403)
            server_name='b.example'; limit=1
            for i=1,3 do assert(response(cc2)==200) end
            assert(response(cc2)==429,'another site history escalated enhanced CC')
            assert(response(drop)==200,'enhanced CC created a cross-site ban')
        ''')

    def assert_enhanced_counter_isolates_clients(self, clients_by_round):
        self.lua.globals().clients_by_round = self.lua.table_from(
            [self.lua.table_from(clients) for clients in clients_by_round]
        )
        self.run_lua('''
            cycle=10; limit=1; retry=1
            server_name='a.example'; uri='/a'; ngx.var.uri=uri; method='GET'
            request_header={['user-agent']='same-browser',host=server_name,
                ['accept-language']='en-US',connection='keep-alive',
                accept='text/html',['accept-encoding']='gzip',
                ['upgrade-insecure-requests']='1',['cache-control']='no-cache'}
            client_responses={}
            for round,clients in ipairs(clients_by_round) do
                now=1000+(round-1)*11
                local seen={}
                client_responses[round]={}
                for index,client in ipairs(clients) do
                    ip=client
                    local normalized=endpoint_normalize_ip(ip)
                    assert(normalized and not seen[normalized],'fixture must use distinct clients')
                    seen[normalized]=true
                    client_responses[round][index]=response(function() drop(); cc2() end)
                end
            end
        ''')
        responses = self.lua.globals().client_responses
        statuses = [[responses[round][client] for client in range(1, 5)]
                    for round in range(1, 4)]
        events = self.lua.globals().events
        self.assertEqual(
            statuses, [[200] * 4 for _ in range(3)],
            f'cross-IP enhanced CC responses={statuses}; independent_ban_events={events}',
        )
        self.assertEqual(events, 0, 'independent bans were created for non-abusive clients')

    def test_enhanced_counter_isolates_four_ipv4_clients_across_expired_windows(self):
        clients = ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4']
        self.assert_enhanced_counter_isolates_clients([clients] * 3)

    def test_enhanced_counter_isolates_four_ipv6_clients_across_spelling_changes(self):
        self.assert_enhanced_counter_isolates_clients([
            [f'2001:0DB8:0:0:0:0:0:{client}' for client in range(1, 5)],
            [f'2001:db8::{client}' for client in range(1, 5)],
            [f'2001:0db8:0000:0000:0000:0000:0000:{client:04x}'
             for client in range(1, 5)],
        ])

    def test_enhanced_same_ip_burst_still_limits_and_bans_once(self):
        self.run_lua('''
            cycle=10; limit=1; retry=1
            for i=1,3 do assert(response(cc2)==200,'burst allowance changed') end
            assert(response(cc2)==429,'same-IP burst bypassed enhanced CC')
            assert(events==0,'verification counted as an independent ban')
            assert(response(cc2)==429)
            assert(response(cc2)==403 and events==1,'repeated burst did not create one ban')
            assert(response(drop)==403,'enhanced CC ban was not enforced')
            assert(response(cc2)==403 and events==1,'overlap created another ban event')
        ''')

    def test_enhanced_request_counter_keeps_site_and_path_boundaries(self):
        self.run_lua('''
            for i=1,3 do assert(response(cc2)==200) end
            server_name='b.example'; assert(response(cc2)==200,'site counter boundary lost')
            server_name='a.example'; ngx.var.uri='/other'
            assert(response(cc2)==200,'path counter boundary lost')
            ngx.var.uri='/a'; assert(response(cc2)==429,'original counter did not retain requests')
        ''')

    def test_enhanced_counter_does_not_adopt_legacy_mixed_fingerprint(self):
        self.run_lua('''
            local fingerprint=method..server_name
            for _,key in ipairs({'user-agent','host','accept-language','connection','accept',
                'accept-encoding','upgrade-insecure-requests','cache-control'}) do
                fingerprint=fingerprint..tostring(request_header[key])
            end
            fingerprint=ngx.md5(fingerprint)..'_cc2'
            local site,path=server_name,ngx.var.uri
            local legacy=ngx.md5('cc2:v2:'..#site..':'..site..':'..#path..':'..path..':'..fingerprint)..'_cc2'
            ngx.shared.free_waf:set(legacy,999,cycle)
            assert(response(cc2)==200,'legacy cross-client counter was adopted')
            assert(ngx.shared.free_waf:get(legacy)==999,'old state was destructively reset')
            assert(events==0 and response(drop)==200)
        ''')

    def test_enhanced_counter_treats_canonical_ipv6_spellings_as_one_client(self):
        self.run_lua('''
            cycle=10; limit=1; retry=1
            local spellings={'2001:0DB8:0:0:0:0:0:1','2001:db8::1',
                '2001:0db8:0000:0000:0000:0000:0000:0001'}
            for _,address in ipairs(spellings) do
                ip=address; assert(response(cc2)==200)
            end
            for index=1,2 do
                ip=spellings[index]
                assert(response(cc2)==429,'IPv6 spelling reset the enhanced counter')
                assert(events==0,'verification counted as an independent ban')
            end
            ip=spellings[3]
            assert(response(cc2)==403 and events==1,'IPv6 spelling reset escalation history')
            for _,address in ipairs(spellings) do
                ip=address; assert(response(drop)==403,'IPv6 spelling bypassed enhanced ban')
            end
            assert(events==1)
        ''')

    def test_ipv6_canonical_addresses_share_the_site_ban(self):
        self.run_lua('''
            ip='2001:0DB8:0:0:0:0:0:1'; limit=0; assert(response(cc)==403)
            ip='2001:db8::1'; assert(response(drop)==403,'IPv6 spelling bypassed the ban')
            server_name='b.example'; assert(response(drop)==200)
        ''')

    def test_legacy_bans_keep_their_original_scope_and_ttl(self):
        self.run_lua('''
            ngx.shared.free_waf_drop_ip:set(ip,9,30)
            assert(response(drop)==403); server_name='b.example'; assert(response(drop)==403)
            assert(ngx.shared.free_waf_drop_ip:ttl(ip)==30)
            now=1030; assert(response(drop)==200)
        ''')

    def test_site_ban_survives_retry_setting_changes_until_expiry(self):
        self.run_lua('''
            limit=0; assert(response(cc)==403); retry=100
            assert(response(drop)==403,'changing retry disabled an active CC ban')
            now=1060; assert(response(drop)==200)
        ''')

    def test_listing_and_targeted_unban_preserve_other_clients(self):
        self.run_lua('''
            limit=0; assert(response(cc)==403)
            server_name='b.example'; assert(response(cc)==403)
            ip='192.0.2.2'; assert(response(cc)==403)
            local rows=get_btwaf_drop_ip(); table.sort(rows)
            assert(#rows==2 and rows[1]=='192.0.2.1' and rows[2]=='192.0.2.2','scoped CC bans missing from list')
            ngx.shared.free_waf_drop_ip:set('cc:v3:ban:999:bad:192.0.2.1',9,60)
            assert(remove_btwaf_drop_ip().status)
            ip='192.0.2.1'; assert(response(drop)==200); server_name='a.example'; assert(response(drop)==200)
            server_name='b.example'; ip='192.0.2.2'; assert(response(drop)==403)
            assert(ngx.shared.free_waf_drop_ip:get('cc:v3:ban:999:bad:192.0.2.1')==9)
        ''')

    def test_manual_unban_matches_legacy_ipv6_spellings_without_aliasing_ipv4(self):
        self.run_lua('''
            local expanded='2001:0DB8:0:0:0:0:0:1'
            local compressed='2001:db8::1'
            ngx.shared.free_waf_drop_ip:set(expanded,9,30)
            ngx.shared.free_waf_drop_ip:set(compressed,9,30)
            ngx.shared.free_waf_drop_ip:set('2001:db8::2',9,30)
            ngx.shared.free_waf_drop_ip:set('192.0.2.1',9,30)
            ngx.shared.free_waf_drop_ip:set('::ffff:192.0.2.1',9,30)
            uri_request_args.ip=compressed
            assert(remove_btwaf_drop_ip().status)
            ip=expanded; assert(response(drop)==200,'equivalent legacy IPv6 ban survived unban')
            ip=compressed; assert(response(drop)==200)
            ip='2001:db8::2'; assert(response(drop)==403,'unrelated IPv6 ban was removed')
            uri_request_args.ip='::ffff:c000:201'
            assert(remove_btwaf_drop_ip().status)
            ip='::ffff:192.0.2.1'; assert(response(drop)==200)
            ip='192.0.2.1'; assert(response(drop)==403,'mapped IPv6 unban cleared IPv4')
        ''')

    def test_mixed_cc_history_preserves_previous_retry_semantics_and_independent_events(self):
        self.run_lua('''
            endtime=1
            assert(response(cc)==200 and response(cc)==403)
            assert(events==1)
            now=1002; assert(response(drop)==200)
            for i=1,3 do assert(response(cc2)==200) end
            assert(response(cc2)==429,'existing first enhanced retry changed')
            assert(events==1,'verification was counted as an independent ban')
            assert(response(cc2)==403 and events==2)
            assert(response(cc2)==403 and events==2,'overlap counted as a new ban')
        ''')

    def test_clean_all_removes_cc_bans_and_histories_without_touching_unknown_keys(self):
        self.run_lua('''
            limit=0; assert(response(cc)==403)
            server_name='b.example'; ip='::ffff:192.0.2.1'; assert(response(cc)==403)
            assert(#ngx.shared.free_waf_drop_sum:get_keys()>0)
            ngx.shared.free_waf_drop_sum:set('unrelated',5,60)
            assert(clean_btwaf_drop_ip().status)
            assert(#get_btwaf_drop_ip()==0,'clean all left scoped CC bans active')
            assert(response(drop)==200)
            local keys=ngx.shared.free_waf_drop_sum:get_keys()
            assert(#keys==1 and keys[1]=='unrelated','clean all left scoped CC history')
        ''')

    def test_scoped_key_parser_requires_exact_boundaries_and_valid_addresses(self):
        self.run_lua('''
            local site='a:child'
            local key=cc_state_key('ban',site,'::ffff:192.0.2.1')
            local scope,address=cc_state_identity(key,'ban')
            assert(scope==site and address=='::ffff:c000:201')
            for _,bad in ipairs({'cc:v3:ban:0::192.0.2.1',
                'cc:v3:ban:01:a:192.0.2.1','cc:v3:ban:999:a:192.0.2.1',
                'cc:v3:ban:1:a:192.0.2.1:extra','cc:v3:counter:1:a:192.0.2.1',
                'cc:v3:ban:1:a:999.0.0.1'}) do
                assert(cc_state_identity(bad)==nil,'accepted malformed CC key: '..bad)
            end
            assert(cc_state_identity(key,'history')==nil)
        ''')

    def test_overlapping_ban_does_not_extend_expiry_or_repeat_escalation(self):
        self.run_lua('''
            limit=0; assert(response(cc)==403)
            local key=cc_state_key('ban',server_name,ip)
            now=1010; assert(response(cc)==403)
            assert(events==1,'overlapping request counted as independent ban')
            assert(ngx.shared.free_waf_drop_ip:ttl(key)==50,'overlap extended ban')
            now=1060; assert(response(drop)==200)
        ''')


if __name__ == '__main__':
    unittest.main()
