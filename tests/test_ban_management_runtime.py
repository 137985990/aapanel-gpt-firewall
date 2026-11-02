"""Run the new loopback snapshot in embedded LuaJIT, without an Nginx process."""
import re
import unittest
from pathlib import Path

from tests import test_cc_scope as fixtures


class BanManagementRuntimeTest(unittest.TestCase):
    def setUp(self):
        fixtures.CCScopeTest.setUp(self)
        self.source = (Path(__file__).resolve().parents[1] / 'init.lua').read_text(encoding='utf-8')
        found = re.search(r'(?m)^function registration_guard_state_key\(.*?\nend', self.source, re.S)
        self.lua.execute(found.group(0))
        self.lua.execute('''
            ngx.time=function() return now end; ngx.now=ngx.time
            config.open=true; config.retry=6; config.cc.open=true
            site_config['a.example'].open=true; site_config['b.example'].open=true
            ip_white_rules={}
            manual_site_ban_state={valid=true,policy_signature=string.rep('d',32),
                snapshot={revision=string.rep('e',32),entries={}}}
            repeat_ban_cache={}
            ngx.md5=function(value) return value end
            ngx.req={get_method=function() return 'POST' end}
            repeat_ban_snapshot=function() error('read must not initialize repeat state') end
            repeat_ban_rows=function() error('read must not initialize repeat state') end
        ''')

    def load(self):
        names = ('ban_management_registration_identity', 'ban_management_enforcement',
                 'get_active_bans_runtime', 'remove_active_ban_runtime', 'ban_management_response')
        for name in names:
            found = re.search(r'(?m)^function ' + name + r'\(.*?\nend', self.source, re.S)
            self.assertIsNotNone(found, name + ' runtime API missing')
            self.lua.execute(found.group(0))

    def test_snapshot_is_scoped_and_does_not_mutate_shared_memory(self):
        self.load()
        self.lua.execute('''
            local key=cc_state_key('ban','a.example',ip)
            ngx.shared.free_waf_drop_ip:set(key,1,60)
            ngx.shared.free_waf_drop_ip:set(ip,2,60) -- retry counter, not yet a ban
            local view=get_active_bans_runtime()
            assert(#view.rows==2)
            local active,disabled=0,0
            for _,row in ipairs(view.rows) do
                if row.source=='cc' then
                    assert(row.site=='a.example' and row.scope=='site')
                    assert(row.expires_at==1060 and row.enforcement=='active')
                    active=active+1
                elseif row.source=='legacy' then
                    assert(row.enforcement=='disabled'); disabled=disabled+1
                end
            end
            assert(active==1 and disabled==1)
            assert(ngx.shared.free_waf_drop_ip:get(key)==1)
            assert(ngx.shared.free_waf_drop_ip:get(ip)==2)
        ''')

    def test_ttl_unknown_disabled_site_and_expiry_are_honest(self):
        self.load()
        self.lua.execute('''
            ngx.shared.free_waf_drop_ip:set(cc_state_key('ban','a.example',ip),1)
            site_config['a.example'].open=false
            local row=get_active_bans_runtime().rows[1]
            assert(row.enforcement=='disabled' and row.expires_at==nil)
            site_config['a.example'].open=true
            ngx.shared.free_waf_drop_ip.ttl=function() error('unsupported') end
            row=get_active_bans_runtime().rows[1]
            assert(row.enforcement=='active' and row.expires_at==nil)
            ngx.shared.free_waf_drop_ip:set(cc_state_key('ban','b.example',ip),1,1)
            now=1002
            assert(#get_active_bans_runtime().rows==1)
        ''')

    def test_registration_shared_scope_is_not_claimed_site_only_or_removable(self):
        self.load()
        self.lua.execute('''
            for _,site in ipairs({'a.example','b.example'}) do
                site_config[site].registration_guard={open=true,scope='shared'}
            end
            ngx.shared.free_waf:set(registration_guard_state_key('ban','shared',ip),1,60)
            local view=get_active_bans_runtime()
            assert(#view.rows==1)
            assert(view.rows[1].site=='' and view.rows[1].scope=='global')
            assert(view.rows[1].enforcement=='unknown' and not view.rows[1].removable)
            assert(view.coverage.partial)
        ''')

    def test_remove_checks_revision_and_only_deletes_one_key_without_counters(self):
        self.load()
        self.lua.execute('''
            local a=cc_state_key('ban','a.example',ip)
            local b=cc_state_key('ban','b.example',ip)
            ngx.shared.free_waf_drop_ip:set(a,1,60); ngx.shared.free_waf_drop_ip:set(b,1,60)
            local row=get_active_bans_runtime().rows[1]
            uri_request_args={id=row.runtime_id,revision='stale'}
            assert(remove_active_ban_runtime().status==false)
            assert(ngx.shared.free_waf_drop_ip:get(a)==1 and ngx.shared.free_waf_drop_ip:get(b)==1)
            uri_request_args.revision=row.runtime_revision
            assert(remove_active_ban_runtime().status==true)
            assert(#get_active_bans_runtime().rows==1)
            assert(ngx.shared.free_waf_drop_ip:get(a) or ngx.shared.free_waf_drop_ip:get(b))
            ngx.req.get_method=function() return 'GET' end
            assert(remove_active_ban_runtime().status==false)
        ''')

    def test_loopback_routes_precede_health_host_and_never_replace_legacy(self):
        self.load()
        route = re.search(r'(?m)^function min_route\(.*?\nend', self.source, re.S).group(0)
        self.assertLess(route.index("remote_addr ~= '127.0.0.1'"), route.index('/get_active_bans_runtime'))
        self.assertLess(route.index('/get_active_bans_runtime'), route.index("server_name == 'gpt-firewall-health.invalid'"))
        self.assertIn("uri == '/get_btwaf_drop_ip'", route)

    def test_legacy_different_site_retry_thresholds_are_not_falsely_disabled(self):
        self.load()
        self.lua.execute('''
            site_config['a.example'].retry=1; site_config['b.example'].retry=6
            ngx.shared.free_waf_drop_ip:set(ip,2,60)
            assert(get_active_bans_runtime().rows[1].enforcement=='unknown')
        ''')

    def test_registration_aliases_are_not_misrepresented_as_one_site(self):
        self.load()
        self.lua.execute('''
            site_config['a.example'].registration_guard={open=true,scope='guard',aliases={'b.example'}}
            ngx.shared.free_waf:set(registration_guard_state_key('ban','guard',ip),1,60)
            local row=get_active_bans_runtime().rows[1]
            assert(row.enforcement=='unknown' and row.removable==false)
        ''')

    def test_whitelisted_and_cached_persistent_sources_are_observed_without_counter_writes(self):
        self.load()
        self.lua.execute('''
            ip_white_rules={{{192,0,2,1},{192,0,2,1}}}
            manual_site_ban_state.snapshot.entries={{site='a.example',ip=ip,started_at=900,expires_at=1100,reason='risk_advice'}}
            ip_black_rules={{{192,0,2,1},{192,0,2,1},1100},{{198,51,100,0},{198,51,100,255}}}
            local view=get_active_bans_runtime()
            assert(#view.rows==2 and view.coverage.range_entries==1)
            for _,row in ipairs(view.rows) do assert(row.enforcement=='disabled') end
        ''')

    def test_new_routes_are_not_available_on_ordinary_loopback_vhost(self):
        self.load()
        found = re.search(r'(?m)^function min_route\(.*?\nend', self.source, re.S)
        self.lua.execute(found.group(0))
        self.lua.execute('''
            ngx.var.remote_addr='127.0.0.1'; ngx.var.server_name='a.example'
            uri='/get_active_bans_runtime'
            ban_management_response=function() error('must require dedicated listener host') end
            assert(min_route()==false)
        ''')

    def test_unknown_default_vhost_prevents_global_false_disabled_claim(self):
        self.load()
        self.lua.execute('''
            site_config['a.example'].open=false; site_config['b.example'].open=false
            ip_black_rules={{{192,0,2,1},{192,0,2,1},1100}}
            assert(get_active_bans_runtime().rows[1].enforcement=='unknown')
        ''')

    def test_legacy_retry_also_accounts_for_default_vhost_threshold(self):
        self.load()
        self.lua.execute('''
            config.retry=1
            site_config['a.example'].retry=6; site_config['b.example'].retry=6
            ngx.shared.free_waf_drop_ip:set(ip,2,60)
            assert(get_active_bans_runtime().rows[1].enforcement=='unknown')
        ''')

    def test_unavailable_ttl_cannot_offer_stale_unsafe_removal(self):
        self.load()
        self.lua.execute('''
            ngx.shared.free_waf_drop_ip:set(cc_state_key('ban','a.example',ip),1,60)
            ngx.shared.free_waf_drop_ip.ttl=function() error('unsupported') end
            local row=get_active_bans_runtime().rows[1]
            assert(row.enforcement=='active' and row.removable==false and row.expires_at==nil)
        ''')

    def test_full_lua_source_compiles(self):
        compiled = self.lua.eval('loadstring')(self.source)
        self.assertTrue(callable(compiled), str(compiled))


if __name__ == '__main__':
    unittest.main()
