'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { harness, html } = require('./test_statistics_v011');

test('console has grouped horizontal navigation and real keyboard buttons', () => {
  assert.match(html, /class="waf-section-tabs"/);
  for (const section of ['overview', 'protection', 'access', 'observation', 'maintenance']) {
    assert.match(html, new RegExp('<button[^>]*data-section="' + section + '"'));
  }
  assert.match(html, /<li[^>]*data-target="statistics"[^>]*>\s*<button/);
  assert.match(html, /\.waf_conter\s*\{[^}]*display:flex[^}]*flex-direction:column/);
});

test('navigation synchronizes page, section and previous page without extra reads', () => {
  const h = harness();
  h.waf.refresh_data_total('statistics');
  assert.equal(h.waf._section_last.observation, 'statistics');
  assert.equal(h.$('.waf-section-tabs button[data-section="observation"]').attr('aria-pressed'), 'true');
  assert.equal(h.$('.waf_left_menu li[data-section="observation"]').prop('hidden'), false);
  assert.equal(h.$('.waf_left_menu li[data-target="statistics"] button').attr('aria-current'), 'page');
  assert.equal(h.of('get_website_statistics_summary').length, 1);
  const before = h.requests.length;
  assert.equal(h.waf.section_page('observation'), 'statistics');
  assert.equal(h.waf.section_page('protection'), 'site');
  assert.equal(h.waf.section_page('untrusted'), null);
  assert.equal(h.requests.length, before);
});

test('configured open never claims an enabled firewall or triggers an automatic check', () => {
  const h = harness();
  h.of('get_total_all')[0].resolve({open:true,safe_day:0,total:{total:0,rules:[]}});
  assert.doesNotMatch(h.$('#overview_dashboard_shield .waf-shield-title').text(), /已启用|已生效/);
  assert.match(h.$('#waf_shell_status').text(), /待核验/);
  assert.equal(h.of('get_runtime_status').length, 0);
  assert.match(h.$('#waf_config_status').text(), /开启/);
});

test('manual inspection separates missing integration from matching configuration', () => {
  const h = harness();
  h.waf.inspect_runtime_status();
  const request = h.of('get_runtime_status').at(-1);
  assert.ok(request);
  request.resolve({status:true,configured_open:true,integration:'missing',execution_verified:false});
  assert.match(h.$('#waf_shell_status').text(), /未接入/);
  assert.match(h.$('#runtime_status_detail').text(), /未发现.*不能据此认为防护已生效/);
  h.waf.inspect_runtime_status();
  h.of('get_runtime_status').at(-1).resolve({status:true,configured_open:true,integration:'configured',execution_verified:false});
  assert.match(h.$('#waf_shell_status').text(), /配置已接入/);
  assert.match(h.$('#runtime_status_detail').text(), /不代表/);
  assert.doesNotMatch(h.$('#overview_dashboard_shield .waf-shield-title').text(), /防火墙已启用/);
});

test('failed inspection is retryable and cannot retain a green success state', () => {
  const h = harness();
  h.waf.inspect_runtime_status();
  h.of('get_runtime_status').at(-1).resolve({status:true,configured_open:true,integration:'configured'});
  h.waf.inspect_runtime_status();
  h.of('get_runtime_status').at(-1).reject();
  assert.match(h.$('#waf_shell_status').text(), /未确认/);
  assert.equal(h.$('#runtime_status_refresh').prop('disabled'), false);
});

test('home reload invalidates an earlier inspection and close aborts pending checks', () => {
  const h = harness();
  h.waf.inspect_runtime_status();
  const earlier = h.of('get_runtime_status').at(-1);
  h.waf.refresh_data_total('home');
  assert.ok(earlier.aborted);
  h.of('get_total_all').at(-1).resolve({open:false,total:{total:0,rules:[]}});
  earlier.options.success({status:true,configured_open:true,integration:'configured'});
  assert.match(h.$('#waf_shell_status').text(), /关闭/);
  h.waf.inspect_runtime_status();
  const pending = h.of('get_runtime_status').at(-1);
  h.close();
  assert.ok(pending.aborted);
});

test('late home failures and malformed responses cannot overwrite a newer inspection', () => {
  for (const response of ['transport', 'malformed']) {
    const h = harness(), home = h.of('get_total_all')[0];
    h.waf.inspect_runtime_status();
    h.of('get_runtime_status').at(-1).resolve({status:true,configured_open:true,integration:'configured'});
    if (response === 'transport') home.reject();
    else home.resolve({status:false});
    assert.match(h.$('#waf_shell_status').text(), /配置已接入/);
  }
});

test('failed inspection still applies its fresh boolean configuration evidence', () => {
  const h = harness();
  h.of('get_total_all')[0].resolve({open:false,total:{total:0,rules:[]}});
  h.waf.inspect_runtime_status();
  h.of('get_runtime_status').at(-1).resolve({status:false,configured_open:true,integration:'unknown'});
  assert.match(h.$('#waf_config_status').text(), /开启/);
  assert.match(h.$('#waf_shell_status').text(), /未确认/);
  assert.equal(h.$('.swicth_container').attr('data-type'), 1);
});

test('an older home response cannot desynchronize the master switch from a newer inspection', () => {
  const h = harness(), home = h.of('get_total_all')[0];
  h.waf.inspect_runtime_status();
  h.of('get_runtime_status').at(-1).resolve({status:true,configured_open:true,integration:'configured'});
  home.resolve({open:false,total:{total:0,rules:[]}});
  assert.match(h.$('#waf_config_status').text(), /开启/);
  assert.equal(h.$('.swicth_container').attr('data-type'), 1);
});

test('master switch binding and state updates cannot target the site configuration switch', () => {
  assert.match(html, /class="switch-wrapper" id="waf_master_switch"/);
  assert.match(html, /\$\('#waf_master_switch'\)\.off\('click\.free_waf'\)/);
  assert.doesNotMatch(html, /set_swicth_view\('\.switch-wrapper'/);
  const h = harness();
  h.fire('.switch-wrapper');
  assert.equal(h.of('set_open').length, 0);
  h.fire('#waf_master_switch');
  assert.equal(h.of('set_open').length, 1);
});

test('repair is never automatic and requires a preview plus explicit confirmation', () => {
  const h=harness();
  assert.equal(h.of('get_integration_repair_plan').length,0);
  assert.equal(h.of('repair_nginx_integration').length,0);
  assert.equal(typeof h.waf.begin_integration_repair,'function');
  h.waf.begin_integration_repair();
  h.of('get_integration_repair_plan').at(-1).resolve({status:true,can_repair:true,revision:'a'.repeat(64),configured_open:true,enabled_sites:3});
  assert.equal(h.of('repair_nginx_integration').length,0);
  assert.match(h.confirms.at(-1).message,/3/);
  h.confirms.at(-1).yes(1);
  const write=h.of('repair_nginx_integration').at(-1);
  assert.equal(write.options.type,'POST');
  assert.equal(write.options.data.revision,'a'.repeat(64));
  assert.equal(write.options.data.confirmation,'REPAIR_NGINX_INTEGRATION');
});

test('one-click repair is the last diagnostic tool, never a header action', () => {
  const header = html.match(/<header class="waf-shell-header">([\s\S]*?)<\/header>/)[1];
  const tools = html.split('<div class="item_con" data-type="webshell">')[1]
    .split('<div class="item_con" data-type="history">')[0];
  assert.doesNotMatch(header, /runtime_repair_start/);
  assert.match(header, /runtime_status_refresh/);
  assert.match(tools, /<span>一键修复<\/span>\s*<\/div>/);
  const repair = tools.split('data-type="integration_repair"')[1];
  assert.ok(repair, 'repair needs its own final tools tab');
  assert.match(repair, /<button[^>]*id="runtime_repair_start"[^>]*>一键修复<\/button>/);
  assert.match(repair, /id="runtime_repair_result"[^>]*role="status"/);
  assert.doesNotMatch(repair, /class="waf_nav_item"/);
  assert.equal((html.match(/id="runtime_repair_start"/g) || []).length, 1);
  assert.equal((html.match(/id="runtime_repair_result"/g) || []).length, 1);
});

test('cancelled or stale repair confirmation cannot activate anything',()=>{
  const h=harness();
  h.waf.begin_integration_repair();
  h.of('get_integration_repair_plan').at(-1).resolve({status:true,can_repair:true,revision:'b'.repeat(64),enabled_sites:1});
  h.confirms.at(-1).cancel();
  assert.equal(h.of('repair_nginx_integration').length,0);
  assert.equal(h.$('#runtime_repair_start').prop('disabled'),false);
  h.waf.begin_integration_repair();
  h.of('get_integration_repair_plan').at(-1).resolve({status:true,can_repair:true,revision:'c'.repeat(64),enabled_sites:1});
  const confirmation=h.confirms.at(-1);
  h.close(); confirmation.yes(1);
  assert.equal(h.of('repair_nginx_integration').length,0);
});

test('repair failures stay literal and cannot display successful protection',()=>{
  const h=harness();
  h.waf.begin_integration_repair();
  h.of('get_integration_repair_plan').at(-1).resolve({status:false,msg:'<script>secret</script>'});
  assert.equal(h.confirms.length,0);
  assert.equal(h.$('#runtime_repair_result').text(),'<script>secret</script>');
  assert.equal(h.$('#runtime_repair_start').prop('disabled'),false);
});

test('a local Lua probe never claims every site is protected',()=>{
  const h=harness();
  h.waf.render_runtime_status({status:true,configured_open:true,integration:'configured',execution_verified:true,verification_scope:'local_health_probe'});
  assert.match(h.$('#waf_shell_status').text(),/本机接入已验证/);
  assert.match(h.$('#runtime_status_detail').text(),/不代表全部站点/);
  h.waf.render_runtime_status({status:true,configured_open:false,integration:'configured',execution_verified:true,verification_scope:'local_health_probe'});
  assert.match(h.$('#waf_shell_status').text(),/关闭/);
});

test('double confirmation cannot start two repairs and a late inspection cannot erase proof',()=>{
  const h=harness();
  h.waf.begin_integration_repair();
  h.of('get_integration_repair_plan').at(-1).resolve({status:true,can_repair:true,revision:'a'.repeat(64),enabled_sites:1});
  const dialog=h.confirms.at(-1); dialog.yes(1); dialog.yes(1);
  assert.equal(h.of('repair_nginx_integration').length,1);
  h.waf.inspect_runtime_status();
  const stale=h.of('get_runtime_status').at(-1);
  h.of('repair_nginx_integration').at(-1).resolve({status:true,configured_open:true,integration:'configured',execution_verified:true,verification_scope:'local_health_probe',msg:'修复完成'});
  stale.options.success({status:true,configured_open:true,integration:'missing'});
  assert.match(h.$('#waf_shell_status').text(),/本机接入已验证/);
});
