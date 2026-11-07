'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { harness, html } = require('./test_statistics_v011');

test('console has grouped horizontal navigation and real keyboard buttons', () => {
  assert.match(html, /class="waf-section-tabs"/);
  for (const section of ['overview', 'protection', 'events', 'statistics', 'maintenance']) {
    assert.match(html, new RegExp('<button[^>]*data-section="' + section + '"'));
  }
  assert.match(html, /<li[^>]*data-target="statistics"[^>]*>\s*<button/);
  assert.match(html, /\.waf_conter\s*\{[^}]*display:flex[^}]*flex-direction:column/);
});

test('navigation synchronizes page, section and previous page without extra reads', () => {
  const h = harness();
  h.waf.refresh_data_total('statistics');
  assert.equal(h.waf._section_last.statistics, 'statistics');
  assert.equal(h.$('.waf-section-tabs button[data-section="statistics"]').attr('aria-pressed'), 'true');
  assert.equal(h.$('.waf_left_menu li[data-section="statistics"]').prop('hidden'), false);
  assert.equal(h.$('.waf_left_menu li[data-target="statistics"] button').attr('aria-current'), 'page');
  assert.equal(h.of('get_website_statistics_summary').length, 1);
  const before = h.requests.length;
  assert.equal(h.waf.section_page('statistics'), 'statistics');
  assert.equal(h.waf.section_page('protection'), 'site');
  assert.equal(h.waf.section_page('untrusted'), null);
  assert.equal(h.requests.length, before);
});

test('historical endpoint bans remain visible with a retired-feature label and unchanged data', () => {
  const h = harness();
  const rows = [[1792700000, '192.0.2.1', 'a.example', '/login', 60, 'endpoint_limit', false]];
  const original = JSON.stringify(rows);
  let table;
  h.waf.refresh_table_view = options => { table = options; };
  h.waf.render_history_data();
  h.of('get_safe_logs').at(-1).resolve(rows);
  assert.equal(table.el, '#history_table');
  assert.strictEqual(table.data, rows);
  assert.equal(table.config.find(column => column.fid === '3').templet(rows[0]), '历史接口限流');
  assert.equal(h.waf.repeat_ban_reason('endpoint_limit'), '历史接口限流');
  assert.equal(JSON.stringify(rows), original);
  assert.deepEqual(h.requests.slice(2).map(request => request.method), ['get_safe_logs']);
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

test('missing integration confirmation describes entry creation without installing dependencies', () => {
  const h = harness();
  h.waf.begin_integration_repair();
  const plan = {status:true,can_repair:true,repair_kind:'missing',integration:'missing',
    revision:'a'.repeat(64),configured_open:true,enabled_sites:3};
  const original = JSON.stringify(plan);
  h.of('get_integration_repair_plan').at(-1).resolve(plan);
  const dialog = h.confirms.at(-1);
  assert.match(dialog.message, /缺失.*接入入口/);
  assert.doesNotMatch(dialog.message, /当前.*Lua 依赖搜索路径缺失/);
  assert.match(dialog.message, /配置总开关.*开启/);
  assert.match(dialog.message, /3 个站点/);
  assert.match(dialog.message, /不会下载或安装依赖/);
  assert.match(dialog.message, /不会修改.*规则/);
  assert.equal(JSON.stringify(plan), original);
  assert.equal(h.of('repair_nginx_integration').length, 0);
  dialog.yes(1);
  assert.equal(h.of('repair_nginx_integration').length, 1);
  assert.equal(h.of('repair_nginx_integration')[0].options.data.revision, plan.revision);
});

test('Lua search path confirmation limits changes to the managed include and new-worker proof', () => {
  const h = harness();
  h.waf.begin_integration_repair();
  h.of('get_integration_repair_plan').at(-1).resolve({status:true,can_repair:true,
    repair_kind:'lua_path_missing',integration:'lua_path_missing',revision:'b'.repeat(64),
    configured_open:true,enabled_sites:2});
  const dialog = h.confirms.at(-1);
  assert.match(dialog.message, /Lua 依赖搜索路径缺失/);
  assert.match(dialog.message, /受管包含文件.*Lua 搜索路径/);
  assert.doesNotMatch(dialog.message, /补齐缺失.*入口/);
  assert.match(dialog.message, /不修改 nginx\.conf 或启动脚本/);
  assert.match(dialog.message, /短时 Nginx 初始化进程.*隔离依赖检查.*不监听端口.*不执行生产 Lua 初始化/);
  assert.match(dialog.message, /不会下载或安装依赖/);
  assert.match(dialog.message, /不会修改.*规则/);
  assert.match(dialog.message, /平滑重载.*新工作进程.*本机健康/);
  assert.match(dialog.message, /排除重载前的工作进程 PID/);
  assert.match(dialog.message, /其他 lua_package_path 指令.*冲突.*拒绝.*不删除/);
  assert.match(dialog.message, /重载前.*编译或预检失败.*恢复原文件.*不发送重载信号/);
  assert.match(dialog.message, /已尝试重载.*验证失败.*仅恢复原包含文件字节到磁盘.*运行状态未验证/);
  assert.match(dialog.message, /仅恢复.*磁盘.*运行状态未验证.*人工/);
  assert.equal(h.of('repair_nginx_integration').length, 0);
  dialog.yes(1);
  const write = h.of('repair_nginx_integration').at(-1);
  assert.equal(write.options.type, 'POST');
  assert.equal(write.options.data.revision, 'b'.repeat(64));
  assert.equal(write.options.data.confirmation, 'REPAIR_NGINX_INTEGRATION');
});

test('an undefined repair kind keeps the legacy missing-entry confirmation', () => {
  const h = harness();
  h.waf.begin_integration_repair();
  h.of('get_integration_repair_plan').at(-1).resolve({status:true,can_repair:true,
    revision:'c'.repeat(64),enabled_sites:1});
  assert.match(h.confirms.at(-1).message, /缺失.*接入入口/);
  assert.equal(h.of('repair_nginx_integration').length, 0);
  h.confirms.at(-1).cancel();
  assert.equal(h.$('#runtime_repair_start').prop('disabled'), false);
});

test('unknown repair kinds are refused without HTML interpolation or a write', () => {
  const unsafe = '<img src=x onerror=alert(1)>';
  for (const kind of [unsafe, '__proto__', 'constructor', 'toString', '', null, 7, {}, ['missing']]) {
    const h = harness();
    h.waf.begin_integration_repair();
    h.of('get_integration_repair_plan').at(-1).resolve({status:true,can_repair:true,
      repair_kind:kind,integration:'missing',revision:'d'.repeat(64),enabled_sites:1,msg:unsafe});
    assert.equal(h.confirms.length, 0, 'unknown kind must not open a confirmation');
    assert.equal(h.of('repair_nginx_integration').length, 0);
    assert.match(h.$('#runtime_repair_result').text(), /未知的修复类型.*未修改/);
    assert.doesNotMatch(h.$('#runtime_repair_result').text(), /<img|onerror/);
    assert.equal(h.$('#runtime_repair_result').html(), '');
    assert.equal(h.$('#runtime_repair_start').prop('disabled'), false);
    assert.equal(h.waf._repair_busy, false);
  }
});

test('both repair kinds require a successful preview and a 64-character revision', () => {
  for (const kind of ['missing', 'lua_path_missing']) {
    for (const invalid of [{status:false}, {can_repair:false}, {revision:''},
      {revision:'e'.repeat(63)}, {revision:'e'.repeat(65)}, {revision:'z'.repeat(64)}]) {
      const h = harness();
      h.waf.begin_integration_repair();
      h.of('get_integration_repair_plan').at(-1).resolve({status:true,can_repair:true,
        repair_kind:kind,integration:kind,revision:'e'.repeat(64),...invalid});
      assert.equal(h.confirms.length, 0);
      assert.equal(h.of('repair_nginx_integration').length, 0);
      assert.equal(h.$('#runtime_repair_start').prop('disabled'), false);
    }
  }
});

test('repair confirmation preserves the global switch and sanitizes the enabled-site count', () => {
  for (const configured of [true, false, undefined]) {
    const h = harness();
    h.waf.begin_integration_repair();
    h.of('get_integration_repair_plan').at(-1).resolve({status:true,can_repair:true,
      repair_kind:'lua_path_missing',integration:'lua_path_missing',revision:'f'.repeat(64),
      configured_open:configured,enabled_sites:'<img src=x onerror=alert(1)>'});
    const dialog = h.confirms.at(-1);
    assert.match(dialog.message, /0 个站点/);
    assert.doesNotMatch(dialog.message, /<img|onerror/);
    assert.match(dialog.message, configured === true ? /配置总开关.*开启/
      : configured === false ? /配置总开关.*关闭/ : /配置总开关状态未确认/);
    assert.match(dialog.message, /不会开启总开关/);
    assert.doesNotMatch(dialog.message, /原有已开启规则会开始拦截请求/);
    dialog.cancel();
    assert.equal(h.of('repair_nginx_integration').length, 0);
    assert.equal(h.of('set_open').length, 0);
  }
});

test('Lua path repair cancellation, duplicate confirmation and stale callbacks remain inert', () => {
  const h = harness();
  const plan = {status:true,can_repair:true,repair_kind:'lua_path_missing',integration:'lua_path_missing',
    revision:'a'.repeat(64),configured_open:true,enabled_sites:1};
  h.waf.begin_integration_repair();
  h.waf.begin_integration_repair();
  assert.equal(h.of('get_integration_repair_plan').length, 1);
  h.of('get_integration_repair_plan').at(-1).resolve(plan);
  const cancelled = h.confirms.at(-1);
  cancelled.cancel();
  h.waf.begin_integration_repair();
  cancelled.yes(1);
  assert.equal(h.of('repair_nginx_integration').length, 0);
  h.of('get_integration_repair_plan').at(-1).resolve(plan);
  const dialog = h.confirms.at(-1);
  dialog.yes(1);
  dialog.yes(1);
  assert.equal(h.of('repair_nginx_integration').length, 1);
  h.close();
  dialog.yes(1);
  assert.equal(h.of('repair_nginx_integration').length, 1);
});

test('failed Lua repair keeps disk-only recovery warnings literal and never reports protection', () => {
  const h = harness();
  h.waf.begin_integration_repair();
  h.of('get_integration_repair_plan').at(-1).resolve({status:true,can_repair:true,
    repair_kind:'lua_path_missing',integration:'lua_path_missing',revision:'b'.repeat(64),enabled_sites:1});
  h.confirms.at(-1).yes(1);
  const message = '旧配置仅恢复到磁盘，运行状态未验证，需人工恢复。<img src=x onerror=alert(1)>';
  h.of('repair_nginx_integration').at(-1).resolve({status:false,recovery_required:true,msg:message});
  assert.equal(h.$('#runtime_repair_result').text(), message);
  assert.equal(h.$('#runtime_repair_result').html(), '');
  assert.match(h.$('#waf_shell_status').text(), /未确认/);
  assert.doesNotMatch(h.$('#waf_shell_status').text(), /已验证|已启用|已生效/);
  assert.equal(h.of('repair_nginx_integration').length, 1);
});

test('repair tools explain Lua path limits and do not promise automatic runtime recovery', () => {
  const repair = html.split('<div class="waf_nav_item" data-type="integration_repair">')[1]
    .split('<div class="item_con" data-type="history">')[0];
  assert.match(repair, /Lua 依赖搜索路径缺失/);
  assert.match(repair, /已知旧版接入文件/);
  assert.match(repair, /未知.*自定义.*冲突.*拒绝/);
  assert.match(repair, /不会下载或安装依赖/);
  assert.match(repair, /受管包含文件.*Lua 搜索路径/);
  assert.match(repair, /不修改 nginx\.conf 或启动脚本/);
  assert.match(repair, /短时 Nginx 初始化进程.*隔离依赖检查.*不监听端口.*不执行生产 Lua 初始化/);
  assert.match(repair, /新工作进程.*本机健康/);
  assert.match(repair, /排除重载前的工作进程 PID/);
  assert.match(repair, /其他 lua_package_path 指令.*冲突.*拒绝.*不删除/);
  assert.match(repair, /重载前.*编译或预检失败.*恢复原文件.*不发送重载信号/);
  assert.match(repair, /已尝试重载.*验证失败.*仅恢复原包含文件字节到磁盘.*运行状态未验证/);
  assert.match(repair, /仅恢复.*磁盘.*运行状态未验证.*人工/);
});

test('current Chinese repair documentation records managed scope and disk-only recovery limits', () => {
  const sections = [
    ['docs/UPDATES.md', '## 手动一键修复接入'],
    ['docs/UPGRADE.md', '## 手动一键修复接入与 Lua 依赖路径'],
    ['CHANGELOG.md', '## v0.1.13（2026-11-02）'],
  ];
  for (const [file, heading] of sections) {
    const text = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
    assert.ok(text.includes(heading), file + ' needs its current repair section');
    const section = text.split(heading)[1].split('\n## ')[0].replace(/`/g, '');
    for (const boundary of [/Lua 依赖搜索路径缺失/, /已知旧版接入文件/,
      /未知.*自定义.*冲突.*拒绝/, /不会下载或安装依赖/,
      /受管包含文件.*Lua 搜索路径/, /不修改 nginx\.conf 或启动脚本/,
      /短时 Nginx 初始化进程.*隔离依赖检查.*不监听端口.*不执行生产 Lua 初始化/,
      /新工作进程.*本机健康/, /排除重载前的工作进程 PID/,
      /其他 lua_package_path 指令.*冲突.*拒绝.*不删除/,
      /重载前.*编译或预检失败.*恢复原文件.*不发送重载信号/,
      /已尝试重载.*验证失败.*仅恢复原包含文件字节到磁盘.*运行状态未验证/,
      /仅恢复.*磁盘.*运行状态未验证/, /recovery_required/]) {
      assert.match(section, boundary, file + ' must describe ' + boundary);
    }
  }
});

test('README explains the current managed Lua-path repair without promising generic fixes', () => {
  const readme = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
  assert.match(readme, /Lua 依赖搜索路径缺失/);
  assert.match(readme, /已知旧版受管接入文件/);
  assert.match(readme, /不会下载或安装依赖/);
  assert.doesNotMatch(readme, /不支持覆盖已有入口/);
  assert.doesNotMatch(readme, /不覆盖已有入口；/);
  const security = fs.readFileSync(path.join(__dirname, '..', 'SECURITY.md'), 'utf8');
  assert.match(security, /当前项目版本为 v0\.1\.15/);
  assert.match(security, /## v0\.1\.13 接入修复边界/);
  assert.match(security, /主进程.*权限.*所有者/);
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
