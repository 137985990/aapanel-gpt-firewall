'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { harness, html, report } = require('./test_statistics_v011');

function profiles(extra = {}) {
  return { schema_version: 1, request_count: 42, represented_requests: 37,
    omitted_requests: 5, partial: true, notice: 'Only retained request groups <bounded>', rows: [
      { country_code: 'US', country_name: 'United States', browser: 'Chrome', os: 'Windows', device: 'Desktop', client_type: 'browser', count: 12 },
      { country_code: 'CN', country_name: 'China', browser: 'WeChat', os: 'Android', device: 'Mobile', client_type: 'app', count: 10 },
      { country_code: '', country_name: '', browser: 'curl', os: 'Unknown', device: 'Unknown', client_type: 'api_tool', count: 8 },
      { country_code: 'JP', country_name: 'Japan', browser: 'Unknown', os: 'iOS', device: 'Tablet', client_type: 'unknown', count: 7 },
    ], ...extra };
}

function openProfiles(h, payload = profiles()) {
  h.navigate('statistics');
  h.stats().at(-1).resolve(report({ client_profiles: payload }));
  h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'clients' });
}

function site(h, name = 'a.example', extra = {}) {
  h.waf.refresh_table_view = options => options.done?.(options.data);
  h.waf._active_page = 'site';
  h.waf.set_site_config_view({ siteName: name });
  h.of('get_site_config_byname').at(-1).resolve({ open: false, cdn: true, top: {}, cc: { cycle: 60, limit: 100, endtime: 600 }, ...extra });
}

function prepareStrict(h, count = 0) {
  h.fire('#site_detail_cdn_strict');
  const read = h.of('get_site_cdn_trust_mode').at(-1);
  assert.ok(read, 'strict mode needs a fresh manual preview');
  read.resolve({ status: true, mode: 'legacy', trusted_proxy_count: count, notice: 'Current configuration only' });
  assert.ok(h.confirms.at(-1), 'strict mode needs confirmation');
  return h.confirms.at(-1);
}

function release(extra = {}) {
  return { status: true, current_version: '0.1.12', latest_version: '0.1.13', tag: 'v0.1.13',
    prerelease: false, available: true, checked_at: '2026-10-29 10:00:00', notes: 'Release <notes>', ...extra };
}

function checkUpdate(h, result) {
  h.fire('#plugin_update_check');
  h.of('check_plugin_update').at(-1).resolve(result);
}

test('v0.1.12 keeps every page in the five approved groups', () => {
  const buttons = [...html.matchAll(/<button type="button" data-section="([^"]+)"[^>]*>([^<]+)<\/button>/g)];
  assert.deepEqual(buttons.map(m => m[2]), ['总览', '网站防护', '安全事件', '访问统计', '系统与维护']);
  const groups = { home: 'overview', site: 'protection', overall: 'protection', repeat_ban: 'protection',
    blacklist: 'protection', whitelist: 'protection', history: 'events', ipstats: 'events', notification: 'events',
    statistics: 'statistics', logs: 'maintenance', updates: 'maintenance', task_manager: 'maintenance', webshell: 'maintenance' };
  const h = harness(), before = h.requests.length;
  for (const [page, group] of Object.entries(groups)) {
    assert.match(html, new RegExp('<li[^>]*data-target="' + page + '"[^>]*data-section="' + group + '"'));
    assert.equal(h.waf.panel_section(page), group);
    assert.equal(h.waf.sync_panel_navigation(page), true);
    assert.equal(h.waf.section_page(group), page);
    assert.ok(h.$('#waf_scope_badge').text(), 'every page explains its scope');
  }
  assert.equal(h.requests.length, before);
  assert.match(html, /data-version="0\.1\.12"/);
});

test('repair guidance uses the current navigation labels and keeps manual confirmation', () => {
  const group = html.match(/<button[^>]*data-section="maintenance"[^>]*>([^<]+)<\/button>/)[1];
  const page = html.match(/<li[^>]*data-target="webshell"[^>]*><button[^>]*>([^<]+)<\/button>/)[1];
  const action = html.match(/<button[^>]*id="runtime_repair_start"[^>]*>([^<]+)<\/button>/)[1];
  const guidance = html.match(/<p>缺少接入时，[\s\S]*?<\/p>/)[0];
  assert.ok(guidance.includes('“' + [group, page, action].join(' → ') + '”'));
  assert.match(guidance, /预览影响范围并确认后再修复/);
  assert.doesNotMatch(html, /(?:安全总览|防护配置|访问控制|观测分析|维护工具)\s*(?:→|&rarr;)/);
});

test('site and related configuration tables scroll locally instead of squeezing mobile controls', () => {
  const css = html.match(/<style[^>]*>([\s\S]*?)<\/style>/)[1];
  for (const id of ['site_table', 'overall_table', 'site_config_table', 'site_detail_rule_override_table',
    'site_detail_url_white_table', 'site_detail_url_rule_table', 'site_detail_url_tell_table',
    'site_detail_cdn_header_table', 'site_detail_cdn_proxy_table']) {
    const wrapper = html.match(new RegExp('<div(?=[^>]*id="' + id + '")[^>]*>'))[0];
    assert.match(wrapper, /class="[^"]*\bwaf-config-scroll\b[^"]*"/, id);
    assert.match(wrapper, /tabindex="0"/, id + ' must support keyboard scrolling');
    assert.match(wrapper, /aria-label="[^"]+"/, id + ' must identify its scroll region');
  }
  const scroll = css.match(/\.waf_conter \.waf-config-scroll\{([^}]+)\}/)[1];
  assert.match(scroll, /max-width:100%/);
  assert.match(scroll, /min-width:0/);
  assert.match(scroll, /overflow-x:auto/);
  assert.match(css, /\.waf_conter \.waf-config-scroll>table\{[^}]*min-width:620px/);
  assert.match(css, /\.waf_conter #site_table>table\{[^}]*min-width:860px/);
  assert.match(css, /\.waf_conter \.waf-config-scroll th[^}]*white-space:nowrap/);
  assert.match(css, /\.waf_conter #site_table td\{[^}]*white-space:nowrap[^}]*max-width:none/);
  assert.match(html, /窄屏可横向滚动表格/);
});

test('first paint stays at two reads with no force, scans or CDN requests', () => {
  const h = harness();
  assert.deepEqual(h.requests.map(r => r.method), ['get_total_all', 'get_overview_report']);
  for (const r of h.requests) assert.equal(r.options.data.force, undefined);
  assert.doesNotMatch(html, /<(?:script|link)[^>]+(?:src|href)=["']https?:/);
});

for (const [name, result] of [
  ['legacy failed defaults', release({ status: false, error: 'network unavailable', latest_version: '0.1.12', tag: '', checked_at: null, releases: [] })],
  ['error with success flag', release({ error: 'network unavailable' })],
  ['missing release identity', release({ latest_version: '0.1.12', tag: '', releases: [] })],
  ['unproven stale fields', release({ status: false, stale: true, error: 'network unavailable' })],
]) {
  test(`unavailable update metadata does not invent a release: ${name}`, () => {
    const h = harness(), original = JSON.stringify(result);
    checkUpdate(h, result);
    assert.equal(h.$('#plugin_update_current').text(), '0.1.12');
    assert.equal(h.$('#plugin_update_latest').text(), '未获取');
    assert.equal(h.$('#plugin_update_prerelease').text(), '未知');
    assert.equal(h.$('#plugin_update_checked').text(), '未获取');
    assert.equal(h.$('#plugin_update_start').prop('disabled'), true);
    assert.doesNotMatch(h.$('#plugin_update_status').text(), /发现可用更新|当前没有可用更新/);
    h.fire('#plugin_update_start');
    assert.equal(h.of('start_plugin_update').length, 0);
    assert.equal(JSON.stringify(result), original);
  });
}

for (const transport of [false, true]) {
  test(`failed update refresh keeps explicitly stale successful metadata (${transport ? 'transport' : 'API'})`, () => {
    const h = harness(); checkUpdate(h, release());
    assert.equal(h.$('#plugin_update_latest').text(), '0.1.13');
    h.fire('#plugin_update_check');
    assert.match(h.$('#plugin_update_latest').text(), /上次.*非本次/);
    const pending = h.of('check_plugin_update').at(-1);
    if (transport) pending.reject();
    else pending.resolve(release({ status: false, error: 'network unavailable', latest_version: '0.1.12', tag: '', prerelease: true, checked_at: null }));
    assert.match(h.$('#plugin_update_latest').text(), /0\.1\.13.*上次.*非本次/);
    assert.match(h.$('#plugin_update_prerelease').text(), /正式版本.*上次/);
    assert.match(h.$('#plugin_update_checked').text(), /2026-10-29.*上次/);
    assert.match(h.$('#plugin_update_status').text(), /失败.*快照.*过期/);
    assert.equal(h.$('#plugin_update_start').prop('disabled'), true);
    h.fire('#plugin_update_start'); assert.equal(h.confirms.length, 0);
    checkUpdate(h, release({ latest_version: '0.1.14', tag: 'v0.1.14', prerelease: true }));
    assert.equal(h.$('#plugin_update_latest').text(), '0.1.14');
    assert.doesNotMatch(h.$('#plugin_update_prerelease').text(), /上次|非本次/);
  });
}

test('validated backend stale releases remain historical and cannot enable installation', () => {
  const h = harness();
  h.navigate('updates'); h.of('get_plugin_update_status').at(-1).resolve({ status: true, job: null });
  checkUpdate(h, release({ status: false, error: 'network unavailable', stale: true, cached: true,
    releases: [{ version: '0.1.13', tag: 'v0.1.13', prerelease: false, published_at: '2026-10-29T09:00:00Z' }] }));
  assert.match(h.$('#plugin_update_latest').text(), /0\.1\.13.*上次.*非本次/);
  assert.match(h.$('#plugin_update_prerelease').text(), /正式版本.*上次/);
  assert.match(h.$('#plugin_update_status').text(), /快照.*过期/);
  assert.equal(h.$('#plugin_update_start').prop('disabled'), true);
  h.fire('#plugin_update_start'); assert.equal(h.confirms.length, 0);
});

test('partial release metadata never guesses a release channel', () => {
  const h = harness(); checkUpdate(h, release({ prerelease: null }));
  assert.equal(h.$('#plugin_update_latest').text(), '0.1.13');
  assert.equal(h.$('#plugin_update_prerelease').text(), '未知');
});

test('only explicit overview refresh forces both reads and retains the last snapshot on failure', () => {
  const h = harness();
  h.of('get_total_all')[0].resolve({ open: true, total: { total: 12, rules: [] } });
  h.of('get_overview_report')[0].resolve({ summary: { total_protection: 12 }, cached: true, cache_age_seconds: 14, checked_at: '2026-10-29 10:00:00' });
  assert.match(h.$('#overview_report_status').text(), /缓存.*14/);
  h.fire('#overview_report_refresh');
  for (const method of ['get_total_all', 'get_overview_report']) assert.equal(String(h.of(method).at(-1).options.data.force), '1');
  h.of('get_overview_report').at(-1).reject();
  assert.equal(h.$('#overview_total_protection').text(), '12');
  assert.match(h.$('#overview_report_status').text(), /保留.*快照/);
  h.navigate('home');
  for (const method of ['get_total_all', 'get_overview_report']) assert.equal(h.of(method).at(-1).options.data.force, undefined);
});

test('manual security dashboard and notification refresh bypass caches without polling', () => {
  const h = harness();
  h.waf.render_report_dashboard_summary();
  assert.equal(h.of('get_report_dashboard_summary').at(-1).options.data.force, undefined);
  h.fire('#report_summary_refresh');
  assert.equal(String(h.of('get_report_dashboard_summary').at(-1).options.data.force), '1');
  h.waf.render_defense_notifications();
  assert.equal(h.of('get_defense_notifications').at(-1).options.data.force, undefined);
  h.fire('#notification_refresh');
  assert.equal(String(h.of('get_defense_notifications').at(-1).options.data.force), '1');
});

test('rule samples are not advertised as a runtime Lua attack simulation', () => {
  assert.doesNotMatch(html, /模拟攻击|攻击模拟|开始模拟/);
  assert.match(html, /data-type="simulation"[\s\S]*?规则样本检查[\s\S]*?不.*运行时 Lua/);
  assert.match(html, /id="simulation_run"[^>]*>检查样本/);
  assert.match(html, /Python 规则文件匹配及独立基础特征检查/);
  assert.doesNotMatch(html, /结果只代表当前规则文件/);
});

test('capability checks show configuration-only scope and the literal backend notice', () => {
  const h = harness(); h.waf.render_official_feature_audit();
  h.of('get_official_feature_audit').at(-1).resolve({ status: true, checked_at: 'now', scope: 'configuration_structure_only', runtime_verified: false,
    notice: '仅核对本地配置结构，不代表防护已启用、Lua 已执行或与商业产品功能等价。<notice>',
    summary: { ok: 1, warn: 0, total: 1 }, items: [{ title: '<title>', status: true, detail: 'configuration field', action: '' }] });
  assert.match(h.$('#official_feature_status').text(), /配置结构/);
  assert.match(h.$('#official_feature_notice').text(), /不代表防护已启用[\s\S]*<notice>/);
  assert.doesNotMatch(h.$('#official_feature_table').html(), /已对齐|已覆盖|<title>/);
  assert.match(h.$('#official_feature_table').html(), /结构符合/);
});

test('sample result names Python matching and explicitly disclaims runtime Lua evaluation', () => {
  const h = harness(); h.waf.render_attack_simulation_result({ engine: 'python-re-sample', runtime_evaluated: false,
    decision: 'block', decision_text: '样本命中 <rule>', matched: [], notes: ['<note>'] });
  const result = h.$('#simulation_result').html();
  assert.match(result, /Python[\s\S]*未.*运行时 Lua/);
  assert.match(result, /&lt;rule&gt;[\s\S]*&lt;note&gt;/);
});

test('notification refresh preserves snapshots, does not mutate response rows and ignores older callbacks', () => {
  const h = harness(); h.waf.render_defense_notifications();
  const data = { items: [{ time: '2026-10-29 11:00:59', message: 'old snapshot' }], summary: { total: 1 } };
  const original = JSON.stringify(data); h.of('get_defense_notifications').at(-1).resolve(data);
  assert.equal(JSON.stringify(data), original);
  h.fire('#notification_refresh'); const older = h.of('get_defense_notifications').at(-1);
  h.fire('#notification_refresh'); const current = h.of('get_defense_notifications').at(-1);
  current.reject();
  assert.match(h.$('#notification_summary').text(), /保留.*快照/);
  assert.match(h.$('#notification_table').html(), /old snapshot/);
  older.options.success({ items: [], summary: { total: 0 } });
  assert.match(h.$('#notification_table').html(), /old snapshot/);
});

test('clients keeps its original tab and shows request groups with honest Chinese labels', () => {
  const h = harness(), payload = profiles(), original = JSON.stringify(payload);
  openProfiles(h, payload);
  assert.match(html, /data-stats-page="clients"[^>]*>访客与设备/);
  const table = h.$('#website_stats_profile_table').html();
  for (const label of ['中国', '美国', '桌面', '手机', '平板', '浏览器', '应用', '已知 API 工具', '未知']) assert.ok(table.includes(label), label);
  assert.match(h.$('#website_stats_device_table').html(), /手机/);
  assert.match(h.$('#website_stats_profile_status').text(), /42[\s\S]*37[\s\S]*5/);
  assert.match(h.$('#website_stats_profile_status').text(), /部分/);
  assert.match(html, /不是人数[\s\S]*独立设备[\s\S]*具体型号[\s\S]*指纹/);
  assert.equal(JSON.stringify(payload), original);
});

test('backend in_app and crawler types keep their supplied meaning without browser-based guessing', () => {
  const h = harness(), rows = [
    { ...profiles().rows[1], client_type: 'in_app', count: 1 },
    { ...profiles().rows[0], browser: 'ExampleBot', client_type: 'crawler', count: 1 },
    { ...profiles().rows[2], client_type: 'unknown', count: 1 },
  ];
  openProfiles(h, profiles({ rows, request_count: 3, represented_requests: 3, omitted_requests: 0, partial: false }));
  const table = h.$('#website_stats_profile_table').html();
  assert.match(table, /data-kind="in_app"[^>]*>应用内浏览器/);
  assert.match(table, /data-kind="crawler"[^>]*>疑似爬虫/);
  assert.doesNotMatch(table, /已知 API 工具/);
});

test('manual CDN response takes precedence over an older site-config response', () => {
  const h = harness(); h.waf.refresh_table_view = () => {}; h.waf._active_page = 'site';
  h.waf.set_site_config_view({ siteName: 'a.example' }); const config = h.of('get_site_config_byname').at(-1);
  h.fire('#site_detail_cdn_mode_refresh');
  h.of('get_site_cdn_trust_mode').at(-1).resolve({ status: true, mode: 'strict', trusted_proxy_count: 2 });
  config.resolve({ open: true, cdn: true, top: {}, cc: { cycle: 60, limit: 100, endtime: 600 } });
  assert.match(h.$('#site_detail_cdn_mode_status').text(), /严格/);
  assert.equal(h.$('#site_detail_cdn_strict').prop('disabled'), true);
});

test('country, device and browser filters combine over cached rows without requests', () => {
  const h = harness(); openProfiles(h); const before = h.requests.length;
  h.$('#website_stats_profile_country').val('CN');
  h.$('#website_stats_profile_device').val('Mobile');
  h.$('#website_stats_profile_browser').val('WeChat');
  h.fire('.website_stats_profile_filter', 'change');
  assert.match(h.$('#website_stats_profile_table').html(), /WeChat/);
  assert.doesNotMatch(h.$('#website_stats_profile_table').html(), /Chrome|curl/);
  assert.match(h.$('#website_stats_profile_page_info').text(), /1.*10/);
  h.$('#website_stats_profile_browser').val('.*'); h.fire('.website_stats_profile_filter', 'change');
  assert.match(h.$('#website_stats_profile_table').html(), /无匹配/);
  assert.equal(h.requests.length, before);
  assert.match(h.$('#website_stats_profile_status').text(), /42[\s\S]*37[\s\S]*5/);
});

test('all bounded profile rows remain accessible through local pagination', () => {
  const rows = Array.from({ length: 122 }, (_, i) => ({ ...profiles().rows[0], browser: 'browser-' + i, count: 1 }));
  const h = harness(); openProfiles(h, profiles({ rows, request_count: 122, represented_requests: 122, omitted_requests: 0, partial: false }));
  const before = h.requests.length;
  assert.equal((h.$('#website_stats_profile_table').html().match(/<tr>/g) || []).length, 50);
  h.fire('#website_stats_profile_next'); h.fire('#website_stats_profile_next');
  assert.match(h.$('#website_stats_profile_table').html(), /browser-121/);
  assert.equal(h.$('#website_stats_profile_next').prop('disabled'), true);
  h.fire('#website_stats_profile_prev');
  assert.match(h.$('#website_stats_profile_table').html(), /browser-50/);
  assert.equal(h.requests.length, before);
});

for (const [name, payload] of [
  ['missing', undefined], ['future', profiles({ schema_version: 2 })], ['bad rows', profiles({ rows: null })],
  ['negative', profiles({ request_count: -1 })], ['inconsistent', profiles({ represented_requests: 40 })],
  ['bad row', profiles({ rows: [{ ...profiles().rows[0], count: '37' }] })],
]) {
  test(name + ' profile data is unavailable, never a fabricated zero or a perpetual loader', () => {
    const h = harness(); openProfiles(h, payload === undefined ? null : payload);
    assert.match(h.$('#website_stats_profile_status').text(), /未提供|不可用/);
    assert.equal(h.$('#website_stats_profile_country').prop('disabled'), true);
    assert.doesNotMatch(h.$('#website_stats_profile_table').html(), /<td>0<\/td>|正在加载/);
    assert.match(h.$('#website_stats_browser_table').html(), /Chrome/);
  });
}

test('valid empty profiles are distinct from missing data', () => {
  const h = harness(); openProfiles(h, profiles({ rows: [], request_count: 0, represented_requests: 0, omitted_requests: 0, partial: false }));
  assert.match(h.$('#website_stats_profile_status').text(), /0/);
  assert.match(h.$('#website_stats_profile_table').html(), /暂无.*请求/);
  assert.doesNotMatch(h.$('#website_stats_profile_status').text(), /不可用/);
});

test('profile labels, option attributes and notices cannot inject markup or classify arbitrary tools', () => {
  const row = { country_code: '', country_name: '<img>', device: '"><svg>', browser: '"><img onerror="x">', os: '<script>', client_type: '<script>', count: 1 };
  const h = harness(); openProfiles(h, profiles({ rows: [row], request_count: 1, represented_requests: 1, omitted_requests: 0, partial: false, notice: '<script>notice</script>' }));
  const table = h.$('#website_stats_profile_table').html();
  assert.doesNotMatch(table, /<img|<script|<svg|已知 API 工具/);
  assert.match(table, /&lt;script&gt;/);
  assert.doesNotMatch(h.$('#website_stats_profile_browser').html(), /<img/);
  assert.match(h.$('#website_stats_profile_browser').html(), /&quot;&gt;&lt;img/);
  assert.match(h.$('#website_stats_profile_status').text(), /<script>notice<\/script>/);
});

test('site/time changes clear profile filters and rows, while stale A-B-A responses stay ignored', () => {
  const h = harness(); openProfiles(h);
  h.$('#website_stats_profile_country').val('CN');
  h.$('#website_stats_site_filter').val('B'); h.fire('#website_stats_site_filter', 'change');
  const pending = h.stats().at(-1);
  assert.equal(h.$('#website_stats_profile_country').val(), '');
  assert.match(h.$('#website_stats_profile_status').text(), /等待/);
  assert.doesNotMatch(h.$('#website_stats_profile_table').html(), /Chrome|WeChat/);
  h.$('#website_stats_site_filter').val(''); h.$('#website_stats_days').val('1'); h.fire('#website_stats_days', 'change');
  h.stats().at(-1).resolve(report({ client_profiles: profiles() }));
  const snapshot = h.$('#website_stats_profile_table').html();
  pending.options.success(report({ client_profiles: profiles({ rows: [] }) }));
  assert.equal(h.$('#website_stats_profile_table').html(), snapshot);
});

test('statistics to site settings uses the current selection only and never all-sites fallback', () => {
  const h = harness(); openProfiles(h); h.waf.refresh_table_view = () => {};
  h.waf.current_site_name = 'old.example';
  h.fire('#website_stats_open_site');
  assert.equal(h.of('get_site_config_byname').length, 0);
  h.$('#website_stats_site_filter').val('chosen.example'); h.fire('#website_stats_site_filter', 'change');
  assert.match(h.$('#website_stats_scope').text(), /chosen\.example/);
  h.fire('#website_stats_open_site');
  assert.equal(h.waf._active_page, 'site');
  assert.equal(h.of('get_site_config_byname').at(-1).options.data.siteName, 'chosen.example');
  assert.equal(h.of('set_site_obj_open').length, 0);
});

test('statistics event link resets old site filters, prefills manual search and explains global summary scope', () => {
  const h = harness(); openProfiles(h);
  h.$('#report_search_site').val('old.example'); h.$('#report_search_ip').val('old IP');
  h.$('#website_stats_site_filter').val('chosen.example'); h.$('#website_stats_days').val('3');
  h.fire('#website_stats_open_events');
  assert.equal(h.waf._active_page, 'ipstats');
  assert.equal(h.$('#report_search_site').val(), 'chosen.example');
  assert.equal(h.$('#report_search_days').val(), '3');
  assert.equal(h.$('#report_search_ip').val(), '');
  assert.equal(h.of('get_report_search').length, 0);
  assert.match(h.$('#report_search_summary').text(), /手动|点击搜索/);
  assert.match(h.$('#report_scope_note').text(), /全部站点.*7/);
  h.navigate('statistics'); h.$('#website_stats_site_filter').val(''); h.fire('#website_stats_open_events');
  assert.equal(h.$('#report_search_site').val(), '');
});

test('CDN mode is rendered from site configuration without extra reads and missing fields warn about legacy', () => {
  const h = harness(); site(h);
  assert.match(h.$('#site_detail_cdn_mode_status').text(), /兼容.*未保存|未保存.*兼容/);
  assert.equal(h.of('get_site_cdn_trust_mode').length, 0);
  assert.equal(h.of('set_site_cdn_trust_mode').length, 0);
  site(h, 'b.example', { cdn_trust_mode: 'strict' });
  assert.match(h.$('#site_detail_cdn_mode_status').text(), /严格/);
  assert.equal(h.$('#site_detail_cdn_strict').prop('disabled'), true);
});

test('manual CDN read displays count and literal notice and unknown states remain retryable', () => {
  const h = harness(); site(h);
  h.fire('#site_detail_cdn_mode_refresh');
  h.of('get_site_cdn_trust_mode').at(-1).resolve({ status: true, mode: 'strict', trusted_proxy_count: 0, notice: '<img>notice' });
  assert.match(h.$('#site_detail_cdn_mode_status').text(), /严格[\s\S]*0[\s\S]*<img>notice/);
  h.fire('#site_detail_cdn_mode_refresh'); h.of('get_site_cdn_trust_mode').at(-1).reject();
  assert.match(h.$('#site_detail_cdn_mode_status').text(), /未确认|失败/);
  assert.equal(h.$('#site_detail_cdn_mode_refresh').prop('disabled'), false);
  assert.equal(h.of('set_site_cdn_trust_mode').length, 0);
});

test('strict CDN requires an escaped fresh confirmation explaining empty trusted ranges before one exact POST', () => {
  const h = harness(); site(h, 'a<&>.example');
  const confirmation = prepareStrict(h);
  assert.match(confirmation.message, /a&lt;&amp;&gt;\.example/);
  assert.match(confirmation.message, /0[\s\S]*(?:为空|留空)[\s\S]*忽略.*请求头/);
  assert.match(confirmation.message, /不会.*开启/);
  assert.equal(h.of('set_site_cdn_trust_mode').length, 0);
  confirmation.yes(1); confirmation.yes(1);
  const writes = h.of('set_site_cdn_trust_mode');
  assert.equal(writes.length, 1);
  assert.equal(writes[0].options.type, 'POST');
  assert.deepEqual(JSON.parse(JSON.stringify(writes[0].options.data)), { siteName: 'a<&>.example', mode: 'strict', confirmation: 'CONFIRM_STRICT_CDN' });
  writes[0].resolve({ status: true, msg: 'saved' });
  assert.match(h.$('#site_detail_cdn_mode_status').text(), /保存.*运行端未核验/);
  assert.equal(h.of('set_site_obj_open').length, 0);
});

for (const exit of ['cancel', 'site', 'back', 'leave', 'close', 'reload']) {
  test('CDN confirmation cannot submit after ' + exit, () => {
    const h = harness(); site(h); const confirmation = prepareStrict(h, 2);
    if (exit === 'cancel') confirmation.cancel();
    if (exit === 'site') site(h, 'b.example');
    if (exit === 'back') h.waf.show_site_list_view(false);
    if (exit === 'leave') h.navigate('home');
    if (exit === 'close') h.close();
    if (exit === 'reload') h.reload();
    confirmation.yes(1);
    assert.equal(h.of('set_site_cdn_trust_mode').length, 0);
  });
}

test('late CDN reads and write results cannot change a different site or the next detail session', () => {
  const h = harness(); site(h); h.fire('#site_detail_cdn_mode_refresh');
  const read = h.of('get_site_cdn_trust_mode').at(-1);
  site(h, 'b.example'); const status = h.$('#site_detail_cdn_mode_status').text();
  read.options.success({ status: true, mode: 'strict', trusted_proxy_count: 1 });
  assert.equal(h.$('#site_detail_cdn_mode_status').text(), status);
  assert.equal(read.aborted, true);
  prepareStrict(h).yes(1); const write = h.of('set_site_cdn_trust_mode').at(-1);
  site(h, 'a.example'); site(h, 'b.example'); const next = h.$('#site_detail_cdn_mode_status').text();
  write.options.success({ status: true, mode: 'strict', trusted_proxy_count: 0 });
  assert.equal(h.$('#site_detail_cdn_mode_status').text(), next);
});

test('uncertain CDN write does not imply success, auto-retry, or retain an actionable stale preview', () => {
  const h = harness(); site(h); prepareStrict(h).yes(1);
  h.of('set_site_cdn_trust_mode').at(-1).reject();
  assert.match(h.$('#site_detail_cdn_mode_status').text(), /未确认[\s\S]*手动读取/);
  assert.equal(h.$('#site_detail_cdn_strict').prop('disabled'), true);
  assert.equal(h.$('#site_detail_cdn_mode_refresh').prop('disabled'), false);
  assert.equal(h.of('set_site_cdn_trust_mode').length, 1);
});

test('site-config reads overlapping CDN submission cannot restore an actionable legacy preview', () => {
  for (const outcome of ['success', 'failure']) {
    const h = harness(); site(h); prepareStrict(h).yes(1);
    const write = h.of('set_site_cdn_trust_mode').at(-1);
    h.waf.render_site_config({ siteName: 'a.example' });
    const older = h.of('get_site_config_byname').at(-1);
    if (outcome === 'success') write.resolve({ status: true });
    else write.reject();
    const status = h.$('#site_detail_cdn_mode_status').text();
    older.resolve({ open: true, cdn: true, top: {}, cc: { cycle: 60, limit: 100, endtime: 60 } });
    assert.equal(h.$('#site_detail_cdn_mode_status').text(), status);
    assert.equal(h.$('#site_detail_cdn_strict').prop('disabled'), true);
  }
});

function cdnToggleSurface(h, surface, name = 'a<&>.example', enabled = false) {
  const tables = new Map();
  h.waf.refresh_table_view = options => { tables.set(options.el, options); options.done?.(options.data); };
  h.navigate('site');
  if (surface === 'list') {
    h.of('get_site_config').at(-1).resolve([{ siteName: name, cdn: enabled }]);
  } else {
    h.waf.set_site_config_view({ siteName: name });
    h.of('get_site_config_byname').at(-1).resolve({ open: false, cdn: enabled, top: {}, cc: { cycle: 60, limit: 100, endtime: 60 } });
  }
  const table = tables.get(surface === 'list' ? '#site_table' : '#site_config_table');
  const index = surface === 'list' ? 0 : table.data.findIndex(row => row.type === 'cdn');
  const row = table.data[index];
  const handler = table.config.find(column => column.fid === (surface === 'list' ? 'cdn' : 'open')).event;
  return { row, click() {
    const event = { prevented: false, stopped: false,
      preventDefault() { this.prevented = true; }, stopPropagation() { this.stopped = true; } };
    handler(row, index, event);
    return event;
  } };
}

for (const surface of ['list', 'detail']) {
  for (const enabled of [false, true]) {
    test(`CDN ${surface} ${enabled ? 'disable' : 'enable'} waits for scoped confirmation without optimistic toggles`, () => {
      const h = harness(), control = cdnToggleSurface(h, surface, 'a<&>.example', enabled);
      const before = h.requests.length, snapshot = JSON.stringify(control.row), event = control.click();
      assert.equal(h.requests.length, before, 'opening confirmation must not read or write');
      assert.equal(event.prevented, true, 'the checkbox must not change before confirmation');
      assert.equal(event.stopped, true, 'the generic checkbox delegate must not flip CDN');
      const confirmation = h.confirms.at(-1);
      assert.ok(confirmation);
      assert.match(confirmation.message, /仅.*站点[\s\S]*a&lt;&amp;&gt;\.example/);
      assert.match(confirmation.message, enabled ? /关闭/ : /启用/);
      assert.match(confirmation.message, /启用[\s\S]*严格模式/);
      assert.match(confirmation.message, /(?:为空|留空)[\s\S]*忽略[\s\S]*转发[\s\S]*连接来源 IP/);
      assert.match(confirmation.message, /其他站点[\s\S]*不/);
      assert.match(confirmation.message, /不.*开启.*防护|不.*开启.*防火墙/);
      confirmation.cancel(); confirmation.yes(1);
      assert.equal(h.requests.length, before, 'cancel must neither write nor refresh');
      assert.equal(JSON.stringify(control.row), snapshot);
      control.click();
      const confirmed = h.confirms.at(-1);
      confirmed.yes(2); confirmed.yes(2); control.click();
      const writes = h.of('set_site_obj_open');
      assert.equal(writes.length, 1);
      assert.equal(writes[0].options.type, 'POST');
      assert.deepEqual(JSON.parse(JSON.stringify(writes[0].options.data)), { siteName: 'a<&>.example', obj: 'cdn' });
      assert.equal(h.of('set_site_cdn_trust_mode').length, 0);
      writes[0].resolve({ status: true, msg: 'saved' });
      assert.equal(h.requests.at(-1).method, surface === 'list' ? 'get_site_config' : 'get_site_config_byname');
    });
  }

  for (const exit of ['cancel', 'dismiss', 'end', 'site', 'back', 'roundtrip', 'refresh', 'close', 'reload']) {
    test(`CDN ${surface} toggle cannot submit after ${exit}`, () => {
      const h = harness(), control = cdnToggleSurface(h, surface);
      control.click();
      const confirmation = h.confirms.at(-1);
      assert.ok(confirmation, 'CDN toggle needs confirmation before a write');
      if (exit === 'cancel') confirmation.cancel();
      if (exit === 'dismiss') confirmation.options.cancel();
      if (exit === 'end') confirmation.options.end();
      if (exit === 'site') site(h, 'b.example');
      if (exit === 'back') h.waf.show_site_list_view(false);
      if (exit === 'roundtrip') { h.navigate('home'); cdnToggleSurface(h, surface); }
      if (exit === 'refresh') {
        if (surface === 'detail') h.waf.render_site_config({ siteName: 'a<&>.example' });
        else h.navigate('site');
      }
      if (exit === 'close') h.close();
      if (exit === 'reload') h.reload();
      confirmation.yes(1);
      assert.equal(h.of('set_site_obj_open').length, 0);
    });
  }

  test(`CDN ${surface} late write responses cannot refresh or message a later page or site session`, () => {
    for (const outcome of ['success', 'failure']) {
      const h = harness(), control = cdnToggleSurface(h, surface);
      control.click();
      assert.ok(h.confirms.at(-1)); h.confirms.at(-1).yes(1);
      const write = h.of('set_site_obj_open').at(-1);
      site(h, 'b.example'); cdnToggleSurface(h, surface);
      const reads = h.requests.length, messages = h.messages.length;
      if (outcome === 'success') write.options.success({ status: true, msg: 'stale saved' });
      else write.options.error({}, 'timeout');
      assert.equal(h.requests.length, reads);
      assert.equal(h.messages.length, messages);
    }
  });

  test(`retained CDN ${surface} controls cannot create a fresh confirmation after their view expires`, () => {
    const h = harness(), control = cdnToggleSurface(h, surface);
    cdnToggleSurface(h, surface);
    const reads = h.requests.length;
    control.click();
    assert.equal(h.confirms.length, 0);
    assert.equal(h.requests.length, reads);
  });
}

test('CDN helper captures the confirmed site and suppresses overlapping confirmations', () => {
  const h = harness(); h.navigate('site');
  const obj = { siteName: 'a.example', obj: 'cdn' };
  h.waf.set_site_obj_open(obj);
  h.waf.set_site_obj_open({ siteName: 'b.example', obj: 'cdn' });
  assert.equal(h.confirms.length, 1);
  obj.siteName = 'b.example'; obj.obj = 'open';
  h.confirms[0].yes(1);
  assert.deepEqual(JSON.parse(JSON.stringify(h.of('set_site_obj_open')[0].options.data)), { siteName: 'a.example', obj: 'cdn' });
});

test('CDN toggle cannot overlap the explicit trust-mode read or confirmation', () => {
  const h = harness(); site(h);
  h.fire('#site_detail_cdn_mode_refresh');
  h.waf.set_site_obj_open({ siteName: 'a.example', obj: 'cdn' });
  assert.equal(h.confirms.length, 0);
  assert.equal(h.of('set_site_obj_open').length, 0);
  h.of('get_site_cdn_trust_mode').at(-1).resolve({ status: true, mode: 'legacy', trusted_proxy_count: 0 });
  const strict = prepareStrict(h);
  h.waf.set_site_obj_open({ siteName: 'a.example', obj: 'cdn' });
  assert.equal(h.confirms.length, 1);
  strict.cancel();
  h.waf.set_site_obj_open({ siteName: 'a.example', obj: 'cdn' });
  const reads = h.of('get_site_cdn_trust_mode').length;
  h.fire('#site_detail_cdn_mode_refresh'); h.fire('#site_detail_cdn_strict');
  assert.equal(h.of('get_site_cdn_trust_mode').length, reads);
});

test('uncertain CDN toggle reports the site and does not refresh, retry or invoke success', () => {
  for (const outcome of ['timeout', 'backend']) {
    const h = harness(); h.navigate('site'); let callbacks = 0;
    h.waf.set_site_obj_open({ siteName: 'a.example', obj: 'cdn' }, () => callbacks++);
    assert.ok(h.confirms.at(-1)); h.confirms.at(-1).yes(1);
    const write = h.of('set_site_obj_open').at(-1), before = h.requests.length;
    if (outcome === 'timeout') write.reject();
    else write.resolve({ status: false, msg: '<unconfirmed>' });
    assert.equal(callbacks, 0);
    assert.equal(h.requests.length, before);
    assert.match(h.messages.at(-1).message, /a\.example[\s\S]*未确认[\s\S]*刷新/);
    assert.doesNotMatch(h.messages.at(-1).message, /<unconfirmed>/);
  }
});

test('non-CDN site switches retain their existing immediate request behavior', () => {
  const h = harness(); site(h); let callbacks = 0;
  h.waf.set_site_obj_open({ siteName: 'a.example', obj: 'get' }, () => callbacks++);
  assert.equal(h.confirms.length, 0);
  h.of('set_site_obj_open').at(-1).resolve({ status: true });
  assert.equal(callbacks, 1);
});
