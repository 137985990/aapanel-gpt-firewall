'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const {harness, html} = require('./test_statistics_v011');
const ip = '203.0.113.40', site = 'shop.example';
const revision = 'a'.repeat(64);
const row = (extra = {}) => ({id: 'fixture-entry', ip, site, scope: 'site', source: 'cc',
  reason_text: 'CC 限速', remaining_seconds: 60, expires_at: 1792627260,
  enforcement: 'active', removable: true, ...extra});
const current = (extra = {}) => ({status: true, schema_version: 1, p: 1, limit: 20,
  rows: [row()], total: 1, checked_at: 1792627200, coverage: {partial: false}, config_revision: revision,
  summary: {active_ips: 1, active_entries: 1, inactive_entries: 0, unknown_entries: 0}, ...extra});
const history = (extra = {}) => ({status: true, p: 1, limit: 20, view: 'grouped', total: 1,
  total_exact: true, coverage: {partial: false, scanned_lines: 3}, rows: [{ip, site,
    reason: 'cc', reason_text: 'CC 限速', count: 3, first_time: 1792627000,
    last_time: 1792627200, duration: 60, group_id: 'fixture-group'}], ...extra});
function open() { const h = harness(); h.navigate('history'); return h; }
function ready() { const h = open(); h.of('get_active_bans').at(-1).resolve(current()); return h; }
function quickReady(h, selected = site) {
  h.waf.open_quick_ban(ip, selected);
  h.of('get_active_bans').at(-1).resolve(current());
}

test('broad queries omit blank site while exact empty-site detail keeps it', () => {
  const h = ready();
  assert.equal(Object.hasOwn(h.of('get_active_bans')[0].options.data, 'site'), false);
  h.fire('#ban-history-refresh'); const req = h.of('get_ban_history').at(-1);
  assert.equal(Object.hasOwn(req.options.data, 'site'), false);
  const res = history(); res.rows[0].site = ''; req.resolve(res);
  h.fire('.ban-history-detail', 'click', {'data-index': '0'});
  assert.equal(h.of('get_ban_history').at(-1).options.data.site, '');
});
test('quick ban requires a fresh preflight and freezes its revision before confirmation', () => {
  const h = ready(); h.waf.open_quick_ban(ip,site);
  h.fire('#ban-quick-submit'); assert.equal(h.confirms.length,0);
  const preflight = h.of('get_active_bans').at(-1); preflight.resolve(current());
  h.fire('#ban-quick-submit'); assert.equal(h.confirms.length,1);
  preflight.options.success(current({config_revision:'b'.repeat(64)}));
  h.confirms.at(-1).yes(1);
  assert.equal(h.of('add_quick_ban').at(-1).options.data.config_revision, revision);
});
test('failed revision preflight disables quick writes including the reports shortcut', () => {
  const h = harness(); h.navigate('reports'); h.waf.open_quick_ban(ip,site);
  h.of('get_active_bans').at(-1).reject(); h.fire('#ban-quick-submit');
  assert.equal(h.confirms.length,0); assert.equal(h.of('add_quick_ban').length,0);
  assert.match(h.$('#ban-dialog-status').text(),/配置|核验/);
});
test('quick-ban preview uses an integer expiry timestamp', () => {
  const h = ready(); quickReady(h); h.tick(123);
  let stamp; h.waf.risk_advice_time = value => {stamp=value;return 'fixture expiry';};
  h.waf.preview_quick_ban(); assert.equal(Number.isSafeInteger(stamp),true);
  assert.match(h.$('#ban-quick-preview').text(),/fixture expiry/);
});
test('dashboard count uses unified current state and legacy responses cannot overwrite it', () => {
  const h = harness();
  h.of('get_overview_report').at(-1).resolve({summary:{active_bans:99}});
  const req = h.of('get_active_bans').at(-1); assert.ok(req);
  assert.equal(req.options.data.limit,1); req.resolve(current());
  assert.equal(h.$('#overview_active_bans').text(),'1');
  h.waf.render_overview_report(); h.of('get_overview_report').at(-1).resolve({summary:{active_bans:99}});
  h.of('get_active_bans').at(-1).reject();
  assert.equal(h.$('#overview_active_bans').text(),'--');
  assert.match(h.$('#overview_bans_status').text(),/未知/);
});
test('report card preserves unknown coverage instead of counting disabled records as active', () => {
  const h = harness(); h.navigate('ipstats');
  h.of('get_report_dashboard_summary').at(-1).resolve({summary:{active_bans:99}});
  const req = h.of('get_active_bans').at(-1); assert.ok(req);
  req.resolve(current({summary:{active_ips:0,active_entries:0,inactive_entries:2,unknown_entries:1},coverage:{partial:true}}));
  assert.equal(h.$('#report_summary_bans').text(),'0');
  assert.match(h.$('#report_bans_status').text(),/部分|未核验/);
});

test('current enforcement precedes suggestions, history and legacy audit', () => {
  assert.ok(html.indexOf('id="ban-current-card"') < html.indexOf('id="risk-advice-card"'));
  assert.ok(html.indexOf('id="ban-current-card"') < html.indexOf('id="ban-history-card"'));
  for (const label of ['正在封禁的 IP', '封禁条目', '状态未核验', '重复记录合并', '快捷封禁']) assert.ok(html.includes(label), label);
});
test('entering ban management reads current state but not raw logs or write APIs', () => {
  const h = open(); assert.equal(h.of('get_active_bans').length, 1);
  assert.equal(h.of('get_safe_logs').length, 0); assert.equal(h.of('get_blockade_records').length, 0);
  assert.equal(h.of('add_quick_ban').length, 0); h.tick(600000);
  assert.equal(h.of('get_active_bans').length, 1, 'no automatic polling');
});
test('current list shows unique-IP count, scope, source, duration and explicit remove control', () => {
  const h = ready(); assert.equal(h.$('#ban-active-ips').text(), '1');
  for (const value of [ip, site, 'CC', '60', '解除此项']) assert.ok(h.$('#ban-current-rows').html().includes(value), value);
  assert.doesNotMatch(h.$('#ban-current-rows').html(), /已解封/);
});
test('unknown and disabled are not displayed as active and cannot be batch-unbanned', () => {
  const h = open(); h.of('get_active_bans').at(-1).resolve(current({rows: [row({enforcement: 'unknown', removable: false}), row({id: 'disabled', enforcement: 'disabled', removable: false})], total: 2,
    summary: {active_ips: 0, active_entries: 0, inactive_entries: 1, unknown_entries: 1}}));
  assert.equal(h.$('#ban-active-ips').text(), '0'); assert.equal(h.$('#ban-unknown-entries').text(), '1');
  assert.match(h.$('#ban-current-rows').html(), /状态未核验/); assert.match(h.$('#ban-current-rows').html(), /未执行/);
  assert.doesNotMatch(h.$('#ban-current-rows').html(), /ban-remove-entry/);
});
test('read failure preserves last list but invalidates counts and actions', () => {
  const h = ready(), before = h.$('#ban-current-rows').html(); h.fire('#ban-current-refresh');
  h.of('get_active_bans').at(-1).reject();
  assert.match(h.$('#ban-current-status').text(), /读取失败.*旧快照/);
  assert.equal(h.$('#ban-active-ips').text(), '--'); assert.equal(h.$('#ban-current-rows').html(), before);
  h.fire('.ban-remove-entry', 'click', {'data-index': '0'}); assert.equal(h.confirms.length, 0);
});
test('grouped history asks backend to aggregate before pagination and displays the count', () => {
  const h = ready(); h.fire('#ban-history-refresh');
  const req = h.of('get_ban_history').at(-1); assert.equal(req.options.data.view, 'grouped');
  req.resolve(history()); assert.match(h.$('#ban-history-rows').html(), /3 次/);
  assert.match(h.$('#ban-history-rows').html(), /查看明细/); assert.match(h.$('#ban-history-status').text(), /合并/);
});
test('history details requests the exact group, not every event from the same IP', () => {
  const h = ready(); h.fire('#ban-history-refresh'); h.of('get_ban_history').at(-1).resolve(history());
  h.fire('.ban-history-detail', 'click', {'data-index': '0'});
  const req = h.of('get_ban_history').at(-1); assert.equal(req.options.data.view, 'raw');
  assert.equal(req.options.data.ip, ip); assert.equal(req.options.data.site, site); assert.equal(req.options.data.reason, 'cc');
  assert.equal(h.$('#ban-dialog').prop('hidden'), false);
});
test('a different history group clears prior detail rows and paging before reading', () => {
  const h = ready(); h.fire('#ban-history-refresh'); h.of('get_ban_history').at(-1).resolve(history());
  h.fire('.ban-history-detail', 'click', {'data-index': '0'});
  h.of('get_ban_history').at(-1).resolve(history({view: 'raw'}));
  h.fire('#ban-dialog-close'); h.$('#ban-history-detail-rows').html('old group data');
  h.$('#ban-detail-next').prop('disabled',false);
  h.fire('.ban-history-detail', 'click', {'data-index': '0'});
  assert.doesNotMatch(h.$('#ban-history-detail-rows').html(), /old group data/);
  assert.equal(h.$('#ban-detail-next').prop('disabled'), true);
  h.of('get_ban_history').at(-1).reject();
  assert.doesNotMatch(h.$('#ban-history-detail-rows').html(), /old group data/);
});
test('raw-audit uses a direct toggle listener because native details toggle does not bubble', () => {
  assert.match(html, /\$\('#history-raw-audit'\)\.off\('toggle\.free_waf'\)\.on\('toggle\.free_waf'/);
});
test('local viewport resize recalculates the new dialog height', () => {
  const h = ready(); h.waf.open_quick_ban(ip,site);
  let calls = 0; h.waf.risk_advice_dialog_height = () => {calls++;return 400;};
  h.fire('window','resize'); assert.ok(calls > 0);
});
test('filter changes invalidate in-flight rows, stale success never replaces current data', () => {
  const h = open(), old = h.of('get_active_bans').at(-1);
  h.$('#ban-current-ip').val('203.0.113.41'); h.fire('#ban-current-search');
  const req = h.of('get_active_bans').at(-1); assert.equal(req.options.data.ip, '203.0.113.41');
  req.resolve(current({rows: [row({ip: '203.0.113.41'})]}));
  old.options.success(current()); assert.match(h.$('#ban-current-rows').html(), /203\.0\.113\.41/);
});
test('TOP IP has a shortcut and opening its modal never bans automatically', () => {
  const h = harness(); h.navigate('reports');
  h.waf.render_report_dashboard_summary(); h.of('get_report_dashboard_summary').at(-1).resolve({summary: {}, top_ips: [{ip, count: 2536}], coverage: {partial: false}});
  assert.match(h.$('#report_top_ip_table').html(), /ban-quick-open/);
  h.fire('.ban-quick-open', 'click', {'data-ip': ip, 'data-site': ''});
  assert.equal(h.$('#ban-quick-ip').val(), ip); assert.equal(h.$('#ban-quick-scope').val(), 'site');
  assert.equal(h.$('#ban-quick-site').val(), ''); assert.equal(h.of('add_quick_ban').length, 0);
});
test('quick ban requires a specific site or explicit global choice and confirmed duration', () => {
  const h = ready(); quickReady(h,''); h.$('#ban-quick-value').val('8'); h.$('#ban-quick-unit').val('3600');
  h.fire('#ban-quick-submit'); assert.equal(h.confirms.length, 0); assert.match(h.$('#ban-dialog-status').text(), /站点/);
  h.$('#ban-quick-site').val(site); h.fire('#ban-quick-submit');
  assert.match(h.confirms.at(-1).message, /shop\.example/); assert.equal(h.of('add_quick_ban').length, 0);
  h.confirms.at(-1).yes(1); const req = h.of('add_quick_ban').at(-1);
  assert.equal(req.options.data.scope, 'site'); assert.equal(req.options.data.siteName, site);
  assert.equal(req.options.data.duration_seconds, '28800'); assert.equal(req.options.type, 'POST');
});
test('ten-year choice has a second confirmation and cancellation never writes', () => {
  const h = ready(); quickReady(h); h.$('#ban-quick-value').val('3650'); h.$('#ban-quick-unit').val('86400');
  h.fire('#ban-quick-submit'); h.confirms.at(-1).yes(1);
  assert.equal(h.confirms.length, 2); assert.equal(h.of('add_quick_ban').length, 0);
  h.confirms.at(-1).cancel(); assert.equal(h.of('add_quick_ban').length, 0);
});
test('source-specific unban carries exact identity and never invokes global clear', () => {
  const h = ready(); h.fire('.ban-remove-entry', 'click', {'data-index': '0'}); h.confirms.at(-1).yes(1);
  const req = h.of('remove_active_ban').at(-1); assert.equal(req.options.data.id, 'fixture-entry');
  assert.equal(h.of('clean_waf_drop_ip').length, 0); assert.equal(h.of('remove_waf_drop_ip').length, 0);
});
test('leaving the page invalidates pending confirmation and history detail responses', () => {
  const h = ready(); quickReady(h); h.$('#ban-quick-value').val('8'); h.$('#ban-quick-unit').val('3600'); h.fire('#ban-quick-submit');
  const question = h.confirms.at(-1); h.navigate('overall'); question.yes(1);
  assert.equal(h.of('add_quick_ban').length, 0); assert.equal(h.$('#ban-dialog').prop('hidden'), true);
});
test('server-provided IP/site/reason are rendered only as escaped text', () => {
  const h = open(); h.of('get_active_bans').at(-1).resolve(current({rows: [row({reason_text: '<img onerror=alert(1)>', site: '<script>example</script>'})]}));
  assert.doesNotMatch(h.$('#ban-current-rows').html(), /<img|<script>/);
  assert.match(h.$('#ban-current-rows').html(), /&lt;img/);
});
