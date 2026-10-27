'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { harness, html } = require('./test_statistics_v011');
const names = ['a.example', 'b.example', 'c.example'];
const defaults = enabled => ({enabled: !!enabled, window_seconds: 86400,
  tiers: [{threshold: 5, ban_seconds: 604800}, {threshold: 10, ban_seconds: 2592000}]});
const response = (policies = [defaults(true), defaults(false)], selected = names.slice(0, 2)) => ({
  status: true, revision: 'a'.repeat(64), sites: selected.map((siteName, index) => ({siteName, policy: policies[index]})),
});
function open(sites = names) {
  const h = harness(); h.navigate('repeat_ban');
  h.of('get_repeat_ban_sites').at(-1).resolve({status: true, sites: sites.map(siteName => ({siteName})), defaults: defaults(false)});
  h.fire('#repeat_ban_mode_bulk');
  return h;
}
function select(h, index, checked = true) {
  h.fire('.repeat-ban-site-check', 'change', {'data-index': String(index), checked});
}
function loaded(policies) {
  const h = open(); select(h, 0); select(h, 1);
  h.fire('#repeat_ban_bulk_read');
  h.of('get_repeat_ban_policies').at(-1).resolve(response(policies));
  return h;
}

test('batch mode provides checkboxes, filtered selection and explicit activation action', () => {
  for (const id of ['repeat_ban_mode_bulk', 'repeat_ban_bulk_filter', 'repeat_ban_bulk_all',
    'repeat_ban_bulk_clear', 'repeat_ban_bulk_read', 'repeat_ban_bulk_snapshot', 'repeat_ban_enabled_action']) {
    assert.ok(html.includes('id="' + id + '"'), id);
  }
  assert.match(html, /value="preserve"[^>]*>保留各站原有启用状态/);
});

test('opening and selecting sites is lazy and does not reload policies or records', () => {
  const h = open(), reads = h.requests.length, timers = h.timers.size;
  select(h, 0); select(h, 1);
  assert.equal(h.requests.length, reads);
  assert.equal(h.timers.size, timers);
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
  assert.match(h.$('#repeat_ban_bulk_count').text(), /2/);
  h.fire('#repeat_ban_bulk_read');
  const read = h.of('get_repeat_ban_policies').at(-1);
  assert.deepEqual(JSON.parse(read.options.data.siteNames), names.slice(0, 2));
  assert.equal(read.options.type, 'POST');
  assert.equal(h.of('get_repeat_ban_policy').length, 0);
  assert.equal(h.of('get_repeat_bans').length, 0);
});

test('filtered select and clear only affect visible sites and never submit', () => {
  const h = open(); select(h, 0);
  h.$('#repeat_ban_bulk_filter').val('b.example'); h.fire('#repeat_ban_bulk_filter', 'input');
  h.fire('#repeat_ban_bulk_all');
  assert.deepEqual(Array.from(h.waf._repeat_selected), names.slice(0, 2));
  h.fire('#repeat_ban_bulk_clear');
  assert.deepEqual(Array.from(h.waf._repeat_selected), ['a.example']);
  h.$('#repeat_ban_bulk_filter').val(''); h.fire('#repeat_ban_bulk_filter', 'input'); h.fire('#repeat_ban_bulk_all');
  assert.deepEqual(Array.from(h.waf._repeat_selected), names);
  assert.equal(h.of('get_repeat_ban_policies').length, 0);
  assert.equal(h.of('save_repeat_ban_policies').length, 0);
});

test('one read shows activation differences honestly and defaults to preserving them', () => {
  const h = loaded();
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), false);
  assert.equal(h.$('#repeat_ban_enabled_action').val(), 'preserve');
  assert.match(h.$('#repeat_ban_bulk_snapshot').html(), /a.example[\s\S]*已启用[\s\S]*b.example[\s\S]*已停用/);
  assert.match(h.$('#repeat_ban_status').text(), /启用状态不同/);
  assert.equal(h.$('#repeat_ban_threshold_0').val(), 5);
});

test('mixed ladders are not described as a current uniform policy', () => {
  const other = defaults(false); other.window_seconds = 3600;
  const h = loaded([defaults(true), other]);
  assert.match(h.$('#repeat_ban_status').text(), /阶梯不一致/);
  assert.match(h.$('#repeat_ban_status').text(), /默认预设/);
  assert.match(h.$('#repeat_ban_bulk_snapshot').html(), /1 小时/);
  assert.equal(h.$('#repeat_ban_enabled_action').val(), 'preserve');
});

for (const action of ['preserve', 'enable', 'disable']) test('batch ' + action + ' confirms every site and submits exactly one request', () => {
  const h = loaded(); h.$('#repeat_ban_enabled_action').val(action);
  h.fire('#repeat_ban_save'); const confirmation = h.confirms.at(-1); assert.ok(confirmation);
  for (const text of ['a.example', 'b.example', '独立', '不合并', 'IP 白名单', '覆盖']) assert.ok(confirmation.message.includes(text), text);
  assert.equal(h.of('save_repeat_ban_policies').length, 0);
  confirmation.yes(1); confirmation.yes(1); h.fire('#repeat_ban_save');
  assert.equal(h.of('save_repeat_ban_policies').length, 1);
  assert.equal(h.of('save_repeat_ban_policy').length, 0);
  const write = h.of('save_repeat_ban_policies')[0];
  assert.deepEqual(JSON.parse(write.options.data.siteNames), names.slice(0, 2));
  assert.equal(write.options.data.enabled_action, action);
  assert.equal(write.options.data.revision, 'a'.repeat(64));
  const draft = defaults(false); delete draft.enabled;
  assert.deepEqual(JSON.parse(write.options.data.policy), draft);
  const policies = [defaults(action !== 'disable'), defaults(action === 'enable')];
  write.resolve(response(policies));
  assert.match(h.$('#repeat_ban_status').text(), /批量保存成功.*2/);
  assert.equal(h.$('#repeat_ban_enabled_action').val(), 'preserve');
  assert.equal(h.of('get_repeat_ban_policies').length, 1, 'fresh write readback is returned by the server');
  assert.equal(h.of('get_repeat_bans').length, 0);
});

test('cancelled batch confirmation cannot submit late and does not change targets', () => {
  const h = loaded(); h.fire('#repeat_ban_save'); const item = h.confirms.at(-1);
  select(h, 2); h.fire('#repeat_ban_mode_single');
  assert.equal(h.waf._repeat_mode, 'bulk'); assert.equal(h.waf._repeat_selected.length, 2);
  item.cancel(); item.yes(1);
  assert.equal(h.of('save_repeat_ban_policies').length, 0);
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), false);
});

test('confirmation uses the exact current nondefault draft even before an input preview event', () => {
  const h = loaded();
  h.$('#repeat_ban_window_seconds').val('7200');
  h.$('#repeat_ban_threshold_0').val('3'); h.$('#repeat_ban_seconds_0').val('3600');
  h.$('#repeat_ban_threshold_1').val('8'); h.$('#repeat_ban_seconds_1').val('86400');
  h.fire('#repeat_ban_save'); const item = h.confirms.at(-1);
  for (const text of ['2 小时', '3 次 / 1 小时', '8 次 / 1 天']) assert.ok(item.message.includes(text), text);
  item.yes(1);
  assert.deepEqual(JSON.parse(h.of('save_repeat_ban_policies')[0].options.data.policy), {
    window_seconds: 7200, tiers: [{threshold: 3, ban_seconds: 3600}, {threshold: 8, ban_seconds: 86400}],
  });
});

for (const action of ['leave', 'close', 'reinit', 'reload']) test('late submitted batch write cannot alter UI after ' + action, () => {
  const h = loaded(); h.fire('#repeat_ban_save'); h.confirms.at(-1).yes(1);
  const old = h.of('save_repeat_ban_policies')[0];
  if (action === 'leave') { h.navigate('home'); h.navigate('repeat_ban'); }
  if (action === 'close') h.close();
  if (action === 'reinit') h.waf.init();
  if (action === 'reload') h.reload();
  assert.ok(old.aborted);
  const status = h.$('#repeat_ban_status').text(), snapshot = h.$('#repeat_ban_bulk_snapshot').html(), count = h.requests.length;
  old.options.success(response()); old.options.error({}, 'timeout'); old.options.complete({}, 'success');
  assert.equal(h.$('#repeat_ban_status').text(), status);
  assert.equal(h.$('#repeat_ban_bulk_snapshot').html(), snapshot);
  assert.equal(h.requests.length, count);
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
});

test('pending write locks selection, mode and refresh instead of implying cancellation', () => {
  const h = loaded(); h.fire('#repeat_ban_save'); h.confirms.at(-1).yes(1);
  const write = h.of('save_repeat_ban_policies')[0], count = h.requests.length;
  select(h, 2); h.fire('#repeat_ban_mode_single'); h.fire('#repeat_ban_bulk_all'); h.fire('#repeat_ban_bulk_read');
  h.fire('#repeat_ban_sites_refresh');
  assert.equal(h.waf._repeat_selected.length, 2); assert.equal(h.waf._repeat_mode, 'bulk');
  assert.equal(h.requests.length, count); assert.equal(write.aborted, false);
});

test('changing selected sites invalidates the snapshot and ignores old reads', () => {
  const h = open(); select(h, 0); select(h, 1); h.fire('#repeat_ban_bulk_read');
  const old = h.of('get_repeat_ban_policies')[0]; select(h, 2);
  assert.ok(old.aborted); old.options.success(response()); old.options.complete({}, 'success');
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
  assert.match(h.$('#repeat_ban_bulk_snapshot').text(), /尚未读取/);
});

for (const failure of ['network', 'wrong-targets', 'wrong-policy', 'api', 'malformed']) test('uncertain batch ' + failure + ' keeps draft but blocks stale resubmission', () => {
  const h = loaded(); h.$('#repeat_ban_threshold_0').val('6'); h.fire('#repeat_ban_save'); h.confirms.at(-1).yes(1);
  const write = h.of('save_repeat_ban_policies')[0];
  if (failure === 'network') write.reject();
  else if (failure === 'wrong-targets') write.resolve(response([defaults(true)], ['a.example']));
  else if (failure === 'wrong-policy') write.resolve(response());
  else write.resolve(failure === 'api' ? {status: false, msg: '冲突'} : {status: true});
  assert.equal(h.$('#repeat_ban_threshold_0').val(), '6');
  assert.match(h.$('#repeat_ban_status').text(), /未确认|失败/);
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
  h.fire('#repeat_ban_save'); assert.equal(h.of('save_repeat_ban_policies').length, 1);
  assert.equal(h.$('#repeat_ban_bulk_read').prop('disabled'), false);
});

test('batch response validates target identity, uniqueness, revision and policies before editing', () => {
  for (const bad of [response([defaults(true)], ['a.example']), {...response(), revision: ''},
    response([defaults(true), defaults(false)], ['a.example', 'a.example']),
    response([defaults(true), {...defaults(false), tiers: []}])]) {
    const h = open(); select(h, 0); select(h, 1); h.fire('#repeat_ban_bulk_read');
    h.of('get_repeat_ban_policies')[0].resolve(bad);
    assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
    assert.match(h.$('#repeat_ban_status').text(), /失败/);
  }
});

test('leaving batch cancels confirmation and stale callbacks cannot save on return', () => {
  const h = loaded(); h.fire('#repeat_ban_save'); const item = h.confirms.at(-1);
  h.navigate('home'); h.navigate('repeat_ban'); item.yes(1);
  assert.equal(h.of('save_repeat_ban_policies').length, 0);
});

test('batch site labels and confirmation escape remote strings once', () => {
  const dirty = '<img src=x onerror="bad">&\'', h = open([dirty]); select(h, 0);
  assert.match(h.$('#repeat_ban_bulk_sites').html(), /&lt;img/);
  assert.doesNotMatch(h.$('#repeat_ban_bulk_sites').html(), /<img/);
  h.fire('#repeat_ban_bulk_read'); h.of('get_repeat_ban_policies')[0].resolve(response([defaults(false)], [dirty]));
  h.fire('#repeat_ban_save'); assert.doesNotMatch(h.confirms.at(-1).message, /<img|&amp;lt;/);
});

test('batch limits target count and keeps empty selection uneditable', () => {
  const h = open(Array.from({length: 501}, (_, i) => 'site' + i + '.example'));
  h.fire('#repeat_ban_bulk_all');
  assert.equal(h.waf._repeat_selected.length, 0);
  assert.match(h.$('#repeat_ban_status').text(), /500/);
  h.fire('#repeat_ban_bulk_read'); assert.equal(h.of('get_repeat_ban_policies').length, 0);
});
