'use strict';

// Standalone: node --test tests/test_repeat_ban_ui.js
// Reuse the existing isolated VM/jQuery lifecycle fixture without registering its tests.
const assert = require('node:assert/strict');
const test = require('node:test');
const { harness, html } = require('./test_statistics_v011');
const plain = value => JSON.parse(JSON.stringify(value));
const defaults = () => ({ enabled: false, window_seconds: 86400,
  tiers: [{ threshold: 5, ban_seconds: 604800 }, { threshold: 10, ban_seconds: 2592000 }] });
const policy = (extra = {}, siteName = 'a.example', revision = 'revision-1') =>
  ({ status: true, siteName, policy: { ...defaults(), ...extra }, revision });
const record = (extra = {}) => ({ site: 'a.example', ip: '2001:db8::1', started_at: 1792700000,
  expires_at: 1793304800, duration: 604800, trigger_count: 5, window_seconds: 86400,
  threshold: 5, reason: 'endpoint_limit', path: '/login', ...extra });
const bans = (extra = {}) => ({ status: true, siteName: 'a.example', rows: [], total: 0,
  page: 1, per_page: 50, now: 1792700000, policy_enabled: false, notes: [], ...extra });

function open(h, extra = {}) {
  h.navigate('repeat_ban');
  assert.equal(h.requests.at(-1).method, 'get_repeat_ban_sites', 'the protection page lazily discovers sites');
  h.requests.at(-1).resolve({ status: true, sites: [{ siteName: 'a.example' }, { siteName: 'b.example' }],
    defaults: defaults(), limits: {}, ...extra });
}
function select(h, site = 'a.example') { h.$('#repeat_ban_site').val(site); h.fire('#repeat_ban_site', 'change'); }
function loaded(h, settings = {}, listing = {}) {
  open(h); select(h);
  h.of('get_repeat_ban_policy').at(-1).resolve(policy(settings));
  h.of('get_repeat_bans').at(-1).resolve(bans(listing));
}
function fill(h, settings = defaults()) {
  h.$('#repeat_ban_window_seconds').val(String(settings.window_seconds));
  h.$('#repeat_ban_enabled').prop('checked', settings.enabled);
  settings.tiers.forEach((tier, index) => {
    h.$('#repeat_ban_threshold_' + index).val(String(tier.threshold));
    h.$('#repeat_ban_seconds_' + index).val(String(tier.ban_seconds));
  });
}
function remove(h, index = 0, resetCounts = false) {
  h.fire(resetCounts ? '.repeat-ban-reset' : '.repeat-ban-remove', 'click', { 'data-index': String(index) });
}
function confirm(h) { const item = h.confirms.at(-1); assert.ok(item, 'requires a confirmation'); item.yes(123); return item; }

test('Chinese protection subnav, ladder bounds and unchecked lazy editor are discoverable', () => {
  assert.ok(html.includes('data-target="repeat_ban" data-section="protection"'));
  assert.ok(html.includes('data-type="repeat_ban"'));
  assert.match(html, /<h3>重复封禁升级<\/h3>/);
  for (const text of ['IP 白名单', '共享', '误封', '独立', '自动封禁', '手动封禁', '普通规则命中', '整个站点', '其他站点', '不会自动刷新', '7 天', '30 天']) assert.ok(html.includes(text), text);
  assert.match(html, /id="repeat_ban_window_seconds"[^>]*min="60"[^>]*max="604800"/);
  assert.doesNotMatch(html, /id="repeat_ban_enabled"[^>]*\bchecked\b/);
  assert.match(html, /id="repeat_ban_fields"[^>]*disabled/);
  assert.match(html, /id="repeat_ban_save"[^>]*disabled/);
});

test('Chinese help explains retained rolling counts, natural expiry and distinct reoffenses without retry escalation', () => {
  const page = html.split('data-type="repeat_ban"')[1].split('data-type="policies"')[0];
  for (const text of ['默认解封保留滚动计数', '解封并清零', '自然到期', '7 天', '24 小时', '提前', '独立', '继续累计']) assert.ok(page.includes(text), text);
  assert.match(page, /重复请求[^。]*不计数/);
  assert.match(page, /重复请求[^。]*不[^。]*升级/);
  assert.doesNotMatch(page, /解除只清除[^。]*重复历史/);
});

test('startup adds no repeat requests or timers, and opening waits for explicit site selection', () => {
  const h = harness();
  assert.deepEqual(h.requests.map(r => r.method), ['get_total_all', 'get_overview_report']);
  const timers = h.timers.size; open(h);
  assert.equal(h.timers.size, timers);
  assert.equal(h.of('get_repeat_ban_policy').length, 0);
  assert.equal(h.of('get_repeat_bans').length, 0);
  assert.equal(h.of('get_repeat_ban_sites')[0].options.type, 'POST');
  assert.deepEqual(plain(h.of('get_repeat_ban_sites')[0].options.data), {});
  assert.equal(h.waf.panel_section('repeat_ban'), 'protection');
  assert.equal(h.$('#repeat_ban_enabled').prop('checked'), false);
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
  assert.match(h.$('#repeat_ban_status').text(), /选择站点/);
  const count = h.requests.length; h.tick(1000000);
  assert.equal(h.requests.length, count + 1, 'only the pre-existing deferred update check runs');
});

test('selection sends exactly site-scoped policy and paginated POST reads, never enables before success', () => {
  const h = harness(); open(h); select(h);
  for (const [method, data] of [['get_repeat_ban_policy', { siteName: 'a.example' }],
    ['get_repeat_bans', { siteName: 'a.example', page: 1, per_page: 50 }]]) {
    const read = h.of(method).at(-1); assert.equal(read.options.type, 'POST'); assert.deepEqual(plain(read.options.data), data);
  }
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
  h.fire('#repeat_ban_save'); assert.equal(h.of('save_repeat_ban_policy').length, 0);
  h.of('get_repeat_ban_policy').at(-1).resolve(policy({ enabled: true }));
  assert.equal(h.$('#repeat_ban_enabled').prop('checked'), true);
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), false);
  assert.equal(h.$('#repeat_ban_threshold_0').val(), 5);
  assert.equal(h.$('#repeat_ban_seconds_1').val(), 2592000);
  assert.match(h.$('#repeat_ban_preview').text(), /5.*7 天[\s\S]*10.*30 天/);
});

test('disabled save carries revision and numeric tiers JSON, never legacy flat fields', () => {
  const h = harness(); loaded(h); fill(h); h.fire('#repeat_ban_save');
  const write = h.of('save_repeat_ban_policy').at(-1); assert.ok(write);
  assert.equal(write.options.type, 'POST'); assert.equal(write.options.data.siteName, 'a.example');
  assert.equal(write.options.data.revision, 'revision-1'); assert.deepEqual(JSON.parse(write.options.data.policy), defaults());
  assert.equal(h.confirms.length, 0); assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
  h.fire('#repeat_ban_save'); assert.equal(h.of('save_repeat_ban_policy').length, 1);
  write.resolve(policy({}, 'a.example', 'revision-2'));
  assert.equal(h.of('get_repeat_ban_policy').length, 2); assert.equal(h.of('get_repeat_bans').length, 2);
  h.of('get_repeat_ban_policy').at(-1).resolve(policy({}, 'a.example', 'revision-2'));
  h.of('get_repeat_bans').at(-1).resolve(bans()); h.fire('#repeat_ban_save');
  assert.equal(h.of('save_repeat_ban_policy').at(-1).options.data.revision, 'revision-2');
});

test('enabling requires escaped site-specific sitewide risk confirmation, cancel never saves', () => {
  const h = harness(); loaded(h); fill(h, { ...defaults(), enabled: true }); h.fire('#repeat_ban_save');
  const item = h.confirms.at(-1); assert.ok(item);
  for (const text of ['a.example', '整个站点', '接口', 'IP 白名单', '共享', '独立']) assert.ok(item.message.includes(text), text);
  assert.equal(h.of('save_repeat_ban_policy').length, 0);
  h.fire('#repeat_ban_save'); assert.equal(h.confirms.length, 1);
  h.fire('#repeat_ban_refresh'); assert.equal(h.of('get_repeat_bans').length, 1);
  item.cancel(); assert.equal(h.$('#repeat_ban_save').prop('disabled'), false);
  item.yes(1); assert.equal(h.of('save_repeat_ban_policy').length, 0);
  h.fire('#repeat_ban_save'); const active = confirm(h); active.yes(1);
  assert.equal(h.of('save_repeat_ban_policy').length, 1);
  assert.equal(JSON.parse(h.of('save_repeat_ban_policy')[0].options.data.policy).enabled, true);
});

test('every enabled save reconfirms consequences; a disabled save does not opt in', () => {
  const h = harness(); loaded(h, { enabled: true }); h.fire('#repeat_ban_save');
  assert.equal(h.of('save_repeat_ban_policy').length, 0); h.confirms.at(-1).options.cancel();
  h.$('#repeat_ban_enabled').prop('checked', false); h.fire('#repeat_ban_save');
  assert.equal(JSON.parse(h.of('save_repeat_ban_policy').at(-1).options.data.policy).enabled, false);
});

test('ladder supports one through eight editable rows and keeps drafts while adding/removing', () => {
  const h = harness(); loaded(h); h.$('#repeat_ban_threshold_0').val('6');
  h.fire('.repeat-ban-remove-tier', 'click', { 'data-index': '1' });
  assert.equal(h.$('#repeat_ban_threshold_0').val(), '6'); h.fire('#repeat_ban_save');
  assert.equal(JSON.parse(h.of('save_repeat_ban_policy').at(-1).options.data.policy).tiers.length, 1);
  h.of('save_repeat_ban_policy').at(-1).resolve({ status: false });
  h.fire('.repeat-ban-remove-tier', 'click', { 'data-index': '0' });
  for (let i = 0; i < 10; i++) h.fire('#repeat_ban_tiers_add');
  assert.equal(h.$('#repeat_ban_tiers_add').prop('disabled'), true);
  const tiers = Array.from({ length: 8 }, (_, i) => ({ threshold: 2 + i, ban_seconds: 60 + i }));
  fill(h, { ...defaults(), tiers }); h.fire('#repeat_ban_save');
  assert.deepEqual(JSON.parse(h.of('save_repeat_ban_policy').at(-1).options.data.policy).tiers, tiers);
});

test('default preset restores 24 hours, 5/7 days and 10/30 days without changing enabled state or saving', () => {
  const h = harness(); loaded(h); fill(h, { ...defaults(), window_seconds: 60 });
  h.fire('#repeat_ban_defaults');
  assert.equal(h.$('#repeat_ban_window_seconds').val(), 86400);
  assert.equal(h.$('#repeat_ban_seconds_0').val(), 604800); assert.equal(h.$('#repeat_ban_threshold_1').val(), 10);
  assert.equal(h.$('#repeat_ban_enabled').prop('checked'), false);
  assert.equal(h.of('save_repeat_ban_policy').length, 0);
});

test('invalid ranges, fractional values and non-increasing tier thresholds or durations never write', () => {
  const h = harness(); loaded(h);
  const invalid = [
    { window_seconds: 59 }, { window_seconds: 604801 }, { window_seconds: '60abc' }, { window_seconds: 60.5 },
    { tiers: [{ threshold: 1, ban_seconds: 60 }] }, { tiers: [{ threshold: 1001, ban_seconds: 60 }] },
    { tiers: [{ threshold: 2.5, ban_seconds: 60 }] }, { tiers: [{ threshold: 5, ban_seconds: 59 }] },
    { tiers: [{ threshold: 5, ban_seconds: 31536001 }] }, { tiers: [{ threshold: 5, ban_seconds: '1e3' }] },
    { tiers: [{ threshold: 5, ban_seconds: 600 }, { threshold: 5, ban_seconds: 900 }] },
    { tiers: [{ threshold: 10, ban_seconds: 600 }, { threshold: 5, ban_seconds: 900 }] },
    { tiers: [{ threshold: 5, ban_seconds: 900 }, { threshold: 10, ban_seconds: 900 }] },
    { tiers: [{ threshold: 5, ban_seconds: 900 }, { threshold: 10, ban_seconds: 600 }] },
  ];
  for (const extra of invalid) {
    const values = { ...defaults(), ...extra };
    if (values.tiers.length === 1) values.tiers.push({ threshold: 1000, ban_seconds: 31536000 });
    fill(h, values); h.fire('#repeat_ban_save');
    assert.equal(h.of('save_repeat_ban_policy').length, 0, JSON.stringify(extra));
    assert.match(h.$('#repeat_ban_status').text(), /未保存/);
  }
  fill(h, { enabled: false, window_seconds: 604800, tiers: [{ threshold: 2, ban_seconds: 60 }, { threshold: 1000, ban_seconds: 31536000 }] });
  h.fire('#repeat_ban_save'); assert.equal(h.of('save_repeat_ban_policy').length, 1);
});

test('raw snapshot rows show matched tier, scope, server-relative expiry and disabled non-enforcement', () => {
  const h = harness(); loaded(h, {}, { rows: [record()], total: 1 });
  const output = h.$('#repeat_ban_rows').html();
  for (const text of ['a.example', '2001:db8::1', '5', '86400', '604800', '接口限流', '/login', '7 天', '不执行']) assert.ok(output.includes(text), text);
  assert.match(h.$('#repeat_ban_rows_status').text(), /停用.*不执行/);
  assert.ok(output.includes(new Date(record().expires_at * 1000).toLocaleString('zh-CN')));
  const before = output; h.tick(10000000); assert.equal(h.$('#repeat_ban_rows').html(), before);
  h.fire('#repeat_ban_refresh'); h.of('get_repeat_bans').at(-1).resolve(bans({ policy_enabled: true,
    rows: [record({ expires_at: 1792700060 })], total: 1 }));
  assert.match(h.$('#repeat_ban_rows').html(), /60 秒/);
  h.fire('#repeat_ban_refresh'); h.of('get_repeat_bans').at(-1).resolve(bans({ rows: [record({ expires_at: 1792699999 })], total: 1 }));
  assert.match(h.$('#repeat_ban_rows').html(), /已到期/);
});

test('remote site, IP, reason, path and notes are escaped once without altering raw records', () => {
  const h = harness(), dirty = '<img src=x onerror="bad">&\'', escaped = '&lt;img src=x onerror=&quot;bad&quot;&gt;&amp;&#39;';
  open(h, { sites: [{ siteName: dirty }] }); assert.ok(h.$('#repeat_ban_site').html().includes(escaped));
  select(h, dirty); h.of('get_repeat_ban_policy').at(-1).resolve(policy({}, dirty));
  const data = bans({ siteName: dirty, rows: [record({ site: dirty, ip: dirty, reason: dirty, path: dirty })], total: 1, notes: [dirty] });
  const original = JSON.stringify(data); h.of('get_repeat_bans').at(-1).resolve(data);
  const output = h.$('#repeat_ban_rows').html(); assert.ok(output.includes(escaped));
  assert.ok(!output.includes('<img')); assert.ok(!output.includes('&amp;lt;'));
  assert.ok(h.$('#repeat_ban_notes').text().includes(dirty)); assert.equal(JSON.stringify(data), original);
  for (const reset of [false, true]) {
    const count = h.confirms.length; remove(h, 0, reset); assert.equal(h.confirms.length, count + 1);
    const item = h.confirms.at(-1); assert.ok(item.message.includes(escaped)); assert.ok(!item.message.includes('<img'));
    item.cancel();
  }
});

test('known automatic-ban reasons and legacy escalation history have Chinese labels', () => {
  const labels = {cc:'CC 防护',registration_abuse_verify:'注册验证码滥用',
    registration_abuse_register:'异常注册',endpoint_limit:'接口限流', '404_flood':'扫描式 404 请求'};
  for (const [reason, label] of Object.entries(labels)) {
    const h = harness();
    loaded(h, {}, {rows:[record({reason})],total:1});
    assert.ok(h.$('#repeat_ban_rows').html().includes(label), reason + ' lacks a Chinese label');
    assert.ok(!h.$('#repeat_ban_rows').html().includes('>'+reason+'<br>'), 'internal reason leaked');
  }
  assert.match(html, /row\[5\] === 'repeat_ban' \? '重复封禁升级（本站点）'/);
});

test('pagination uses fixed 50 page size and preserves server page bounds and manual refresh', () => {
  const h = harness(); loaded(h, {}, { rows: [record()], total: 101 });
  h.fire('#repeat_ban_prev'); assert.equal(h.of('get_repeat_bans').length, 1);
  h.fire('#repeat_ban_next'); assert.deepEqual(plain(h.of('get_repeat_bans').at(-1).options.data), { siteName: 'a.example', page: 2, per_page: 50 });
  h.fire('#repeat_ban_next'); assert.equal(h.of('get_repeat_bans').length, 2);
  h.of('get_repeat_bans').at(-1).resolve(bans({ page: 2, total: 101, rows: [record()] }));
  assert.match(h.$('#repeat_ban_page_info').text(), /2\s*\/\s*3.*101/);
  h.fire('#repeat_ban_refresh'); assert.equal(h.of('get_repeat_bans').at(-1).options.data.page, 2);
  h.of('get_repeat_bans').at(-1).resolve(bans({ page: 2, total: 101 }));
  h.fire('#repeat_ban_next'); h.of('get_repeat_bans').at(-1).resolve(bans({ page: 3, total: 101 }));
  const count = h.requests.length; h.fire('#repeat_ban_next'); assert.equal(h.requests.length, count);
});

test('a shrunk last page is honest and permits a manual return without an automatic follow-up read', () => {
  const h = harness(); loaded(h, {}, { rows: [record()], total: 101 });
  h.fire('#repeat_ban_next'); h.of('get_repeat_bans').at(-1).resolve(bans({ page: 2, total: 101, rows: [record()] }));
  h.fire('#repeat_ban_next'); h.of('get_repeat_bans').at(-1).resolve(bans({ page: 3, total: 101, rows: [record()] }));
  h.fire('#repeat_ban_refresh'); const count = h.of('get_repeat_bans').length;
  h.of('get_repeat_bans').at(-1).resolve(bans({ page: 3, total: 1 }));
  assert.equal(h.of('get_repeat_bans').length, count, 'no automatic page repair fetch');
  assert.match(h.$('#repeat_ban_rows').html(), /本页.*记录.*上一页/);
  assert.doesNotMatch(h.$('#repeat_ban_rows_status').text(), /失败/);
  assert.equal(h.$('#repeat_ban_prev').prop('disabled'), false);
  h.fire('#repeat_ban_prev'); assert.equal(h.of('get_repeat_bans').at(-1).options.data.page, 1);
});

test('default remove confirms retention, POSTs reset_counts zero and refreshes only after success', () => {
  const h = harness(); loaded(h, {}, { rows: [record()], total: 1 }); remove(h);
  const item = h.confirms.at(-1); for (const text of ['a.example', '2001:db8::1', '保留', '滚动计数', '继续累计', '手动', '基础']) assert.ok(item.message.includes(text), text);
  assert.doesNotMatch(item.message, /清除[^。]*历史|清零/);
  assert.match(h.$('#repeat_ban_rows').html(), /解除[^<]*保留计数/);
  item.cancel(); item.yes(1); assert.equal(h.of('remove_repeat_ban').length, 0);
  remove(h); const active = confirm(h); active.yes(1); remove(h);
  assert.equal(h.of('remove_repeat_ban').length, 1);
  const write = h.of('remove_repeat_ban')[0]; assert.equal(write.options.type, 'POST');
  assert.deepEqual(plain(write.options.data), { siteName: 'a.example', ip: '2001:db8::1', reset_counts: '0' });
  write.resolve({ status: true }); assert.equal(h.of('get_repeat_bans').length, 2); assert.equal(h.of('get_repeat_ban_policy').length, 2);
});

test('explicit reset action confirms clearing, POSTs reset_counts one and cannot duplicate or overlap default remove', () => {
  const h = harness(); loaded(h, {}, { rows: [record()], total: 1 });
  assert.match(h.$('#repeat_ban_rows').html(), /repeat-ban-reset[^>]*>解封并清零/);
  remove(h, 0, true); const item = h.confirms.at(-1); assert.ok(item);
  for (const text of ['a.example', '2001:db8::1', '清零', '滚动计数', '重新累计', '手动', '基础']) assert.ok(item.message.includes(text), text);
  assert.equal(h.of('remove_repeat_ban').length, 0); remove(h); remove(h, 0, true);
  assert.equal(h.confirms.length, 1); assert.equal(h.$('.repeat-ban-remove').prop('disabled'), true);
  assert.equal(h.$('.repeat-ban-reset').prop('disabled'), true);
  item.options.cancel(); item.yes(1); assert.equal(h.of('remove_repeat_ban').length, 0);
  assert.equal(h.$('.repeat-ban-reset').prop('disabled'), false);
  remove(h, 0, true); const active = confirm(h); active.yes(1); remove(h); remove(h, 0, true);
  assert.equal(h.of('remove_repeat_ban').length, 1);
  const write = h.of('remove_repeat_ban')[0]; assert.equal(write.options.type, 'POST');
  assert.deepEqual(plain(write.options.data), { siteName: 'a.example', ip: '2001:db8::1', reset_counts: '1' });
  write.resolve({ status: true }); assert.equal(h.of('get_repeat_bans').length, 2); assert.equal(h.of('get_repeat_ban_policy').length, 2);
});

for (const resetCounts of [false, true]) test((resetCounts ? 'reset' : 'retaining') + ' removal confirmation cannot survive site changes, navigation, close or reinit', () => {
  for (const action of ['site', 'leave', 'close', 'reinit', 'reload']) {
    const h = harness(); loaded(h, {}, { rows: [record()], total: 1 }); remove(h, 0, resetCounts);
    const item = h.confirms.at(-1); assert.ok(item); const closed = [];
    h.context.layer.close = index => closed.push(index);
    if (action === 'site') { select(h, 'b.example'); select(h); }
    if (action === 'leave') { h.navigate('home'); h.navigate('repeat_ban'); }
    if (action === 'close') h.close(); if (action === 'reinit') h.waf.init(); if (action === 'reload') h.reload();
    assert.ok(closed.length, action); item.yes(1); assert.equal(h.of('remove_repeat_ban').length, 0, action);
  }
});

for (const resetCounts of [false, true]) test((resetCounts ? 'reset' : 'retaining') + ' pending removal is single-flight and late results cannot affect another site', () => {
  const h = harness(); loaded(h, {}, { rows: [record()], total: 1 }); remove(h, 0, resetCounts); confirm(h);
  const write = h.of('remove_repeat_ban').at(-1); assert.ok(write);
  remove(h, 0, !resetCounts); assert.equal(h.of('remove_repeat_ban').length, 1); assert.equal(h.confirms.length, 1);
  select(h, 'b.example'); assert.ok(write.aborted);
  h.of('get_repeat_ban_policy').at(-1).resolve(policy({}, 'b.example'));
  h.of('get_repeat_bans').at(-1).resolve(bans({ siteName: 'b.example' }));
  const count = h.requests.length, status = h.$('#repeat_ban_status').text(), rows = h.$('#repeat_ban_rows').html();
  write.options.success({ status: true }); write.options.error({}, 'timeout'); write.options.complete({}, 'success');
  assert.equal(h.requests.length, count); assert.equal(h.$('#repeat_ban_status').text(), status); assert.equal(h.$('#repeat_ban_rows').html(), rows);
});

for (const action of ['leave', 'close', 'reinit', 'reload']) test(action + ' aborts discovery and rejects late callbacks', () => {
  const h = harness(); h.navigate('repeat_ban'); const old = h.requests.at(-1);
  assert.equal(old.method, 'get_repeat_ban_sites');
  if (action === 'leave') h.navigate('home'); if (action === 'close') h.close();
  if (action === 'reinit') h.waf.init(); if (action === 'reload') h.reload();
  assert.ok(old.aborted); const count = h.requests.length;
  old.options.success({ status: true, sites: [{ siteName: 'late.example' }], defaults: defaults(), limits: {} });
  old.options.error({}, 'timeout'); old.options.complete({}, 'success');
  assert.equal(h.requests.length, count); assert.ok(!h.$('#repeat_ban_site').html().includes('late.example'));
});

test('A-B-A site changes abort reads and reject forced stale success/error/complete and confirmations', () => {
  const h = harness(); open(h); select(h); const old = h.requests.slice(-2); select(h, 'b.example'); select(h);
  assert.ok(old.every(r => r.aborted)); h.of('get_repeat_ban_policy').at(-1).resolve(policy());
  h.of('get_repeat_bans').at(-1).resolve(bans({ rows: [record()], total: 1 }));
  const count = h.requests.length, before = h.$('#repeat_ban_rows').html();
  old[0].options.success(policy({ enabled: true })); old[0].options.error({}, 'timeout'); old[0].options.complete({}, 'success');
  old[1].options.success(bans({ rows: [record({ path: 'STALE' })], total: 1 }));
  assert.equal(h.$('#repeat_ban_enabled').prop('checked'), false); assert.equal(h.$('#repeat_ban_rows').html(), before);
  assert.equal(h.requests.length, count); remove(h); const item = h.confirms.at(-1);
  select(h, 'b.example'); select(h); item.yes(1); assert.equal(h.of('remove_repeat_ban').length, 0);
});

test('pending confirmations cancel on navigation, reinit, reload and site changes, even when original site returns', () => {
  for (const action of ['leave', 'reinit', 'reload', 'site']) {
    const h = harness(); loaded(h); fill(h, { ...defaults(), enabled: true }); h.fire('#repeat_ban_save');
    const item = h.confirms.at(-1); assert.ok(item); const closed = [];
    h.context.layer.close = index => closed.push(index);
    if (action === 'leave') { h.navigate('home'); h.navigate('repeat_ban'); }
    if (action === 'site') { select(h, 'b.example'); select(h); }
    if (action === 'reinit') h.waf.init(); if (action === 'reload') h.reload();
    assert.ok(closed.length, action); item.yes(1); assert.equal(h.of('save_repeat_ban_policy').length, 0, action);
  }
});

test('site changes abort writes and old write completion cannot overwrite the next site draft', () => {
  const h = harness(); loaded(h); h.fire('#repeat_ban_save'); const old = h.of('save_repeat_ban_policy').at(-1);
  select(h, 'b.example'); assert.ok(old.aborted);
  h.of('get_repeat_ban_policy').at(-1).resolve(policy({}, 'b.example'));
  h.$('#repeat_ban_threshold_0').val('7'); const count = h.requests.length;
  old.options.success(policy({ enabled: true })); old.options.error({}, 'timeout'); old.options.complete({}, 'success');
  assert.equal(h.$('#repeat_ban_threshold_0').val(), '7'); assert.equal(h.requests.length, count);
});

test('writes cancel an in-flight snapshot and block refresh, tier edits and duplicate submit', () => {
  const h = harness(); loaded(h); h.fire('#repeat_ban_refresh'); const list = h.of('get_repeat_bans').at(-1);
  h.fire('#repeat_ban_save'); assert.ok(list.aborted); const count = h.requests.length;
  h.fire('#repeat_ban_refresh'); h.fire('#repeat_ban_policy_refresh'); h.fire('#repeat_ban_sites_refresh');
  h.fire('#repeat_ban_tiers_add'); h.fire('#repeat_ban_defaults'); h.fire('#repeat_ban_editor', 'submit');
  assert.equal(h.requests.length, count); assert.equal(h.of('save_repeat_ban_policy').length, 1);
  list.options.success(bans({ rows: [record({ path: 'STALE' })], total: 1 })); list.options.error({}, 'timeout'); list.options.complete({}, 'success');
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), true); assert.ok(!h.$('#repeat_ban_rows').html().includes('STALE'));
});

test('a cancelled list read does not remain stuck loading after a failed concurrent save', () => {
  const h = harness(); loaded(h); h.fire('#repeat_ban_refresh'); h.fire('#repeat_ban_save');
  h.of('save_repeat_ban_policy').at(-1).reject();
  assert.match(h.$('#repeat_ban_rows_status').text(), /已取消.*手动刷新/);
  assert.doesNotMatch(h.$('#repeat_ban_rows').html(), /正在读取/);
  assert.equal(h.$('#repeat_ban_refresh').prop('disabled'), false);
  h.fire('#repeat_ban_refresh'); h.of('get_repeat_bans').at(-1).resolve(bans());
  assert.match(h.$('#repeat_ban_rows').html(), /暂无/);
});

test('reinitialization keeps exactly one live delegated handler and remains lazy', () => {
  const h = harness(); h.waf.init(); h.waf.init(); const count = h.requests.length;
  assert.equal(h.of('get_repeat_ban_sites').length, 0); open(h); select(h);
  assert.equal(h.of('get_repeat_ban_policy').length, 1); assert.equal(h.requests.length, count + 3);
  h.of('get_repeat_ban_policy').at(-1).resolve(policy()); h.of('get_repeat_bans').at(-1).resolve(bans());
  h.fire('#repeat_ban_editor', 'submit'); assert.equal(h.of('save_repeat_ban_policy').length, 1);
});

test('replacement manual reads abort owners and stale completion cannot enable saving', () => {
  const h = harness(); loaded(h); h.fire('#repeat_ban_policy_refresh'); const old = h.of('get_repeat_ban_policy').at(-1);
  h.fire('#repeat_ban_policy_refresh'); assert.ok(old.aborted); const next = h.of('get_repeat_ban_policy').at(-1);
  old.options.success(policy({ enabled: true })); old.options.complete({}, 'success');
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
  next.resolve(policy()); assert.equal(h.$('#repeat_ban_save').prop('disabled'), false);
  h.fire('#repeat_ban_refresh'); const list = h.of('get_repeat_bans').at(-1); h.fire('#repeat_ban_refresh'); assert.ok(list.aborted);
  list.options.success(bans({ rows: [record({ path: 'STALE' })], total: 1 })); assert.ok(!h.$('#repeat_ban_rows').html().includes('STALE'));
});

for (const failure of ['api', 'network', 'malformed', 'wrong-site']) test(failure + ' policy read never fabricates enabled/editable success', () => {
  const h = harness(); loaded(h, { enabled: true }); h.fire('#repeat_ban_policy_refresh');
  assert.equal(h.$('#repeat_ban_enabled').prop('checked'), false); const read = h.of('get_repeat_ban_policy').at(-1);
  if (failure === 'network') read.reject();
  else read.resolve(failure === 'api' ? { status: false, msg: '<b>失败</b>' } : failure === 'wrong-site' ? policy({}, 'b.example') : policy({ tiers: [] }));
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), true); assert.match(h.$('#repeat_ban_status').text(), /失败/);
  h.fire('#repeat_ban_save'); assert.equal(h.of('save_repeat_ban_policy').length, 0);
  h.fire('#repeat_ban_policy_refresh'); h.of('get_repeat_ban_policy').at(-1).resolve(policy());
  assert.equal(h.$('#repeat_ban_save').prop('disabled'), false);
});

for (const action of ['save_repeat_ban_policy', 'remove_repeat_ban', 'reset_repeat_ban']) {
  const method = action === 'reset_repeat_ban' ? 'remove_repeat_ban' : action;
  for (const failure of ['api', 'network', 'malformed']) test(action + ' ' + failure + ' failure preserves evidence/draft and does not claim success', () => {
    const h = harness(); loaded(h, {}, { rows: [record()], total: 1 }); h.$('#repeat_ban_threshold_0').val('6');
    if (method === 'save_repeat_ban_policy') h.fire('#repeat_ban_save'); else { remove(h, 0, action === 'reset_repeat_ban'); confirm(h); }
    const before = h.$('#repeat_ban_rows').html(), write = h.of(method).at(-1); assert.ok(write);
    if (failure === 'network') write.reject();
    else write.resolve(failure === 'api' ? { status: false, msg: '服务器拒绝' } : method === 'save_repeat_ban_policy' ? { status: true } : { status: 'true' });
    assert.equal(h.$('#repeat_ban_threshold_0').val(), '6'); assert.equal(h.$('#repeat_ban_rows').html(), before);
    assert.match(h.$('#repeat_ban_status').text(), /失败|未确认/); assert.equal(h.of('get_repeat_ban_policy').length, 1);
    assert.equal(h.of('get_repeat_bans').length, 1); assert.equal(h.$('#repeat_ban_save').prop('disabled'), false);
    assert.equal(h.$('.repeat-ban-reset').prop('disabled'), false);
  });
}

test('list failures clear stale records and pagination, show unknown not disabled, and allow manual retry', () => {
  for (const failure of ['network', 'api', 'malformed', 'wrong-site', 'wrong-row-site']) {
    const h = harness(); loaded(h, {}, { rows: [record()], total: 101 }); h.fire('#repeat_ban_refresh');
    const read = h.of('get_repeat_bans').at(-1);
    if (failure === 'network') read.reject();
    else read.resolve(failure === 'api' ? { status: false } : failure === 'malformed' ? bans({ now: null })
      : failure === 'wrong-site' ? bans({ siteName: 'b.example' }) : bans({ rows: [record({ site: 'b.example' })], total: 1 }));
    assert.match(h.$('#repeat_ban_rows_status').text(), /失败/); assert.ok(!h.$('#repeat_ban_rows').html().includes('2001:db8'));
    assert.equal(h.$('#repeat_ban_next').prop('disabled'), true); remove(h); assert.equal(h.confirms.length, 0);
    h.fire('#repeat_ban_refresh'); h.of('get_repeat_bans').at(-1).resolve(bans());
    assert.match(h.$('#repeat_ban_rows').html(), /暂无/);
  }
});

test('empty/failed site discovery and unrecognized selection remain safely disabled and retryable', () => {
  const h = harness(); open(h, { sites: [] }); assert.match(h.$('#repeat_ban_status').text(), /暂无.*站点/);
  select(h, 'unknown.example'); assert.equal(h.of('get_repeat_ban_policy').length, 0);
  h.fire('#repeat_ban_sites_refresh'); h.of('get_repeat_ban_sites').at(-1).reject();
  assert.match(h.$('#repeat_ban_status').text(), /失败/); assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
  h.fire('#repeat_ban_sites_refresh'); h.of('get_repeat_ban_sites').at(-1).resolve({ status: false, sites: [{ siteName: 'a.example' }] });
  assert.equal(h.$('#repeat_ban_site').prop('disabled'), true);
});

test('invalid remote policies, missing revisions and flat legacy policy never unlock save', () => {
  const bad = [{ tiers: [] }, { tiers: Array.from({ length: 9 }, (_, i) => ({ threshold: i + 2, ban_seconds: i + 60 })) },
    { tiers: [{ threshold: 10, ban_seconds: 600 }, { threshold: 5, ban_seconds: 900 }] }, { enabled: 'true' },
    { tiers: [{ threshold: 5, ban_seconds: '604800' }] }];
  for (const extra of bad) {
    const h = harness(); open(h); select(h); h.of('get_repeat_ban_policy').at(-1).resolve(policy(extra));
    assert.equal(h.$('#repeat_ban_save').prop('disabled'), true, JSON.stringify(extra));
  }
  for (const response of [policy({}, 'a.example', ''), { status: true, siteName: 'a.example', revision: 'r', policy: { enabled: false, window_seconds: 86400, threshold: 28, ban_seconds: 2592000 } }]) {
    const h = harness(); open(h); select(h); h.of('get_repeat_ban_policy').at(-1).resolve(response);
    assert.equal(h.$('#repeat_ban_save').prop('disabled'), true);
  }
});
