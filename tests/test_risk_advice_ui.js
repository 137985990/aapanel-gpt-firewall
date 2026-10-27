'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { harness, html } = require('./test_statistics_v011');
const site = 'a.example', other = 'b.example', ip = '203.0.113.25';
const now = Date.UTC(2026, 9, 22) / 1000;
const revision = 'a'.repeat(64), fingerprint = 'b'.repeat(64), banRevision = 'c'.repeat(32);
const item = (extra = {}) => ({site, ip, fingerprint, name: '敏感文件批量探测',
  recommended_seconds: 86400, related_rows: 120, strong_targets: 55, raw_targets: 60,
  family_counts: {env: 50, repository: 5}, first_seen: now - 150, last_seen: now - 60,
  samples: ['/.env', '/.git/config'], location: '本地归属地', actionable: true, hold_reasons: [], ...extra});
const report = (extra = {}) => ({status: true, siteName: site, analyzed_at: now,
  config_revision: revision, coverage: {partial: true, scanned_files: 2, scanned_lines: 140,
    scanned_bytes: 8192, invalid_lines: 3, cutoff: now - 86400, notice: '仅尾部样本'},
  items: [item()], ...extra});
const bans = (entries = [], extra = {}) => ({status: true, siteName: site, revision: banRevision,
  entries, now, site_enabled: true, runtime_verified: false, verification_scope: 'one_local_worker_snapshot', ...extra});
const active = (extra = {}) => ({site, ip, started_at: now - 10, expires_at: now + 604800,
  duration: 604800, reason: 'risk_advice', evidence_hash: fingerprint, ...extra});
function open(sites = [site, other]) {
  const h = harness(); h.navigate('history');
  h.of('get_risk_advice_sites').at(-1).resolve({status: true, sites: sites.map(siteName => ({siteName}))});
  return h;
}
function select(h, name = site) {
  h.$('#risk-advice-site').val(name); h.fire('#risk-advice-site', 'change');
}
function loaded(data = report(), entries = []) {
  const h = open(); select(h);
  h.of('get_risk_site_bans').at(-1).resolve(bans(entries));
  h.fire('#risk-advice-analyze'); h.of('get_risk_advice').at(-1).resolve(data);
  return h;
}
function action(h, kind, index = 0) { h.fire('.risk-advice-' + kind, 'click', {'data-index': String(index)}); }
function confirm(h) { const question = h.confirms.at(-1); assert.ok(question); question.yes(1); return question; }

test('Chinese advice and independent manual bans are above the existing ban list', () => {
  assert.ok(html.indexOf('id="risk-advice-card"') < html.indexOf('id="history_table"'));
  for (const label of ['风险 IP 封禁建议', '本地日志分析，仅供人工确认；本模块不会自动封禁',
    '分析最近 24 小时', '本站人工封禁', '与自动重复封禁开关独立', '归属地', '暂不处理']) assert.ok(html.includes(label), label);
  for (const id of ['risk-advice-site', 'risk-advice-analyze', 'risk-advice-status', 'risk-advice-coverage',
    'risk-advice-analyzed', 'risk-advice-rows', 'risk-advice-evidence', 'risk-advice-mutation',
    'risk-advice-manual-rows', 'risk-advice-manual-status']) assert.ok(html.includes('id="' + id + '"'), id);
});

test('initialization and unrelated pages never request sites, analysis or manual bans', () => {
  const h = harness(); h.navigate('repeat_ban'); h.navigate('home');
  for (const method of ['get_risk_advice_sites', 'get_risk_advice', 'get_risk_site_bans']) assert.equal(h.of(method).length, 0);
});

test('history lazily loads sites; choosing a site loads manual bans but never scans or polls', () => {
  const h = open(), timers = h.timers.size;
  assert.equal(h.of('get_risk_advice').length, 0);
  assert.equal(h.of('get_risk_site_bans').length, 0);
  select(h); assert.equal(h.of('get_risk_site_bans').length, 1);
  assert.equal(h.of('get_risk_advice').length, 0);
  assert.match(h.$('#risk-advice-status').text(), /尚未分析/);
  h.tick(600000); assert.equal(h.of('get_risk_advice').length, 0); assert.ok(h.timers.size <= timers, 'no new polling timer');
  h.fire('#risk-advice-analyze'); h.fire('#risk-advice-analyze');
  assert.equal(h.of('get_risk_advice').length, 1);
  assert.equal(h.of('get_risk_advice')[0].options.data.siteName, site);
});

test('analysis displays actual partial coverage, evidence and local geography without percentages', () => {
  const h = loaded();
  const text = h.$('#risk-advice-coverage').text();
  for (const fragment of ['部分', '2', '140', '8192', '3', '仅尾部样本']) assert.ok(text.includes(fragment), fragment);
  assert.doesNotMatch(text, /%|完整覆盖|没有攻击/);
  assert.match(h.$('#risk-advice-analyzed').text(), /分析时间/);
  assert.match(h.$('#risk-advice-rows').html(), /203\.0\.113\.25[\s\S]*本地归属地[\s\S]*a.example/);
  assert.match(h.$('#risk-advice-rows').html(), /敏感文件批量探测[\s\S]*120[\s\S]*55[\s\S]*24 小时/);
  action(h, 'evidence');
  for (const fragment of ['/.env', '/.git/config', '60', '50', '版本库', '日志', fingerprint]) assert.ok(h.$('#risk-advice-evidence').html().includes(fragment), fragment);
  assert.equal(h.of('apply_risk_advice').length, 0);
});

for (const extra of [{recommended_seconds: 0}, {actionable: false, hold_reasons: ['IP 白名单冲突']}]) {
  test('observe or held evidence never enables any ban shortcut: ' + JSON.stringify(extra), () => {
    const h = loaded(report({items: [item(extra)]}));
    assert.match(h.$('#risk-advice-rows').html(), /disabled/);
    if (!extra.actionable && extra.actionable !== undefined) assert.match(h.$('#risk-advice-rows').html(), /IP 白名单冲突/);
    if (extra.recommended_seconds === 0) assert.match(h.$('#risk-advice-rows').html(), /建议观察/);
    for (const kind of ['suggest', 'custom', 'long']) action(h, kind);
    assert.equal(h.confirms.length, 0); assert.equal(h.of('apply_risk_advice').length, 0);
  });
}

test('accepting a recommendation confirms exact site, expiry, impact and submits once with server evidence', () => {
  const h = loaded(); action(h, 'suggest'); const question = h.confirms.at(-1);
  for (const text of [site, ip, '24 小时', '到期', '仅', '其他站点', 'IP 白名单', '共享出口']) assert.ok(question.message.includes(text), text);
  assert.equal(h.of('apply_risk_advice').length, 0);
  question.yes(1); question.yes(1); action(h, 'suggest');
  const write = h.of('apply_risk_advice'); assert.equal(write.length, 1);
  assert.equal(write[0].options.type, 'POST');
  assert.deepEqual(JSON.parse(JSON.stringify(write[0].options.data)), {siteName: site, ip,
    fingerprint, config_revision: revision, duration: '86400', confirm_long: '0'});
  assert.equal(h.of('add_ip_black').length, 0); assert.equal(h.of('add_permanent_ban').length, 0);
});

test('seven-day tier uses recommendation while custom 30 days is explicitly manual', () => {
  const h = loaded(report({items: [item({recommended_seconds: 604800})]}));
  assert.match(h.$('#risk-advice-rows').html(), /7 天/);
  action(h, 'custom'); assert.equal(h.$('#risk-advice-custom-value').val(), 30);
  assert.equal(h.$('#risk-advice-custom-unit').val(), '86400');
  h.fire('#risk-advice-custom-confirm'); const question = h.confirms.at(-1);
  assert.match(question.message, /30 天/); assert.match(question.message, /人工自定义/);
  confirm(h); assert.equal(h.of('apply_risk_advice')[0].options.data.duration, '2592000');
  assert.equal(h.of('apply_risk_advice')[0].options.data.confirm_long, '0');
});

test('seven-day suggestion submits its tier rather than a fixed 24-hour or 30-day duration', () => {
  const h = loaded(report({items: [item({recommended_seconds: 604800})]}));
  action(h, 'suggest'); confirm(h);
  assert.equal(h.of('apply_risk_advice')[0].options.data.duration, '604800');
});

for (const raw of ['0', '-1', '1.5', '1e3', '9999999999999', '<script>']) test('invalid custom duration cannot be submitted: ' + raw, () => {
  const h = loaded(); action(h, 'custom'); h.$('#risk-advice-custom-value').val(raw);
  h.fire('#risk-advice-custom-confirm');
  assert.equal(h.confirms.length, 0); assert.equal(h.of('apply_risk_advice').length, 0);
  assert.match(h.$('#risk-advice-status').text(), /整数|时长/);
});

test('10-year action has two independent confirmations, exact expiry and finite duration', () => {
  const h = loaded(); action(h, 'long');
  const first = confirm(h); assert.match(first.message, /10 年/);
  assert.equal(h.of('apply_risk_advice').length, 0);
  assert.equal(h.confirms.length, 2);
  const second = h.confirms.at(-1); assert.match(second.message, /再次确认[\s\S]*到期/);
  assert.doesNotMatch(second.message, /永久/);
  second.yes(2); second.yes(2); first.yes(1);
  assert.equal(h.of('apply_risk_advice').length, 1);
  assert.equal(h.of('apply_risk_advice')[0].options.data.duration, '315360000');
  assert.equal(h.of('apply_risk_advice')[0].options.data.confirm_long, '1');
});

test('custom 3650 days cannot bypass the second long-term confirmation', () => {
  const h = loaded(); action(h, 'custom'); h.$('#risk-advice-custom-value').val('3650');
  h.fire('#risk-advice-custom-confirm'); confirm(h);
  assert.equal(h.of('apply_risk_advice').length, 0); assert.equal(h.confirms.length, 2);
  confirm(h); assert.equal(h.of('apply_risk_advice')[0].options.data.confirm_long, '1');
});

test('cancelled first and second confirmations never submit through stale callbacks', () => {
  for (const step of [1, 2]) {
    const h = loaded(); action(h, 'long'); if (step === 2) confirm(h);
    const question = h.confirms.at(-1); question.cancel(); question.yes(1);
    assert.equal(h.of('apply_risk_advice').length, 0);
  }
});

test('dismiss is local, revocable by reanalysis and never writes a ban', () => {
  const h = loaded(); action(h, 'dismiss');
  assert.doesNotMatch(h.$('#risk-advice-rows').html(), /203\.0\.113\.25/);
  assert.equal(h.of('apply_risk_advice').length, 0); assert.equal(h.of('get_risk_advice').length, 1);
  h.fire('#risk-advice-analyze'); h.of('get_risk_advice').at(-1).resolve(report());
  assert.match(h.$('#risk-advice-rows').html(), /203\.0\.113\.25/);
});

for (const [status, saved, verified] of [[true, true, true], [true, true, false], [false, true, false], [false, false, false]]) {
  test('write reports saved and runtime evidence independently: ' + [status, saved, verified].join('/'), () => {
    const h = loaded(); action(h, 'suggest'); confirm(h);
    h.of('apply_risk_advice')[0].resolve({status, saved, runtime_verified: verified,
      verification_scope: verified ? 'one_local_worker_snapshot' : 'unverified', msg: '服务器说明'});
    const text = h.$('#risk-advice-mutation').text();
    assert.match(text, saved ? /配置已保存/ : /未确认保存/);
    assert.match(text, verified ? /运行端快照已核验/ : /运行端未核验/);
    assert.doesNotMatch(text, /封禁成功|已生效|已拦截/);
    if (saved) assert.equal(h.of('get_risk_site_bans').length, 2);
    action(h, 'suggest'); assert.equal(h.of('apply_risk_advice').length, 1, 'new confirmation needs fresh analysis');
  });
}

test('write network failure is uncertain and requires analysis before any retry', () => {
  const h = loaded(); action(h, 'suggest'); confirm(h); h.of('apply_risk_advice')[0].reject();
  assert.match(h.$('#risk-advice-mutation').text(), /未确认[\s\S]*服务器可能/);
  action(h, 'suggest'); assert.equal(h.of('apply_risk_advice').length, 1);
});

test('a response without the known observation scope cannot be presented as runtime verified', () => {
  const h = loaded(); action(h, 'suggest'); confirm(h);
  h.of('apply_risk_advice')[0].resolve({status: true, saved: true, runtime_verified: true, verification_scope: 'all_workers'});
  assert.match(h.$('#risk-advice-mutation').text(), /配置已保存[\s\S]*运行端未核验/);
});

test('manual bans work with no escalation switch and unban carries site and snapshot revision', () => {
  const h = loaded(report(), [active()]);
  assert.match(h.$('#risk-advice-manual-rows').html(), /203\.0\.113\.25[\s\S]*a.example[\s\S]*7 天/);
  assert.match(h.$('#risk-advice-manual-status').text(), /运行端未核验/);
  action(h, 'remove'); const question = h.confirms.at(-1);
  for (const text of [site, ip, '不', '自动', '其他站点']) assert.ok(question.message.includes(text), text);
  confirm(h); const write = h.of('remove_risk_site_ban')[0]; assert.ok(write);
  assert.deepEqual(JSON.parse(JSON.stringify(write.options.data)), {siteName: site, ip, revision: banRevision});
  write.resolve({status: true, saved: true, runtime_verified: false});
  assert.match(h.$('#risk-advice-mutation').text(), /配置已保存[\s\S]*运行端未核验/);
  assert.equal(h.of('remove_repeat_ban').length, 0); assert.equal(h.of('remove_ip_black').length, 0);
});

test('existing stronger ban is disclosed, not promised to be shortened', () => {
  const h = loaded(report(), [active({duration: 2592000, expires_at: now + 2592000})]);
  action(h, 'suggest'); assert.match(h.confirms.at(-1).message, /已有更长[\s\S]*不会缩短/);
});

test('snapshot observation never hides a disabled site or claims all-worker enforcement', () => {
  const h = open(); select(h);
  h.of('get_risk_site_bans')[0].resolve(bans([active()], {site_enabled: false, runtime_verified: true}));
  const text = h.$('#risk-advice-manual-status').text();
  assert.match(text, /本站防护已关闭/); assert.match(text, /单个[\s\S]*快照已核验/);
  assert.match(text, /不代表[\s\S]*全部/); assert.doesNotMatch(text, /已生效|正在拦截/);
  assert.match(h.$('#risk-advice-manual-rows').html(), /203\.0\.113\.25/);
});

test('manual records use server time rather than local clock to show expiry', () => {
  const h = open(); select(h);
  h.of('get_risk_site_bans')[0].resolve(bans([active({expires_at: now + 100})], {now: now + 101}));
  assert.match(h.$('#risk-advice-manual-rows').html(), /已到期/);
});

test('unban during an analysis cancels it without leaving a permanent analyzing label', () => {
  const h = loaded(report(), [active()]); h.fire('#risk-advice-analyze');
  const pending = h.of('get_risk_advice').at(-1);
  action(h, 'remove'); confirm(h);
  assert.ok(pending.aborted);
  assert.match(h.$('#risk-advice-status').text(), /重新分析/);
  assert.doesNotMatch(h.$('#risk-advice-analyzed').text(), /正在分析/);
  assert.equal(h.of('remove_risk_site_ban').length, 1);
});

test('coverage reports observed and requested windows and item limit explicitly', () => {
  const h = loaded(report({coverage: {partial: false, scanned_lines: 100, scanned_bytes: 4096,
    scanned_files: 1, invalid_lines: 0, requested_from: now - 86400, requested_to: now,
    first_seen: now - 3600, last_seen: now - 100, items_limited: true}}));
  const text = h.$('#risk-advice-coverage').text();
  for (const label of ['请求区间', '实际记录区间', '列表', '上限']) assert.ok(text.includes(label), label);
  assert.doesNotMatch(text, /%|^完整覆盖/);
});

for (const transition of ['site', 'leave', 'close', 'reinit', 'reload']) {
  test('stale analysis and callbacks cannot repaint or write after ' + transition, () => {
    const h = open(); select(h); h.fire('#risk-advice-analyze');
    const read = h.of('get_risk_advice')[0], manual = h.of('get_risk_site_bans')[0];
    if (transition === 'site') select(h, other);
    if (transition === 'leave') { h.navigate('home'); h.navigate('history'); }
    if (transition === 'close') h.close();
    if (transition === 'reinit') h.waf.init();
    if (transition === 'reload') h.reload();
    assert.ok(read.aborted); assert.ok(manual.aborted);
    const count = h.requests.length, before = h.$('#risk-advice-rows').html(), status = h.$('#risk-advice-status').text();
    read.options.success(report()); read.options.error({}, 'timeout'); read.options.complete({}, 'success');
    manual.options.success(bans([active()])); manual.options.complete({}, 'success');
    assert.equal(h.requests.length, count); assert.equal(h.$('#risk-advice-rows').html(), before);
    assert.equal(h.$('#risk-advice-status').text(), status);
    assert.equal(h.$('#risk-advice-analyze').prop('disabled'), transition !== 'site');
  });
  test('stale confirmation does not submit after ' + transition, () => {
    const h = loaded(); action(h, 'long'); confirm(h); const old = h.confirms.at(-1);
    if (transition === 'site') select(h, other);
    if (transition === 'leave') { h.navigate('home'); h.navigate('history'); }
    if (transition === 'close') h.close();
    if (transition === 'reinit') h.waf.init();
    if (transition === 'reload') h.reload();
    old.yes(1); assert.equal(h.of('apply_risk_advice').length, 0);
  });
  test('stale submitted write callbacks do not repaint or refresh after ' + transition, () => {
    const h = loaded(); action(h, 'suggest'); confirm(h); const old = h.of('apply_risk_advice')[0];
    if (transition === 'site') select(h, other);
    if (transition === 'leave') { h.navigate('home'); h.navigate('history'); }
    if (transition === 'close') h.close();
    if (transition === 'reinit') h.waf.init();
    if (transition === 'reload') h.reload();
    assert.ok(old.aborted); const count = h.requests.length, text = h.$('#risk-advice-mutation').text();
    old.options.success({status: true, saved: true, runtime_verified: true});
    old.options.error({}, 'timeout'); old.options.complete({}, 'success');
    assert.equal(h.requests.length, count); assert.equal(h.$('#risk-advice-mutation').text(), text);
  });
}

test('site list late response cannot reset a new page', () => {
  const h = harness(); h.navigate('history'); const old = h.of('get_risk_advice_sites')[0];
  h.navigate('home'); h.navigate('history');
  old.options.success({status: true, sites: [{siteName: site}]});
  assert.ok(old.aborted); assert.doesNotMatch(h.$('#risk-advice-site').html(), /a.example/);
});

test('analysis rejects a mismatched site, malformed evidence, invalid tier or missing version', () => {
  for (const bad of [report({siteName: other}), report({config_revision: ''}), report({items: [item({site: other})]}),
    report({items: [item({fingerprint: ''})]}), report({items: [item({recommended_seconds: 2592000})]}),
    report({items: [item({actionable: 'true'})]}), {status: true}]) {
    const h = loaded(bad); action(h, 'suggest');
    assert.equal(h.confirms.length, 0); assert.match(h.$('#risk-advice-status').text(), /失败|不匹配|不可用/);
  }
});

test('manual snapshot must be valid and same-site before it can enable mutation', () => {
  for (const bad of [bans([active({site: other})]), bans([], {revision: ''}), {status: false, msg: '损坏'}]) {
    const h = open(); select(h); h.of('get_risk_site_bans')[0].resolve(bad);
    h.fire('#risk-advice-analyze'); h.of('get_risk_advice')[0].resolve(report());
    action(h, 'suggest'); action(h, 'remove'); assert.equal(h.confirms.length, 0);
    assert.match(h.$('#risk-advice-manual-status').text(), /失败|未确认/);
  }
});

test('analysis failure and missing coverage never imply a clean site or complete statistics', () => {
  const h = loaded(report({coverage: undefined, items: []}));
  assert.match(h.$('#risk-advice-coverage').text(), /未提供|未知/);
  assert.match(h.$('#risk-advice-status').text(), /不代表没有/);
  h.fire('#risk-advice-analyze'); h.of('get_risk_advice').at(-1).reject();
  assert.match(h.$('#risk-advice-status').text(), /失败/);
  assert.doesNotMatch(h.$('#risk-advice-rows').html(), /没有攻击|安全无风险/);
});

test('server strings are escaped once in selectors, rows, evidence and confirmations without mutation', () => {
  const dirty = '<img src=x onerror="bad">&\'', h = open([dirty]); select(h, dirty);
  h.of('get_risk_site_bans').at(-1).resolve(bans([], {siteName: dirty}));
  const data = report({siteName: dirty, items: [item({site: dirty, name: dirty, location: dirty, samples: [dirty], hold_reasons: []})]}), before = JSON.stringify(data);
  h.fire('#risk-advice-analyze'); h.of('get_risk_advice').at(-1).resolve(data);
  action(h, 'evidence'); action(h, 'suggest');
  for (const fragment of [h.$('#risk-advice-site').html(), h.$('#risk-advice-rows').html(), h.$('#risk-advice-evidence').html(), h.confirms.at(-1).message]) {
    assert.match(fragment, /&lt;img/); assert.doesNotMatch(fragment, /<img|&amp;lt;/);
  }
  assert.equal(JSON.stringify(data), before);
});
