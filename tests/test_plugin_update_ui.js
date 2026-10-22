'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { harness, html } = require('./test_statistics_v011');
const check = (extra = {}) => ({ status: true, current_version: '0.1.1', latest_version: '0.1.2', tag: 'v0.1.2', available: true,
  prerelease: true, notes: '<img src=x onerror=alert(1)>\n**plain text**', checked_at: '2026-10-22 12:00:00', cached: true, ...extra });
function ready() {
  const h = harness(); h.navigate('updates'); h.tick(3000);
  h.of('get_plugin_update_status').at(-1)?.resolve({ status: true, job: null });
  h.of('check_plugin_update').at(-1).resolve(check());
  return h;
}
function start(h) {
  h.fire('#plugin_update_start'); h.confirms.at(-1).yes(1);
  h.of('start_plugin_update').at(-1).resolve({ status: true, job_id: 'fixture-job' });
}

test('update nav exists and check waits three seconds without a blocking map overlay', () => {
  assert.match(html, /data-target="updates"/);
  const h = harness();
  assert.deepEqual(h.requests.map(r => r.method), ['get_total_all', 'get_overview_report']);
  h.tick(2999); assert.equal(h.of('check_plugin_update').length, 0);
  h.tick(1); assert.equal(h.of('check_plugin_update').length, 1);
  assert.equal(h.of('check_plugin_update')[0].options.data.force, 'false');
  assert.equal(h.messages.length, 0);
  assert.equal(h.of('start_plugin_update').length, 0);
});
test('check renders API versions, prerelease, timestamps and notes as plain text', () => {
  const h = ready();
  assert.equal(h.$('#plugin_update_current').text(), '0.1.1');
  assert.equal(h.$('#plugin_update_latest').text(), '0.1.2');
  assert.match(h.$('#plugin_update_prerelease').text(), /预发布/);
  assert.match(h.$('#plugin_update_checked').text(), /2026-10-22/);
  assert.equal(h.$('#plugin_update_notes').text(), check().notes);
  assert.equal(h.$('#plugin_update_notes').html(), '');
  assert.equal(h.$('#plugin_update_start').prop('disabled'), false);
  h.fire('#plugin_update_check');
  assert.equal(h.of('check_plugin_update').at(-1).options.data.force, 'true');
});
test('install requires Chinese backup warning confirmation and sends only selected tag', () => {
  const h = ready(); h.fire('#plugin_update_start');
  assert.equal(h.of('start_plugin_update').length, 0);
  assert.match(h.confirms[0].message, /备份/);
  assert.match(h.confirms[0].message, /预发布/);
  h.fire('#plugin_update_start'); assert.equal(h.confirms.length, 1);
  h.confirms[0].yes(1);
  assert.deepEqual(JSON.parse(JSON.stringify(h.of('start_plugin_update')[0].options.data)), { tag: 'v0.1.2' });
  assert.equal(h.$('#plugin_update_start').prop('disabled'), true);
});
test('cancelled confirmation never starts a server job', () => {
  const h = ready(); h.fire('#plugin_update_start'); h.confirms[0].cancel?.();
  assert.equal(h.of('start_plugin_update').length, 0);
  h.fire('#plugin_update_start'); assert.equal(h.confirms.length, 2);
});
test('status uses empty params, renders last job, and stops on success without reload', () => {
  const h = ready(); start(h);
  const request = h.of('get_plugin_update_status').at(-1);
  assert.deepEqual(JSON.parse(JSON.stringify(request.options.data)), {});
  request.resolve({ status: true, job: { id: 'fixture-job', state: 'succeeded', stage: 'done', message: 'finished', target_version: '0.1.2', rollback: false } });
  assert.match(h.$('#plugin_update_job').text(), /fixture-job[\s\S]*0.1.2[\s\S]*finished/);
  assert.match(h.$('#plugin_update_status').text(), /关闭.*重新打开/);
  const count = h.of('get_plugin_update_status').length; h.tick(10000);
  assert.equal(h.of('get_plugin_update_status').length, count);
});
test('API failures and notes are not rendered as success or offered for install', () => {
  const h = ready(); h.fire('#plugin_update_check');
  h.of('check_plugin_update').at(-1).resolve(check({ error: 'release failure', notes: '<failure notes>' }));
  assert.match(h.$('#plugin_update_status').text(), /release failure/);
  assert.equal(h.$('#plugin_update_notes').text(), '<failure notes>');
  assert.equal(h.$('#plugin_update_start').prop('disabled'), true);
  h.fire('#plugin_update_start'); assert.equal(h.confirms.length, 0);
  h.fire('#plugin_update_check'); h.of('check_plugin_update').at(-1).resolve({ status: false, error: 'network failed', notes: '<details>' });
  assert.match(h.$('#plugin_update_status').text(), /network failed/);
  assert.equal(h.$('#plugin_update_notes').text(), '<details>');
});
test('job failure including rollback stays an error and polling stops', () => {
  const h = ready(); start(h);
  h.of('get_plugin_update_status').at(-1).resolve({ status: true, job: { id: 'fixture-job', state: 'failed', stage: 'rollback', message: '<failed>', rollback: { restored: true }, notes: '<notes>' } });
  assert.match(h.$('#plugin_update_job').text(), /回退[\s\S]*restored/);
  assert.match(h.$('#plugin_update_status').text(), /失败/);
  assert.doesNotMatch(h.$('#plugin_update_status').text(), /更新成功/);
  const reads = h.of('get_plugin_update_status').length; h.tick(10000);
  assert.equal(h.of('get_plugin_update_status').length, reads);
});
test('infinite running jobs are bounded to five minutes and remain disabled until checked', () => {
  const h = ready(); start(h);
  for (let i = 0; i < 180; i++) {
    const request = h.of('get_plugin_update_status').at(-1);
    if (!request.settled) request.resolve({ status: true, job: { id: 'fixture-job', state: 'running', stage: 'download', message: 'waiting' } });
    h.tick(2000);
  }
  assert.ok(h.of('get_plugin_update_status').length <= 151);
  assert.match(h.$('#plugin_update_status').text(), /暂停|超时|5 分钟/);
  const reads = h.of('get_plugin_update_status').length; h.tick(60000);
  assert.equal(h.of('get_plugin_update_status').length, reads);
  assert.equal(h.$('#plugin_update_start').prop('disabled'), true);
});
test('closing cancels delayed check, in-flight check and status polling but never the server job', () => {
  let h = harness(); h.close(); h.tick(5000); assert.equal(h.of('check_plugin_update').length, 0);
  h = harness(); h.tick(3000); const checkRequest = h.of('check_plugin_update')[0]; h.close(); assert.equal(checkRequest.aborted, true);
  h = ready(); start(h); const request = h.of('get_plugin_update_status').at(-1); h.close();
  assert.equal(request.aborted, true); h.tick(600000);
  assert.equal(h.timers.size, 0);
  assert.equal(h.requests.some(r => /cancel.*update|stop.*update/.test(r.method)), false);
});
test('reopen discovers an existing job and leaving updates ignores late status responses', () => {
  const h = ready();
  h.navigate('home'); h.navigate('updates');
  assert.ok(h.of('get_plugin_update_status').length > 0);
  const request = h.of('get_plugin_update_status').at(-1);
  h.navigate('statistics'); assert.equal(request.aborted, true);
  request.options.success({ status: true, job: { state: 'succeeded', message: 'late' } });
  assert.doesNotMatch(h.$('#plugin_update_status').text(), /更新成功/);
});
test('stale confirmation cannot install after close or reinitialization', () => {
  const h = ready(); h.fire('#plugin_update_start'); const confirm = h.confirms[0];
  h.reload(); confirm.yes(1); assert.equal(h.of('start_plugin_update').length, 0);
});
test('epoch check timestamps are readable rather than bare seconds', () => {
  const h = ready(); h.fire('#plugin_update_check');
  h.of('check_plugin_update').at(-1).resolve(check({checked_at:1792670400}));
  assert.doesNotMatch(h.$('#plugin_update_checked').text(), /^1792670400/);
  assert.match(h.$('#plugin_update_checked').text(), /2026/);
});
test('recovery_required and failed rollback remain locked even after checking versions', () => {
  for (const job of [{id:'old',state:'recovery_required',message:'manual recovery'},
    {id:'old',state:'failed',rollback:{state:'failed',errors:['restore error']}}]) {
    const h = ready(); h.navigate('home'); h.navigate('updates');
    h.of('get_plugin_update_status').at(-1).resolve({status:true,job});
    assert.match(h.$('#plugin_update_status').text(), /人工/);
    h.fire('#plugin_update_check'); h.of('check_plugin_update').at(-1).resolve(check());
    assert.equal(h.$('#plugin_update_start').prop('disabled'),true);
    assert.match(h.$('#plugin_update_job').text(), /recovery_required|restore error/);
    const reads = h.of('get_plugin_update_status').length; h.tick(10000);
    assert.equal(h.of('get_plugin_update_status').length,reads);
  }
});
test('a previous successful job cannot acknowledge a newly started update', () => {
  const h = ready(); start(h);
  h.of('get_plugin_update_status').at(-1).resolve({status:true,job:{id:'previous-job',state:'succeeded',message:'old success'}});
  assert.doesNotMatch(h.$('#plugin_update_status').text(),/更新成功/);
  assert.equal(h.$('#plugin_update_start').prop('disabled'),true);
  const reads = h.of('get_plugin_update_status').length; h.tick(2000);
  assert.equal(h.of('get_plugin_update_status').length,reads+1);
});
test('failed start preserves failure notes and ambiguous transport errors never unlock installation', () => {
  for (const transport of [false,true]) {
    const h = ready(); h.fire('#plugin_update_start'); h.confirms[0].yes(1);
    const request = h.of('start_plugin_update').at(-1);
    if (transport) request.reject(); else request.resolve({status:false,error:'start failed',notes:'<failure details>'});
    assert.equal(h.$('#plugin_update_start').prop('disabled'),true);
    assert.doesNotMatch(h.$('#plugin_update_status').text(),/更新成功/);
    if (!transport) assert.equal(h.$('#plugin_update_notes').text(),'<failure details>');
    assert.equal(request.options.type,'POST');
  }
});
test('five-minute wall-clock deadline aborts a slow status read and removes owner timers', () => {
  const h = ready(); start(h);
  const pending = h.of('get_plugin_update_status').at(-1);
  h.tick(300000);
  assert.equal(pending.aborted,true);
  assert.match(h.$('#plugin_update_status').text(), /5 分钟/);
  assert.equal(h.$('#plugin_update_start').prop('disabled'),true);
  assert.ok(h.waf._timers.every(id=>h.timers.has(id)));
});
test('queued jobs are pending, not success, and continue bounded polling', () => {
  const h = ready(); start(h);
  h.of('get_plugin_update_status').at(-1).resolve({status:true,job:{id:'fixture-job',state:'queued',stage:'queued',message:'waiting'}});
  assert.equal(h.$('#plugin_update_start').prop('disabled'),true);
  assert.match(h.$('#plugin_update_status').text(),/排队/);
  assert.doesNotMatch(h.$('#plugin_update_status').text(),/更新成功/);
  const reads=h.of('get_plugin_update_status').length; h.tick(2000);
  assert.equal(h.of('get_plugin_update_status').length,reads+1);
});
test('recovery errors stop polling even when the returned job does not match the new job', () => {
  const h=ready(); start(h);
  h.of('get_plugin_update_status').at(-1).resolve({status:true,job:{id:'other-job',state:'recovery_required',message:'manual recovery'}});
  assert.match(h.$('#plugin_update_status').text(),/人工/);
  const reads=h.of('get_plugin_update_status').length; h.tick(10000);
  assert.equal(h.of('get_plugin_update_status').length,reads);
});
test('only boolean available=true enables installation and manual check cancels the delayed check', () => {
  const h=harness(); h.navigate('updates');
  h.of('get_plugin_update_status').at(-1).resolve({status:true,job:null});
  h.fire('#plugin_update_check');
  h.of('check_plugin_update').at(-1).resolve(check({available:'false'}));
  assert.equal(h.$('#plugin_update_start').prop('disabled'),true);
  h.fire('#plugin_update_start'); assert.equal(h.confirms.length,0);
  h.tick(3000); assert.equal(h.of('check_plugin_update').length,1);
});
