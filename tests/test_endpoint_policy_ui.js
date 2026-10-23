'use strict';

// Same isolated VM/jQuery lifecycle model as test_frontend_performance.js.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const source = html.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];
const id = '0123456789abcdef0123456789abcdef';

function harness() {
  const nodes = new Map(), bindings = [], requests = [], confirmations = [], observers = [];
  const timers = new Map(), document = { body: {}, documentElement: {} };
  const window = { innerWidth: 1280, innerHeight: 800 };
  let sequence = 0, now = 0;
  function node(key) {
    if (!nodes.has(key)) nodes.set(key, { key, isConnected: true, values: {}, classes: new Set() });
    return nodes.get(key);
  }
  function $(selector) {
    const key = selector === document ? 'document' : selector === window ? 'window'
      : typeof selector === 'object' ? selector.key : selector;
    const current = node(key);
    const api = {
      0: current, length: 1,
      on(events, delegated, callback) {
        if (typeof delegated === 'function') { callback = delegated; delegated = undefined; }
        for (const event of events.split(' ')) bindings.push({ key, event, delegated, callback });
        return api;
      },
      off(events, delegated) {
        for (let i = bindings.length - 1; i >= 0; i--) {
          const b = bindings[i];
          if (b.key === key && (!events || events.split(' ').some(e => e.startsWith('.')
            ? b.event.includes(e) : b.event === e)) && (delegated === undefined || b.delegated === delegated)) bindings.splice(i, 1);
        }
        return api;
      },
      find(child) { return $(child); }, children(child) { return $(key + ' > ' + child); },
      closest() { return $('plugin-layer'); }, first() { return api; }, last() { return api; },
      eq() { return api; }, addBack() { return api; }, siblings() { return api; },
      css() { return api; }, show() { return api; }, hide() { return api; }, focus() { return api; },
      each() { return api; }, append() { return api; },
      addClass(value) { current.classes.add(value); return api; },
      removeClass(value) { current.classes.delete(value); return api; },
      hasClass(value) { return current.classes.has(value); },
      text(value) { if (value === undefined) return current.values.text || ''; current.values.text = String(value); return api; },
      html(value) { if (value === undefined) return current.values.html || ''; current.values.html = String(value); return api; },
      val(value) { if (value === undefined) return current.values.val || ''; current.values.val = value; return api; },
      prop(name, value) { if (value === undefined) return current.values[name]; current.values[name] = value; return api; },
      attr(name, value) { if (value === undefined) return current.values[name] || ''; current.values[name] = value; return api; },
      data(name, value) { return api.prop(name, value); },
    };
    return api;
  }
  $.trim = value => String(value || '').trim();
  $.isArray = Array.isArray;
  $.ajax = options => {
    const request = {
      options, method: new URL('http://fixture' + options.url).searchParams.get('s'), aborted: false, settled: false,
      resolve(result) { if (this.settled) return; this.settled = true; options.success(result); options.complete(this, 'success'); },
      reject(reason = 'timeout') { if (this.settled) return; this.settled = true; options.error(this, reason); options.complete(this, reason); },
      abort() { this.aborted = true; this.reject('abort'); },
    };
    requests.push(request);
    return request;
  };
  const layer = {
    msg() { return ++sequence; }, load() { return ++sequence; }, close() {},
    confirm(message, options, yes, cancel) { confirmations.push({ message, options, yes, cancel }); return ++sequence; },
  };
  const context = vm.createContext({ $, layer, window, document, console, bt: {},
    setTimeout(callback, delay) { const key = ++sequence; timers.set(key, { callback, delay, due: now + delay }); return key; },
    clearTimeout(key) { timers.delete(key); },
    MutationObserver: class { constructor(callback) { this.callback = callback; observers.push(this); } observe() {} disconnect() {} },
  });
  function reload() { vm.runInContext(source, context); }
  function fire(selector, event = 'click') {
    for (const b of [...bindings]) if (b.event.split('.')[0] === event && (b.key === selector || b.delegated === selector)) {
      b.callback.call(node(selector), { preventDefault() {}, stopPropagation() {} });
    }
  }
  reload();
  return { $, context, requests, confirmations, timers, bindings, reload, fire,
    get waf() { return context.free_waf; },
    navigate(page) { context.free_waf.refresh_data_total(page); },
    tick(ms) { now += ms; for (const [key, t] of [...timers]) if (t.due <= now) { timers.delete(key); t.callback(); } },
    close() { node('.waf_conter').isConnected = false; for (const observer of observers) observer.callback(); },
    reads(method) { return requests.filter(r => r.method === method); },
  };
}

function open(h, sites = [{ siteName: 'a.example' }, { siteName: 'b.example' }]) {
  h.navigate('policies');
  const request = h.requests.at(-1);
  assert.equal(request.method, 'get_site_config', 'policies lazily reads existing site configs');
  request.resolve(sites);
}

function select(h, site = 'a.example') {
  h.$('#endpoint_policy_site').val(site);
  h.fire('#endpoint_policy_site', 'change');
}

function rule(extra = {}) {
  return { id, name: 'Login', path: '/login', match: 'exact', method: 'POST',
    window_seconds: 60, max_requests: 30, action: 'observe', ban_seconds: 60, enabled: false, ...extra };
}

function loaded(h, rules = []) {
  open(h); select(h);
  h.reads('get_endpoint_policies').at(-1).resolve({ status: true, siteName: 'a.example', rules });
  h.reads('get_endpoint_policy_events').at(-1).resolve({ status: true, events: [], summary: { recorded_events: 0 }, coverage: { partial: true, notice: 'sampled' } });
}

function fill(h, extra = {}) {
  const values = rule(extra);
  for (const key of ['name', 'path', 'match', 'method', 'window_seconds', 'max_requests', 'action', 'ban_seconds']) h.$('#endpoint_policy_' + key).val(values[key]);
  h.$('#endpoint_policy_enabled').prop('checked', values.enabled);
}

test('policies nav, help, numeric limits and disabled observe defaults are explicit Chinese UI', () => {
  assert.match(html, /data-target="policies"/);
  assert.match(html, /data-type="policies"/);
  for (const text of ['接口策略', '功能指南', '默认停用', '仅记录', '其他站点', '已记录事件', '不会自动刷新']) assert.ok(html.includes(text), text);
  for (const [name, max] of [['window_seconds', 3600], ['max_requests', 100000], ['ban_seconds', 28800]]) {
    assert.match(html, new RegExp('id="endpoint_policy_' + name + '"[^>]*min="1"[^>]*max="' + max + '"'));
  }
  assert.doesNotMatch(html, /id="endpoint_policy_enabled"[^>]*\bchecked\b/);
});

test('initial paint remains two reads, deferred updates and no policy or audit reads', () => {
  const h = harness();
  assert.deepEqual(h.requests.map(r => r.method), ['get_total_all', 'get_overview_report']);
  h.tick(3000);
  assert.equal(h.requests.at(-1).method, 'check_plugin_update');
  assert.equal(h.reads('get_endpoint_policies').length, 0);
  assert.equal(h.reads('get_site_config').length, 0);
});

test('opening policies waits for explicit site selection; new editor defaults are safe', () => {
  const h = harness(); open(h);
  assert.equal(h.reads('get_endpoint_policies').length, 0);
  assert.match(h.$('#endpoint_policy_status').text(), /选择站点/);
  select(h);
  assert.equal(h.$('#endpoint_policy_enabled').prop('checked'), false);
  assert.equal(h.$('#endpoint_policy_action').val(), 'observe');
  assert.equal(h.$('#endpoint_policy_match').val(), 'exact');
  assert.equal(h.$('#endpoint_policy_method').val(), 'ALL');
  assert.equal(h.reads('get_endpoint_policies').length, 1);
  assert.equal(h.reads('get_endpoint_policy_events').at(-1).options.data.days, 1);
  h.tick(20000);
  assert.equal(h.reads('get_endpoint_policies').length, 1);
  assert.equal(h.reads('get_endpoint_policy_events').length, 1);
});

test('site names, rules and sampled event fields are escaped exactly once without mutating source', () => {
  const h = harness(), dirty = '<img src=x onerror="alert(1)">&\'=', escaped = '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;&amp;&#39;=';
  open(h, [{ siteName: dirty }]);
  assert.ok(h.$('#endpoint_policy_site').html().includes(escaped));
  select(h, dirty);
  const item = rule({ name: dirty, path: dirty, method: dirty, match: dirty, action: dirty, max_requests: dirty });
  const original = JSON.stringify(item);
  h.reads('get_endpoint_policies').at(-1).resolve({ status: true, siteName: dirty, rules: [item] });
  const list = h.$('#endpoint_policy_rules').html();
  assert.ok(list.includes(escaped));
  assert.ok(!list.includes('<img'));
  assert.ok(!list.includes('&amp;lt;'));
  h.reads('get_endpoint_policy_events').at(-1).resolve({ status: true, events: [{ timestamp: dirty, site: dirty, ip: dirty, path: dirty, method: dirty, rule_id: dirty, rule_name: dirty, action: dirty, count: dirty, limit: dirty, window_seconds: dirty, retry_after: dirty }], summary: { recorded_events: 1 }, coverage: { partial: true, notice: dirty } });
  assert.ok(h.$('#endpoint_policy_events').html().includes(escaped));
  assert.ok(!h.$('#endpoint_policy_events').html().includes('<img'));
  assert.ok(h.$('#endpoint_policy_coverage').text().includes(dirty));
  assert.equal(JSON.stringify(item), original);
});

test('all returned policies including enabled ones stay visible, with method and scoped action', () => {
  const h = harness(); loaded(h, [rule({ enabled: true, action: 'ban' }), rule({ id: 'a'.repeat(32), name: 'Disabled' })]);
  const list = h.$('#endpoint_policy_rules').html();
  assert.match(list, /Login/); assert.match(list, /Disabled/);
  assert.match(list, /已启用/); assert.match(list, /已停用/); assert.match(list, /POST/); assert.match(list, /限域封禁/);
});

test('site switch aborts pending reads and late success/error/complete cannot replace the selected site', () => {
  const h = harness(); open(h); select(h);
  const previous = h.requests.slice(-2);
  select(h, 'b.example');
  assert.ok(previous.every(r => r.aborted));
  h.reads('get_endpoint_policies').at(-1).resolve({ status: true, siteName: 'b.example', rules: [rule({ name: 'Current' })] });
  const before = h.$('#endpoint_policy_rules').html(), status = h.$('#endpoint_policy_status').text();
  previous[0].options.success({ status: true, siteName: 'a.example', rules: [rule({ name: 'Stale' })] });
  previous[0].options.error({}, 'timeout'); previous[0].options.complete({}, 'success');
  previous[1].options.success({ status: true, events: [{ path: 'Stale' }], summary: { recorded_events: 999 } });
  assert.equal(h.$('#endpoint_policy_rules').html(), before);
  assert.equal(h.$('#endpoint_policy_status').text(), status);
  assert.ok(!h.$('#endpoint_policy_event_summary').text().includes('999'));
});

test('leaving, closing and reinitializing cancel policy owners and late site discovery', () => {
  for (const action of ['leave', 'close', 'reinit']) {
    const h = harness(); h.navigate('policies'); const sites = h.requests.at(-1);
    assert.equal(sites.method, 'get_site_config');
    if (action === 'leave') h.navigate('home');
    if (action === 'close') h.close();
    if (action === 'reinit') h.waf.init();
    assert.equal(sites.aborted, true, action);
    const count = h.requests.length;
    sites.options.success([{ siteName: 'late.example' }]);
    assert.equal(h.requests.length, count);
    assert.ok(!h.$('#endpoint_policy_site').html().includes('late.example'));
  }
});

test('creates omit id, edits carry returned hex32 id, all writes POST and successful writes reload list', () => {
  const h = harness(); loaded(h, [rule()]); fill(h);
  h.fire('#endpoint_policy_save');
  const create = h.requests.at(-1), payload = JSON.parse(create.options.data.policy);
  assert.equal(create.method, 'save_endpoint_policy'); assert.equal(create.options.type, 'POST');
  assert.equal(create.options.data.siteName, 'a.example'); assert.ok(!Object.hasOwn(payload, 'id'));
  assert.equal(payload.enabled, false); assert.equal(payload.action, 'observe');
  assert.equal(payload.window_seconds, 60); assert.equal(typeof payload.window_seconds, 'number');
  create.resolve({ status: true });
  assert.equal(h.reads('get_endpoint_policies').length, 2);
  h.reads('get_endpoint_policies').at(-1).resolve({ status: true, siteName: 'a.example', rules: [rule()] });
  h.$('.endpoint-policy-edit').attr('data-id', id); h.fire('.endpoint-policy-edit');
  assert.equal(h.$('#endpoint_policy_name').val(), 'Login');
  h.$('#endpoint_policy_name').val('Updated'); h.fire('#endpoint_policy_save');
  const edit = h.requests.at(-1);
  assert.equal(JSON.parse(edit.options.data.policy).id, id);
  assert.equal(JSON.parse(edit.options.data.policy).name, 'Updated');
});

test('delete cancellation never writes, confirmation is escaped and stale confirmation cannot delete another site', () => {
  const h = harness(); loaded(h, [rule({ name: '<b>Login</b>' })]);
  h.$('.endpoint-policy-delete').attr('data-id', id); h.fire('.endpoint-policy-delete');
  const confirm = h.confirmations.at(-1);
  assert.ok(confirm); assert.ok(!confirm.message.includes('<b>'));
  const count = h.requests.length; confirm.cancel();
  assert.equal(h.requests.length, count);
  h.fire('.endpoint-policy-delete'); const stale = h.confirmations.at(-1);
  select(h, 'b.example'); stale.yes(1);
  assert.equal(h.reads('delete_endpoint_policy').length, 0);
});

test('confirmed delete POSTs only site and id, then reloads list', () => {
  const h = harness(); loaded(h, [rule()]);
  h.$('.endpoint-policy-delete').attr('data-id', id); h.fire('.endpoint-policy-delete');
  h.confirmations.at(-1).yes(1);
  const request = h.requests.at(-1);
  assert.equal(request.method, 'delete_endpoint_policy'); assert.equal(request.options.type, 'POST');
  assert.deepEqual(JSON.parse(JSON.stringify(request.options.data)), { siteName: 'a.example', id });
  request.resolve({ status: true });
  assert.equal(h.reads('get_endpoint_policies').length, 2);
});

test('API and transport write failures preserve editor and rules, unlock retry and never show success', () => {
  for (const transport of [false, true]) {
    const h = harness(); loaded(h, [rule()]); fill(h, { name: 'Unsaved' }); h.fire('#endpoint_policy_save');
    const write = h.requests.at(-1), list = h.$('#endpoint_policy_rules').html();
    if (transport) write.reject(); else write.resolve({ status: false, msg: '<b>denied</b>' });
    assert.equal(h.$('#endpoint_policy_name').val(), 'Unsaved');
    assert.equal(h.$('#endpoint_policy_rules').html(), list);
    assert.equal(h.reads('get_endpoint_policies').length, 1);
    assert.match(h.$('#endpoint_policy_status').text(), /失败/);
    assert.equal(h.$('#endpoint_policy_save').prop('disabled'), false);
    h.fire('#endpoint_policy_save'); assert.equal(h.reads('save_endpoint_policy').length, 2);
  }
});

test('pending writes are single-flight and site-switch late write completion cannot reset a new editor', () => {
  const h = harness(); loaded(h); fill(h); h.fire('#endpoint_policy_save'); const old = h.requests.at(-1);
  h.fire('#endpoint_policy_save'); assert.equal(h.reads('save_endpoint_policy').length, 1);
  select(h, 'b.example'); assert.equal(old.aborted, true);
  h.reads('get_endpoint_policies').at(-1).resolve({ status: true, siteName: 'b.example', rules: [] });
  fill(h, { name: 'New site draft' }); const count = h.requests.length;
  old.options.success({ status: true }); old.options.error({}, 'timeout'); old.options.complete({}, 'success');
  assert.equal(h.$('#endpoint_policy_name').val(), 'New site draft'); assert.equal(h.requests.length, count);
});

test('invalid names, paths, ranges and enum values never submit', () => {
  const h = harness(); loaded(h);
  const invalid = [{ name: '' }, { path: '/x?token=secret' }, { path: '/x#fragment' }, { path: 'no-leading-slash' }, { path: '/a\n' }, { path: '/a.*' },
    { window_seconds: 0 }, { window_seconds: 3601 }, { window_seconds: 1.5 }, { max_requests: 0 }, { max_requests: 100001 }, { ban_seconds: 0 }, { ban_seconds: 28801 },
    { method: 'TRACE' }, { action: 'allow' }, { match: 'regex' }];
  for (const value of invalid) { fill(h, value); h.fire('#endpoint_policy_save'); assert.equal(h.reads('save_endpoint_policy').length, 0, JSON.stringify(value)); }
});

test('all allowed methods/actions and inclusive numeric bounds are supported', () => {
  const h = harness(); loaded(h);
  for (const method of ['ALL', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
    fill(h, { method, window_seconds: 1, max_requests: 1, ban_seconds: 1 }); h.fire('#endpoint_policy_save');
    assert.equal(h.requests.at(-1).method, 'save_endpoint_policy'); h.requests.at(-1).resolve({ status: false });
  }
  for (const action of ['observe', 'reject', 'ban']) {
    fill(h, { action, match: 'prefix', enabled: true, window_seconds: 3600, max_requests: 100000, ban_seconds: 28800 });
    h.fire('#endpoint_policy_save'); const request = h.requests.at(-1);
    assert.equal(JSON.parse(request.options.data.policy).action, action); request.resolve({ status: false });
  }
});

test('missing/failed site discovery and clearing site show explicit state and cannot write', () => {
  const h = harness(); open(h, []);
  assert.match(h.$('#endpoint_policy_status').text(), /暂无.*站点/);
  assert.equal(h.$('#endpoint_policy_site').prop('disabled'), true);
  h.fire('#endpoint_policy_save'); assert.equal(h.reads('save_endpoint_policy').length, 0);
  h.navigate('home'); h.navigate('policies'); h.requests.at(-1).reject();
  assert.match(h.$('#endpoint_policy_status').text(), /站点.*失败/);
  h.fire('#endpoint_policy_sites_refresh'); h.requests.at(-1).resolve([{ siteName: 'a.example' }]); select(h);
  const pending = h.requests.slice(-2); select(h, '');
  assert.ok(pending.every(r => r.aborted));
  assert.match(h.$('#endpoint_policy_status').text(), /选择站点/);
  assert.equal(h.$('#endpoint_policy_save').prop('disabled'), true);
  assert.ok(!h.$('#endpoint_policy_rules').html().includes('Login'));
});

test('sample count and coverage remain distinct from requests; refresh is explicit and site-scoped', () => {
  const h = harness(); loaded(h);
  h.fire('#endpoint_policy_events_refresh');
  h.requests.at(-1).resolve({ status: true, summary: { recorded_events: 7, observed: 3, rejected: 2, banned: 2 }, events: [], coverage: { partial: true, notice: 'Bounded sample' } });
  assert.match(h.$('#endpoint_policy_event_summary').text(), /已记录事件.*7/);
  assert.match(h.$('#endpoint_policy_coverage').text(), /部分|采样/);
  assert.match(h.$('#endpoint_policy_coverage').text(), /Bounded sample/);
  assert.doesNotMatch(h.$('#endpoint_policy_event_summary').text(), /总请求|累计命中/);
  assert.ok(h.requests.every(r => !/^(set_|add_ip|remove_ip|update_overall)/.test(r.method)));
});

test('mismatched policy site and read failures do not expose editable stale rules', () => {
  const h = harness(); open(h); select(h);
  h.reads('get_endpoint_policies').at(-1).resolve({ status: true, siteName: 'b.example', rules: [rule({ name: 'Wrong site' })] });
  assert.ok(!h.$('#endpoint_policy_rules').html().includes('Wrong site'));
  assert.equal(h.$('#endpoint_policy_save').prop('disabled'), true);
  assert.match(h.$('#endpoint_policy_status').text(), /失败|不匹配/);
  h.fire('#endpoint_policy_refresh'); h.reads('get_endpoint_policies').at(-1).reject();
  assert.match(h.$('#endpoint_policy_status').text(), /失败/);
  h.reads('get_endpoint_policy_events').at(-1).resolve({ status: false, msg: 'Unavailable' });
  assert.match(h.$('#endpoint_policy_coverage').text(), /失败/);
});

test('name and normalized path validation match backend byte and ambiguity limits', () => {
  const h = harness(); loaded(h);
  const invalid = [{ name: 'x'.repeat(129) }, { path: '/' + 'x'.repeat(512) }, { path: '/' + '\u4e2d'.repeat(171) },
    { path: '/a%2fb' }, { path: '/a//b' }, { path: '/a/../b' }, { path: '/a/./b' }, { path: '/a/..' }, { path: '/a/.' }];
  for (const value of invalid) {
    fill(h, value); h.fire('#endpoint_policy_save');
    assert.equal(h.reads('save_endpoint_policy').length, 0, JSON.stringify(value));
    assert.match(h.$('#endpoint_policy_status').text(), /未保存/);
  }
  fill(h, { name: 'x'.repeat(128), path: '/' + '\u4e2d'.repeat(170) + 'x' });
  h.fire('#endpoint_policy_save'); assert.equal(h.reads('save_endpoint_policy').length, 1);
});

test('legacy reason mapping adds endpoint limits without changing historical CC or blacklist labels', () => {
  const h = harness();
  let table;
  h.waf.get_safe_logs_ip = (params, callback) => callback([]);
  h.waf.refresh_table_view = options => { table = options; };
  h.waf.render_history_data();
  const reason = table.config.find(c => c.title === '封锁原因').templet;
  assert.equal(reason([null, null, null, null, null, 'endpoint_limit']), '接口限流（限域封禁）');
  assert.equal(reason([null, null, null, null, null, 'cc']), 'CC攻击');
  assert.equal(reason([null, null, null, null, null, 'ip_black']), '黑名单');
  assert.equal(reason([null, null, null, null, null, 'other']), '多次恶意请求');
  assert.match(html, /ALL[^<]*所有方法/);
  assert.ok(html.includes('ALL 将所有请求方法合并计数'));
  assert.ok(html.includes('固定阈值预设，不会自动学习流量'));
});

test('historical evidence dates, deleted rule IDs and all numeric fields are escaped independently', () => {
  const h = harness(); loaded(h, [rule()]);
  const fields = ['timestamp', 'site', 'ip', 'path', 'method', 'rule_id', 'rule_name', 'action', 'count', 'limit', 'window_seconds', 'retry_after'];
  const event = Object.fromEntries(fields.map(field => [field, '<b>' + field + '</b>&"\'']));
  h.fire('#endpoint_policy_events_refresh');
  const response = { status: true, events: [event, { timestamp: '2026-10-22 23:59:59', rule_id: 'f'.repeat(32), rule_name: 'Deleted rule', action: 'observe', count: 0, retry_after: 0 }], summary: { recorded_events: 2 }, coverage: { partial: true } };
  const before = JSON.stringify(response);
  h.requests.at(-1).resolve(response);
  const output = h.$('#endpoint_policy_events').html();
  for (const field of fields) assert.ok(output.includes('&lt;b&gt;' + field + '&lt;/b&gt;&amp;&quot;&#39;'), field);
  assert.match(output, /2026-10-22 23:59:59/); assert.ok(output.includes('f'.repeat(32))); assert.match(output, /Deleted rule/);
  assert.ok(!output.includes('&amp;lt;')); assert.equal(JSON.stringify(response), before);
});

test('opening policies and receiving evidence leave all historical application state unchanged', () => {
  const h = harness();
  const historical = { config: { get: true, cc: { limit: 90 } }, statistics: { summary: { total_requests: 123 } }, site: { endpoint_limits: ['untouched'] } };
  h.waf.overall_config = historical.config;
  h.waf._statistics_report = historical.statistics;
  h.waf.site_config = historical.site;
  h.waf.current_site_name = 'legacy.example';
  loaded(h, [rule()]);
  assert.equal(h.waf.overall_config, historical.config);
  assert.equal(h.waf._statistics_report, historical.statistics);
  assert.equal(h.waf.site_config, historical.site);
  assert.equal(h.waf.current_site_name, 'legacy.example');
  h.navigate('home');
  assert.equal(h.waf.site_config, historical.site);
  assert.equal(h.waf._statistics_report, historical.statistics);
});

test('same-site replacement reads and A-B-A switching reject stale epochs and stale confirmations', () => {
  const h = harness(); loaded(h, [rule()]);
  h.fire('#endpoint_policy_refresh'); const first = h.requests.at(-1);
  h.fire('#endpoint_policy_refresh'); const second = h.requests.at(-1);
  assert.equal(first.aborted, true);
  second.resolve({ status: true, siteName: 'a.example', rules: [rule({ name: 'Fresh' })] });
  first.options.success({ status: true, siteName: 'a.example', rules: [rule({ name: 'Old' })] });
  assert.ok(!h.$('#endpoint_policy_rules').html().includes('Old'));
  h.$('.endpoint-policy-delete').attr('data-id', id); h.fire('.endpoint-policy-delete'); const confirm = h.confirmations.at(-1);
  h.fire('#endpoint_policy_events_refresh'); const events = h.requests.at(-1);
  select(h, 'b.example'); select(h);
  events.options.success({ status: true, events: [{ path: 'Stale evidence' }], summary: { recorded_events: 999 } });
  confirm.yes(1);
  assert.equal(h.reads('delete_endpoint_policy').length, 0);
  assert.ok(!h.$('#endpoint_policy_events').html().includes('Stale evidence'));
});

test('failed deletes keep the rule and are retryable without silently reloading', () => {
  const h = harness(); loaded(h, [rule()]);
  h.$('.endpoint-policy-delete').attr('data-id', id); h.fire('.endpoint-policy-delete'); h.confirmations.at(-1).yes(1);
  h.requests.at(-1).resolve({ status: false, msg: '<script>failed</script>' });
  assert.match(h.$('#endpoint_policy_rules').html(), /Login/);
  assert.equal(h.reads('get_endpoint_policies').length, 1);
  assert.match(h.$('#endpoint_policy_status').text(), /失败/);
  h.fire('.endpoint-policy-delete'); assert.equal(h.confirmations.length, 2);
});
