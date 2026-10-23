'use strict';

// No browser, network, panel credentials or third-party packages are needed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const source = html.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];

function harness(width = 1280, height = 800) {
  const nodes = new Map();
  const bindings = [];
  const requests = [];
  const timers = new Map();
  const observers = [];
  const styles = [];
  const loads = new Set();
  let now = 0;
  let nextId = 1;
  const document = { body: {}, documentElement: {} };
  const window = { innerWidth: width, innerHeight: height };

  function node(key) {
    if (!nodes.has(key)) nodes.set(key, {
      key, isConnected: true, offsetWidth: 88, offsetHeight: 0,
      values: {}, classes: new Set(), scrollIntoView() {},
    });
    return nodes.get(key);
  }

  function matches(actual, query) {
    if (!query) return true;
    const [type, ...namespaces] = query.split('.');
    const [boundType, ...boundNamespaces] = actual.split('.');
    return (!type || type === boundType) && namespaces.every(n => boundNamespaces.includes(n));
  }

  function $(selector) {
    const key = selector === document ? 'document' : selector === window ? 'window'
      : typeof selector === 'object' ? selector.key : selector;
    const current = node(key);
    let allPanel = false;
    const api = {
      0: current, length: 1,
      on(events, delegated, callback) {
        if (typeof delegated === 'function') { callback = delegated; delegated = undefined; }
        for (const event of events.split(' ')) bindings.push({ key, event, delegated, callback });
        return api;
      },
      one(events, delegated, callback) {
        if (typeof delegated === 'function') { callback = delegated; delegated = undefined; }
        function once(...args) { api.off(events, delegated); return callback.apply(this, args); }
        return api.on(events, delegated, once);
      },
      off(events, delegated) {
        for (let i = bindings.length - 1; i >= 0; i--) {
          const b = bindings[i];
          const target = allPanel ? b.key !== 'document' && b.key !== 'window' : b.key === key;
          if (target && (!events || events.split(' ').some(e => matches(b.event, e)))
              && (delegated === undefined || b.delegated === delegated)) bindings.splice(i, 1);
        }
        return api;
      },
      bind(events, callback) { return api.on(events, callback); },
      unbind(events) { return api.off(events); },
      click(callback) { return api.on('click', callback); },
      change(callback) { return api.on('change', callback); },
      scroll(callback) { return api.on('scroll', callback); },
      hover(enter, leave) { return api.on('mouseenter', enter).on('mouseleave', leave); },
      find(child) { return $(child === '*' ? 'panel-descendants' : child); },
      children(child) { return $(key + ' > ' + child); },
      closest(selector) { return $(selector === '.layui-layer-page' ? 'plugin-layer' : selector); },
      first() { return api; }, last() { return api; }, eq() { return api; },
      addBack() { allPanel = true; return api; },
      parent() { return api; }, next() { return api; }, prev() { return api; }, siblings() { return api; },
      each() { return api; },
      css(name, value) {
        if (typeof name === 'object') styles.push({ key, value: name });
        else if (value !== undefined) styles.push({ key, value: { [name]: value } });
        return api;
      },
      addClass(value) { current.classes.add(value); return api; },
      removeClass(value) { current.classes.delete(value); return api; },
      hasClass(value) { return current.classes.has(value); },
      show() { return api; }, hide() { return api; }, focus() { return api; },
      before() { return api; }, after() { return api; }, append() { return api; }, remove() { return api; },
      empty() { current.values.html = ''; return api; },
      scrollTop(value) { if (value === undefined) return current.values.scrollTop || 0; current.values.scrollTop=value; return api; },
      text(value) {
        if (value === undefined) return current.values.text || '';
        current.values.text = String(value); return api;
      },
      html(value) {
        if (value === undefined) return current.values.html || '';
        current.values.html = String(value); return api;
      },
      val(value) {
        if (value === undefined) return current.values.val || (String(key).endsWith('_days') ? '7' : '');
        current.values.val = value; return api;
      },
      prop(name, value) {
        if (value === undefined) return current.values[name];
        current.values[name] = value; return api;
      },
      attr(name, value) {
        if (value === undefined) return current.values[name] || '';
        current.values[name] = value; return api;
      },
      data(name, value) { return api.prop(name, value); },
    };
    return api;
  }

  $.trim = value => String(value || '').trim();
  $.isArray = Array.isArray;
  $.ajax = options => {
    const request = {
      options, method: new URL('http://local' + options.url).searchParams.get('s'),
      settled: false, aborted: false,
      resolve(result) {
        if (this.settled) return;
        this.settled = true;
        try { options.success(result); } finally { if (options.complete) options.complete(this, 'success'); }
      },
      reject(reason = 'timeout') {
        if (this.settled) return;
        this.settled = true;
        try { if (options.error) options.error(this, reason); }
        finally { if (options.complete) options.complete(this, reason); }
      },
      abort() { this.aborted = true; this.reject('abort'); },
    };
    requests.push(request);
    return request;
  };
  const layer = {
    msg(message, options = {}) { const id = nextId++; if (options.icon === 16) loads.add(id); return id; },
    load() { const id = nextId++; loads.add(id); return id; },
    close(id) { loads.delete(id); },
    confirm() {},
    open(options) { if (options.success) options.success({}, nextId++); return nextId++; },
  };
  const context = vm.createContext({
    $, document, window, layer, console,
    Date: class extends Date { static now() { return Date.UTC(2026, 9, 22) + now; } }, bt: {},
    setTimeout(callback, delay) { const id = nextId++; timers.set(id, { callback, delay, due: now + delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    MutationObserver: class {
      constructor(callback) { this.callback = callback; this.active = true; observers.push(this); }
      observe() {} disconnect() { this.active = false; }
    },
  });

  function reload() { vm.runInContext(source, context, { filename: 'index.html' }); }
  function tick(ms) {
    now += ms;
    for (let steps = 0; steps < 1000; steps++) {
      const entry = [...timers.entries()].find(([, task]) => task.due <= now);
      if (!entry) return;
      timers.delete(entry[0]); entry[1].callback();
    }
    throw new Error('Unbounded timer loop');
  }
  function fire(selector, event = 'click') {
    const target = node(selector);
    for (const b of [...bindings]) {
      if (b.event.split('.')[0] === event && (b.delegated === selector || b.key === selector)) {
        b.callback.call(target, { currentTarget: target, stopPropagation() {}, preventDefault() {} });
      }
    }
  }
  reload();
  return {
    $, context, requests, timers, bindings, styles, loads, reload, tick, fire,
    get waf() { return context.free_waf; },
    navigate(page) { context.free_waf.refresh_data_total(page); },
    stats() { return requests.filter(r => r.method === 'get_website_statistics_summary'); },
    pollTimers() { return [...timers.values()].filter(t => t.delay === 2000); },
    close() {
      node('.waf_conter').isConnected = false;
      for (const observer of observers) if (observer.active) observer.callback();
    },
  };
}

function cached(extra = {}) {
  return { status: true, checked_at: '2026-10-22 12:00:00',
    summary: { total_requests: 123, unique_clients: 4 }, ...extra };
}

test('first paint has exactly two read requests and no blocking load', () => {
  const h = harness();
  assert.deepEqual(h.requests.map(r => r.method), ['get_total_all', 'get_overview_report']);
  assert.equal(h.loads.size, 0);
});

test('branding updates only the owning panel title and survives resizing', () => {
  const h = harness();
  h.waf.fit_panel_shell();
  assert.equal(h.$('plugin-layer > .layui-layer-title').text(), 'aapanel GPT Firewall');
  assert.equal(h.$('.layui-layer-title').text(), '');
  h.$('plugin-layer > .layui-layer-title').text('old title');
  h.waf.fit_panel_shell();
  assert.equal(h.$('plugin-layer > .layui-layer-title').text(), 'aapanel GPT Firewall');
});

test('no external CSS or JavaScript is loaded', () => {
  assert.equal(/<(?:script|link)\b[^>]*(?:src|href)\s*=\s*["'](?:https?:)?\/\//i.test(html), false);
});

test('all three audits are manual and negative audit results still render', () => {
  const h = harness();
  h.fire('#rule_risk_refresh');
  const request = h.requests.at(-1);
  assert.equal(request.method, 'get_rule_risk_audit');
  request.resolve({ status: false, checked_at: 'now', summary: { high: 1 },
    items: [{ level: 'high', scope: 'fixture', rule_name: 'test', reason: 'too broad' }] });
  assert.match(h.$('#rule_risk_table').html(), /too broad/);
});

test('http returns the abortable ajax request, defaults to 30 seconds and keeps reads quiet', () => {
  const h = harness();
  const xhr = h.waf.http({ method: 'get_example', success() {} });
  assert.equal(xhr, h.requests.at(-1));
  assert.equal(xhr.options.timeout, 30000);
  assert.equal(h.loads.size, 0);
});

test('write loading closes on errors and explicit no-load mode stays quiet', () => {
  const h = harness();
  let failures = 0, completed = 0;
  h.waf.http({ method: 'set_example', tips: 'write', success() {},
    error() { failures++; }, complete() { completed++; } });
  assert.equal(h.loads.size, 1);
  h.requests.at(-1).reject();
  assert.equal(h.loads.size, 0);
  assert.equal(failures, 1);
  assert.equal(completed, 1);
  h.waf.http({ method: 'get_example', load: 2, success() {} });
  assert.equal(h.loads.size, 0);
});

test('scan and upload explicitly allow 120 seconds', () => {
  const h = harness();
  for (const name of ['webshell_san_dir', 'upload_file_url', 'webshell_send_baota']) {
    h.waf[name]({ path: '/fixture' }, () => {});
    assert.equal(h.requests.at(-1).options.timeout, 120000, name);
  }
});

test('reopening keeps one delegated handler and aborts old statistics', () => {
  const h = harness();
  h.navigate('statistics');
  const pending = h.stats().at(-1);
  const old = h.waf;
  h.reload();
  assert.notEqual(h.waf, old);
  assert.equal(pending.aborted, true);
  const count = h.requests.length;
  h.fire('#simulation_run');
  assert.equal(h.requests.length - count, 1);
  assert.equal(h.pollTimers().length, 0);
});

test('opening the date dropdown does not erase unrelated document click handlers', () => {
  const h = harness();
  h.$(h.context.document).on('click.other_plugin', () => {});
  h.waf.get_site_logs_view({ siteName: 'fixture' }, ['2026-10-22']);
  h.fire('.waf-unselect .waf-inputs');
  assert.ok(h.bindings.some(b => b.event === 'click.other_plugin'));
});

test('table refresh binds one scroll handler rather than accumulating handlers', () => {
  const h = harness();
  for (let i = 0; i < 4; i++) h.waf.render_san_webshell({ data: [] });
  assert.equal(h.bindings.filter(b => b.key === '#scan_webshell_table' && b.event.startsWith('scroll')).length, 1);
});

test('panel sizing uses only its closest layer and fits a narrow viewport', () => {
  const h = harness(390, 600);
  h.waf.fit_panel_shell();
  assert.ok(!h.styles.some(s => s.key === '.layui-layer-page'));
  const panel = h.styles.find(s => s.key === 'plugin-layer' && s.value.width);
  assert.ok(panel);
  assert.ok(parseInt(panel.value.width, 10) <= 390);
  const content = h.styles.find(s => s.key.includes('.layui-layer-content'));
  assert.ok(parseInt(content.value.height, 10) < 600);
});

test('initial statistics request is unforced; first background build polls once after two seconds', () => {
  const h = harness();
  h.navigate('statistics');
  const first = h.stats().at(-1);
  assert.notEqual(first.options.data.force, '1');
  first.resolve({ status: true, loading: true });
  assert.equal(h.$('#website_stats_refresh').prop('disabled'), false);
  assert.equal(h.pollTimers().length, 1);
  h.tick(1999);
  assert.equal(h.stats().length, 1);
  h.tick(1);
  assert.equal(h.stats().length, 2);
  assert.equal(h.pollTimers().length, 0);
  h.stats().at(-1).resolve(cached());
  assert.equal(h.$('#website_stats_requests').text(), '123');
  assert.equal(h.pollTimers().length, 0);
  assert.equal(h.loads.size, 0);
});

test('cached summary remains visible during generation and checked_at is displayed', () => {
  const h = harness();
  h.navigate('statistics');
  h.stats().at(-1).resolve(cached({ loading: true }));
  assert.equal(h.$('#website_stats_requests').text(), '123');
  assert.match(h.$('#website_stats_status').text(), /2026-10-22 12:00:00/);
  h.tick(2000);
  h.stats().at(-1).resolve({ status: true, loading: true });
  assert.equal(h.$('#website_stats_requests').text(), '123');
  assert.equal(h.pollTimers().length, 1);
});

test('leaving statistics clears the timer and ignores a late response', () => {
  const h = harness();
  h.navigate('statistics');
  const first = h.stats().at(-1);
  first.resolve(cached({ loading: true }));
  h.navigate('home');
  assert.equal(h.pollTimers().length, 0);
  first.options.success(cached({ loading: true, summary: { total_requests: 999 } }));
  h.tick(20000);
  assert.equal(h.stats().length, 1);
  assert.equal(h.$('#website_stats_requests').text(), '123');
});

test('closing the panel cancels a pending request and leaves no polling timer', () => {
  const h = harness();
  h.navigate('statistics');
  const request = h.stats().at(-1);
  h.close();
  assert.equal(request.aborted, true);
  h.tick(10000);
  assert.equal(h.pollTimers().length, 0);
  assert.equal(h.$('#website_stats_refresh').prop('disabled'), false);
});

test('backend error stops polling, retains cached data and manual retry forces freshness', () => {
  const h = harness();
  h.navigate('statistics');
  h.stats().at(-1).resolve(cached({ error: '\u65e5\u5fd7\u8bfb\u53d6\u5931\u8d25' }));
  assert.equal(h.$('#website_stats_requests').text(), '123');
  assert.match(h.$('#website_stats_status').text(), /\u65e5\u5fd7\u8bfb\u53d6\u5931\u8d25/);
  assert.equal(h.pollTimers().length, 0);
  h.fire('#website_stats_refresh');
  assert.equal(h.stats().at(-1).options.data.force, '1');
  h.stats().at(-1).reject();
  assert.equal(h.$('#website_stats_refresh').prop('disabled'), false);
  assert.equal(h.pollTimers().length, 0);
});

test('a filter change aborts old requests and stale responses cannot overwrite the new result', () => {
  const h = harness();
  h.navigate('statistics');
  const first = h.stats().at(-1);
  h.$('#website_stats_days').val('3');
  h.fire('#website_stats_days,#website_stats_site_filter', 'change');
  assert.equal(first.aborted, true);
  h.stats().at(-1).resolve(cached({ summary: { total_requests: 456 } }));
  first.options.success(cached({ loading: true }));
  assert.equal(h.$('#website_stats_requests').text(), '456');
  assert.equal(h.pollTimers().length, 0);
});

test('polling is bounded when a backend keeps reporting loading forever', () => {
  const h = harness();
  h.navigate('statistics');
  for (let i = 0; i < 90; i++) {
    const pending = h.stats().at(-1);
    if (!pending.settled) pending.resolve({ status: true, loading: true });
    h.tick(2000);
  }
  assert.ok(h.stats().length > 1 && h.stats().length <= 61);
  assert.equal(h.pollTimers().length, 0);
  assert.equal(h.$('#website_stats_refresh').prop('disabled'), false);
});

test('first build populates site options before any summary is available', () => {
  const h = harness();
  h.navigate('statistics');
  h.stats().at(-1).resolve({ status: true, loading: true, cached: false,
    site_options: [{ site: 'small-fixture' }, { site: '<unsafe>' }] });
  assert.match(h.$('#website_stats_site_filter').html(), /small-fixture/);
  assert.match(h.$('#website_stats_site_filter').html(), /&lt;unsafe&gt;/);
  assert.equal(h.pollTimers().length, 1);
  assert.equal(h.$('#website_stats_refresh').prop('disabled'), false);
});

test('only the manual refresh request is forced, never its follow-up polls', () => {
  const h = harness();
  h.navigate('statistics');
  h.stats().at(-1).resolve(cached());
  h.fire('#website_stats_refresh');
  assert.equal(h.stats().at(-1).options.data.force, '1');
  h.stats().at(-1).resolve(cached({ loading: true }));
  h.tick(2000);
  assert.equal(h.stats().at(-1).options.data.force, '0');
});

test('errors without a summary remain retryable rather than polling forever', () => {
  const h = harness();
  h.navigate('statistics');
  h.stats().at(-1).resolve({ status: true, loading: false, error: 'fixture failure' });
  assert.match(h.$('#website_stats_status').text(), /fixture failure/);
  assert.equal(h.$('#website_stats_refresh').prop('disabled'), false);
  assert.equal(h.pollTimers().length, 0);
});

test('cancelled polling timers are removed from the owner registry', () => {
  const h = harness();
  for (let i = 0; i < 10; i++) {
    h.navigate('statistics');
    h.stats().at(-1).resolve({ status: true, loading: true });
    h.navigate('home');
  }
  assert.ok(h.waf._timers.every(id => h.timers.has(id)));
});

test('detached panel responses are ignored even before its observer has fired', () => {
  const h = harness();
  let writes = 0;
  h.waf.http({ method: 'get_example', success() { writes++; } });
  h.$('.waf_conter')[0].isConnected = false;
  h.requests.at(-1).resolve({ status: true });
  assert.equal(writes, 0);
});

test('same-object reinitialization rejects old request callbacks and pending table callbacks', () => {
  const h = harness();
  let writes = 0;
  h.waf.http({ method: 'get_example', success() { writes++; } });
  const old = h.requests.at(-1);
  h.waf.defer_panel(() => { writes++; }, 100);
  h.waf.init();
  old.options.success({ status: true });
  h.tick(100);
  assert.equal(writes, 0);
});

test('hovering a scan result repeatedly does not accumulate close handlers', () => {
  const h = harness();
  h.waf.render_san_webshell({ data: [{ '/fixture': 'fixture-rule' }] });
  h.tick(100);
  for (let i = 0; i < 4; i++) h.fire('#scan_webshell_table .fixed-table .file_rule', 'mouseenter');
  assert.equal(h.bindings.filter(b => b.delegated === '.iconguanbi').length, 1);
});

test('tenant filenames and scan signatures never become HTML or inline script', () => {
  const h = harness();
  let table;
  h.waf.refresh_table_view = options => { table = options; };
  const filename = "/site/x');globalThis.injected=1;('y<img src=x onerror=alert(1)>.php";
  const signature = '<img src=x onerror=alert(2)>';
  const row = { [filename]: signature };
  h.waf.render_san_webshell({ data: [row] });
  const cell = table.config[0].templet(row, 0);
  assert.doesNotMatch(cell, /\bonclick\s*=|<img\b/);
  assert.match(cell, /&lt;img/);
  assert.doesNotMatch(table.config[1].templet(row, 0), /<img\b/);
  assert.equal(typeof table.config[0].event, 'function');
  let opened;
  h.context.OnlineEditFile = (mode, path) => { opened = path; };
  table.config[0].event(row, 0);
  assert.equal(opened, filename);
  assert.equal(h.context.injected, undefined);
});

test('scan incomplete coverage and failures remain explicit plain text', () => {
  const h = harness();
  let table;
  h.waf.refresh_table_view = options => { table = options; };
  h.waf.render_san_webshell({ data: { status: true, data: [], coverage: { partial: true, notice: '<timeout>' } } });
  assert.equal(table.data.length, 0);
  assert.match(h.$('#webshell_scan_coverage').text(), /结果不完整/);
  assert.match(h.$('#webshell_scan_coverage').text(), /<timeout>/);
  h.waf.render_san_webshell({ data: { status: false, msg: '扫描失败<fixture>' } });
  assert.match(h.$('#webshell_scan_coverage').text(), /扫描失败<fixture>/);
  h.waf.render_san_webshell({ data: [] });
  assert.match(h.$('#webshell_scan_coverage').text(), /未提供覆盖信息/);
});

test('poll responses without site_options preserve the initial selectable sites', () => {
  const h = harness();
  h.navigate('statistics');
  h.stats().at(-1).resolve({ status: true, loading: true, site_options: [{ site: 'small-fixture' }] });
  h.tick(2000);
  h.stats().at(-1).resolve({ status: true, loading: true });
  assert.match(h.$('#website_stats_site_filter').html(), /small-fixture/);
});

test('polling also has a wall-clock budget when individual requests are slow', () => {
  const h = harness();
  h.navigate('statistics');
  h.tick(100000);
  h.stats().at(-1).resolve({ status: true, loading: true });
  h.tick(25000);
  assert.equal(h.stats().length, 1);
  assert.equal(h.pollTimers().length, 0);
  assert.equal(h.$('#website_stats_refresh').prop('disabled'), false);
});

test('shield status follows the actual master switch rather than a static running claim', () => {
  const h = harness();
  h.requests[0].resolve({ open: false, total: { rules: [], total: 0 }, safe_day: 0 });
  assert.equal(h.$('.waf-shield-title').text(), '\u9632\u706b\u5899\u5df2\u5173\u95ed');
});

test('destroy is idempotent so old owners cannot remove the reopened panel handlers', () => {
  const h = harness();
  const old = h.waf;
  h.reload();
  old.destroy();
  assert.equal(h.bindings.filter(b => b.key === 'window' && b.event === 'resize.free_waf_panel').length, 1);
  const before = h.requests.length;
  h.fire('#simulation_run');
  assert.equal(h.requests.length - before, 1);
});

test('scan site options are loaded only when the tools page is opened', () => {
  const h = harness();
  assert.equal(h.requests.filter(r => r.method === 'return_site').length, 0);
  h.navigate('webshell');
  assert.equal(h.requests.filter(r => r.method === 'return_site').length, 1);
  h.requests.at(-1).resolve({ status: true, msg: { '<fixture>': '/fixture' } });
  assert.match(h.$('[name="static_site_list"]').html(), /&lt;fixture&gt;/);
});

test('overview refresh is an explicit retry of exactly the two first-paint reads', () => {
  const h = harness();
  assert.ok(/\bid="overview_report_refresh"/.test(html));
  const before = h.requests.length;
  h.fire('#overview_report_refresh');
  assert.deepEqual(h.requests.slice(before).map(r => r.method), ['get_total_all', 'get_overview_report']);
  assert.equal(h.loads.size, 0);
});

function chartEngine(h) {
  const instances = [];
  h.context.window.echarts = {
    registerMap() {},
    init(node) {
      const chart = { node, options: [], disposed: false, resizes: 0,
        setOption(option) { this.options.push(option); },
        dispose() { this.disposed = true; },
        resize() { this.resizes++; }, dispatchAction() {},
      };
      instances.push(chart);
      return chart;
    },
  };
  h.context.window.__free_waf_world = { type: 'FeatureCollection', features: [
    { properties: { name: 'United States' }, geometry: {} },
  ] };
  return instances;
}

function resolveOverview(h) {
  h.requests.find(r => r.method === 'get_overview_report' && !r.settled).resolve({
    summary: { total_protection: 9 }, trend: [{ date: '2026-10-22', count: 9 }],
    attack_geography: { countries: [{ code: 'US', count: 7 }], total: 9, located: 7, unlocated: 2, database_available: true },
  });
}

test('overview draws real country and trend series with an already cached engine', () => {
  const h = harness();
  const instances = chartEngine(h);
  resolveOverview(h);
  assert.equal(instances.length, 2);
  assert.equal(instances[0].options[0].series[0].type, 'line');
  assert.equal(instances[1].options[0].series[0].type, 'map');
  assert.match(h.$('#overview_map_ranking').html(), /美国/);
  assert.match(h.$('#overview_map_status').text(), /2/);
});

test('closing the plugin disposes chart instances and aborts pending asset reads', () => {
  const h = harness();
  const instances = chartEngine(h);
  resolveOverview(h);
  h.waf.destroy();
  assert.equal(instances.every(c => c.disposed), true);
  const pending = harness();
  resolveOverview(pending);
  const assets = pending.requests.filter(r => r.options.url.startsWith('/static/'));
  assert.equal(assets.length, 1);
  assert.equal(assets[0].options.timeout, 12000);
  pending.close();
  assert.equal(assets[0].aborted, true);
});

test('asset failure keeps a useful fallback and retries without refetching overview logs', () => {
  const h = harness();
  resolveOverview(h);
  const asset = h.requests.at(-1);
  assert.match(asset.options.url, /echarts\.min\.js/);
  asset.reject();
  assert.match(h.$('#overview_map_status').text(), /重试/);
  assert.match(h.$('#overview_map_ranking').html(), /美国/);
  const count = h.requests.filter(r => r.method === 'get_overview_report').length;
  h.fire('#overview_map_retry');
  assert.match(h.requests.at(-1).options.url, /echarts\.min\.js/);
  assert.equal(h.requests.filter(r => r.method === 'get_overview_report').length, count);
});

test('map expansion is reversible and leaving home closes the expanded view', () => {
  const h = harness();
  chartEngine(h);
  resolveOverview(h);
  h.fire('#overview_map_expand');
  assert.equal(h.waf._map_expanded, true);
  h.navigate('statistics');
  assert.equal(h.waf._map_expanded, false);
});

test('late overview responses cannot overwrite the newer map and summary', () => {
  const h=harness();
  chartEngine(h);
  const earlier=h.requests.find(r=>r.method==='get_overview_report');
  h.fire('#overview_report_refresh');
  const latest=h.requests.filter(r=>r.method==='get_overview_report').at(-1);
  latest.resolve({summary:{total_protection:17},trend:[],attack_geography:{countries:[],total:17}});
  earlier.resolve({summary:{total_protection:99},trend:[],attack_geography:{countries:[],total:99}});
  assert.equal(h.$('#overview_total_protection').text(),'17');
});

test('leaving home during an asset request does not prevent loading on return', () => {
  const h=harness();
  resolveOverview(h);
  const request=h.requests.at(-1);
  h.navigate('statistics');
  assert.equal(request.aborted,true);
  h.navigate('home');
  resolveOverview(h);
  assert.match(h.requests.at(-1).options.url,/echarts\.min\.js/);
});

test('failed initial overview clears the map loading state and offers the main refresh', () => {
  const h=harness();
  h.requests.find(r=>r.method==='get_overview_report').reject();
  assert.match(h.$('#overview_map_placeholder').text(),/刷新概览/);
  assert.match(h.$('#overview_report_status').text(),/重试/);
});

test('overview failure with an existing map retains it and shows a retryable error',()=>{
  const h=harness();chartEngine(h);resolveOverview(h);
  h.waf.render_overview_report();h.requests.at(-1).reject();
  assert.match(h.$('#overview_report_status').text(),/重试/);
  assert.match(h.$('#overview_map_ranking').html(),/美国/);
});

test('asset failure still exposes unlocated counts and unavailable geolocation database',()=>{
  const h=harness();
  h.requests.find(r=>r.method==='get_overview_report').resolve({summary:{total_protection:23},attack_geography:{countries:[],total:23,unlocated:23,database_available:false}});
  h.requests.at(-1).reject();
  assert.match(h.$('#overview_map_status').text(),/23/);
  assert.match(h.$('#overview_map_status').text(),/归属地库不可用/);
  assert.match(h.$('#overview_map_status').text(),/重试/);
});

test('expanded map exposes countries below the sixth rank including unmapped territories',()=>{
  const h=harness();chartEngine(h);
  const countries=['US','CN','DE','NL','GB','RU','HK','TW'].map((code,i)=>({code,count:20-i}));
  h.requests.find(r=>r.method==='get_overview_report').resolve({summary:{},attack_geography:{countries}});
  assert.doesNotMatch(h.$('#overview_map_ranking').html(),/中国香港/);
  h.fire('#overview_map_expand');
  assert.match(h.$('#overview_map_ranking').html(),/中国香港/);
  assert.match(h.$('#overview_map_ranking').html(),/中国台湾/);
  h.fire('#overview_map_expand');
  assert.doesNotMatch(h.$('#overview_map_ranking').html(),/中国香港/);
});

test('late asset failure uses latest geography totals rather than the initial request snapshot',()=>{
  const h=harness();resolveOverview(h);
  const pending=h.requests.at(-1);
  h.waf.render_overview_report();
  h.requests.at(-1).resolve({summary:{total_protection:23},attack_geography:{countries:[],total:23,unlocated:23,database_available:false}});
  pending.reject();
  assert.match(h.$('#overview_map_status').text(),/23/);
  assert.match(h.$('#overview_map_status').text(),/归属地库不可用/);
  assert.doesNotMatch(h.$('#overview_map_status').text(),/已定位 7/);
});
