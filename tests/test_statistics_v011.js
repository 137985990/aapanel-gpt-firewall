'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const source = html.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];

function harness() {
  const nodes = new Map(), bindings = [], requests = [], timers = new Map(), confirms = [], messages = [];
  const document = { body: {}, documentElement: {} }, window = { innerWidth: 1280, innerHeight: 800 };
  let now = 0, nextId = 1;
  function node(key) {
    if (!nodes.has(key)) nodes.set(key, { key, isConnected: true, values: {}, classes: new Set(), scrollIntoView() {} });
    return nodes.get(key);
  }
  function $(selector) {
    const key = selector === window ? 'window' : selector === document ? 'document'
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
          if (b.key === key && (!events || events.split(' ').some(e => {
            const [type, ...ns] = e.split('.');
            return (!type || b.event.split('.')[0] === type) && ns.every(n => b.event.split('.').includes(n));
          })) && (delegated === undefined || b.delegated === delegated)) bindings.splice(i, 1);
        }
        return api;
      },
      click(callback) { return api.on('click', callback); },
      find(child) { return $(child); }, children(child) { return $(key + ' > ' + child); },
      closest(child) { return $(child); }, first() { return api; }, last() { return api; },
      eq() { return api; }, parent() { return api; }, siblings() { return api; },
      addBack() { return api; }, each() { return api; }, css() { return api; },
      addClass(value) { current.classes.add(value); return api; },
      removeClass(value) { current.classes.delete(value); return api; },
      hasClass(value) { return current.classes.has(value); },
      show() { current.values.hidden = false; return api; }, hide() { current.values.hidden = true; return api; },
      append(value) { current.values.html = (current.values.html || '') + value; return api; },
      text(value) { if (value === undefined) return current.values.text || ''; current.values.text = String(value); return api; },
      html(value) { if (value === undefined) return current.values.html || ''; current.values.html = String(value); return api; },
      val(value) { if (value === undefined) return current.values.val || (key === '#website_stats_days' ? '7' : ''); current.values.val = value; return api; },
      prop(name, value) { if (value === undefined) return current.values[name]; current.values[name] = value; return api; },
      attr(name, value) { return api.prop(name, value); }, data(name, value) { return api.prop(name, value); },
    };
    return api;
  }
  $.trim = value => String(value || '').trim();
  $.isArray = Array.isArray;
  $.ajax = options => {
    const request = {
      options, method: new URL('http://fixture' + options.url).searchParams.get('s'), settled: false, aborted: false,
      resolve(result) { if (this.settled) return; this.settled = true; try { options.success(result); } finally { options.complete?.(this, 'success'); } },
      reject(reason = 'timeout') { if (this.settled) return; this.settled = true; try { options.error?.(this, reason); } finally { options.complete?.(this, reason); } },
      abort() { this.aborted = true; this.reject('abort'); },
    };
    requests.push(request);
    return request;
  };
  const layer = {
    msg(message, options) { messages.push({ message, options }); return nextId++; },
    load() { throw new Error('Read-only UI must not block the map'); }, close() {},
    confirm(message, options, yes, cancel) { confirms.push({ message, options, yes, cancel }); return nextId++; },
  };
  const context = vm.createContext({ $, window, document, layer, console, bt: {},
    Date: class extends Date { static now() { return Date.UTC(2026, 9, 22) + now; } },
    setTimeout(callback, delay) { const id = nextId++; timers.set(id, { callback, delay, due: now + delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    MutationObserver: class { observe() {} disconnect() {} },
  });
  function reload() { vm.runInContext(source, context, { filename: 'index.html' }); }
  reload();
  return { $, context, requests, timers, confirms, messages, reload,
    get waf() { return context.free_waf; },
    of(method) { return requests.filter(r => r.method === method); },
    stats() { return this.of('get_website_statistics_summary'); },
    navigate(page) { context.free_waf.refresh_data_total(page); },
    fire(selector, event = 'click', attrs = {}) {
      Object.assign(node(selector).values, attrs);
      for (const b of [...bindings]) if (b.event.split('.')[0] === event &&
        (b.key === selector || b.delegated?.split(',').includes(selector))) {
        b.callback.call(node(selector), { preventDefault() {}, stopPropagation() {} });
      }
    },
    tick(ms) {
      now += ms;
      for (let i = 0; i < 1000; i++) {
        const entry = [...timers].find(([, t]) => t.due <= now);
        if (!entry) return;
        timers.delete(entry[0]); entry[1].callback();
      }
      throw new Error('Unbounded polling');
    },
    close() { node('.waf_conter').isConnected = false; context.free_waf.destroy(); },
  };
}

function report(extra = {}) {
  return { status: true, schema_version: 2, checked_at: '2026-10-22 12:00:00',
    summary: { total_requests: 12, unique_clients: 3, total_bytes: 4096, error_requests: 2, errors_4xx: 1, errors_5xx: 1, spider_requests: 4 },
    sites: [{ site: 'a<&>.example', requests: 12, clients: 3, bytes: 4096, errors: 2 }],
    trend: [{ label: '00:00', time: 1792627200, requests: 0, clients: 0, bytes: 0, errors: 0 },
      { label: '<12:00>', time: 1792670400, requests: 12, clients: 3, bytes: 4096, errors: 2 }],
    browsers: [{ name: 'Chrome<&>', count: 10 }], operating_systems: [{ name: 'Windows', count: 9 }], devices: [{ name: 'Mobile', count: 3 }],
    window: { start: '2026-10-22 00:00:00', end: '2026-10-22 12:00:00', timezone: 'Asia/Shanghai' },
    coverage: { complete: false, partial: true, reasons: ['scan_limit'], notice: 'coverage <partial>', files_scanned: 2, invalid_lines: 1, bytes_read: 8192 },
    recent_access: Array.from({ length: 80 }, (_, i) => ({ time: '2026-10-22 12:00:00', site: 'a<&>.example', ip: '2001:db8::1',
      method: i % 2 ? 'POST' : 'GET', status: i % 3 ? 200 : (i % 2 ? 503 : 404), uri: '/literal[.]?n=' + i, bytes: i, raw: 'GET <raw> & "once"' })),
    recent_errors: Array.from({ length: 120 }, (_, i) => ({ time: '2026-10-22 12:00:00', site: 'a<&>.example', ip: '2001:db8::1', method: 'GET', status: i % 2 ? 503 : 404, uri: '/error-only/' + i, raw: '<http error>' })),
    server_errors: Array.from({ length: 120 }, (_, i) => ({ time: '2026/10/22 12:00:00', site: 'a<&>.example', client: '2001:db8::1', level: 'error', raw: '<diagnostic> &' + i })),
    ...extra };
}

if (require.main === module) {
  test('statistics has exactly seven subpages and honest labels', () => {
    assert.deepEqual([...html.matchAll(/class="website_stats_tab[^\"]*"[^>]*data-stats-page="([^"]+)"/g)].map(m => m[1]),
      ['overview', 'sites', 'spiders', 'clients', 'access', 'errors', 'settings']);
    for (const label of ['独立 IP', '响应体流量', '疑似蜘蛛', 'HTTP 错误请求', 'Nginx 诊断日志', '自然日', 'UA']) assert.ok(html.includes(label), label);
  });
  test('schema 2 renders a real safe chart, coverage, window and separate UA distributions', () => {
    const h = harness(); h.navigate('statistics'); h.stats().at(-1).resolve(report());
    assert.match(h.$('#website_stats_trend').html(), /<svg[\s\S]*polyline/);
    assert.match(h.$('#website_stats_trend').html(), /&lt;12:00&gt;/);
    assert.doesNotMatch(h.$('#website_stats_trend').html(), /<12:00>/);
    assert.match(h.$('#website_stats_browser_table').html(), /Chrome&lt;&amp;&gt;/);
    assert.match(h.$('#website_stats_os_table').html(), /Windows/);
    assert.match(h.$('#website_stats_device_table').html(), /Mobile/);
    assert.match(h.$('#website_stats_coverage').text(), /部分[\s\S]*scan_limit[\s\S]*2[\s\S]*1/);
    assert.match(h.$('#website_stats_window').text(), /2026-10-22 00:00:00[\s\S]*Asia\/Shanghai/);
    assert.equal(h.$('#website_stats_errors4xx').text(), '1');
    assert.equal(h.$('#website_stats_errors5xx').text(), '1');
  });
  test('old reports remain usable without inventing trend, coverage or error splits', () => {
    const h = harness(); h.navigate('statistics'); h.stats().at(-1).resolve({ status: true, summary: { total_requests: 9, unique_clients: 2 } });
    assert.equal(h.$('#website_stats_requests').text(), '9');
    assert.match(h.$('#website_stats_trend').html(), /未提供/);
    assert.match(h.$('#website_stats_coverage').text(), /未提供/);
    assert.equal(h.$('#website_stats_errors4xx').text(), '--');
  });
  test('tail sampling has an explicit Chinese incomplete-coverage warning', () => {
    for (const complete of [false, true]) {
      const h = harness(), data = report({ coverage: {
        complete, partial: !complete, reasons: ['tail_sampling', 'scan_limit'], files_scanned: 1,
      } }), original = JSON.stringify(data);
      h.navigate('statistics'); h.stats().at(-1).resolve(data);
      const message = h.$('#website_stats_coverage').text();
      assert.match(message, /大日志仅分析末尾样本，不能视为完整统计/);
      assert.match(message, /部分覆盖/);
      assert.doesNotMatch(message, /tail_sampling|报告覆盖完整/);
      assert.equal(JSON.stringify(data), original);
      assert.equal(h.stats().length, 1);
    }
  });
  test('subpages, literal sample filters and pagination never rescan', () => {
    const h = harness(); h.navigate('statistics'); h.stats().at(-1).resolve(report());
    const reads = h.stats().length;
    for (const page of ['sites', 'spiders', 'clients', 'access', 'errors', 'settings']) {
      h.fire('.website_stats_tab', 'click', { 'data-stats-page': page });
      assert.equal(h.waf._statistics_page, page);
    }
    h.$('#website_stats_access_uri').val('[.]'); h.fire('.website_stats_sample_filter', 'input', { 'data-sample': 'access' });
    assert.match(h.$('#website_stats_access_page_info').text(), /80/);
    h.fire('.website_stats_sample_next', 'click', { 'data-sample': 'access' });
    assert.match(h.$('#website_stats_access_table').html(), /n=20/);
    h.$('#website_stats_access_method').val('POST'); h.$('#website_stats_access_status').val('503'); h.$('#website_stats_access_ip').val('db8::');
    h.fire('.website_stats_sample_filter', 'input', { 'data-sample': 'access' });
    assert.match(h.$('#website_stats_access_page_info').text(), /13/);
    assert.doesNotMatch(h.$('#website_stats_access_table').html(), /<td>200<\/td>|<td>GET<\/td>/);
    h.$('#website_stats_access_uri').val('.*'); h.fire('.website_stats_sample_filter', 'input', { 'data-sample': 'access' });
    assert.match(h.$('#website_stats_access_page_info').text(), /0/);
    assert.equal(h.stats().length, reads);
  });
  test('error subpage separates HTTP >=400 samples from 120 diagnostic rows', () => {
    const h = harness(); h.navigate('statistics'); h.stats().at(-1).resolve(report());
    assert.match(h.$('#website_stats_http_error_page_info').text(), /120/);
    assert.match(h.$('#website_stats_http_error_table').html(), /error-only/);
    assert.doesNotMatch(h.$('#website_stats_http_error_table').html(), /<td>200<\/td>|diagnostic/);
    assert.match(h.$('#website_stats_error_page_info').text(), /120/);
    h.fire('.website_stats_sample_next', 'click', { 'data-sample': 'error' });
    assert.match(h.$('#website_stats_error_table').html(), /&lt;diagnostic&gt; &amp;20/);
    h.$('#website_stats_http_error_status').val('503'); h.fire('.website_stats_sample_filter', 'input', { 'data-sample': 'http_error' });
    assert.match(h.$('#website_stats_http_error_page_info').text(), /60/);
    assert.equal(h.stats().length, 1);
  });
  test('site click refilters server report while today is a calendar-day label', () => {
    const h = harness(); h.navigate('statistics'); h.stats().at(-1).resolve(report());
    h.$('#website_stats_days').val('1');
    h.fire('.website_stats_site_link', 'click', { 'data-site': 'a<&>.example' });
    assert.equal(h.stats().at(-1).options.data.siteName, 'a<&>.example');
    assert.match(h.$('#website_stats_status').text(), /今日|自然日/);
    assert.doesNotMatch(h.$('#website_stats_status').text(), /近1日/);
  });
  test('raw strings are escaped exactly once without mutating the response', () => {
    const h = harness(), data = report(), original = JSON.stringify(data);
    h.navigate('statistics'); h.stats().at(-1).resolve(data);
    assert.match(h.$('#website_stats_access_table').html(), /&lt;raw&gt; &amp; &quot;once&quot;/);
    assert.doesNotMatch(h.$('#website_stats_access_table').html(), /&amp;lt;raw/);
    assert.equal(JSON.stringify(data), original);
  });
  test('changing report scope clears cached samples and chart before replacement arrives', () => {
    const h = harness(); h.navigate('statistics'); h.stats().at(-1).resolve(report());
    h.$('#website_stats_site_filter').val('other'); h.fire('#website_stats_site_filter', 'change');
    h.fire('.website_stats_sample_next', 'click', { 'data-sample': 'access' });
    assert.doesNotMatch(h.$('#website_stats_access_table').html(), /literal/);
    assert.doesNotMatch(h.$('#website_stats_trend').html(), /polyline/);
  });
  test('legacy diagnostics stay diagnostic while HTTP errors fall back to access samples', () => {
    const h = harness(); h.navigate('statistics');
    h.stats().at(-1).resolve({ status: true, summary: {}, recent_access: [{ status: 404, uri: '/legacy-http' }], recent_errors: [{ raw: '<legacy diagnostic>' }] });
    assert.match(h.$('#website_stats_http_error_table').html(), /legacy-http/);
    assert.match(h.$('#website_stats_error_table').html(), /&lt;legacy diagnostic&gt;/);
  });
  test('explicit future/unobserved buckets are gaps, never observed zero points', () => {
    const h = harness(); h.navigate('statistics'); h.stats().at(-1).resolve(report({ trend: [
      { label: 'past', requests: 7 }, { label: 'future', requests: 0, future: true },
      { label: 'unobserved', requests: 0, observed: false }, { label: 'later', requests: 2 },
    ] }));
    assert.equal((h.$('#website_stats_trend').html().match(/<circle /g) || []).length, 2);
    assert.match(h.$('#website_stats_trend').html(), /未观测/);
  });
  test('exact core schema infers future hourly gaps from offset-aware window end', () => {
    const h=harness(); h.navigate('statistics'); h.stats().at(-1).resolve(report({
      window:{start:'2026-10-22T00:00:00+08:00',end:'2026-10-22T12:30:00+08:00',timezone:'Asia/Shanghai'},
      trend:[{label:'11:00',time:'2026-10-22T11:00:00+08:00',requests:7},
        {label:'12:00',time:'2026-10-22T12:00:00+08:00',requests:0},
        {label:'13:00',time:'2026-10-22T13:00:00+08:00',requests:0}],
    }));
    assert.equal((h.$('#website_stats_trend').html().match(/<circle /g)||[]).length,2);
    assert.doesNotMatch(h.$('#website_stats_trend').html(),/<title>13:00 · 请求 0/);
    assert.match(h.$('#website_stats_trend').html(),/未来/);
  });
  test('mobile trend keeps readable label scale instead of shrinking a desktop viewBox', () => {
    const h=harness(); h.$('#website_stats_trend')[0].clientWidth=218;
    h.navigate('statistics'); h.stats().at(-1).resolve(report());
    const box=h.$('#website_stats_trend').html().match(/viewBox="0 0 (\d+) (\d+)"/);
    assert.ok(box && Number(box[1])<=260);
  });
}

module.exports = { harness, report, html };
