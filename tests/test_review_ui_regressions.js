'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const source = html.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];

// Run the real page with controllable transport and a minimal in-memory DOM.
function harness() {
  const nodes = new Map(), removed = new Set(), bindings = [], requests = [], dialogs = [], tables = new Map();
  const document = { body: {}, documentElement: {} }, window = { innerWidth: 1280, innerHeight: 800 };
  let nextId = 1;
  function node(key) {
    if (!nodes.has(key)) nodes.set(key, { key, isConnected: true, offsetWidth: 88, values: {}, classes: new Set(), scrollIntoView() {} });
    return nodes.get(key);
  }
  function $(selector) {
    const key = selector === document ? 'document' : selector === window ? 'window'
      : typeof selector === 'object' ? selector.key : selector;
    const absent = [...removed].some(selector => key === selector || String(key).startsWith(selector + ' '));
    const current = node(key), values = current.values;
    const api = {
      0: absent ? undefined : current, length: absent ? 0 : 1,
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
      unbind(events) { return api.off(events); },
      find(child) { return $(child); }, children(child) { return $(key + ' > ' + child); },
      closest(child) { return $(child); }, first() { return api; }, last() { return api; },
      eq() { return api; }, parent() { return api; }, siblings() { return api; },
      next() { return api; }, before() { return api; }, after() { return api; },
      scrollTop(value) { if (value === undefined) return values.scrollTop || 0; values.scrollTop = value; return api; },
      addBack() { return api; }, each() { return api; }, css() { return api; }, focus() { return api; },
      addClass(value) { current.classes.add(value); return api; },
      removeClass(value) { current.classes.delete(value); return api; },
      hasClass(value) { return current.classes.has(value); },
      show() { values.hidden = false; return api; }, hide() { values.hidden = true; return api; },
      append(value) {
        values.html = (values.html || '') + (typeof value === 'object' ? '<option value="' + value.val() + '">' + value.text() + '</option>' : value);
        return api;
      },
      empty() { return api.html(''); },
      text(value) {
        if (value === undefined) return values.text || '';
        values.text = String(value);
        if (/^\[name=scan_/.test(String(key))) values.val = String(value);
        return api;
      },
      html(value) { if (value === undefined) return absent ? undefined : values.html || ''; if (!absent) values.html = String(value); return api; },
      val(value) { if (value === undefined) return values.val || ''; values.val = value; return api; },
      prop(name, value) { if (value === undefined) return values[name]; values[name] = value; return api; },
      attr(name, value) { return api.prop(name, value); }, data(name, value) { return api.prop(name, value); },
    };
    return api;
  }
  $.trim = value => String(value || '').trim();
  $.isArray = Array.isArray;
  $.ajax = options => {
    const request = {
      options, method: new URL('http://fixture' + options.url).searchParams.get('s'), aborted: false, settled: false,
      resolve(result) { if (this.settled) return; this.settled = true; try { options.success?.(result); } finally { options.complete?.(this, 'success'); } },
      reject(reason = 'timeout') { if (this.settled) return; this.settled = true; try { options.error?.(this, reason); } finally { options.complete?.(this, reason); } },
      abort() { this.aborted = true; this.reject('abort'); },
      // Cancellation is not enough: simulate a callback already queued before abort.
      late(result) { options.success?.(result); options.complete?.(this, 'success'); },
      lateError() { options.error?.(this, 'timeout'); options.complete?.(this, 'timeout'); },
    };
    requests.push(request);
    return request;
  };
  const layer = {
    msg() { return nextId++; }, load() { return nextId++; }, close() {},
    open(options) { dialogs.push(options); options.success?.({}, nextId++); return nextId++; },
    confirm(message, options, yes) { dialogs.push({ message, yes }); return nextId++; },
  };
  const context = vm.createContext({ $, window, document, layer, console, bt: {},
    setTimeout() { return nextId++; }, clearTimeout() {}, MutationObserver: class { observe() {} disconnect() {} },
  });
  vm.runInContext(source, context, { filename: 'index.html' });
  const waf = context.free_waf;
  const renderTable = waf.refresh_table_view.bind(waf);
  waf.refresh_table_view = options => {
    tables.set(options.el, options);
    $(options.el).html(JSON.stringify(options.data));
    options.done?.(options.data);
  };
  return { $, waf, requests, dialogs, tables,
    useRealTables() { waf.refresh_table_view = renderTable; },
    remove(selector) {
      removed.add(selector);
      for (const [key, element] of nodes) if (key === selector || String(key).startsWith(selector + ' ')) element.isConnected = false;
    },
    mount(selector) {
      removed.delete(selector);
      for (const key of nodes.keys()) if (key === selector || String(key).startsWith(selector + ' ')) nodes.delete(key);
      return $(selector)[0];
    },
    of(method) { return requests.filter(r => r.method === method); },
    site(name) { if (waf._active_page !== 'site') waf.refresh_data_total('site'); waf.set_site_config_view({ siteName: name }); return this.of('get_site_config_byname').at(-1); },
    fire(selector, event = 'click', attrs = {}) {
      Object.assign(node(selector).values, attrs);
      for (const b of [...bindings]) if (b.event.split('.')[0] === event && (b.key === selector || b.delegated === selector)) {
        b.callback.call(node(selector), { preventDefault() {}, stopPropagation() {} });
      }
    },
  };
}

function config(waf, marker) {
  const result = { open: true, cdn: false, cc: { open: true, cycle: 60, limit: 20, endtime: 300 }, top: {}, marker };
  for (const row of waf.overall_show_config) result.top[row.type] = { ps: marker };
  return result;
}
function ip(value = '192.0.2.10', site = 'a.example') {
  return { ip: value, count: 3, last_time: '2026-10-23 12:00:00', sites: [site], types: { cc: 3 }, is_banned: false };
}
function uri(value) { return { uri: value, count: 2, last_time: '2026-10-23 12:00:00', sites: ['a.example'], types: { args: 2 } }; }
function switchEvent(table) { return table.config.find(column => column.fid === 'open').event; }

test('forum: legacy log details display PCRE rules as text without compiling JavaScript', () => {
  const h = harness();
  h.waf.render_site_logs({ siteName: 'fixture.example', toDate: '2026-10-26', p: 1 });
  const row = ['2026-10-26 12:00:00', '192.0.2.1', 'POST', '/save?x=&lt;img&gt;&amp;y=1',
    '&lt;img src=x onerror=alert(1)&gt;', 'post', '(?i)&lt;script&gt; &gt;&gt; value:&lt;img&gt; &gt;&gt; tail'];
  h.of('get_safe_logs').at(-1).resolve([row]);
  const columns = h.tables.get('#site_logs_table').config;
  const detail = columns.at(-1).group.find(action => action.title === '\u8be6\u60c5');
  assert.doesNotThrow(() => detail.event(row, 0));
  const content = h.dialogs.at(-1).content;
  assert.ok(content.includes('(?i)&lt;script&gt;'));
  assert.ok(content.includes('value:&lt;img&gt; &gt;&gt; tail'));
  assert.ok(content.includes('/save?x=&lt;img&gt;&amp;y=1'));
  assert.doesNotMatch(content, /<img|&amp;lt;|&amp;gt;/);
  const address = columns.find(column => column.fid === '3').templet(row, 0);
  assert.equal(address, '/save?x=&lt;img&gt;&amp;y=1');
});

test('forum: log entities are decoded once then escaped for text display', () => {
  const h = harness();
  assert.equal(h.waf.legacy_log_html('&amp;lt;img&amp;gt;'), '&amp;lt;img&amp;gt;');
  assert.equal(h.waf.legacy_log_html('&lt;img&gt;'), '&lt;img&gt;');
  assert.equal(h.waf.legacy_log_html('<img>'), '&lt;img&gt;');
  assert.equal(h.waf.legacy_log_html('&#x27;quoted&#x27;=&quot;value&quot;'), '&#39;quoted&#39;=&quot;value&quot;');
});

test('forum: a log without a rule value still opens details', () => {
  const h = harness();
  h.waf.render_site_logs({ siteName: 'fixture.example', toDate: '2026-10-26', p: 1 });
  const row = ['2026-10-26 12:00:00', '192.0.2.1', 'GET', '/save', '', 'url', ''];
  h.of('get_safe_logs').at(-1).resolve([row]);
  const actions = h.tables.get('#site_logs_table').config.at(-1).group;
  assert.doesNotThrow(() => actions.find(action => action.title === '\u8be6\u60c5').event(row, 0));
  assert.doesNotMatch(h.dialogs.at(-1).content, /undefined|NaN/);
});

test('R01: late A config cannot replace B or make its CC button write A', () => {
  const h = harness(), a = h.site('a.example'), b = h.site('b.example');
  b.resolve(config(h.waf, 'B')); a.late(config(h.waf, 'A'));
  const table = h.tables.get('#site_config_table');
  switchEvent(table)(table.data[0], 0);
  assert.equal(h.of('set_site_obj_open').at(-1).options.data.siteName, 'b.example');
  assert.equal(h.waf.site_config.marker, 'B');
  assert.match(h.$('#site_detail_title').text(), /b\.example/);
});

test('R01: retained A buttons cannot write during B load or after A-B-A navigation', () => {
  const h = harness(); h.site('a.example').resolve(config(h.waf, 'A'));
  const table = h.tables.get('#site_config_table'), toggle = switchEvent(table);
  h.site('b.example'); toggle(table.data[0], 0);
  h.site('a.example'); toggle(table.data[0], 0);
  assert.equal(h.of('set_site_obj_open').length, 0);
});

for (const leave of ['back', 'page', 'close']) test('R01: ' + leave + ' invalidates pending site detail reads', () => {
  const h = harness(), a = h.site('a.example');
  if (leave === 'back') h.waf.show_site_list_view(false);
  else if (leave === 'page') h.waf.refresh_data_total('overall');
  else h.waf.destroy();
  a.late(config(h.waf, 'late A'));
  assert.equal(h.tables.has('#site_config_table'), false);
  assert.equal(a.aborted, true);
});

const detailCases = [
  ['render_site_rule', '#site_rule_table', 'get_site_disable_rule', [[true, 'rule', 'description']]],
  ['render_site_rule_override', '#site_detail_rule_override_table', 'get_site_disable_rule', [[true, 'rule', 'description']]],
  ['render_site_url_white_rules', '#site_detail_url_white_table', 'get_site_rule', ['^/health']],
  ['render_site_url_rules', '#site_detail_url_rule_table', 'get_site_rule', [['^/uri', 'body']]],
  ['render_site_url_tell_rules', '#site_detail_url_tell_table', 'get_site_rule', [['^/uri', 'param', 'pass']]],
  ['render_site_cdn_headers', '#site_detail_cdn_header_table', 'get_site_cdn_header', ['x-client-ip']],
  ['render_site_cdn_trusted_proxy', '#site_detail_cdn_proxy_table', 'get_site_cdn_trusted_proxy', [[[192, 0, 2, 1], [192, 0, 2, 2]]]],
  ['render_cdn_table', '#other_rule_table', 'get_site_cdn_header', ['x-client-ip']],
  ['render_disable_upload', '#other_rule_table', 'get_site_rule', ['php']],
];
for (const [render, selector, method, rows] of detailCases) test('R01: ' + render + ' rejects stale reads and retained write callbacks', () => {
  const h = harness(); h.site('a.example');
  h.waf[render]({ siteName: 'a.example', ruleName: 'header' });
  const old = h.of(method).at(-1); old.resolve(rows);
  const table = h.tables.get(selector), column = table.config.at(-1);
  const event = column.event || column.group[0].event;
  const writes = () => h.requests.filter(r => /^(set_site_disable_rule|remove_site_)/.test(r.method));
  event(rows[0], 0);
  assert.equal(writes().length, 1, 'the current site action must remain usable');
  assert.equal(writes()[0].options.data.siteName, 'a.example');
  h.site('b.example'); h.$(selector).html('B loading');
  old.late(rows); event(rows[0], 0);
  assert.equal(h.$(selector).html(), 'B loading');
  assert.equal(writes().length, 1, 'retained actions must not create an additional write');
});

test('R01: same-site replacement reads cannot restore older configuration', () => {
  const h = harness(), old = h.site('a.example');
  h.waf.render_site_config({ siteName: 'a.example' });
  h.of('get_site_config_byname').at(-1).resolve(config(h.waf, 'new configuration'));
  old.late(config(h.waf, 'old configuration'));
  assert.equal(h.waf.site_config.marker, 'new configuration');
});

test('R01: changing override family rejects the old Header response', () => {
  const h = harness(); h.site('a.example');
  h.waf.show_site_rule_override({ siteName: 'a.example', name: 'Header', ruleName: 'header' }, true);
  const header = h.of('get_site_disable_rule').at(-1);
  h.waf.show_site_rule_override({ siteName: 'a.example', name: 'Cookie', ruleName: 'cookie' }, true);
  h.of('get_site_disable_rule').at(-1).resolve([[true, 'cookie rule', 'cookie']]);
  header.late([[true, 'header rule', 'header']]);
  assert.equal(h.tables.get('#site_detail_rule_override_table').data[0][1], 'cookie rule');
});

test('R01: CC dialog opened for A cannot submit after switching to B', () => {
  const h = harness(); h.site('a.example');
  h.waf.set_cc_rule_view({ siteName: 'a.example', cc_cycle: 60, cc_limit: 20, cc_endtime: 300 });
  const dialog = h.dialogs.at(-1);
  for (const name of ['cc_cycle', 'cc_limit', 'cc_endtime']) h.$('[name="' + name + '"]').val('60');
  h.site('b.example'); dialog.yes();
  assert.equal(h.of('set_site_cc_conf').length, 0);
});

test('R01: CDN dialog opened for A cannot add a header after switching to B', () => {
  const h = harness(); h.site('a.example'); h.waf.set_other_rule_one_view({ siteName: 'a.example', type: 'cdn' });
  h.$('[name=rule_url]').val('x-test-ip'); h.site('b.example'); h.fire('.add_other_rule');
  assert.equal(h.of('add_site_cdn_header').length, 0);
});

test('R13: empty IP results clear sort cache, site options and bulk targets', () => {
  const h = harness(); h.waf.render_ip_stats(); h.of('get_ip_stats').at(-1).resolve([ip()]);
  h.waf.render_ip_stats(); h.of('get_ip_stats').at(-1).resolve([]);
  h.fire('#ipstats_sort_count'); h.fire('#ipstats_ban_all');
  assert.doesNotMatch(h.$('#ipstats_tbody').html(), /192\.0\.2\.10/);
  assert.equal(h.waf._ipstats_data.length, 0);
  assert.equal((h.$('#ipstats_ban_all').data('ips') || []).length, 0);
  assert.doesNotMatch(h.$('#ipstats_site_filter').html(), /a\.example/);
  assert.equal(h.dialogs.length, 0);
});

test('R13: empty filtered IP results and fully banned results clear bulk targets', () => {
  const h = harness(); h.waf.render_ip_stats(); h.of('get_ip_stats').at(-1).resolve([ip()]);
  h.$('#ipstats_site_filter').val('absent.example'); h.fire('#ipstats_site_filter', 'change');
  assert.equal((h.$('#ipstats_ban_all').data('ips') || []).length, 0);
  h.$('#ipstats_site_filter').val(''); h.waf._ipstats_data[0].is_banned = true; h.waf.render_ip_stats_table();
  assert.equal((h.$('#ipstats_ban_all').data('ips') || []).length, 0);
});

for (const kind of ['ip', 'uri']) {
  const prefix = kind + 'stats', method = 'get_' + kind + '_stats', render = 'render_' + kind + '_stats';
  const row = marker => kind === 'ip' ? ip(marker) : uri(marker);
  test('R18 integration: ' + kind + ' requests coverage and sorts only envelope rows', () => {
    const h = harness(); h.waf[render](); const request = h.of(method).at(-1);
    assert.equal(request.options.data.include_coverage, '1');
    request.resolve({ rows: [row('sample-only')], coverage: { partial: true, scanned_lines: 80 } });
    h.fire('#' + prefix + '_sort_count');
    assert.match(h.$('#' + prefix + '_tbody').html(), /sample-only/);
    assert.match(h.$('#' + prefix + '_summary').text(), /\u6709\u754c|\u6837\u672c/);
    assert.match(h.$('#' + prefix + '_summary').text(), /\u6392\u5e8f/);
    assert.equal(h.of(method).length, 1);
  });
  test('R14: ' + kind + ' late 30-day response cannot overwrite the 1-day result', () => {
    const h = harness(); h.$('#' + prefix + '_days').val('30'); h.waf[render](); const old = h.of(method).at(-1);
    h.$('#' + prefix + '_days').val('1'); h.waf[render](); const current = h.of(method).at(-1);
    current.resolve([row('current-one-day')]); old.late([row('old-thirty-days')]);
    assert.match(h.$('#' + prefix + '_tbody').html(), /current-one-day/);
    assert.doesNotMatch(h.$('#' + prefix + '_tbody').html(), /old-thirty-days/);
    assert.equal(old.aborted, true);
  });
  test('R14: ' + kind + ' same-range refresh rejects the older response', () => {
    const h = harness(); h.waf[render](); const old = h.of(method).at(-1);
    h.waf[render](); h.of(method).at(-1).resolve([row('new-snapshot')]); old.late([row('old-snapshot')]);
    assert.match(h.$('#' + prefix + '_tbody').html(), /new-snapshot/);
  });
  test('R14: ' + kind + ' changing the range invalidates targets immediately', () => {
    const h = harness(); h.waf[render](); h.of(method).at(-1).resolve([row('old-range-target')]);
    h.$('#' + prefix + '_days').val('1'); h.fire('#' + prefix + '_days', 'change');
    assert.equal(h.of(method).at(-1).options.data.days, '1');
    assert.equal(h.waf['_' + prefix + '_data'].length, 0);
    assert.doesNotMatch(h.$('#' + prefix + '_tbody').html(), /old-range-target/);
  });
  test('R14: ' + kind + ' leaving the report cancels reads and invalidates A-B-A results', () => {
    const h = harness(); h.waf.refresh_data_total('ipstats');
    if (kind === 'uri') h.waf[render]();
    const old = h.of(method).at(-1);
    h.waf.refresh_data_total('overall');
    assert.equal(old.aborted, true);
    h.waf.refresh_data_total('ipstats');
    if (kind === 'uri') h.waf[render]();
    h.of(method).at(-1).resolve([row('new-visit')]); old.late([row('old-visit')]); old.lateError();
    assert.match(h.$('#' + prefix + '_tbody').html(), /new-visit/);
  });
  test('R18 integration: ' + kind + ' empty envelope retains partial coverage after sorting', () => {
    const h = harness(); h.waf[render]();
    h.of(method).at(-1).resolve({ rows: [], coverage: { partial: true, scanned_lines: 80 } });
    h.fire('#' + prefix + '_sort_count');
    assert.match(h.$('#' + prefix + '_summary').text(), /\u4e0d\u4ee3\u8868\u5168\u91cf/);
    assert.equal(h.waf['_' + prefix + '_current'].length, 0);
  });
  test('R13/R14: ' + kind + ' range change and failed refresh cannot resurrect old targets', () => {
    const h = harness(); h.waf[render](); h.of(method).at(-1).resolve([row('stale-target')]);
    h.$('#' + prefix + '_days').val('1'); h.waf[render]();
    h.fire('#' + prefix + '_sort_count');
    assert.doesNotMatch(h.$('#' + prefix + '_tbody').html(), /stale-target/);
    h.of(method).at(-1).reject(); h.fire('#' + prefix + '_sort_time');
    assert.equal(h.waf['_' + prefix + '_data'].length, 0);
    assert.doesNotMatch(h.$('#' + prefix + '_site_filter').html(), /a\.example/);
    if (kind === 'ip') assert.equal((h.$('#ipstats_ban_all').data('ips') || []).length, 0);
    else assert.equal(h.waf._uristats_current.length, 0);
  });
}

test('R13/R14: pending bulk confirmation cannot ban targets from a previous sample', () => {
  const h = harness(); h.waf.render_ip_stats(); h.of('get_ip_stats').at(-1).resolve([ip()]);
  h.fire('#ipstats_ban_all'); const confirmation = h.dialogs.at(-1);
  h.waf.render_ip_stats(); h.of('get_ip_stats').at(-1).resolve([]); confirmation.yes();
  assert.equal(h.of('add_permanent_ban').length, 0);
});

test('R14: pending URI confirmation cannot whitelist a previous sample', () => {
  const h = harness(); h.waf.render_uri_stats(); h.of('get_uri_stats').at(-1).resolve([uri('/old-uri')]);
  h.fire('.uristats_whitelist', 'click', { index: 0 }); const confirmation = h.dialogs.at(-1);
  h.waf.render_uri_stats(); h.of('get_uri_stats').at(-1).resolve([]); confirmation.yes();
  assert.equal(h.of('add_url_white').length, 0);
});

test('R16: each labelled scanner field loads and saves the matching backend key', () => {
  const h = harness(); h.waf.set_scan_rule_view();
  const dialog = h.dialogs.at(-1), fields = [...dialog.content.matchAll(/<span class="name-l">([^<]+)<\/span>[\s\S]*?<textarea name="([^"]+)"/g)];
  h.of('get_rule').at(-1).resolve({ header: 'old-header', args: 'old-args', cookie: 'old-cookie' });
  const expected = new Map([['Header', 'header'], ['Cookie', 'cookie'], ['\u53c2\u6570', 'args']]);
  for (const [, label, name] of fields) {
    assert.equal(h.$('[name=' + name + ']').val(), 'old-' + expected.get(label));
    h.$('[name=' + name + ']').val('new-' + expected.get(label));
  }
  dialog.yes();
  const data = h.of('save_scan_rule').at(-1).options.data;
  assert.equal(data.header, 'new-header'); assert.equal(data.cookie, 'new-cookie'); assert.equal(data.args, 'new-args');
});

for (const failure of ['timeout', 'error', 'backend', 'malformed']) test('R17: ' + failure + ' releases report refresh and permits retry', () => {
  const h = harness(); h.waf.render_report_dashboard_summary(); const request = h.of('get_report_dashboard_summary').at(-1);
  assert.equal(h.$('#report_summary_refresh').prop('disabled'), true);
  if (failure === 'backend') request.resolve({ status: false, msg: 'failed' });
  else if (failure === 'malformed') request.resolve({ status: true });
  else request.reject(failure);
  assert.equal(h.$('#report_summary_refresh').prop('disabled'), false);
  assert.doesNotMatch(h.$('#report_summary_status').text(), /\u52a0\u8f7d\u4e2d/);
  h.fire('#report_summary_refresh'); h.of('get_report_dashboard_summary').at(-1).resolve({ status: true, summary: { total_hits: 7 } });
  assert.equal(h.$('#report_summary_hits').text(), '7');
  assert.equal(h.$('#report_summary_refresh').prop('disabled'), false);
});

test('R17: an old report completion cannot release a newer refresh button', () => {
  const h = harness(); h.waf.render_report_dashboard_summary(); const old = h.of('get_report_dashboard_summary').at(-1);
  h.waf.render_report_dashboard_summary(); old.lateError();
  assert.equal(h.$('#report_summary_refresh').prop('disabled'), true);
  h.of('get_report_dashboard_summary').at(-1).resolve({ status: true, summary: { total_hits: 9 } });
  assert.equal(h.$('#report_summary_hits').text(), '9');
  assert.equal(h.$('#report_summary_refresh').prop('disabled'), false);
});

for (const empty of [false, true]) test('R18 integration: bounded search labels inexact totals even with ' + (empty ? 'no rows' : 'rows'), () => {
  const h = harness(); h.waf.render_report_search();
  h.of('get_report_search').at(-1).resolve({ status: true, rows: empty ? [] : [{ site: 'a.example', uri: '/sample' }],
    total: empty ? 0 : 51, total_exact: false, has_more: !empty, coverage: { partial: true, scanned_lines: 80 } });
  const text = h.$('#report_search_summary').text();
  assert.match(text, /\u6709\u754c|\u90e8\u5206|\u6837\u672c/);
  assert.match(text, /\u975e\u7cbe\u786e|\u4e0d\u7cbe\u786e|\u4e0d\u4ee3\u8868\u5168\u91cf/);
  if (!empty) assert.match(text, /51/);
});

test('R18 integration: complete search keeps an exact count', () => {
  const h = harness(); h.waf.render_report_search();
  h.of('get_report_search').at(-1).resolve({ status: true, rows: [{ uri: '/only' }], total: 1, total_exact: true,
    has_more: false, coverage: { partial: false, scanned_lines: 1 } });
  assert.match(h.$('#report_search_summary').text(), /\u5339\u914d 1 \u6761/);
  assert.doesNotMatch(h.$('#report_search_summary').text(), /\u975e\u7cbe\u786e/);
});

for (const offset of [0, 4096]) test('R18 integration: HTTP detail sends byte offset ' + offset + ' when line number is unknown', () => {
  const h = harness(); h.waf.show_report_http_detail({ site: 'a.example', date: '2026-10-23', line_no: 0, offset });
  const request = h.of('get_report_http_detail').at(-1);
  assert.equal(request.options.data.offset, offset);
  request.resolve({ status: true, data: { line_no: 0, offset, site: 'a.example' } });
  assert.match(h.dialogs.at(-1).content, /\u672a\u77e5/);
});

test('R19 integration: notification summary is bounded and scoped to returned items', () => {
  const h = harness(); h.waf.render_defense_notifications();
  h.of('get_defense_notifications').at(-1).resolve({ status: true, items: [], summary: { total: 0 },
    summary_scope: 'returned_items', partial: true, coverage: { partial: true, scanned_lines: 80 } });
  const text = h.$('#notification_summary').text();
  assert.match(text, /\u6709\u754c/);
  assert.match(text, /\u8fd4\u56de\u8bb0\u5f55|\u8fd4\u56de\u6761\u76ee/);
  assert.match(text, /\u4e0d\u4ee3\u8868\u5168\u91cf|\u975e\u5168\u91cf/);
});

test('R18 integration: legacy overview shows incomplete bounded coverage', () => {
  const h = harness(); h.waf.render_overview_report();
  h.of('get_overview_report').at(-1).resolve({ status: true, summary: {}, coverage: { partial: true, scanned_lines: 80 } });
  assert.match(h.$('#overview_report_status').text(), /\u6709\u754c|\u90e8\u5206|\u6837\u672c/);
});

for (const failure of ['timeout', 'backend']) test('UI re-review: same-site config ' + failure + ' clears dead controls and offers a working retry', () => {
  const h = harness(); h.site('a.example').resolve(config(h.waf, 'old-config-content'));
  const oldTable = h.tables.get('#site_config_table'), oldHtml = h.$('#site_config_table').html();
  h.waf.render_site_config({ siteName: 'a.example' });
  assert.notEqual(h.$('#site_config_table').html(), oldHtml);
  assert.match(h.$('#site_config_table').html(), /\u52a0\u8f7d/);
  const request = h.of('get_site_config_byname').at(-1);
  if (failure === 'backend') request.resolve({ status: false, msg: 'failed' }); else request.reject();
  assert.match(h.$('#site_config_table').html(), /\u5931\u8d25|\u8d85\u65f6/);
  assert.match(h.$('#site_config_table').html(), /\u91cd\u8bd5/);
  switchEvent(oldTable)(oldTable.data[0], 0);
  assert.equal(h.of('set_site_obj_open').length, 0);
  h.fire('#site_config_table .site_detail_retry');
  assert.notEqual(h.of('get_site_config_byname').at(-1), request);
  h.of('get_site_config_byname').at(-1).resolve(config(h.waf, 'new-config-content'));
  const table = h.tables.get('#site_config_table'); switchEvent(table)(table.data[0], 0);
  assert.equal(h.of('set_site_obj_open').at(-1).options.data.siteName, 'a.example');
  assert.equal(h.$('.site_config_switch').prop('disabled'), false);
});

test('UI re-review: failed Cookie override never retains Header rows under a Cookie title', () => {
  const h = harness(); h.site('a.example');
  h.waf.show_site_rule_override({ siteName: 'a.example', name: 'Header', ruleName: 'header' }, true);
  h.of('get_site_disable_rule').at(-1).resolve([[true, 'old-header-content', 'header']]);
  h.waf.show_site_rule_override({ siteName: 'a.example', name: 'Cookie', ruleName: 'cookie' }, true);
  assert.equal(h.$('#site_detail_rule_override_title').text(), 'Cookie');
  assert.doesNotMatch(h.$('#site_detail_rule_override_table').html(), /old-header-content/);
  h.of('get_site_disable_rule').at(-1).reject();
  assert.match(h.$('#site_detail_rule_override_table').html(), /\u91cd\u8bd5/);
  h.fire('#site_detail_rule_override_table .site_detail_retry');
  assert.equal(h.of('get_site_disable_rule').at(-1).options.data.ruleName, 'cookie');
  h.of('get_site_disable_rule').at(-1).resolve([[true, 'new-cookie-content', 'cookie']]);
  assert.match(h.$('#site_detail_rule_override_table').html(), /new-cookie-content/);
  assert.doesNotMatch(h.$('#site_detail_rule_override_table').html(), /old-header-content/);
});

test('UI re-review: a superseded site-config error cannot clear the current table', () => {
  const h = harness(), old = h.site('a.example');
  h.waf.render_site_config({ siteName: 'a.example' });
  h.of('get_site_config_byname').at(-1).resolve(config(h.waf, 'new-config-content'));
  const currentHtml = h.$('#site_config_table').html();
  old.lateError();
  assert.equal(h.$('#site_config_table').html(), currentHtml);
});

test('UI re-review: a deferred old config completion cannot restore its switch state', () => {
  const h = harness(), deferred = []; h.useRealTables(); h.waf.defer_panel = callback => deferred.push(callback);
  h.site('a.example').resolve(config(h.waf, 'old-config'));
  h.waf.render_site_config({ siteName: 'a.example' });
  const fresh = config(h.waf, 'fresh-config'); fresh.open = false;
  h.of('get_site_config_byname').at(-1).resolve(fresh);
  assert.equal(h.$('input[type=checkbox]').prop('checked'), false);
  deferred[0]();
  assert.equal(h.waf.site_config.open, false);
  assert.equal(h.$('input[type=checkbox]').prop('checked'), false);
});

test('UI re-review: a deferred Header completion cannot overwrite the Cookie view', () => {
  const h = harness(), deferred = []; h.site('a.example');
  h.useRealTables(); h.waf.defer_panel = callback => deferred.push(callback);
  h.waf.render_site_rule_override({ siteName: 'a.example', ruleName: 'header' }, () => h.$('#site_detail_rule_override_title').text('Header'));
  h.of('get_site_disable_rule').at(-1).resolve([[true, 'header rule', 'header']]);
  h.waf.show_site_rule_override({ siteName: 'a.example', name: 'Cookie', ruleName: 'cookie' }, true);
  h.of('get_site_disable_rule').at(-1).resolve([[true, 'cookie rule', 'cookie']]);
  deferred[0]();
  assert.equal(h.$('#site_detail_rule_override_title').text(), 'Cookie');
});

test('UI re-review: CDN late response cannot render into a truly removed popup table', () => {
  const h = harness(); h.site('a.example');
  h.waf.set_other_rule_one_view({ siteName: 'a.example', type: 'cdn' });
  const request = h.of('get_site_cdn_header').at(-1), dialog = h.dialogs.at(-1);
  h.remove('#other_rule_table'); dialog.end?.(); h.useRealTables();
  assert.equal(h.$('#other_rule_table').length, 0);
  assert.equal(h.$('#other_rule_table .fixed-table')[0], undefined);
  assert.doesNotThrow(() => request.late(['x-late-ip']));
  assert.equal(h.$('#other_rule_table').length, 0);
});

test('UI re-review: a replaced popup node rejects the old CDN response and retained delete', () => {
  const h = harness(); h.site('a.example');
  h.waf.set_other_rule_one_view({ siteName: 'a.example', type: 'cdn' });
  const old = h.of('get_site_cdn_header').at(-1); old.resolve(['x-old-ip']);
  const table = h.tables.get('#other_rule_table');
  h.remove('#other_rule_table'); h.mount('#other_rule_table'); h.$('#other_rule_table').html('replacement popup');
  old.late(['x-late-ip']); table.config.at(-1).group[0].event('x-old-ip', 0);
  assert.equal(h.$('#other_rule_table').html(), 'replacement popup');
  assert.equal(h.of('remove_site_cdn_header').length, 0);
});

test('UI re-review: removed CDN dialog cannot add a header in the same site', () => {
  const h = harness(); h.site('a.example'); h.waf.set_other_rule_one_view({ siteName: 'a.example', type: 'cdn' });
  const dialog = h.dialogs.at(-1);
  h.remove('#other_rule_table'); dialog.end?.(); h.$('[name=rule_url]').val('x-stale-ip'); h.fire('.add_other_rule');
  assert.equal(h.of('add_site_cdn_header').length, 0);
});

test('UI re-review: CDN dialog close invalidates a read even before DOM removal', () => {
  const h = harness(); h.site('a.example'); h.waf.set_other_rule_one_view({ siteName: 'a.example', type: 'cdn' });
  const request = h.of('get_site_cdn_header').at(-1), dialog = h.dialogs.at(-1);
  h.$('#other_rule_table').html('closing popup'); dialog.cancel?.();
  request.late(['x-late-ip']);
  assert.equal(h.$('#other_rule_table').html(), 'closing popup');
});

for (const kind of ['ip', 'uri']) for (const failure of ['timeout', 'backend', 'malformed']) test('UI re-review: ' + kind + ' ' + failure + ' remains an error through sorting and retry until success', () => {
  const h = harness(), prefix = kind + 'stats', method = 'get_' + kind + '_stats', render = 'render_' + kind + '_stats';
  h.waf[render](); const failed = h.of(method).at(-1);
  if (failure === 'backend') failed.resolve({ status: false, msg: 'backend failed' });
  else if (failure === 'malformed') failed.resolve({ status: true, rows: null });
  else failed.reject();
  const message = h.$('#' + prefix + '_summary').text();
  assert.match(message, /\u5931\u8d25|\u8d85\u65f6|failed/);
  for (const selector of ['sort_count', 'sort_time', 'site_filter']) h.fire('#' + prefix + '_' + selector, selector === 'site_filter' ? 'change' : 'click');
  assert.equal(h.$('#' + prefix + '_summary').text(), message);
  assert.match(h.$('#' + prefix + '_tbody').html(), /\u5931\u8d25|\u8d85\u65f6/);
  h.waf[render](); h.fire('#' + prefix + '_sort_count');
  assert.doesNotMatch(h.$('#' + prefix + '_summary').text(), /\u6682\u65e0\u6570\u636e/);
  h.of(method).at(-1).resolve([]); h.fire('#' + prefix + '_sort_count');
  assert.match(h.$('#' + prefix + '_summary').text(), /\u6682\u65e0\u6570\u636e/);
  assert.doesNotMatch(h.$('#' + prefix + '_summary').text(), /\u5931\u8d25|\u8d85\u65f6|failed/);
});
