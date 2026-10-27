'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const source = html.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];

// Execute the real page; transport callbacks can arrive even after cancellation.
function harness() {
  const nodes = new Map(), bindings = [], requests = [], dialogs = [], messages = [], downloads = [];
  const document = { body: {}, documentElement: {} }, window = { innerWidth: 1280, innerHeight: 800 };
  let nextId = 1;
  function node(key) {
    if (!nodes.has(key)) nodes.set(key, { key, isConnected: true, values: {}, scrollIntoView() {} });
    return nodes.get(key);
  }
  function $(selector) {
    const key = selector === document ? 'document' : selector === window ? 'window'
      : typeof selector === 'object' ? selector.key : selector;
    const current = node(key), values = current.values;
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
      click(callback) { return api.on('click', callback); }, unbind(events) { return api.off(events); },
      find(child) { return $(child); }, children(child) { return $(key + ' > ' + child); },
      closest(child) { return $(child); }, first() { return api; }, last() { return api; },
      eq() { return api; }, parent() { return api; }, siblings() { return api; }, next() { return api; },
      addBack() { return api; }, each() { return api; }, focus() { return api; },
      addClass() { return api; }, removeClass() { return api; }, css() { return api; },
      show() { return api; }, hide() { return api; }, append() { return api; },
      empty() { return api.html(''); },
      text(value) { if (value === undefined) return values.text || ''; values.text = String(value); return api; },
      html(value) { if (value === undefined) return values.html || ''; values.html = String(value); return api; },
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
      options, method: new URL('http://fixture' + options.url).searchParams.get('s'), settled: false, aborted: false,
      resolve(result) { if (this.settled) return; this.settled = true; try { options.success?.(result); } finally { options.complete?.(this, 'success'); } },
      reject(reason = 'timeout') { if (this.settled) return; this.settled = true; try { options.error?.(this, reason); } finally { options.complete?.(this, reason); } },
      abort() { this.aborted = true; this.reject('abort'); },
      late(result) { options.success?.(result); options.complete?.(this, 'success'); },
      lateError() { options.error?.(this, 'timeout'); options.complete?.(this, 'timeout'); },
    };
    requests.push(request);
    return request;
  };
  const layer = {
    msg(message) { messages.push(message); return nextId++; }, load() { return nextId++; }, close() {},
    open(options) { dialogs.push(options); options.success?.({}, nextId++); return nextId++; },
    confirm() { return nextId++; },
  };
  const context = vm.createContext({ $, window, document, layer, console, bt: {},
    setTimeout() { return nextId++; }, clearTimeout() {}, MutationObserver: class { observe() {} disconnect() {} },
  });
  vm.runInContext(source, context, { filename: 'index.html' });
  const waf = context.free_waf;
  waf.render_download_link = (content, filename) => downloads.push({ content: JSON.parse(content), filename });
  return { $, waf, bindings, requests, dialogs, messages, downloads,
    of(method) { return requests.filter(r => r.method === method); },
    fire(selector, event = 'click', attrs = {}) {
      Object.assign(node(selector).values, attrs);
      const found = bindings.filter(b => b.event.split('.')[0] === event &&
        (b.key === selector || (b.delegated || '').split(',').map(s => s.trim()).includes(selector)));
      assert.ok(found.length, 'missing binding: ' + event + ' ' + selector);
      for (const b of found) b.callback.call(node(selector), { preventDefault() {}, stopPropagation() {} });
    },
    open(view) {
      waf.refresh_data_total(view === 'search' ? 'ipstats' : 'history');
      if (view === 'search') waf.render_report_search();
    },
  };
}

const views = {
  search: { method: 'get_report_search', prefix: '#report_search', table: '#report_search_tbody', status: '#report_search_summary', limit: 50, render: 'render_report_search' },
  history: { method: 'get_blockade_records', prefix: '#history_detail', table: '#history_detail_table', status: '#history_detail_status', limit: 100, render: 'render_blockade_records' },
};
function payload(p = 1, limit = 50, extra = {}) {
  return { rows: [{ time: '2026-10-26 10:00:00', site: 'fixture.example', ip: '192.0.2.1', uri: '/page-' + p,
    user_agent: 'fixture', rule_type: 'cc', start_time_text: '2026-10-26', reason: 'cc', duration: 60, active: true }],
  total: p * limit + 1, p, limit, has_more: true, total_exact: false,
  coverage: { partial: true, scanned_lines: 123 }, ...extra };
}
function latest(h, v) { return h.of(v.method).at(-1); }

for (const [view, v] of Object.entries(views)) {
  test(view + ': real controls paginate once, respect has_more, and return to previous page', () => {
    const h = harness(); h.open(view);
    assert.equal(latest(h, v).options.data.p, 1);
    latest(h, v).resolve(payload(1, v.limit));
    const count = h.of(v.method).length;
    h.fire(v.prefix + '_next'); h.fire(v.prefix + '_next');
    assert.equal(h.of(v.method).length, count + 1, 'no double click or automatic draining');
    assert.equal(latest(h, v).options.data.p, 2);
    latest(h, v).resolve(payload(2, v.limit, { has_more: false }));
    assert.match(h.$(v.prefix + '_page_info').text(), /2/);
    assert.equal(h.$(v.prefix + '_next').prop('disabled'), true);
    h.fire(v.prefix + '_next');
    assert.equal(h.of(v.method).length, count + 1);
    h.fire(v.prefix + '_prev');
    assert.equal(latest(h, v).options.data.p, 1);
  });

  test(view + ': page size change resets page and rejects an older response and error', () => {
    const h = harness(); h.open(view); latest(h, v).resolve(payload(1, v.limit));
    h.fire(v.prefix + '_next'); const old = latest(h, v);
    h.$(v.prefix + '_limit').val('10'); h.fire(v.prefix + '_limit', 'change');
    const current = latest(h, v);
    assert.equal(current.options.data.p, 1); assert.equal(current.options.data.limit, 10);
    current.resolve(payload(1, 10, { rows: [{ uri: '/new-size' }] }));
    const status = h.$(v.status).text(), table = h.$(v.table).html();
    old.late(payload(2, v.limit)); old.lateError();
    assert.equal(h.$(v.status).text(), status); assert.equal(h.$(v.table).html(), table);
    assert.equal(h.$(v.prefix + '_next').prop('disabled'), false);
  });

  for (const failure of ['timeout', 'status-false', 'missing', 'bad-rows', 'bad-total', 'wrong-page', 'wrong-limit', 'null-row']) {
    test(view + ': ' + failure + ' is a read failure, never empty success', () => {
      const h = harness(); h.open(view);
      const bad = {
        'status-false': { status: false, msg: 'fixture failure' }, missing: {},
        'bad-rows': payload(1, v.limit, { rows: {} }), 'bad-total': payload(1, v.limit, { total: 'unknown' }),
        'wrong-page': payload(99, v.limit), 'wrong-limit': payload(1, 999),
        'null-row': payload(1, v.limit, { rows: [null] }),
      };
      if (failure === 'timeout') latest(h, v).reject(); else latest(h, v).resolve(bad[failure]);
      assert.match(h.$(v.status).text(), /\u8bfb\u53d6\u5931\u8d25/);
      assert.match(h.$(v.table).html(), /\u5931\u8d25/);
      assert.doesNotMatch(h.$(v.table).html(), /\u6682\u65e0|\u6ca1\u6709\u5339\u914d/);
      assert.equal(h.$(v.prefix + '_next').prop('disabled'), true);
      if (view === 'search') assert.equal(h.waf._report_search_rows.length, 0);
      else assert.equal(h.$('#history_export').prop('disabled'), true);
    });
  }

  test(view + ': partial empty response keeps coverage and never asserts a complete total', () => {
    const h = harness(); h.open(view);
    latest(h, v).resolve(payload(1, v.limit, { rows: [], total: 0, has_more: false }));
    assert.match(h.$(v.status).text(), /\u4e0d\u4ee3\u8868\u5168\u91cf/);
    assert.match(h.$(v.status).text(), /123/);
    assert.match(h.$(v.table).html(), /\u8303\u56f4/);
    assert.equal(h.$(v.prefix + '_next').prop('disabled'), true);
  });

  for (const leave of ['navigate', 'destroy', 'detach']) test(view + ': ' + leave + ' rejects queued success and failure', () => {
    const h = harness(); h.open(view); const pending = latest(h, v);
    if (leave === 'navigate') h.waf.refresh_data_total('overall');
    else if (leave === 'destroy') h.waf.destroy();
    else h.waf.$root[0].isConnected = false;
    h.$(v.table).html('new owner'); h.$(v.status).text('new status');
    pending.late(payload(1, v.limit)); pending.lateError();
    assert.equal(h.$(v.table).html(), 'new owner'); assert.equal(h.$(v.status).text(), 'new status');
    if (leave !== 'detach') assert.equal(pending.aborted, true);
  });

  test(view + ': refresh supersedes an in-flight read even on the same page', () => {
    const h = harness(); h.open(view); const old = latest(h, v);
    h.fire(view === 'search' ? '#report_search_refresh' : '#history_detail_refresh');
    const current = latest(h, v); assert.notEqual(old, current);
    current.resolve(payload(1, v.limit, { rows: [{ uri: '/fresh' }] }));
    old.late(payload(1, v.limit)); old.lateError();
    assert.match(h.$(v.table).html(), /\/fresh/);
  });

  test(view + ': empty page after log shrink still allows returning, without automatic fetching', () => {
    const h = harness(); h.open(view); latest(h, v).resolve(payload(1, v.limit));
    h.fire(v.prefix + '_next');
    const count = h.of(v.method).length;
    latest(h, v).resolve(payload(2, v.limit, { rows: [], total: 0, has_more: false }));
    assert.equal(h.of(v.method).length, count);
    assert.equal(h.$(v.prefix + '_prev').prop('disabled'), false);
    h.fire(v.prefix + '_prev'); assert.equal(latest(h, v).options.data.p, 1);
  });

  test(view + ': failed second page can be retried or left using previous page', () => {
    const h = harness(); h.open(view); latest(h, v).resolve(payload(1, v.limit));
    h.fire(v.prefix + '_next'); latest(h, v).reject();
    assert.equal(h.$(v.prefix + '_prev').prop('disabled'), false);
    h.fire(view === 'search' ? '#report_search_refresh' : '#history_detail_refresh');
    assert.equal(latest(h, v).options.data.p, 2); latest(h, v).reject();
    h.fire(v.prefix + '_prev'); assert.equal(latest(h, v).options.data.p, 1);
  });

  test(view + ': exact totals and HTML-like data are safe, missing coverage stays unknown', () => {
    const h = harness(); h.open(view);
    latest(h, v).resolve(payload(1, v.limit, { rows: [{ uri: '<script>bad</script>' }], total: 1,
      total_exact: true, has_more: false, coverage: { partial: false } }));
    assert.doesNotMatch(h.$(v.status).text(), /\u975e\u7cbe\u786e/);
    assert.match(h.$(v.table).html(), /&lt;script&gt;/); assert.doesNotMatch(h.$(v.table).html(), /<script>/);
    h.waf[v.render](); latest(h, v).resolve(payload(1, v.limit, { coverage: undefined, total_exact: true, has_more: false }));
    assert.match(h.$(v.status).text(), /\u8303\u56f4\u672a\u63d0\u4f9b/);
    assert.match(h.$(v.status).text(), /\u975e\u7cbe\u786e/);
  });
}

for (const field of ['days', 'site', 'type', 'ip', 'uri', 'keyword']) test('search: editing ' + field + ' resets page and invalidates pending rows immediately', () => {
  const h = harness(), v = views.search; h.open('search'); latest(h, v).resolve(payload());
  h.fire('#report_search_next'); const old = latest(h, v);
  h.$('#report_search_' + field).val(field === 'days' ? '3' : 'changed');
  h.fire('#report_search_' + field, field === 'days' ? 'change' : 'input');
  old.late(payload(2)); old.lateError();
  assert.doesNotMatch(h.$(v.table).html(), /\/page-2/);
  assert.equal(h.waf._report_search_rows.length, 0);
  h.fire('#report_search_refresh');
  assert.equal(latest(h, v).options.data.p, 1);
});

test('search: programmatic filter change also resets page before a new query', () => {
  const h = harness(), v = views.search; h.open('search'); latest(h, v).resolve(payload());
  h.fire('#report_search_next'); latest(h, v).resolve(payload(2));
  h.$('#report_search_keyword').val('new'); h.waf.render_report_search();
  assert.equal(latest(h, v).options.data.p, 1);
  assert.equal(latest(h, v).options.data.keyword, 'new');
});

test('history: export requests only the current page with an explicit scope', () => {
  const h = harness(), v = views.history; h.open('history'); latest(h, v).resolve(payload(1, 100));
  h.fire('#history_detail_next'); latest(h, v).resolve(payload(2, 100));
  const count = h.of(v.method).length;
  h.fire('#history_export'); h.fire('#history_export');
  const exports = h.of('export_blockade_records');
  assert.equal(exports.length, 1);
  assert.equal(exports[0].options.data.p, 2); assert.equal(exports[0].options.data.limit, 100);
  exports[0].resolve({ records: [{ uri: '/exported' }], total: 201, total_exact: false, coverage: { partial: true } });
  assert.equal(h.downloads.length, 1);
  assert.equal(h.downloads[0].content.p, 2); assert.equal(h.downloads[0].content.limit, 100);
  assert.equal(h.downloads[0].content.export_scope, 'current_page');
  assert.match(h.downloads[0].filename, /page_2/);
  assert.equal(h.of(v.method).length, count, 'export must not scan other pages');
});

for (const failure of ['timeout', 'malformed', 'status-false']) test('history: export ' + failure + ' never downloads a fake empty file', () => {
  const h = harness(), v = views.history; h.open('history'); latest(h, v).resolve(payload(1, 100)); h.fire('#history_export');
  const request = h.of('export_blockade_records').at(-1);
  if (failure === 'timeout') request.reject();
  else request.resolve(failure === 'malformed' ? {} : { status: false, msg: 'disabled' });
  assert.equal(h.downloads.length, 0);
  assert.match(h.$(v.status).text(), /\u5bfc\u51fa\u5931\u8d25/);
  assert.equal(h.$('#history_export').prop('disabled'), false);
});

for (const change of ['page', 'leave', 'destroy']) test('history: ' + change + ' invalidates a queued export', () => {
  const h = harness(), v = views.history; h.open('history'); latest(h, v).resolve(payload(1, 100)); h.fire('#history_export');
  const old = h.of('export_blockade_records').at(-1);
  if (change === 'page') h.fire('#history_detail_next');
  else if (change === 'leave') h.waf.refresh_data_total('overall');
  else h.waf.destroy();
  old.late({ records: [], total: 0 }); old.lateError();
  assert.equal(h.downloads.length, 0);
});

test('search: request summary says it is not raw HTTP and escapes the stored log', () => {
  const h = harness(); h.open('search'); latest(h, views.search).resolve(payload());
  h.fire('.report_http_detail', 'click', { 'data-index': '0' });
  h.of('get_report_http_detail').at(-1).resolve({ data: { uri: '<img src=x>', offset: 0 }, raw: '<script>bad</script>' });
  const dialog = h.dialogs.at(-1);
  assert.equal(dialog.title, '\u8bf7\u6c42\u6458\u8981');
  assert.match(dialog.content, /\u975e\u5b8c\u6574 HTTP \u539f\u6587/);
  assert.match(dialog.content, /&lt;script&gt;/); assert.doesNotMatch(dialog.content, /<script>|<img/);
});

test('search: changed filters invalidate a pending summary dialog', () => {
  const h = harness(); h.open('search'); latest(h, views.search).resolve(payload());
  h.fire('.report_http_detail', 'click', { 'data-index': '0' }); const old = h.of('get_report_http_detail').at(-1);
  const count = h.dialogs.length;
  h.$('#report_search_ip').val('192.0.2.2'); h.fire('#report_search_ip', 'input');
  old.late({ data: { uri: '/old-detail' } }); old.lateError();
  assert.equal(h.dialogs.length, count);
});

test('search: choosing a different summary rejects a queued earlier detail response', () => {
  const h = harness(); h.open('search'); latest(h, views.search).resolve(payload());
  h.waf.show_report_http_detail({ site: 'fixture.example', offset: 1 }); const old = h.of('get_report_http_detail').at(-1);
  h.waf.show_report_http_detail({ site: 'fixture.example', offset: 2 });
  const current = h.of('get_report_http_detail').at(-1), count = h.dialogs.length;
  current.resolve({ data: { uri: '/new-detail' } }); old.late({ data: { uri: '/old-detail' } }); old.lateError();
  assert.equal(h.dialogs.length, count + 1);
  assert.match(h.dialogs.at(-1).content, /\/new-detail/);
});

test('history: malformed active flag is not presented as an active IP ban', () => {
  const h = harness(); h.open('history'); latest(h, views.history).resolve(payload(1, 100, { rows: [{ active: 'false' }] }));
  assert.match(h.$('#history_detail_status').text(), /\u8bfb\u53d6\u5931\u8d25/);
});

test('history: malformed export rows are not downloaded', () => {
  const h = harness(); h.open('history'); latest(h, views.history).resolve(payload(1, 100));
  h.fire('#history_export'); h.of('export_blockade_records').at(-1).resolve({ records: [null], total: 1 });
  assert.equal(h.downloads.length, 0);
  assert.match(h.$('#history_detail_status').text(), /\u5bfc\u51fa\u5931\u8d25/);
});

test('controls: pagination uses root-scoped namespaced events and bounded sizes', () => {
  const h = harness();
  for (const [view, v] of Object.entries(views)) {
    for (const suffix of ['prev', 'next', 'limit']) {
      const id = v.prefix.slice(1) + '_' + suffix;
      assert.ok(html.includes('id="' + id + '"'));
      const bound = h.bindings.filter(b => (b.delegated || '').split(',').map(s => s.trim()).includes('#' + id));
      assert.equal(bound.length, 1);
      assert.match(bound[0].event, /\.free_waf$/);
      assert.equal(bound[0].key, h.waf.$root[0].key);
    }
    const select = html.match(new RegExp('<select id="' + v.prefix.slice(1) + '_limit">([\\s\\S]*?)</select>'))[1];
    const sizes = [...select.matchAll(/value="(\d+)"/g)].map(m => Number(m[1]));
    assert.deepEqual(sizes, view === 'search' ? [10, 50, 100, 200] : [10, 50, 100, 200, 500]);
  }
  for (const event of ['input', 'change']) {
    const bound = h.bindings.filter(b => b.event.split('.')[0] === event && (b.delegated || '').includes('#report_search_keyword'));
    assert.equal(bound.length, 1); assert.match(bound[0].event, /\.free_waf$/);
  }
});

test('copy: actual request order and double switches are explicit, old cloud sync is disabled', () => {
  assert.match(html, /IP\u767d\u540d\u5355 > \u91cd\u590d\u5c01\u7981\u5347\u7ea7 > \u6ce8\u518c\u6ee5\u7528\u9632\u62a4 > \u6d3b\u52a8\u5c01\u7981 > IP\u9ed1\u540d\u5355 > UA\u767d\u540d\u5355 > URL\u767d\u540d\u5355/);
  assert.match(html, /\u5168\u5c40\u4e0e\u7ad9\u70b9\u5f00\u5173\u9700\u540c\u65f6\u5f00\u542f/);
  assert.match(html, /\u65e7\u4e91\u7aef\u89c4\u5219\u540c\u6b65\u5df2\u505c\u7528/);
  assert.doesNotMatch(html, /\u5168\u5c40\u8bbe\u7f6e\u4f1a\u81ea\u52a8\u4f5c\u4e3a\u9ed8\u8ba4\u503c|\u4ee5\u4e0a\u662f\u529f\u80fd\u53c2\u8003\u987a\u5e8f/);
  assert.match(html, /id="history_export"[^>]*>\u5bfc\u51fa\u5c01\u7981\u8bb0\u5f55\uff08\u5f53\u524d\u9875\uff09/);
});

for (const invalid of ['0', '-1', '1.5', '61', '300', 'abc', '']) test('CC: invalid short ban ' + JSON.stringify(invalid) + ' is rejected without rewriting defaults', () => {
  const h = harness(); h.waf.set_cc_rule_view({ cc_cycle: 60, cc_limit: 80, cc_endtime: 300 });
  const dialog = h.dialogs.at(-1);
  assert.match(dialog.content, /name="cc_endtime"[^>]*value="300"/);
  assert.match(dialog.content, /name="cc_endtime"[^>]*min="1"[^>]*max="60"/);
  assert.match(dialog.content, /1-60/);
  h.$('[name="cc_cycle"]').val('60'); h.$('[name="cc_limit"]').val('80'); h.$('[name="cc_endtime"]').val(invalid);
  dialog.yes(); assert.equal(h.of('set_cc_conf').length, 0);
});

test('CC: valid short ban still saves the original threshold values', () => {
  const h = harness(); h.waf.set_cc_rule_view({ cc_cycle: 60, cc_limit: 80, cc_endtime: 60 });
  const dialog = h.dialogs.at(-1);
  h.$('[name="cc_cycle"]').val('60'); h.$('[name="cc_limit"]').val('80'); h.$('[name="cc_endtime"]').val('60');
  dialog.yes(); const data = h.of('set_cc_conf').at(-1).options.data;
  assert.equal(data.cycle, '60'); assert.equal(data.limit, '80'); assert.equal(data.endtime, '60');
});

for (const [field, invalid] of [['cc_cycle', '1.5'], ['cc_cycle', '86401'], ['cc_limit', '-1'], ['cc_limit', '1000001']]) {
  test('CC: rejects invalid ' + field + ' on both dialog actions', () => {
    const h = harness(); h.waf.set_cc_rule_view({ cc_cycle: 60, cc_limit: 80, cc_endtime: 60 });
    const dialog = h.dialogs.at(-1);
    for (const action of ['yes', 'btn2']) {
      h.$('[name="cc_cycle"]').val('60'); h.$('[name="cc_limit"]').val('80'); h.$('[name="cc_endtime"]').val('60');
      h.$('[name="' + field + '"]').val(invalid); dialog[action]();
    }
    assert.equal(h.of('set_cc_conf').length, 0);
  });
}

test('history: flat IP activity never claims this historical row or site is still enforced', () => {
  const h = harness(), v = views.history; h.open('history'); latest(h, v).resolve(payload(1, 100));
  assert.match(h.$(v.table).html(), /IP\u6709\u5c01\u7981/);
  assert.doesNotMatch(h.$(v.table).html(), /\u5c01\u7981\u4e2d|\u5df2\u7ed3\u675f/);
  assert.match(h.$(v.status).text(), /\u4e0d\u786e\u8ba4\u8be5\u5386\u53f2\u8bb0\u5f55\u6216\u672c\u7ad9\u70b9\u4ecd\u5728\u6267\u884c/);
});

test('copy: URL allowlist cannot bypass earlier IP blocks, and disabled sync never connects', () => {
  assert.doesNotMatch(html, /URL \u767d\u540d\u5355\u7684\u8def\u5f84[^<]*\u5305\u62ec IP \u9ed1\u540d\u5355/);
  const h = harness(), calls = [];
  h.waf.update_overall_rule(res => calls.push(res));
  assert.equal(h.of('sync_rule').length, 0);
  assert.equal(calls[0].status, false);
});

for (const [view, v] of Object.entries(views)) test(view + ': backend escaped fields render as text without double encoding', () => {
  const h = harness(); h.open(view);
  latest(h, v).resolve(payload(1, v.limit, { rows: [{ uri: '/save?x=&lt;img&gt;&amp;y=1',
    site: 'fixture.example', rule_type: 'cc', reason: '&lt;tag&gt;', active: true }] }));
  const table = h.$(v.table).html();
  assert.ok(table.includes('/save?x=&lt;img&gt;&amp;y=1'));
  assert.doesNotMatch(table, /<img|&amp;lt;|&amp;gt;/);
});

test('request summary decodes backend entities once then safely escapes markup', () => {
  const h = harness(); h.open('search'); latest(h, views.search).resolve(payload());
  h.waf.show_report_http_detail({site: 'fixture.example', date: '2026-10-26', offset: 0});
  h.of('get_report_http_detail').at(-1).resolve({status: true, data: {uri: '/&lt;img&gt;?x=1&amp;y=2'},
    raw: '[&quot;&lt;script&gt;&quot;]'});
  const content = h.dialogs.at(-1).content;
  assert.ok(content.includes('/&lt;img&gt;?x=1&amp;y=2'));
  assert.ok(content.includes('[&quot;&lt;script&gt;&quot;]'));
  assert.doesNotMatch(content, /<img|<script|&amp;lt;|&amp;quot;/);
});
