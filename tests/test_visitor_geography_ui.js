'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { harness, report, html } = require('./test_statistics_v011');

const counts = (clients, requests, bytes, errors = 0) => ({ clients, requests, bytes, errors });
function geography(extra = {}) {
  return {
    schema_version: 1, site: '', database_available: true, lookup_complete: true,
    partial: false, reasons: [], totals: counts(9, 42, 15000, 3),
    located: counts(6, 30, 12000, 2), unlocated: counts(3, 12, 3000, 1), private: counts(1, 4, 1000),
    countries: [
      { code: 'CN', name: 'China', ...counts(4, 10, 4000, 1), active_days: 2,
        trend: [{ label: '10-21', time: 1792540800, ...counts(2, 6, 2500) }, { label: '10-22', time: 1792627200, ...counts(3, 4, 1500, 1) }] },
      { code: 'US', name: 'United States', ...counts(2, 20, 8000, 1), active_days: 1,
        trend: [{ label: '<12:00>', time: 1792670400, ...counts(2, 20, 8000, 1) }] },
    ],
    regions: [
      { country_code: 'CN', country_name: 'China', region_code: 'ZJ', region_name: '浙江', ...counts(3, 7, 2000), active_days: 2 },
      { country_code: 'CN', country_name: 'China', region_code: '', region_name: '', ...counts(1, 3, 2000, 1), active_days: 1 },
      { country_code: 'US', country_name: 'United States', region_code: 'CA', region_name: '加利福尼亚', ...counts(2, 20, 8000, 1), active_days: 1 },
    ],
    cities: [
      { country_code: 'CN', country_name: 'China', region_code: 'ZJ', region_name: '浙江', city_name: '杭州', ...counts(3, 7, 2000), active_days: 2 },
      { country_code: 'CN', country_name: 'China', region_code: '', region_name: '', city_name: '', ...counts(1, 3, 2000, 1), active_days: 1 },
      { country_code: 'US', country_name: 'United States', region_code: 'CA', region_name: '加利福尼亚', city_name: '洛杉矶', ...counts(2, 20, 8000, 1), active_days: 1 },
    ],
    regions_truncated: false, cities_truncated: false, ...extra,
  };
}
const world = { type: 'FeatureCollection', features: ['United States', 'China', 'Russian'].map(name => ({ properties: { name }, geometry: {} })) };
function chartEngine(h) {
  const charts = [];
  h.context.window.__free_waf_world = world;
  h.context.window.echarts = {
    getMap() { return true; }, registerMap() {},
    init(node) {
      const chart = { node, options: [], handlers: {}, disposed: false, resizes: 0,
        setOption(option) { this.options.push(option); },
        on(event, callback) { this.handlers[event] = callback; },
        off(event) { delete this.handlers[event]; },
        resize() { this.resizes++; }, dispose() { this.disposed = true; },
      };
      charts.push(chart); return chart;
    },
  };
  return charts;
}
function open(h, geo = geography(), extra = {}) {
  h.navigate('statistics');
  h.stats().at(-1).resolve(report({ geography: geo, ...extra }));
  h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'geography' });
}
function metric(h, value) { h.$('#website_stats_geo_metric').val(value); h.fire('#website_stats_geo_metric', 'change'); }
function country(h, value) { h.$('#website_stats_geo_country').val(value); h.fire('#website_stats_geo_country', 'change'); }
function assets(h) { return h.requests.filter(request => request.options.url.startsWith('/static/')); }

function panelMaps(h) {
  const charts = chartEngine(h), maps = new Map(), modules = [];
  h.waf._trend_chart = { setOption() {}, resize() {}, dispose() {} };
  delete h.context.window.__free_waf_world;
  h.context.window.echarts.getMap = name => maps.get(name);
  h.context.window.echarts.registerMap = (name, geoJSON) => maps.set(name, { geoJSON });
  h.waf.world_map_module = () => new Promise((resolve, reject) => modules.push({ resolve, reject }));
  return { charts, maps, modules };
}

test('registered panel maps are reused for overview and visitors without loading assets', () => {
  for (const field of ['geoJSON', 'geoJson']) {
    const h = harness(), panel = panelMaps(h);
    panel.maps.set('world', { [field]: world });
    h.of('get_overview_report')[0].resolve({ summary: {}, trend: [], attack_geography: { countries: [{ code: 'CN', count: 4 }] } });
    assert.equal(h.context.window.__free_waf_world, world);
    assert.equal(h.waf._map_model.data.find(row => row.name === 'China').value, 4);
    open(h);
    assert.equal(panel.modules.length, 0);
    assert.equal(assets(h).length, 0);
    assert.ok(panel.charts.some(chart => chart.node.key === '#website_stats_geo_map'));
  }
});

test('panel12 default-export geometry loads lazily and is shared with the overview', async () => {
  const h = harness(), panel = panelMaps(h);
  h.navigate('statistics'); h.stats().at(-1).resolve(report({ geography: geography() }));
  assert.equal(panel.modules.length, 0);
  h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'geography' });
  assert.equal(panel.modules.length, 1);
  metric(h, 'requests'); country(h, 'CN');
  assert.equal(panel.modules.length, 1, 'do not duplicate an in-flight map load');
  panel.modules[0].resolve({ default: world });
  await Promise.resolve();
  assert.equal(h.context.window.__free_waf_world, world);
  assert.equal(panel.maps.get('free_waf_world_v1').geoJSON, world);
  assert.equal(h.waf._statistics_geo_model.data.find(row => row.code === 'CN').value, 10);
  assert.equal(h.$('#website_stats_geo_retry').prop('hidden'), true);
  h.navigate('home');
  h.waf._trend_chart = { setOption() {}, resize() {}, dispose() {} };
  h.of('get_overview_report').at(-1).resolve({ summary: {}, trend: [], attack_geography: { countries: [{ code: 'CN', count: 2 }] } });
  assert.equal(panel.modules.length, 1);
  assert.equal(assets(h).length, 0);
});

test('overview loads panel12 geometry and renders the registered map', async () => {
  const h = harness(), panel = panelMaps(h);
  h.of('get_overview_report')[0].resolve({ summary: {}, trend: [], attack_geography: { countries: [{ code: 'CN', count: 2 }] } });
  assert.equal(panel.modules.length, 1);
  panel.modules[0].resolve({ default: world });
  await Promise.resolve();
  assert.equal(h.waf._map_model.data.find(row => row.name === 'China').value, 2);
  assert.ok(panel.charts.some(chart => chart.node.key === '#overview_attack_map'));
  assert.equal(assets(h).length, 0);
});

test('module failure falls back to fixed legacy JSON without running response text', async () => {
  const h = harness(), panel = panelMaps(h); open(h);
  assert.equal(panel.modules.length, 1);
  panel.modules[0].reject(Error('module unavailable'));
  await Promise.resolve();
  const fallback = assets(h).at(-1);
  assert.equal(fallback.options.url, '/static/vite/data/world.json');
  assert.equal(fallback.options.dataType, 'json');
  fallback.resolve(world);
  assert.equal(h.context.window.__free_waf_world, world);
  assert.equal(h.$('#website_stats_geo_retry').prop('hidden'), true);
});

test('invalid module and legacy geometry fail once and retry only on demand', async () => {
  const h = harness(), panel = panelMaps(h); open(h);
  assert.equal(panel.modules.length, 1);
  panel.modules[0].resolve({ default: { features: [] } });
  await Promise.resolve();
  assets(h).at(-1).resolve({ features: [] });
  assert.equal(h.$('#website_stats_geo_retry').prop('hidden'), false);
  metric(h, 'bytes'); country(h, 'CN');
  assert.equal(panel.modules.length, 1);
  assert.equal(assets(h).length, 1);
  h.fire('#website_stats_geo_retry');
  assert.equal(panel.modules.length, 2);
  assert.equal(h.stats().length, 1);
});

test('module timeout stops loading and ignores late geometry', async () => {
  const h = harness(), panel = panelMaps(h); open(h);
  assert.equal(panel.modules.length, 1);
  h.tick(12000);
  assert.equal(h.$('#website_stats_geo_retry').prop('hidden'), false);
  const before = panel.charts.length;
  panel.modules[0].resolve({ default: world });
  await Promise.resolve();
  assert.equal(h.context.window.__free_waf_world, undefined);
  assert.equal(panel.charts.length, before);
});

for (const exit of ['tab', 'leave', 'close', 'reinit', 'reload']) {
  test(exit + ' ignores late panel12 module completion', async () => {
    const h = harness(), panel = panelMaps(h); open(h);
    assert.equal(panel.modules.length, 1);
    if (exit === 'tab') h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'clients' });
    if (exit === 'leave') h.navigate('home');
    if (exit === 'close') h.close();
    if (exit === 'reinit') h.waf.init();
    if (exit === 'reload') h.reload();
    const status = h.$('#website_stats_geo_map_status').text();
    panel.modules[0].resolve({ default: world });
    await Promise.resolve();
    assert.equal(h.context.window.__free_waf_world, undefined);
    assert.equal(h.$('#website_stats_geo_map_status').text(), status);
    assert.equal(assets(h).length, 0);
  });
}

test('geography is the eighth Chinese tab, responsive and honest about IP/log coverage', () => {
  const version = require('../info.json').versions;
  assert.equal(html.match(/class="waf_conter"[^>]*data-version="([^"]+)"/)[1], version);
  const tabs = [...html.matchAll(/class="website_stats_tab[^\"]*"[^>]*data-stats-page="([^"]+)"/g)].map(match => match[1]);
  assert.equal(tabs.length, 8); assert.equal(tabs.at(-1), 'geography');
  for (const text of ['访客地域', '独立 IP 不是人数', '网络出口', '机器人', 'API', '本地日志', '省份', '城市']) assert.ok(html.includes(text), text);
  assert.match(html, /id="website_stats_geo_metric"[\s\S]*?value="clients"[\s\S]*?value="requests"[\s\S]*?value="bytes"/);
  assert.match(html, /\.website_geo_layout\s*\{[^}]*grid-template-columns/);
  assert.match(html, /@media[^}]*720px[\s\S]*?\.website_geo_layout\s*\{[^}]*grid-template-columns:1fr/);
  assert.doesNotMatch(html, /<(?:script|link)[^>]+(?:src|href)=["']https?:/);
});

test('first paint still has exactly two reads; geography does not load until explicit tab entry', () => {
  const h = harness();
  assert.deepEqual(h.requests.map(request => request.method), ['get_total_all', 'get_overview_report']);
  h.navigate('statistics'); h.stats().at(-1).resolve(report({ geography: geography() }));
  assert.equal(assets(h).length, 0);
  h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'geography' });
  assert.equal(assets(h).length, 1);
  assert.equal(assets(h)[0].options.url, '/static/js/echarts.min.js');
  assert.equal(assets(h)[0].options.timeout, 12000);
});

test('visitor model ranks actual independent IPs by default without summing daily IPs', () => {
  const h = harness(), geo = geography(), original = JSON.stringify(geo);
  const model = h.context.waf_dashboard.visitorGeography(geo, world);
  assert.equal(model.available, true); assert.equal(model.metric, 'clients');
  assert.deepEqual(Array.from(model.countries, row => row.code), ['CN', 'US']);
  assert.equal(model.countries[0].value, 4);
  assert.equal(model.data.find(row => row.name === 'China').value, 4);
  assert.equal(model.data.find(row => row.name === 'China').code, 'CN');
  assert.equal(model.totals.clients, 9); assert.equal(model.unlocated.clients, 3); assert.equal(model.private.clients, 1);
  assert.equal(model.countries[0].name, '中国');
  assert.equal(JSON.stringify(geo), original);
});

test('metrics rank cached countries and map values without changing server aggregates', () => {
  const h = harness(), geo = geography();
  for (const [value, first, amount] of [['clients', 'CN', 4], ['requests', 'US', 20], ['bytes', 'US', 8000]]) {
    const model = h.context.waf_dashboard.visitorGeography(geo, world, value);
    assert.equal(model.countries[0].code, first); assert.equal(model.countries[0].value, amount);
  }
  assert.equal(h.context.waf_dashboard.visitorGeography(geo, world, 'engagement').metric, 'clients');
});

test('cached tab, metric, country select and rank interactions never rescan or call backend', () => {
  const h = harness(); const charts = chartEngine(h); open(h);
  assert.match(h.$('#website_stats_geo_country_table').html(), /中国[\s\S]*美国/);
  const before = h.requests.length;
  metric(h, 'requests');
  assert.match(h.$('#website_stats_geo_country_table').html(), /美国[\s\S]*中国/);
  country(h, 'CN');
  assert.match(h.$('#website_stats_geo_region_table').html(), /浙江/);
  assert.doesNotMatch(h.$('#website_stats_geo_region_table').html(), /加利福尼亚/);
  h.fire('.website_stats_country', 'click', { 'data-country': 'US' });
  assert.equal(h.$('#website_stats_geo_country').val(), 'US');
  assert.match(h.$('#website_stats_geo_city_table').html(), /洛杉矶/);
  assert.doesNotMatch(h.$('#website_stats_geo_city_table').html(), /杭州/);
  metric(h, 'bytes'); country(h, '');
  h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'clients' });
  h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'geography' });
  assert.equal(h.requests.length, before); assert.equal(h.stats().length, 1);
  assert.equal(charts[0].disposed, true);
});

test('country map is green, clickable and uses the selected metric in safe tooltips', () => {
  const h = harness(); const charts = chartEngine(h); open(h);
  const map = charts.find(chart => chart.node.key === '#website_stats_geo_map');
  assert.ok(map); const option = map.options.at(-1);
  assert.equal(option.series[0].type, 'map'); assert.equal(option.series[0].selectedMode, 'single');
  assert.equal(option.series[0].scaleLimit.max, 5);
  assert.match(option.tooltip.formatter({ name: 'China', data: option.series[0].data.find(row => row.code === 'CN') }), /中国[\s\S]*独立 IP[\s\S]*4/);
  assert.doesNotMatch(option.tooltip.formatter({ name: '<img>', data: {} }), /<img>/);
  const click = map.handlers.click; click({ name: 'China', data: { code: 'CN' } });
  assert.equal(h.$('#website_stats_geo_country').val(), 'CN');
  assert.match(h.$('#website_stats_geo_trend_title').text(), /中国.*独立 IP/);
  assert.match(h.$('#website_stats_geo_trend').html(), /<svg[\s\S]*独立 IP 2/);
  const before = h.$('#website_stats_geo_country').val();
  click({ name: 'Russian', data: { code: 'RU' } });
  assert.equal(h.$('#website_stats_geo_country').val(), before, 'unrepresented map areas cannot select invented rows');
  assert.equal(h.stats().length, 1);
});

test('map retry hidden state wins over panel Bootstrap button styles only inside this plugin', () => {
  assert.ok(/\.waf_conter\s+#website_stats_geo_retry\[hidden\]\s*\{\s*display:none!important\s*;?\s*\}/.test(html));
  const h = harness(); chartEngine(h); open(h);
  assert.equal(h.$('#website_stats_geo_retry').prop('hidden'), true);
  h.context.window.echarts.init = () => { throw Error('renderer unavailable'); };
  h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'overview' });
  h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'geography' });
  assert.equal(h.$('#website_stats_geo_retry').prop('hidden'), false);
});

test('country trend switches metric, escapes labels and preserves future gaps', () => {
  const h = harness(); chartEngine(h);
  const geo = geography(); geo.countries[0].trend.push({ label: '<future>', future: true, ...counts(0, 0, 0) });
  open(h, geo); country(h, 'CN'); metric(h, 'bytes');
  assert.match(h.$('#website_stats_geo_trend_title').text(), /中国.*响应体/);
  const svg = h.$('#website_stats_geo_trend').html();
  assert.match(svg, /&lt;future&gt;/); assert.doesNotMatch(svg, /<future>/);
  assert.equal((svg.match(/<circle /g) || []).length, 2);
  country(h, '');
  assert.doesNotMatch(h.$('#website_stats_geo_trend').html(), /polyline/);
  assert.match(h.$('#website_stats_geo_trend').html(), /选择国家/);
});

test('mobile byte trend uses compact axis units while tooltips and request axes keep raw counts', () => {
  const h = harness(); chartEngine(h);
  h.$('#website_stats_geo_trend')[0].clientWidth = 218;
  const axis = svg => svg.match(/<text x="52" y="44"[^>]*>([^<]*)<\/text>/)[1];
  for (const [bytes, label] of [[9876543210, '9.20 GB'], [1048576, '1.00 MB'], [1536, '1.50 KB'], [512, '512 B'], [0, '0 B']]) {
    const geo = geography();
    geo.countries[0].trend = [{ label: '10-21', time: 1792540800, ...counts(2, 9876543210, bytes) }];
    open(h, geo); country(h, 'CN'); metric(h, 'bytes');
    const svg = h.$('#website_stats_geo_trend').html();
    assert.equal(axis(svg), label);
    assert.match(svg, /viewBox="0 0 240 255"/);
    assert.ok(svg.includes('响应体字节 ' + bytes + ' · 错误 0</title>'));
    metric(h, 'requests');
    assert.equal(axis(h.$('#website_stats_geo_trend').html()), '9876543210');
    metric(h, 'clients');
    assert.equal(axis(h.$('#website_stats_geo_trend').html()), '2');
  }
});

test('coverage distinguishes processed logs, lookup gaps, private subset and truncated rankings', () => {
  const h = harness(); chartEngine(h);
  open(h, geography({ lookup_complete: false, partial: true, reasons: ['lookup_budget'], regions_truncated: true, cities_truncated: true }));
  assert.equal(h.$('#website_stats_geo_total').text(), '9');
  assert.equal(h.$('#website_stats_geo_unlocated').text(), '3');
  assert.equal(h.$('#website_stats_geo_private').text(), '1');
  assert.match(h.$('#website_stats_geo_status').text(), /定位.*部分|部分.*定位/);
  assert.match(h.$('#website_stats_geo_status').text(), /本地日志|已处理/);
  assert.match(h.$('#website_stats_geo_status').text(), /定位达到数量或时间预算/);
  assert.match(h.$('#website_stats_geo_details_note').text(), /截断|上限/);
  assert.match(h.$('#website_stats_geo_details_note').text(), /独立 IP[\s\S]*200[\s\S]*500/);
  assert.match(h.$('#website_stats_geo_details_note').text(), /保留[\s\S]*重排[\s\S]*不是全量/);
  assert.match(h.$('#website_stats_geo_region_table').html(), /中国[\s\S]*省份未知/);
  assert.match(h.$('#website_stats_geo_city_table').html(), /中国[\s\S]*城市未知/);
  assert.match(h.$('#website_stats_coverage').text(), /部分/);
});

for (const [name, geo] of [['absent', null], ['old', { countries: [] }], ['future', geography({ schema_version: 2 })], ['malformed', geography({ totals: null })]]) {
  test(name + ' geography is explicitly unavailable, never a fabricated zero', () => {
    const h = harness(); open(h, geo);
    assert.match(h.$('#website_stats_geo_status').text(), /未提供|不可用/);
    assert.equal(h.$('#website_stats_geo_total').text(), '--');
    assert.equal(h.$('#website_stats_geo_metric').prop('disabled'), true);
    assert.doesNotMatch(h.$('#website_stats_geo_country_table').html(), /data-country=/);
    assert.equal(assets(h).length, 0);
  });
}

test('complete lookups do not hide partial log coverage and never infer proxy identity', () => {
  const h = harness(); chartEngine(h); open(h);
  assert.match(h.$('#website_stats_geo_status').text(), /定位.*完成/);
  assert.match(h.$('#website_stats_geo_status').text(), /日志.*部分样本|部分.*日志/);
  assert.doesNotMatch(h.$('#website_stats_geo_status').text(), /全时段完整|已识别真实用户/);
  assert.match(html, /CDN.*代理.*出口/);
});

test('missing database is a bounded fallback, not an endless loader or a zero-location claim', () => {
  const h = harness();
  open(h, geography({ database_available: false, lookup_complete: false, countries: [], regions: [], cities: [], located: counts(0, 0, 0), unlocated: counts(9, 42, 15000, 3) }));
  assert.match(h.$('#website_stats_geo_status').text(), /归属地库不可用/);
  assert.equal(h.$('#website_stats_geo_unlocated').text(), '9');
  assert.equal(assets(h).length, 0);
});

test('empty valid geography is distinct from unavailable and never requests unnecessary assets', () => {
  const h = harness();
  open(h, geography({ totals: counts(0, 0, 0), located: counts(0, 0, 0), unlocated: counts(0, 0, 0), private: counts(0, 0, 0), countries: [], regions: [], cities: [] }));
  assert.match(h.$('#website_stats_geo_country_table').html(), /暂无可定位/);
  assert.equal(h.$('#website_stats_geo_total').text(), '0');
  assert.equal(assets(h).length, 0);
});

test('all country rows remain discoverable including below rank six and absent map geometry', () => {
  const h = harness(); chartEngine(h);
  const rows = ['US', 'CN', 'GB', 'DE', 'JP', 'RU', 'SG', 'HK'].map((code, i) => ({ code, name: code, ...counts(20 - i, 20 - i, 20 - i), active_days: 1, trend: [] }));
  open(h, geography({ countries: rows }));
  assert.equal((h.$('#website_stats_geo_country_table').html().match(/data-country=/g) || []).length, 8);
  assert.match(h.$('#website_stats_geo_country').html(), /中国香港/);
  assert.match(h.$('#website_stats_geo_map_status').text(), /底图/);
  country(h, 'HK'); assert.match(h.$('#website_stats_geo_trend_title').text(), /中国香港/);
});

test('raw region names, country evidence, reasons and attributes are escaped without mutation', () => {
  const h = harness(); chartEngine(h); const geo = geography();
  geo.regions[0].region_name = '<img src=x onerror="x">&';
  geo.cities[0].city_name = '"><svg onload="x">'; geo.reasons = ['<unsafe>'];
  const original = JSON.stringify(geo); open(h, geo); country(h, 'CN');
  assert.match(h.$('#website_stats_geo_region_table').html(), /&lt;img/);
  assert.match(h.$('#website_stats_geo_city_table').html(), /&quot;&gt;&lt;svg/);
  assert.doesNotMatch(h.$('#website_stats_geo_city_table').html(), /<svg|&amp;quot;/);
  assert.equal(JSON.stringify(geo), original);
});

test('asset failure is bounded; only explicit local map retry reloads resources, never statistics', async () => {
  const h = harness(), modules = [];
  h.waf.world_map_module = () => new Promise((resolve, reject) => modules.push({ resolve, reject }));
  open(h); const asset = assets(h)[0]; assert.ok(asset); asset.reject();
  assert.match(h.$('#website_stats_geo_map_status').text(), /不可用|失败/);
  const before = h.requests.length;
  for (let i = 0; i < 3; i++) { metric(h, i % 2 ? 'bytes' : 'requests'); country(h, 'CN'); }
  assert.equal(h.requests.length, before);
  h.fire('#website_stats_geo_retry');
  assert.equal(assets(h).length, 2); assert.equal(h.stats().length, 1);
  h.context.window.echarts = { init() { throw Error('invalid renderer'); } };
  assets(h).at(-1).resolve('');
  assert.equal(modules.length, 1);
  modules[0].reject(Error('module unavailable'));
  await Promise.resolve();
  assert.equal(assets(h).length, 3); assert.equal(assets(h).at(-1).options.url, '/static/vite/data/world.json');
  assets(h).at(-1).resolve({ features: [] });
  assert.match(h.$('#website_stats_geo_map_status').text(), /不可用|失败/);
});

for (const exit of ['tab', 'leave', 'close', 'reinit', 'reload']) {
  test(exit + ' aborts geography assets and rejects forced late callbacks', () => {
    const h = harness(); open(h); const request = assets(h)[0]; assert.ok(request);
    if (exit === 'tab') h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'clients' });
    if (exit === 'leave') h.navigate('home');
    if (exit === 'close') h.close();
    if (exit === 'reinit') h.waf.init();
    if (exit === 'reload') h.reload();
    assert.equal(request.aborted, true);
    const before = h.requests.length, status = h.$('#website_stats_geo_map_status').text();
    request.options.success(''); request.options.error(request, 'timeout'); request.options.complete?.(request);
    assert.equal(h.requests.length, before); assert.equal(h.$('#website_stats_geo_map_status').text(), status);
  });
}

test('site/time changes clear map, country and details; stale A-B-A results cannot leak sites', () => {
  const h = harness(); const charts = chartEngine(h); open(h); country(h, 'CN');
  const click = charts[0].handlers.click;
  h.$('#website_stats_site_filter').val('B'); h.fire('#website_stats_site_filter', 'change'); const b = h.stats().at(-1);
  assert.equal(charts[0].disposed, true);
  assert.equal(h.$('#website_stats_geo_country').val(), '');
  assert.doesNotMatch(h.$('#website_stats_geo_region_table').html(), /浙江/);
  assert.equal(h.$('#website_stats_geo_total').text(), '--');
  h.$('#website_stats_site_filter').val(''); h.$('#website_stats_days').val('1'); h.fire('#website_stats_days', 'change');
  h.stats().at(-1).resolve(report({ geography: geography() }));
  const before = h.$('#website_stats_geo_country_table').html();
  b.options.success(report({ geography: geography({ site: 'B', countries: [] }) }));
  click({ data: { code: 'US' }, name: 'United States' });
  assert.equal(h.$('#website_stats_geo_country_table').html(), before);
  assert.equal(h.$('#website_stats_geo_country').val(), '');
  assert.match(h.$('#website_stats_status').text(), /今日/);
});

test('mismatched geography scope is unavailable even if the top-level response is current', () => {
  const h = harness(); chartEngine(h); open(h, geography({ site: 'different.example' }));
  assert.match(h.$('#website_stats_geo_status').text(), /范围不匹配|站点不匹配/);
  assert.equal(h.$('#website_stats_geo_total').text(), '--');
});

test('map instances are disposed on tab exit and late map clicks cannot change another view', () => {
  const h = harness(); const charts = chartEngine(h); open(h);
  const old = charts[0], click = old.handlers.click;
  h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'overview' });
  assert.equal(old.disposed, true); click({ data: { code: 'US' } });
  assert.equal(h.$('#website_stats_geo_country').val(), '');
  h.fire('.website_stats_tab', 'click', { 'data-stats-page': 'geography' });
  assert.equal(charts.length, 2); h.close(); assert.equal(charts[1].disposed, true);
});

test('blocked-IP table inserts escaped location immediately after IP with five-column placeholders', () => {
  const table = html.match(/<div class="waf-blocked-scroll">([\s\S]*?)<\/table>/)[1];
  assert.match(table, /<th>IP 地址<\/th><th>归属地<\/th><th>24小时/);
  assert.match(table, /colspan="5"/);
  assert.match(html, /\.waf-blocked-scroll \.waf_table\s*\{[^}]*min-width:560px/);
  const h = harness();
  const location = '"><img src=x onerror="x"> & 北京';
  const result = { summary: {}, blocked_ips: [{ ip: '<ip>', location, active: true, reason: '<reason>' }, { ip: '2001:db8::1', active: false }] };
  const original = JSON.stringify(result);
  h.of('get_overview_report')[0].resolve(result);
  const body = h.$('#overview_blocked_ip_table').html();
  assert.match(body, /<td>&lt;ip&gt;<\/td><td class="waf-blocked-location" title="&quot;&gt;&lt;img/);
  assert.match(body, /未知归属地/); assert.doesNotMatch(body, /<img|<reason>|&amp;lt;/);
  assert.equal(JSON.stringify(result), original);
  h.waf.render_overview_report(); h.of('get_overview_report').at(-1).resolve({ summary: {}, blocked_ips: [] });
  assert.match(h.$('#overview_blocked_ip_table').html(), /colspan="5"/);
});

test('initial blocked-IP error replaces loading with an honest five-column retry message', () => {
  const h = harness(); h.of('get_overview_report')[0].reject();
  assert.match(h.$('#overview_blocked_ip_table').html(), /colspan="5"[\s\S]*(?:失败|不可用)/);
});
