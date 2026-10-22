'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const script = html.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];
const context = vm.createContext({ window: {}, Intl });
vm.runInContext(script.split('var free_waf =')[0], context);
const charts = context.waf_dashboard;
const geometry = { type: 'FeatureCollection', features: [
  { type: 'Feature', properties: { name: 'United States' }, geometry: {} },
  { type: 'Feature', properties: { name: 'China' }, geometry: {} },
  { type: 'Feature', properties: { name: 'Russian' }, geometry: {} },
  { type: 'Feature', properties: { name: 'NewZealand' }, geometry: {} },
] };

test('country aggregation matches ISO codes to actual panel geometry and Chinese names', () => {
  assert.ok(charts, 'missing real dashboard chart builder');
  const model = charts.geography({ countries: [
    { code: 'US', name: 'United States', count: 1200 },
    { code: 'CN', count: 42 }, { code: 'RU', count: 9 },
  ], total: 1258, unlocated: 7, database_available: true }, geometry);
  assert.equal(model.countries[0].name, '美国');
  assert.equal(model.data.find(r => r.name === 'United States').value, 1200);
  assert.equal(model.data.find(r => r.name === 'Russian').value, 9);
  assert.equal(model.located, 1251);
  assert.equal(model.unlocated, 7);
  assert.equal(model.unmapped, 0);
});

test('zero counts remain zero and unmapped territories are not falsely plotted', () => {
  const model = charts.geography({ countries: [{ code: 'SG', count: 5 }], total: 8, unlocated: 3 }, geometry);
  assert.equal(model.unmapped, 5);
  assert.equal(model.data.every(r => r.value === 0), true);
  const empty = charts.geography({ countries: [], total: 0, unlocated: 0 }, geometry);
  assert.equal(empty.max, 0);
  assert.equal(empty.located, 0);
  assert.equal(empty.unlocated, 0);
});

test('malformed countries and nonfinite counts cannot pollute chart data', () => {
  const model = charts.geography({ countries: [
    { code: 'US', count: 3 }, { code: 'us', count: 2 }, { code: 'CN', count: -9 },
    { code: '<script>', count: 50 }, { code: 'RU', count: Infinity }, null,
  ] }, geometry);
  assert.equal(model.countries.length, 1);
  assert.equal(model.countries[0].count, 5);
  assert.equal(model.data.find(r => r.name === 'United States').value, 5);
});

test('map is a choropleth with bounded zoom and no fictional flight paths', () => {
  const model = charts.geography({ countries: [{ code: 'US', count: 6 }], total: 6 }, geometry);
  const option = charts.mapOption(model);
  assert.equal(option.series.length, 1);
  assert.equal(option.series[0].type, 'map');
  assert.equal(option.series[0].scaleLimit.max, 5);
  assert.equal(option.series[0].layoutSize,charts.mapSize(520,285));
  assert.ok(charts.mapSize(232,300)<233);
  assert.ok(charts.mapSize(570,285)>500);
  assert.equal(option.series[0].left,undefined,'do not stretch country geometry to fit a narrow viewport');
  assert.equal(option.series[0].data.length, 4);
  assert.equal(option.visualMap.show, false);
  assert.match(option.tooltip.formatter({ name: 'United States', data: model.data[0] }), /美国/);
  assert.match(option.tooltip.formatter({ name: '<img onerror=alert(1)>', value: 0 }), /&lt;img/);
  assert.doesNotMatch(option.tooltip.formatter({ name: '<img>', value: 0 }), /<img>/);
});

test('trend renders actual dated values with integer axes and zero lower bound', () => {
  const option = charts.trendOption([{ date: '2026-10-21', count: 0 }, { date: '2026-10-22', count: 7 }]);
  assert.equal(option.yAxis.min, 0);
  assert.equal(option.yAxis.minInterval, 1);
  assert.equal(option.series[0].type, 'line');
  assert.equal(JSON.stringify(option.series[0].data), '[0,7]');
  assert.equal(JSON.stringify(option.xAxis.data), '["10-21","10-22"]');
});

test('layout contains a real map canvas, separate ranking, expansion and recovery controls', () => {
  for (const id of ['overview_attack_map', 'overview_map_ranking', 'overview_map_expand', 'overview_map_retry', 'overview_map_reset', 'overview_map_status']) {
    assert.match(html, new RegExp('id="' + id + '"'));
  }
  assert.doesNotMatch(html, /\.waf-map:before\s*\{/);
  assert.match(html, /\/static\/js\/echarts\.min\.js/);
  assert.match(html, /\/static\/vite\/data\/world\.json/);
});
