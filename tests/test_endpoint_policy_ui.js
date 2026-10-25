'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { harness, html } = require('./test_statistics_v011');
const source = html.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];

test('removed endpoint policies have no navigation, page, controls or dedicated styles', () => {
  assert.equal(/data-(?:target|type)=["']policies["']/.test(html), false, 'policy navigation/page remains');
  assert.equal(/endpoint[-_]policy|接口策略/.test(html), false, 'policy controls or copy remain');
  assert.equal(/\.waf-policy-(?:tag|actions)\b/.test(html), false, 'policy-only styles remain');
  for (const shared of ['layout', 'form', 'check', 'scroll', 'meta']) {
    assert.ok(html.includes('.waf-policy-' + shared), 'repeat-ban shared style missing: ' + shared);
  }
  assert.match(html, /\.waf-feature-guide\s*\{/);
});

test('removed endpoint navigation is inert and no management API is referenced', () => {
  const h = harness(), before = h.requests.length;
  h.navigate('policies');
  assert.equal(h.requests.length, before, 'removed page must not discover sites or read policies');
  assert.equal(h.waf._active_page, 'home');
  assert.equal(h.waf.panel_section('policies'), null);
  const methods = [...source.matchAll(/\b(?:get_endpoint_policies|get_endpoint_policy_events|save_endpoint_policy|delete_endpoint_policy)\b/g)].map(m => m[0]);
  assert.deepEqual(methods, [], 'endpoint management calls remain');
});

test('initialization, reload and close retain shared escaping without endpoint policy state or hooks', () => {
  const h = harness(), selectors = [], bind = h.waf.bind_panel_event;
  h.waf.bind_panel_event = function(event, selector, callback) {
    selectors.push(selector);
    return bind.call(this, event, selector, callback);
  };
  for (const action of [() => h.waf.init(), () => h.reload(), () => h.close()]) {
    action();
    assert.deepEqual(Object.keys(h.waf).filter(key => key.includes('endpoint') && key !== 'endpoint_text'), []);
    assert.equal(selectors.some(selector => /endpoint[-_]policy/.test(selector)), false);
    assert.equal(h.waf.endpoint_text('<b>&"\''), '&lt;b&gt;&amp;&quot;&#39;');
    assert.equal(h.waf.endpoint_text(null), '');
  }
  assert.equal(/\b(?:init_endpoint_policies|stop_endpoint_requests|load_endpoint_sites|_endpoint_\w+)\b/.test(source), false);
});
