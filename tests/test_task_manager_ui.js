'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { harness, html } = require('./test_statistics_v011');

const plain = value => JSON.parse(JSON.stringify(value));
const processesMethod = 'get_task_processes';
const networkMethod = 'get_task_network';
const detailMethod = 'get_task_process_detail';
const taskReads = h => h.requests.filter(r => /^get_task_/.test(r.method));

function processRow(extra = {}) {
  return { pid: 42, ppid: 1, name: '<worker>(pool)&"', uid: 0, state: 'S', identity: '900',
    cpu_percent: 235.25, rss_bytes: 2048, vms_bytes: 8192, read_rate: null, write_rate: 0,
    started_at: 1792756800, threads: 4, ...extra };
}

function processes(extra = {}) {
  return { status: true, items: [processRow()], total: 63, page: 1, per_page: 25,
    partial: true, reasons: ['process_limit', 'io_unavailable'], sampled_seconds: 0.21,
    checked_at: 1792760400,
    summary: { process_count: 63, cpu_count: 4, memory_total_bytes: 8589934592, load: [0.5, 0.4, 0.3] }, ...extra };
}

function network(extra = {}) {
  return { status: true, items: [{ protocol: 'tcp6', local_address: '::1<&>', local_port: 443,
    remote_address: '2001:db8::2', remote_port: 50000, state: 'ESTABLISHED', uid: 0,
    pid: null, process_name: '<unknown>&' }],
    interfaces: [{ name: '<eth0>&', received_bytes: 4096, sent_bytes: 2048, receive_rate: null, send_rate: 0 }],
    total: 71, page: 1, per_page: 25, partial: false, reasons: [], sampled_seconds: 0.2,
    checked_at: 1792760400, summary: { socket_count: 71, listen_count: 5, established_count: 9 }, ...extra };
}

function open(h, view = 'processes') {
  h.navigate('task_manager');
  if (view !== 'processes') tab(h, view);
  const read = h.of(view === 'network' ? networkMethod : processesMethod).at(-1);
  assert.ok(read, 'explicit task page visit must issue a lazy read for ' + view);
  return read;
}

function tab(h, view) { h.fire('.task_tab', 'click', { 'data-task-view': view }); }
function refresh(h, view = 'processes') { h.fire('.task_refresh', 'click', { 'data-task-view': view }); }
function apply(h, view = 'processes') { h.fire('#task_' + view + '_form', 'submit'); }
function detail(h, index = 0) { h.fire('.task_process_detail', 'click', { 'data-task-index': String(index) }); }
function renderDetail(h, extra = {}) {
  h.of(detailMethod).at(-1).resolve({ status: true, process: processRow({ pss_bytes: 1024, uss_bytes: 512,
    swap_bytes: 0, fd_count: 7, ...extra }), partial: false, reasons: [], checked_at: 1792760401 });
}

test('task manager is a Chinese maintenance page with two read-only tabs and final diagnostics intact', () => {
  assert.match(html, /<li[^>]*data-target="task_manager"[^>]*data-section="maintenance"[^>]*>\s*<button[^>]*>任务管理/);
  const maintenance = [...html.matchAll(/<li[^>]*data-target="([^"]+)"[^>]*data-section="maintenance"/g)].map(m => m[1]);
  assert.equal(maintenance.at(-1), 'webshell');
  assert.match(html, /id="runtime_repair_start"[^>]*>一键修复/);
  assert.deepEqual([...html.matchAll(/class="task_tab[^\"]*"[^>]*data-task-view="([^"]+)"/g)].map(m => m[1]), ['processes', 'network']);
  const page = html.match(/<div class="item_con" data-type="task_manager">([\s\S]*?)(?=<div class="item_con"|<\/script>)/)?.[1] || '';
  assert.match(page, /进程/); assert.match(page, /网络/); assert.match(page, /无自动刷新|不自动刷新/);
  assert.match(page, /命名空间/); assert.match(page, /有限快照/); assert.match(page, /单核[^<]*100%/); assert.match(page, /0\.2/);
  assert.doesNotMatch(page, /<button[^>]*>[^<]*(终止|杀死|断开|封禁|删除|自动刷新)/);
  for (const view of ['processes', 'network']) {
    const options = html.match(new RegExp('<select id="task_' + view + '_per_page"[^>]*>([\\s\\S]*?)</select>'))?.[1] || '';
    assert.deepEqual([...options.matchAll(/value="(\d+)"/g)].map(m => +m[1]), [25, 50, 100]);
  }
  assert.match(html, /\.task_scroll\s*\{[^}]*overflow-x:auto/);
  assert.match(html, /\.task_detail_grid\s*\{[^}]*minmax\(0,1fr\)/);
  assert.match(html, /@media[^}]*max-width:720px[\s\S]*\.task_detail_grid/);
});

test('plugin open and unrelated navigation do not call task APIs, even after timers run', () => {
  const h = harness();
  h.tick(600000); h.navigate('statistics'); h.navigate('home');
  assert.equal(taskReads(h).length, 0);
});

test('first explicit visit samples once and repeat page/tab navigation retains each loaded snapshot', () => {
  const h = harness(); open(h).resolve(processes());
  assert.equal(h.waf.panel_section('task_manager'), 'maintenance');
  assert.equal(h.$('.waf_left_menu li[data-target="task_manager"] button').attr('aria-current'), 'page');
  assert.deepEqual(plain(h.of(processesMethod)[0].options.data), { page: 1, per_page: 25, search: '', sort: 'cpu_percent', order: 'desc' });
  h.navigate('home'); h.navigate('task_manager'); tab(h, 'processes');
  assert.equal(h.of(processesMethod).length, 1);
  tab(h, 'network'); h.of(networkMethod)[0].resolve(network());
  assert.deepEqual(plain(h.of(networkMethod)[0].options.data), { page: 1, per_page: 25, search: '', protocol: 'all', state: 'all', port: '', sort: 'local_port', order: 'asc' });
  tab(h, 'processes'); tab(h, 'network'); h.navigate('home'); h.navigate('task_manager'); h.tick(600000);
  assert.equal(taskReads(h).length, 2);
  assert.match(h.$('#task_processes_table').html(), /worker/);
  assert.match(h.$('#task_network_table').html(), /2001:db8::2/);
});

test('process table renders safe text, CPU over 100%, unknown rates and honest coverage without response mutation', () => {
  const h = harness(), data = processes(), original = JSON.stringify(data);
  open(h).resolve(data);
  const rows = h.$('#task_processes_table').html();
  assert.match(rows, /&lt;worker&gt;\(pool\)&amp;&quot;/); assert.doesNotMatch(rows, /<worker>|&amp;lt;/);
  assert.match(rows, /235\.3%/); assert.match(rows, /2(?:\.0+)? (?:KB|KiB)/);
  assert.match(rows, /<td>--<\/td>/); assert.match(rows, /0 B\/s/);
  assert.match(h.$('#task_processes_summary').text(), /63[\s\S]*4[\s\S]*0\.5/);
  assert.match(h.$('#task_processes_coverage').text(), /部分/);
  assert.match(h.$('#task_processes_coverage').text(), /上限/);
  assert.doesNotMatch(h.$('#task_processes_coverage').text(), /process_limit|io_unavailable/);
  assert.match(h.$('#task_processes_checked').text(), /2026[\s\S]*0\.21/);
  assert.equal(JSON.stringify(data), original);
});

test('network renders IPv6 addresses, ownership gaps, interface totals and nullable rates safely', () => {
  const h = harness(), data = network(), original = JSON.stringify(data);
  open(h, 'network').resolve(data);
  const rows = h.$('#task_network_table').html(), interfaces = h.$('#task_network_interfaces').html();
  assert.match(rows, /::1&lt;&amp;&gt;/); assert.match(rows, /2001:db8::2/);
  assert.match(rows, /&lt;unknown&gt;&amp;/); assert.match(rows, /<td>--<\/td>/);
  assert.match(rows, /已建立|已连接/);
  assert.match(interfaces, /&lt;eth0&gt;&amp;/); assert.match(interfaces, /4(?:\.0+)? (?:KB|KiB)/);
  assert.match(interfaces, /<td>--<\/td>/); assert.match(interfaces, /0 B\/s/);
  assert.match(h.$('#task_network_summary').text(), /71[\s\S]*5[\s\S]*9/);
  assert.match(h.$('#task_network_coverage').text(), /有限快照/);
  assert.doesNotMatch(h.$('#task_network_coverage').text(), /全主机完整|完整统计/);
  assert.equal(JSON.stringify(data), original);
});

test('typing and changing process sort/page size are local until one explicit apply request', () => {
  const h = harness(); open(h).resolve(processes());
  for (const [key, value] of Object.entries({ search: ' worker[.] ', sort: 'read_rate', order: 'asc', per_page: '50' })) {
    h.$('#task_processes_' + key).val(value); h.fire('#task_processes_' + key, 'input'); h.fire('#task_processes_' + key, 'change');
  }
  h.tick(600000); assert.equal(h.of(processesMethod).length, 1);
  apply(h); assert.equal(h.of(processesMethod).length, 2);
  assert.deepEqual(plain(h.of(processesMethod).at(-1).options.data), { page: 1, per_page: 50, search: 'worker[.]', sort: 'read_rate', order: 'asc' });
});

test('all six allowed process sorts are forwarded without adding automatic reads', () => {
  const h = harness(); open(h).resolve(processes());
  for (const sort of ['cpu_percent', 'rss_bytes', 'read_rate', 'write_rate', 'pid', 'name']) {
    h.$('#task_processes_sort').val(sort); apply(h);
    assert.equal(h.of(processesMethod).at(-1).options.data.sort, sort);
    h.of(processesMethod).at(-1).resolve(processes());
  }
  assert.equal(h.of(processesMethod).length, 7);
});

test('network filters are applied together and only contract keys are sent', () => {
  const h = harness(); open(h, 'network').resolve(network());
  for (const [key, value] of Object.entries({ search: 'db8::', protocol: 'tcp6', state: 'ESTABLISHED', port: '443', sort: 'pid', order: 'desc', per_page: '100' })) {
    h.$('#task_network_' + key).val(value); h.fire('#task_network_' + key, 'change');
  }
  assert.equal(h.of(networkMethod).length, 1); apply(h, 'network');
  assert.deepEqual(plain(h.of(networkMethod).at(-1).options.data), { page: 1, per_page: 100, search: 'db8::', protocol: 'tcp6', state: 'ESTABLISHED', port: 443, sort: 'pid', order: 'desc' });
});

test('invalid network ports are rejected locally with a Chinese retryable message', () => {
  const h = harness(); open(h, 'network').resolve(network());
  for (const value of ['-1', '65536', '1.5', '443abc']) {
    h.$('#task_network_port').val(value); apply(h, 'network');
    assert.match(h.$('#task_network_status').text(), /端口[\s\S]*0[\s\S]*65535/);
  }
  assert.equal(h.of(networkMethod).length, 1);
  h.$('#task_network_port').val('0'); apply(h, 'network');
  assert.equal(h.of(networkMethod).at(-1).options.data.port, 0);
});

test('pagination uses the applied query, respects bounds, and page-size apply returns to page 1', () => {
  const h = harness(); open(h).resolve(processes());
  h.fire('.task_prev', 'click', { 'data-task-view': 'processes' }); assert.equal(h.of(processesMethod).length, 1);
  h.$('#task_processes_search').val('unapplied');
  h.fire('.task_next', 'click', { 'data-task-view': 'processes' });
  assert.equal(h.of(processesMethod).at(-1).options.data.page, 2);
  assert.equal(h.of(processesMethod).at(-1).options.data.search, '');
  h.of(processesMethod).at(-1).resolve(processes({ page: 2 }));
  assert.match(h.$('#task_processes_page_info').text(), /2\s*\/\s*3[\s\S]*63/);
  h.fire('.task_next', 'click', { 'data-task-view': 'processes' });
  h.of(processesMethod).at(-1).resolve(processes({ page: 3 }));
  const count = h.of(processesMethod).length;
  h.fire('.task_next', 'click', { 'data-task-view': 'processes' }); assert.equal(h.of(processesMethod).length, count);
  h.$('#task_processes_per_page').val('100'); apply(h);
  assert.equal(h.of(processesMethod).at(-1).options.data.page, 1);
  assert.equal(h.of(processesMethod).at(-1).options.data.per_page, 100);
});

test('manual refresh preserves applied query and does not apply unfinished edits', () => {
  const h = harness(); open(h).resolve(processes());
  h.$('#task_processes_search').val('worker'); apply(h); h.of(processesMethod).at(-1).resolve(processes());
  h.$('#task_processes_search').val('draft'); refresh(h);
  assert.equal(h.of(processesMethod).at(-1).options.data.search, 'worker');
  assert.equal(h.$('#task_processes_refresh').prop('disabled'), true);
  h.of(processesMethod).at(-1).resolve(processes());
  assert.equal(h.$('#task_processes_refresh').prop('disabled'), false);
});

test('task view/page switches abort pending sampling and suppress forced late callbacks', () => {
  const h = harness(), old = open(h);
  tab(h, 'network'); assert.ok(old.aborted);
  const next = h.of(networkMethod).at(-1);
  old.options.success(processes({ items: [processRow({ name: 'stale-process' })] }));
  assert.doesNotMatch(h.$('#task_processes_table').html(), /stale-process/);
  h.navigate('statistics'); assert.ok(next.aborted);
  next.options.success(network({ items: [{ process_name: 'stale-network' }] }));
  assert.doesNotMatch(h.$('#task_network_table').html(), /stale-network/);
  h.navigate('task_manager'); refresh(h, 'network');
  assert.equal(h.of(networkMethod).length, 2);
});

test('replacement refresh cancels the old request before issuing another and old completion cannot unlock it', () => {
  const h = harness(), old = open(h); refresh(h);
  assert.ok(old.aborted);
  const next = h.of(processesMethod).at(-1);
  old.options.complete(old, 'abort');
  assert.equal(h.$('#task_processes_refresh').prop('disabled'), true);
  old.options.success(processes({ items: [processRow({ name: 'late' })] }));
  next.resolve(processes({ items: [processRow({ name: 'fresh' })] }));
  assert.match(h.$('#task_processes_table').html(), /fresh/); assert.doesNotMatch(h.$('#task_processes_table').html(), /late/);
});

for (const view of ['processes', 'network']) {
  for (const failure of ['transport', 'api', 'malformed']) test(view + ' ' + failure + ' failure clears stale success and permits explicit retry', () => {
    const h = harness(), fixture = view === 'network' ? network : processes, method = view === 'network' ? networkMethod : processesMethod;
    open(h, view).resolve(fixture()); refresh(h, view);
    const read = h.of(method).at(-1);
    if (failure === 'transport') read.reject();
    else read.resolve(failure === 'api' ? { status: false, code: 'unavailable', msg: '暂时无法读取，请重试' } : { status: true, items: null });
    assert.doesNotMatch(h.$('#task_' + view + '_table').html(), /worker|2001:db8/);
    assert.doesNotMatch(h.$('#task_' + view + '_summary').text(), /63|71/);
    assert.doesNotMatch(h.$('#task_' + view + '_checked').text(), /2026/);
    assert.match(h.$('#task_' + view + '_status').text(), /失败|无法|重试/);
    if (view === 'network') assert.doesNotMatch(h.$('#task_network_interfaces').html(), /eth0/);
    assert.equal(h.$('#task_' + view + '_refresh').prop('disabled'), false);
    refresh(h, view); h.of(method).at(-1).resolve(fixture());
    assert.match(h.$('#task_' + view + '_table').html(), view === 'network' ? /2001:db8/ : /worker/);
  });
}

test('process details send only the identity from the current list and render an allowlist inline', () => {
  const h = harness(); open(h).resolve(processes()); detail(h);
  assert.deepEqual(plain(h.of(detailMethod).at(-1).options.data), { pid: 42, identity: '900' });
  renderDetail(h, { argv: 'SECRET_ARGV', environ: 'SECRET_ENV', cwd: 'SECRET_CWD', exe: 'SECRET_EXE', open_files: 'SECRET_FILES' });
  assert.equal(h.$('#task_detail').prop('hidden'), false);
  const content = h.$('#task_detail_content').html();
  assert.match(content, /&lt;worker&gt;\(pool\)&amp;&quot;/); assert.match(content, /PSS|比例驻留/); assert.match(content, /USS|独占/); assert.match(content, /7/);
  assert.doesNotMatch(content, /SECRET_/);
  h.fire('#task_detail_close'); assert.equal(h.$('#task_detail').prop('hidden'), true);
  assert.equal(h.$('#task_detail_content').html(), '');
});

test('unknown row indices or missing list identity never request arbitrary PID details', () => {
  const h = harness(); open(h).resolve(processes({ items: [processRow({ identity: '' })] }));
  detail(h, -1); detail(h, 99); detail(h, '0;alert(1)'); detail(h, 0);
  assert.equal(h.of(detailMethod).length, 0);
  assert.match(h.$('#task_detail_status').text(), /刷新.*列表/);
});

test('disappeared or reused PIDs and mismatched success payloads require list reload, never display wrong process', () => {
  for (const response of [
    { status: false, code: 'process_gone', msg: '进程已退出' },
    { status: false, code: 'pid_reused', msg: '进程身份已变化' },
    { status: true, process: processRow({ identity: '901', name: 'WRONG_PROCESS' }) },
    { status: true, process: processRow({ pid: 43, name: 'WRONG_PROCESS' }) },
  ]) {
    const h = harness(); open(h).resolve(processes()); detail(h); h.of(detailMethod).at(-1).resolve({ partial: false, reasons: [], checked_at: 1792760401, ...response });
    assert.match(h.$('#task_detail_status').text(), /刷新.*列表/);
    assert.doesNotMatch(h.$('#task_detail_content').html(), /WRONG_PROCESS|worker/);
    assert.equal(h.of(processesMethod).length, 1, 'identity failure must not silently resample');
  }
});

test('changing detail selection cancels older details and ignores their late identity-valid response', () => {
  const h = harness(); open(h).resolve(processes({ items: [processRow(), processRow({ pid: 43, identity: '901', name: 'new' })] }));
  detail(h, 0); const old = h.of(detailMethod).at(-1); detail(h, 1); assert.ok(old.aborted);
  old.options.success({ status: true, process: processRow({ name: 'OLD_DETAIL' }), partial: false, reasons: [], checked_at: 1792760401 });
  renderDetail(h, { pid: 43, identity: '901', name: 'new' });
  assert.match(h.$('#task_detail_content').html(), /new/); assert.doesNotMatch(h.$('#task_detail_content').html(), /OLD_DETAIL/);
});

test('detail close, tab switches, list refresh and plugin close abort pending details and clear sensitive content', () => {
  for (const action of ['close-detail', 'switch-tab', 'refresh', 'close-plugin']) {
    const h = harness(); open(h).resolve(processes()); detail(h); const pending = h.of(detailMethod).at(-1);
    if (action === 'close-detail') h.fire('#task_detail_close');
    if (action === 'switch-tab') tab(h, 'network');
    if (action === 'refresh') refresh(h);
    if (action === 'close-plugin') h.close();
    assert.ok(pending.aborted, action);
    pending.options.success({ status: true, process: processRow({ name: 'LATE_SECRET' }), partial: false, reasons: [], checked_at: 1792760401 });
    assert.doesNotMatch(h.$('#task_detail_content').html(), /LATE_SECRET/);
    assert.equal(h.$('#task_detail').prop('hidden'), true);
  }
});

test('close and reinitialize abort old sampling, clear cached snapshots, and never initiate a task read', () => {
  const h = harness(), pending = open(h); h.close(); assert.ok(pending.aborted);
  pending.options.success(processes()); assert.doesNotMatch(h.$('#task_processes_table').html(), /worker/);
  const other = harness(); open(other).resolve(processes()); const before = taskReads(other).length;
  other.waf.init(); assert.equal(taskReads(other).length, before);
  assert.doesNotMatch(other.$('#task_processes_table').html(), /worker/);
});

test('empty snapshots and unknown partial-reason codes stay honest and render no raw HTML', () => {
  const h = harness(); open(h).resolve(processes({ items: [], total: 0, summary: { process_count: 0, cpu_count: 4, memory_total_bytes: 8589934592, load: [0, 0, 0] }, partial: true, reasons: ['<script>bad</script>'] }));
  assert.match(h.$('#task_processes_table').html(), /暂无|未找到/);
  assert.match(h.$('#task_processes_page_info').text(), /0/);
  assert.doesNotMatch(h.$('#task_processes_summary').text(), /undefined|NaN/);
  assert.match(h.$('#task_processes_coverage').text(), /部分/);
  assert.doesNotMatch(h.$('#task_processes_coverage').text(), /<script>|bad/);
});

test('task data never uses browser storage, timers or non-read task operations', () => {
  const h = harness();
  const storage = { getItem() { assert.fail('no task storage read'); }, setItem() { assert.fail('no task storage write'); }, removeItem() { assert.fail('no task storage delete'); } };
  h.context.localStorage = storage; h.context.sessionStorage = storage;
  h.context.window.localStorage = storage; h.context.window.sessionStorage = storage;
  open(h).resolve(processes()); detail(h); renderDetail(h); tab(h, 'network'); h.of(networkMethod).at(-1).resolve(network());
  const before = taskReads(h).length; h.tick(600000); assert.equal(taskReads(h).length, before);
  assert.ok(taskReads(h).every(r => [processesMethod, networkMethod, detailMethod].includes(r.method)));
  assert.equal(h.confirms.length, 0); h.close();
});

test('missing or malformed summaries and invalid snapshot envelopes cannot show success', () => {
  for (const view of ['processes', 'network']) {
    for (const extra of [{ summary: undefined }, { summary: {} }, { summary: [] }, { total: -1 }, { checked_at: null }, { page: 0 }, { per_page: 1000 }]) {
      const h = harness(), fixture = view === 'processes' ? processes : network;
      open(h, view).resolve(fixture(extra));
      assert.match(h.$('#task_' + view + '_status').text(), /失败|格式|重试/);
      assert.doesNotMatch(h.$('#task_' + view + '_table').html(), /worker|2001:db8/);
    }
  }
});

test('details validate decimal start-tick identities and keep independently unsampled rates unknown', () => {
  for (const identity of ['', '42:900', '9.5', 'a900', '1'.repeat(25)]) {
    const h = harness(); open(h).resolve(processes({ items: [processRow({ identity })] })); detail(h);
    assert.equal(h.of(detailMethod).length, 0);
    assert.match(h.$('#task_detail_status').text(), /刷新.*列表/);
  }
  const h = harness(); open(h).resolve(processes()); detail(h);
  renderDetail(h, { cpu_percent: null, read_rate: null, write_rate: null, pss_bytes: null, uss_bytes: null, swap_bytes: null, fd_count: null });
  assert.match(h.$('#task_detail_content').html(), /<dd>--<\/dd>/);
  assert.doesNotMatch(h.$('#task_detail_content').html(), /0%|0 B\/s|235\.3%/);
  assert.match(h.$('#task_detail_status').text(), /不单独采样/);
});

test('backend reason codes have fixed Chinese labels and unknown codes use a generic fallback', () => {
  const reasons = ['time_limit', 'process_limit', 'process_unavailable', 'process_changed', 'io_unavailable', 'system_unavailable', 'memory_unavailable', 'fd_limit', 'fd_unavailable', 'socket_limit', 'socket_unavailable', 'interface_limit', 'interface_unavailable', 'ownership_partial', 'counter_reset', 'UNKNOWN_EXCEPTION'];
  const h = harness(); open(h).resolve(processes({ reasons }));
  const notice = h.$('#task_processes_coverage').text();
  for (const reason of reasons) assert.ok(!notice.includes(reason), reason);
  for (const label of ['时间', '进程', '磁盘', '系统', '内存', '描述符', '连接', '接口', '归属', '重置']) assert.ok(notice.includes(label), label);
});

test('partial system metrics remain unknown without hiding a valid process snapshot', () => {
  const h = harness(); open(h).resolve(processes({ summary: { process_count: 63, cpu_count: null, memory_total_bytes: null, load: [] }, reasons: ['system_unavailable'] }));
  assert.match(h.$('#task_processes_table').html(), /worker/);
  assert.match(h.$('#task_processes_summary').text(), /--/);
  assert.doesNotMatch(h.$('#task_processes_summary').text(), /undefined|NaN/);
  assert.match(h.$('#task_processes_coverage').text(), /系统/);
});

test('error codes use fixed Chinese notices rather than raw exception messages', () => {
  const h = harness(); open(h).resolve({ status: false, code: 'unexpected_exception', msg: '/private/path SECRET_EXCEPTION' });
  assert.match(h.$('#task_processes_status').text(), /失败.*手动重试|失败.*刷新重试/);
  assert.doesNotMatch(h.$('#task_processes_status').text(), /private|SECRET/);
});

test('repeated initialize and filter events before task navigation stay lazy with one live binding', () => {
  const h = harness(); h.waf.init(); h.waf.init();
  apply(h); apply(h, 'network'); refresh(h); tab(h, 'network');
  assert.equal(taskReads(h).length, 0);
  open(h).resolve(processes());
  h.$('#task_processes_search').val('a'.repeat(81)); apply(h);
  assert.equal(h.of(processesMethod).length, 1);
  assert.match(h.$('#task_processes_status').text(), /80/);
  h.$('#task_processes_search').val('worker'); apply(h);
  assert.equal(h.of(processesMethod).length, 2);
});
