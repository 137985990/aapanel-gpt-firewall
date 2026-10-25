#!/bin/bash
# Compatibility upgrade only. aaPanel has already overwritten plugin files.
set -Eeuo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

operation=${1:-}
root=
if [[ -n ${GPT_FIREWALL_TEST_ROOT:-} || ${2:-} == --test-mode ]]; then
    [[ ${2:-} == --test-mode && -n ${GPT_FIREWALL_TEST_ROOT:-} ]] || {
        printf '%s\n' '测试根目录只能在显式 --test-mode 模式下使用。' >&2
        exit 1
    }
    root=$(cd -- "$GPT_FIREWALL_TEST_ROOT" && pwd -P)
    [[ $root != / ]] || exit 1
elif [[ $EUID != 0 ]]; then
    printf '%s\n' '请以 root 运行 aaPanel 兼容升级安装器。' >&2
    exit 1
fi

plugin="$root/www/server/panel/plugin/free_waf"
runtime="$root/www/server/free_waf"
nginx="$root/www/server/nginx/sbin/nginx"
nginx_prefix="$root/www/server/nginx/"
nginx_conf="$root/www/server/nginx/conf/nginx.conf"
[[ $# -le 2 && ( $# -lt 2 || ${2:-} == --test-mode ) ]] || exit 1
[[ ! -L $plugin && -d $plugin ]] || exit 1
# The importer recursively sets mode 600, including directories.
chmod 755 "$plugin"
[[ $(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) == "$plugin" ]] || exit 1

python="$root/www/server/panel/pyenv/bin/python"
if [[ ! -x $python ]]; then
    python=$(command -v python3) || {
        printf '%s\n' '缺少 Python 3，无法校验或写入 install-status.json；未更新运行文件。' >&2
        exit 1
    }
fi

# Private generated helper avoids OS command-line length limits; no plugin imports.
helper_source=$(mktemp "$plugin/.gpt-firewall-helper.XXXXXX")
trap 'rm -f -- "$helper_source"' EXIT
cat > "$helper_source" <<'PY'
import base64, hashlib, hmac, json, os, re, secrets, shutil, stat, sys, tempfile, uuid
from pathlib import Path

root, plugin, mode, *args = sys.argv[1:]
plugin = Path(plugin)
diagnostic_codes = {
    'missing_resource', 'unsafe_resource', 'invalid_resource', 'invalid_json', 'json_schema',
    'integration_conflict', 'runtime_incomplete', 'package_identity', 'runtime_entrypoint',
    'config_incomplete', 'response_template', 'scan_rules', 'preflight_failed',
    'nginx_test_failed', 'nginx_reload_failed', 'storage_permissions', 'source_profile', 'migration_conflict',
}
resources = {
    'nginx.conf', 'free_waf.conf', 'init.lua', 'waf.lua', 'free_waf_main.py', 'report_store.py',
    'ban_store.py', 'website_statistics.py', 'update_service.py', 'index.html', 'info.json',
    'rule.json', 'drop_ip.log', 'config.json', 'site.json', 'total.json', 'scan_black.json',
    'cn.json', 'ip_black.json', 'ip_white.json', 'url_white.json', 'url_black.json',
    'user_agent_white.json', 'user_agent.json', 'header.json', 'post.json', 'cookie.json',
    'args.json', 'url.json', 'head_white.json', 'response_template', 'runtime_directory', 'domains.json',
}

class CheckError(ValueError):
    def __init__(self, code, message, resource=''):
        super().__init__(message)
        self.code = code
        self.resource = resource if resource in resources else ''

def mapped(name):
    if not isinstance(name, str) or not name.startswith('/'):
        raise CheckError('unsafe_resource', '旧运行资源必须使用绝对路径')
    result = Path(root + name)
    if root and os.path.commonpath([str(Path(root).resolve()), str(result.resolve())]) != str(Path(root).resolve()):
        raise CheckError('unsafe_resource', '资源路径超出隔离测试目录')
    return result

def file(path):
    if path.is_symlink():
        raise CheckError('unsafe_resource', '必要的既有资源不能为符号链接：' + path.name, path.name)
    if not path.is_file():
        raise CheckError('missing_resource', '必要的既有资源缺失：' + path.name, path.name)
    if path.stat().st_size == 0:
        raise CheckError('invalid_resource', '必要的既有资源为空：' + path.name, path.name)
    return path

def load(path, kind):
    source = file(path)
    try:
        data = json.loads(source.read_text(encoding='utf-8-sig'))
    except (ValueError, UnicodeError):
        raise CheckError('invalid_json', 'JSON 数据无法解析：' + path.name, path.name)
    if not isinstance(data, kind):
        raise CheckError('json_schema', 'JSON 结构不兼容：' + path.name, path.name)
    return data

def directives(body):
    # Keep in sync with update_service.nginx_directives, without importing plugin code.
    long_lua = re.compile(r'\[(=*)\[')

    def skip_lua(position):
        depth = 1
        while position < len(body):
            char = body[position]
            comment = body.startswith('--', position)
            start = position + 2 if comment else position
            long_string = long_lua.match(body, start)
            if long_string:
                closing = ']' + long_string.group(1) + ']'
                end = body.find(closing, start + len(long_string.group(0)))
                if end < 0:
                    raise ValueError('unfinished_lua_string')
                position = end + len(closing)
                continue
            if comment:
                end = body.find('\n', start)
                position = len(body) if end < 0 else end + 1
                continue
            if char in ('"', "'"):
                quote = char
                position += 1
                while position < len(body) and body[position] != quote:
                    position += 2 if body[position] == '\\' else 1
                if position >= len(body):
                    raise ValueError('unfinished_lua_quote')
            elif char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    return position + 1
            position += 1
        raise ValueError('unfinished_lua_block')

    statements, current = [], []
    token, quote, started, position = [], None, False, 0
    while position < len(body):
        char = body[position]
        if char == '\\':
            if position + 1 >= len(body):
                raise ValueError('unfinished_nginx_escape')
            escaped = body[position + 1]
            token.append({'t': '\t', 'r': '\r', 'n': '\n'}.get(
                escaped, escaped if escaped in ('"', "'", '\\') else '\\' + escaped))
            started = True
            position += 2
            continue
        if quote:
            if char == quote:
                quote = None
            else:
                token.append(char)
            position += 1
            continue
        if char in ('"', "'") and not started:
            quote, started = char, True
            position += 1
            continue
        if char not in ' \t\r\n;{}#' or char == '#' and started:
            token.append(char)
            started = True
            position += 1
            continue
        if char == '{' and token and token[-1] == '$':
            end = body.find('}', position + 1)
            if end < 0:
                raise ValueError('unfinished_nginx_variable')
            token.append(body[position:end + 1])
            position = end + 1
            continue
        if started:
            current.append(''.join(token))
            token, started = [], False
        if char == '#':
            end = body.find('\n', position)
            position = len(body) if end < 0 else end + 1
            continue
        if char in ';{}':
            if char == ';' and current:
                statements.append(current)
            if char == '{' and current and current[0].endswith('_by_lua_block'):
                statements.append(current + ['{'])
                position = skip_lua(position + 1)
                current = []
                continue
            current = []
        position += 1
    if quote or started or current:
        raise ValueError('unfinished_nginx_directive')
    return statements

def active(body, required=False):
    rows = directives(body)
    def values(key):
        return [row[1] for row in rows if len(row) >= 2 and row[0] == key]
    init = '/www/server/free_waf/init.lua'
    access = '/www/server/free_waf/waf.lua'
    relevant = any('/www/server/free_waf/' in token for row in rows for token in row)
    if relevant or required:
        if values('init_by_lua_file') != [init] or values('access_by_lua_file') != [access]:
            raise CheckError('integration_conflict', '存在未知或冲突的 Lua 入口，不会改写引用配置')
        shared = values('lua_shared_dict')
        if any(shared.count(name) != 1 for name in ('free_waf', 'free_waf_drop_ip', 'free_waf_drop_sum')):
            raise CheckError('integration_conflict', '旧版 Lua 共享字典缺失或冲突')
    return relevant

lock = plugin / '.gpt-firewall-install.lock'
owner_path = lock / 'owner.json'

def owner():
    if lock.is_symlink() or not lock.is_dir() or owner_path.is_symlink():
        raise ValueError('安装锁路径不安全')
    data = json.loads(owner_path.read_text())
    if (data.get('task_id') != os.environ.get('GPT_FIREWALL_INSTALL_TASK') or
            not hmac.compare_digest(data.get('token', ''), os.environ.get('GPT_FIREWALL_INSTALL_TOKEN', ''))):
        raise ValueError('安装锁身份不符')
    return data

def fingerprint(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('运行文件不是独占普通文件')
        return dict(dev=info.st_dev, ino=info.st_ino, sha256=hashlib.sha256(stream.read()).hexdigest())

# Pin the inspected original runtime, not a vendor name or a forgeable version label.
DOMESTIC_LUA_SHA256 = 'ad3c6b78342859fd9f5fa93a50d4cda2176a16ae832580ffe9c3819a47d4e873'
DOMESTIC_PROFILE = 'bt-free-waf-8.4'
KNOWN_COMMUNITY_LUA_SHA256 = frozenset({
    '817731649860903097321baa2873dc92918e3d8f0670dcb555129e66dfb0c94b',
    '570fa78d20b3803722cf0c1969d441a5cc7083e0d6e49e68b4b2518212a548ca',
    'f4e81a063d46aa985ca47f867182536623a0208d1feb9934686d7003eeb4a85d',
    'd6486cf33fbea9d3da8d667dbd9ca0b7b791052aa2a4d500dc1f26770fd50b2a',
    'f695787c47bd9def72058754951efbf642d1bc8a5b23613eadf65537602975ec',
    '9f06c3b1531a0dc036e19e12205ff2ec146f90720c81cef893847725d5354790',
})

def source_profile(runtime):
    identity = fingerprint(file(runtime / 'init.lua'))['sha256']
    if identity == DOMESTIC_LUA_SHA256:
        return DOMESTIC_PROFILE
    if identity in KNOWN_COMMUNITY_LUA_SHA256 or identity == fingerprint(file(plugin / 'init.lua'))['sha256']:
        return 'known-community'
    raise CheckError('source_profile', '未核验的运行版本或自定义 Lua，请先确认来源，不能直接覆盖升级', 'init.lua')

def domestic_plan(runtime):
    config = load(runtime / 'config.json', dict)
    sites = load(runtime / 'site.json', dict)
    domains = load(runtime / 'domains.json', list)
    def invalid_config(field):
        raise CheckError('json_schema', '旧全局配置字段缺失或类型不兼容：' + field, 'config.json')
    if type(config.get('open')) is not bool: invalid_config('open')
    for field in ('log', 'from_data'):
        if field in config and type(config[field]) is not bool: invalid_config(field)
    for field in ('retry', 'retry_cycle', 'retry_time'):
        if type(config.get(field)) is not int or not 1 <= config[field] <= 2147483647:
            invalid_config(field)
    for kind in ('cc', 'scan', 'drop_abroad', 'get', 'post', 'cookie', 'user-agent', 'other', 'url_black'):
        if kind == 'url_black' and kind not in config: continue
        item = config.get(kind)
        if not isinstance(item, dict): invalid_config(kind)
        if kind != 'other' and type(item.get('open')) is not bool: invalid_config(kind + '.open')
        if type(item.get('status')) is not int or not 400 <= item['status'] <= 599:
            invalid_config(kind + '.status')
        if kind == 'cc':
            for field in ('cycle', 'limit', 'endtime'):
                if type(item.get(field)) is not int or not 1 <= item[field] <= 2147483647:
                    invalid_config(kind + '.' + field)
    changes, aliases, owners = {}, {}, {}
    def safe_name(name):
        return isinstance(name, str) and 0 < len(name) <= 253 and not re.search(r'[/\\\x00-\x20]', name) and name not in ('.', '..')
    for item in domains:
        if (not isinstance(item, dict) or not safe_name(item.get('name')) or
                not isinstance(item.get('domains'), list)):
            raise CheckError('json_schema', '旧站点别名结构不兼容', 'domains.json')
        if item['name'] not in sites:
            raise CheckError('migration_conflict', '域名对应的站点配置缺失，请先核对，未创建默认站点配置', 'domains.json')
        for alias in item['domains']:
            if not safe_name(alias) or alias in owners and owners[alias] != item['name']:
                raise CheckError('migration_conflict', '旧站点别名有冲突，未迁移', 'domains.json')
            if alias in sites and alias != item['name']:
                raise CheckError('migration_conflict', '别名覆盖了独立站点配置，未迁移', 'domains.json')
            owners[alias] = item['name']
            aliases[alias] = item['name']
    if 'url_black' not in config:
        # Original 8.4 always enforces this table using the GET response status.
        config['url_black'] = {'open': True, 'status': config.get('get', {}).get('status', 403)}
    if config.get('compatibility_profile') not in (None, DOMESTIC_PROFILE):
        raise CheckError('source_profile', '已有其他来源迁移标记，未覆盖', 'config.json')
    config['compatibility_profile'] = DOMESTIC_PROFILE
    config['site_aliases'] = aliases
    tables = {}
    for name in ('url', 'post', 'args', 'cookie', 'user_agent', 'header', 'user_agent_white'):
        path = runtime / 'rule' / (name + '.json')
        if not path.exists() and not path.is_symlink() and name in ('cookie', 'header', 'user_agent_white'):
            tables[name] = []
            changes['rule/' + name + '.json'] = '[]\n'
        else:
            tables[name] = load(path, list)
        for row in tables[name]:
            if (not isinstance(row, list) or len(row) < 2 or type(row[0]) is not int
                    or row[0] not in (0, 1) or not isinstance(row[1], str)):
                raise CheckError('json_schema', '旧正则规则行不兼容', name + '.json')
    for rule in load(runtime / 'rule/ip_black.json', list):
        if (not isinstance(rule, list) or len(rule) not in (2, 3) or
                any(not isinstance(ip, list) or len(ip) != 4 or
                    any(type(n) is not int or not 0 <= n <= 255 for n in ip) for ip in rule[:2])):
            raise CheckError('json_schema', '旧 IP 黑名单格式不兼容', 'ip_black.json')
        if rule[0] == rule[1] and (len(rule) == 2 or type(rule[2]) is not int or rule[2] <= 0):
            raise CheckError('migration_conflict', '单 IP 黑名单没有明确到期时间，请先人工确认时长；未改成临时封禁', 'ip_black.json')
    for name, site in sites.items():
        if not safe_name(name) or not isinstance(site, dict):
            raise CheckError('json_schema', '旧站点配置不兼容', 'site.json')
        disabled = site.get('disable_rule')
        if not isinstance(disabled, dict) or not all(
                kind in disabled for kind in ('url', 'post', 'args', 'cookie', 'user_agent')):
            raise CheckError('json_schema', '旧站点规则例外结构不兼容', 'site.json')
        if (any(disabled.values()) and
                any(row[0] == 0 for kind in ('url', 'post', 'args', 'cookie', 'user_agent') for row in tables[kind])):
            raise CheckError('migration_conflict', '原版后台与运行时的规则例外序号含义冲突，请先人工核对，未猜测转换', 'site.json')
        if disabled.get('post', []) != disabled.get('args', []):
            raise CheckError('migration_conflict', '原版多值 GET 与 POST 例外存在交叉引用，无法无歧义迁移，请先人工核对', 'site.json')
        def invalid_site(field):
            raise CheckError('json_schema', '旧站点配置字段缺失或类型不兼容：' + field, 'site.json')
        for field in ('open', 'log', 'cdn', 'get', 'post', 'cookie', 'user-agent', 'scan', 'drop_abroad'):
            if type(site.get(field)) is not bool: invalid_site(field)
        for field in ('retry', 'retry_cycle', 'retry_time'):
            if type(site.get(field)) is not int or not 1 <= site[field] <= 2147483647: invalid_site(field)
        cc = site.get('cc')
        if not isinstance(cc, dict) or type(cc.get('open')) is not bool: invalid_site('cc.open')
        for field in ('cycle', 'limit', 'endtime'):
            if type(cc.get(field)) is not int or not 1 <= cc[field] <= 2147483647: invalid_site('cc.' + field)
        for field in ('cdn_header', 'disable_php_path', 'disable_path', 'disable_ext', 'disable_upload_ext', 'url_white'):
            if not isinstance(site.get(field), list) or not all(isinstance(value, str) for value in site[field]):
                invalid_site(field)
        for field, length in (('url_rule', 2), ('url_tell', 3)):
            if (not isinstance(site.get(field), list) or any(
                    not isinstance(row, list) or len(row) != length or
                    not all(isinstance(value, str) for value in row) for row in site[field])):
                invalid_site(field)
        for field in ('cdn_baidu',):
            if field in site and type(site[field]) is not bool: invalid_site(field)
        if 'increase' in cc and type(cc['increase']) is not bool: invalid_site('cc.increase')
        if 'cdn_trusted_proxy' in site:
            ranges = site['cdn_trusted_proxy']
            if not isinstance(ranges, list): invalid_site('cdn_trusted_proxy')
            for row in ranges:
                if (not isinstance(row, list) or len(row) != 2 or any(
                        not isinstance(ip, list) or len(ip) != 4 or any(type(n) is not int or not 0 <= n <= 255 for n in ip)
                        for ip in row) or row[0] > row[1]):
                    invalid_site('cdn_trusted_proxy')
        for field in ('registration_guard', 'repeat_ban_policy', 'endpoint_limits'):
            if field in site: invalid_site(field)
        for kind in ('url', 'post', 'args', 'cookie', 'user_agent', 'header'):
            offsets = disabled.get(kind, [])
            if not isinstance(offsets, list) or any(type(i) is not int or i < 0 for i in offsets):
                raise CheckError('json_schema', '旧站点规则例外序号无效', 'site.json')
            positions = [i for i, row in enumerate(tables[kind]) if row[0] == 1]
            if any(i >= len(positions) for i in offsets):
                raise CheckError('migration_conflict', '旧站点规则例外超出有效规则范围', 'site.json')
            disabled[kind] = list(offsets)
        if site.get('cdn'):
            if not isinstance(site.get('cdn_header'), list) or not all(isinstance(h, str) for h in site['cdn_header']):
                raise CheckError('json_schema', '旧 CDN 请求头配置不兼容', 'site.json')
            site['cdn_header_order'] = 'first' if site.get('cdn_baidu') else 'last'
    changes['config.json'] = json.dumps(config, ensure_ascii=True) + '\n'
    if sites != load(runtime / 'site.json', dict):
        changes['site.json'] = json.dumps(sites, ensure_ascii=True) + '\n'
    return changes

def migration_entries(runtime):
    entries = {}
    for name, candidate in domestic_plan(runtime).items():
        path = runtime / name
        for parent in (path, *path.parents):
            if parent.is_symlink():
                raise CheckError('unsafe_resource', '迁移路径包含符号链接', path.name)
        exists = path.exists()
        entries[name] = dict(before=base64.b64encode(path.read_bytes()).decode('ascii') if exists else None,
                             original=fingerprint(path) if exists else None, after=candidate, write=None)
    return entries

def migration_guards(runtime):
    sources = ['config.json', 'site.json', 'domains.json']
    sources += ['rule/' + name + '.json' for name in (
        'cn', 'scan_black', 'ip_black', 'ip_white', 'url_white', 'url_black',
        'user_agent_white', 'user_agent', 'header', 'post', 'cookie', 'args', 'url', 'head_white')]
    return {name: fingerprint(runtime / name) if (runtime / name).exists() else None for name in sources}

def migration_digest(entries, runtime):
    guards = migration_guards(runtime)
    return hashlib.sha256(json.dumps([entries, guards], sort_keys=True).encode('utf-8')).hexdigest()

def verify_no_pending_migration(runtime):
    for path in runtime.glob('.gpt-firewall-backup.*/compatibility-migration.json'):
        if path.parent.is_symlink() or path.is_symlink():
            raise CheckError('unsafe_resource', '迁移备份路径包含符号链接')
        record = load(path, dict)
        if record.get('state') not in ('committed', 'restored'):
            raise CheckError('migration_conflict', '检测到未完成的兼容迁移，请先核查安装状态和对应备份，不可直接重试')

def save_journal(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.compatibility-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def sync_directory(path):
    if os.name == 'posix':
        fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)

def migration_identity(path):
    if path.is_symlink():
        raise CheckError('migration_conflict', '迁移文件变为符号链接，未覆盖', path.name)
    return fingerprint(path) if path.exists() else None

def prepare_migration_write(path, text, expected, staging):
    if migration_identity(path) != expected:
        raise CheckError('migration_conflict', '迁移文件发生同期变化，未覆盖', path.name)
    if staging.is_symlink() or not staging.is_dir():
        raise CheckError('unsafe_resource', '迁移暂存目录不安全')
    fd, temporary = tempfile.mkstemp(prefix='.compatibility-', dir=str(staging))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(text.encode('utf-8') if isinstance(text, str) else text)
            stream.flush()
            if os.name == 'posix':
                info = path.lstat() if expected is not None else None
                if info: os.fchown(stream.fileno(), info.st_uid, info.st_gid)
                os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode) if info else 0o644)
            os.fsync(stream.fileno())
        sync_directory(staging)
        return dict(name=Path(temporary).name, identity=fingerprint(Path(temporary)))
    except BaseException:
        if os.path.exists(temporary): os.unlink(temporary)
        raise

def publish_migration_write(path, prepared, expected, staging):
    temporary = staging / prepared['name']
    if (temporary.parent != staging or not prepared['name'].startswith('.compatibility-')
            or fingerprint(temporary) != prepared['identity'] or migration_identity(path) != expected):
        raise CheckError('migration_conflict', '迁移发布前文件已改变，未覆盖', path.name)
    os.replace(temporary, path)
    sync_directory(path.parent)
    sync_directory(staging)
    return prepared['identity']

try:
    if mode == 'lock':
        if args[0] == 'acquire':
            lock.mkdir(mode=0o700)
            data = dict(task_id=uuid.uuid4().hex, token=secrets.token_hex(32), pid=int(args[1]))
            with owner_path.open('x', encoding='utf-8') as stream:
                json.dump(data, stream)
            print(data['task_id'], data['token'])
        elif args[0] == 'inherit':
            data = owner()
            if data.get('pid') != int(args[1]):
                raise ValueError('安装锁不属于直接父更新进程')
            descriptor = int(os.environ['GPT_FIREWALL_INSTALL_FD'])
            actual, expected = os.fstat(descriptor), owner_path.stat()
            if (not stat.S_ISREG(actual.st_mode) or
                    (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)):
                raise ValueError('缺少继承的安装锁句柄')
            print(data['task_id'], data['token'])
        elif args[0] == 'release':
            owner()
            owner_path.unlink()
            lock.rmdir()
        else:
            raise ValueError('未知安装锁操作')
    elif mode == 'fingerprint':
        owner()
        proof = fingerprint(Path(args[0]))
        if len(args) > 1 and proof['sha256'] != json.loads(args[1])['sha256']:
            raise ValueError('原始运行文件与备份摘要不一致')
        print(json.dumps(proof))
    elif mode == 'policy_lock':
        if args[0] == 'supported':
            sys.exit(0 if os.name == 'posix' else 1)
        path = mapped('/www/server/free_waf/.endpoint-policy.lock')
        if args[0] == 'prepare':
            descriptor = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        else:
            descriptor = os.dup(int(args[1]))
        try:
            info, linked = os.fstat(descriptor), path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)):
                raise CheckError('migration_conflict', '配置锁身份不安全，未迁移')
        finally: os.close(descriptor)
    elif mode == 'prepare_storage':
        owner()
        runtime = mapped('/www/server/free_waf')
        backup = Path(args[0])
        rows = directives(sys.stdin.read())
        users = [row for row in rows if row and row[0] == 'user']
        if len(users) > 1 or not users and not root:
            raise CheckError('storage_permissions', '无法唯一确认 Nginx 工作进程身份，未准备运行存储', 'runtime_directory')
        if os.name == 'posix' and users:
            import pwd, grp
            if len(users[0]) not in (2, 3):
                raise CheckError('storage_permissions', 'Nginx 工作进程身份格式不兼容', 'runtime_directory')
            account = pwd.getpwnam(users[0][1])
            uid, gid = account.pw_uid, grp.getgrnam(users[0][2]).gr_gid if len(users[0]) == 3 else account.pw_gid
            if not root and uid == 0:
                raise CheckError('storage_permissions', '不为 root 工作进程准备存储', 'runtime_directory')
        else:
            uid, gid = getattr(os, 'geteuid', lambda: 0)(), getattr(os, 'getegid', lambda: 0)()
        def regular(path):
            for part in (path, *path.parents):
                if part.is_symlink():
                    raise CheckError('unsafe_resource', '运行存储路径包含符号链接', 'runtime_directory')
            descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise CheckError('unsafe_resource', '运行存储不是独占普通文件', path.name)
                body = stream.read()
                current = path.lstat()
                if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                    raise CheckError('storage_permissions', '读取期间运行存储被替换', path.name)
            return body, info
        def set_metadata(path, expected, owner_uid, owner_gid, mode=None, directory=False):
            # Apply privileges to the verified inode, never to a replaceable pathname.
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if directory:
                flags |= os.O_DIRECTORY
            descriptor = os.open(path, flags)
            try:
                info = os.fstat(descriptor)
                if ((info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino) or
                        (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))):
                    raise CheckError('storage_permissions', '权限准备前运行存储被替换', path.name)
                os.fchown(descriptor, owner_uid, owner_gid)
                if mode is not None:
                    os.fchmod(descriptor, mode)
                linked = path.lstat()
                if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
                    raise CheckError('storage_permissions', '权限准备期间运行存储被替换', path.name)
            finally:
                os.close(descriptor)
        rule_directory = runtime / 'rule'
        state_directory = runtime / '.statistics'
        if rule_directory.is_symlink() or state_directory.is_symlink():
            raise CheckError('unsafe_resource', '运行存储目录不能为符号链接', 'runtime_directory')
        blacklist = rule_directory / 'ip_black.json'
        original, original_info = regular(blacklist)
        total = state_directory / 'total.json'
        legacy, legacy_info = regular(runtime / 'total.json')
        state_directory.mkdir(mode=0o700, exist_ok=True)
        if not state_directory.is_dir():
            raise CheckError('unsafe_resource', '统计存储不是目录', 'runtime_directory')
        descriptors = []
        try:
            for target in (blacklist, total):
                lock_path = target.with_name(target.name + '.lock')
                descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
                descriptors.append(descriptor)
                info = os.fstat(descriptor)
                linked = lock_path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)):
                    raise CheckError('unsafe_resource', '运行存储锁不是独占普通文件', 'runtime_directory')
                if os.name == 'posix':
                    import fcntl
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Persist original metadata before touching existing data permissions.
            metadata = {}
            for path in (blacklist, rule_directory, state_directory, runtime / 'total.json'):
                info = path.stat()
                metadata[str(path)] = dict(uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))
            metadata['blacklist_sha256'] = hashlib.sha256(original).hexdigest()
            metadata['legacy_total_sha256'] = hashlib.sha256(legacy).hexdigest()
            with (backup / 'storage-migration.json').open('x', encoding='utf-8') as stream:
                json.dump(metadata, stream)
            os.chmod(backup / 'storage-migration.json', 0o600)
            if not total.exists():
                values = json.loads(legacy)
                if not isinstance(values, dict) or not isinstance(values.get('sites'), dict) or not isinstance(values.get('rules'), dict):
                    raise CheckError('json_schema', '旧统计快照不兼容，未迁移', 'total.json')
                fd, temporary = tempfile.mkstemp(prefix='.total-', dir=state_directory)
                try:
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(legacy)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, total)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
            total_body, total_info = regular(total)
            values = json.loads(total_body)
            if not isinstance(values, dict) or not isinstance(values.get('sites'), dict) or not isinstance(values.get('rules'), dict):
                raise CheckError('json_schema', '已迁移统计损坏，未退回旧快照', 'total.json')
            if regular(blacklist)[0] != original:
                raise CheckError('storage_permissions', '迁移前黑名单发生同期变化，未改权限', 'ip_black.json')
            if os.name == 'posix':
                set_metadata(blacklist, original_info, uid, gid)
                rule_info = rule_directory.lstat()
                set_metadata(rule_directory, rule_info, rule_info.st_uid, gid, 0o770, directory=True)
                set_metadata(total, total_info, uid, gid, 0o600)
                state_info = state_directory.lstat()
                set_metadata(state_directory, state_info, uid, gid, 0o700, directory=True)
                for descriptor, target in zip(descriptors, (blacklist, total)):
                    mode_bits = stat.S_IMODE(target.stat().st_mode)
                    lock_mode = 0o600 | (0o060 if mode_bits & 0o020 else 0) | (0o006 if mode_bits & 0o002 else 0)
                    os.fchown(descriptor, uid, gid)
                    os.fchmod(descriptor, lock_mode)
            # Old workers may legitimately keep updating the legacy snapshot until reload.
            if regular(blacklist)[0] != original:
                raise CheckError('storage_permissions', '存储迁移内容核验失败，请检查备份', 'runtime_directory')
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
    elif mode == 'migrate_domestic':
        owner()
        if os.environ.get('GPT_FIREWALL_SOURCE_PROFILE') == DOMESTIC_PROFILE:
            runtime = mapped('/www/server/free_waf')
            entries = migration_entries(runtime)
            if migration_digest(entries, runtime) != os.environ.get('GPT_FIREWALL_MIGRATION_DIGEST'):
                raise CheckError('migration_conflict', '预检后旧配置发生变化，未迁移', 'config.json')
            journal = Path(args[0]) / 'compatibility-migration.json'
            record = dict(profile=DOMESTIC_PROFILE, state='applying', entries=entries, guards=migration_guards(runtime))
            save_journal(journal, record)
            for name, entry in entries.items():
                entry['pending'] = prepare_migration_write(runtime / name, entry['after'], entry['original'], journal.parent)
                save_journal(journal, record)
                entry['write'] = publish_migration_write(runtime / name, entry['pending'], entry['original'], journal.parent)
                save_journal(journal, record)
    elif mode == 'restore_domestic':
        owner()
        journal = Path(args[0]) / 'compatibility-migration.json'
        if not journal.exists():
            print('not_needed')
        else:
            runtime = mapped('/www/server/free_waf')
            record = json.loads(journal.read_text(encoding='utf-8'))
            entries = record['entries']
            verified = {}
            for name, entry in entries.items():
                path = runtime / name
                actual = migration_identity(path)
                allowed = [entry['original'], entry.get('write'), entry.get('pending', {}).get('identity'),
                           entry.get('restore_pending', {}).get('identity'), entry.get('restored_write')]
                if actual not in [value for value in allowed if value is not None] and not (
                        actual is None and entry['original'] is None):
                    raise CheckError('migration_conflict', '数据回退检测到同期修改，请人工核查', path.name)
                verified[name] = actual
            for name, entry in reversed(list(entries.items())):
                path = runtime / name
                actual = migration_identity(path)
                if actual != verified[name]:
                    raise CheckError('migration_conflict', '数据回退执行前文件发生同期修改，未覆盖', path.name)
                if actual == entry['original'] or (
                        actual is not None and actual in [entry.get('restored_write'), entry.get('restore_pending', {}).get('identity')]):
                    continue
                if entry['before'] is None:
                    save_journal(journal, record)
                    if migration_identity(path) != actual:
                        raise CheckError('migration_conflict', '数据回退删除前文件发生同期修改，未删除', path.name)
                    path.unlink()
                    sync_directory(path.parent)
                else:
                    entry['restore_pending'] = prepare_migration_write(path, base64.b64decode(entry['before']), actual, journal.parent)
                    save_journal(journal, record)
                    entry['restored_write'] = publish_migration_write(path, entry['restore_pending'], actual, journal.parent)
                save_journal(journal, record)
            record['state'] = 'restored'
            save_journal(journal, record)
            print('restored')
    elif mode == 'verify_domestic':
        owner()
        journal = Path(args[0]) / 'compatibility-migration.json'
        if journal.exists():
            record, runtime = load(journal, dict), mapped('/www/server/free_waf')
            for name, before in record['guards'].items():
                entry = record['entries'].get(name)
                expected = entry['write'] if entry else before
                if migration_identity(runtime / name) != expected:
                    raise CheckError('migration_conflict', '迁移激活前配置或规则发生同期修改，停止激活', Path(name).name)
    elif mode == 'commit_domestic':
        owner()
        journal = Path(args[0]) / 'compatibility-migration.json'
        if journal.exists():
            record = load(journal, dict)
            record['state'] = 'committed'
            save_journal(journal, record)
    elif mode == 'restore':
        owner()
        target, backup, expected = Path(args[0]), Path(args[1]), json.loads(args[2])
        backup_hash = json.loads(args[3])['sha256']
        try:
            owned = fingerprint(target) == expected
        except (OSError, ValueError):
            owned = False
        try:
            backup_valid = fingerprint(backup)['sha256'] == backup_hash
        except (OSError, ValueError):
            backup_valid = False
        if not owned:
            print('conflict')
        elif not backup_valid:
            print('backup_invalid')
        else:
            fd, name = tempfile.mkstemp(prefix='.gpt-firewall-restore.', dir=str(target.parent))
            os.close(fd)
            try:
                shutil.copy2(backup, name)
                if os.name == 'posix':
                    info = backup.stat()
                    os.chown(name, info.st_uid, info.st_gid)
                if fingerprint(Path(name))['sha256'] != backup_hash:
                    print('backup_invalid')
                elif fingerprint(target) != expected:
                    print('conflict')
                else:
                    os.replace(name, target)
                    print('restored')
            finally:
                if os.path.exists(name):
                    os.unlink(name)
    elif mode == 'status':
        identity = owner()
        outcome, operation, stage, message, changed, loaded, rollback, backup, diagnostic = args
        target = plugin / 'install-status.json'
        if target.is_symlink():
            raise ValueError('安装状态文件路径不安全')
        data = dict(product='aapanel GPT Firewall', version='0.1.9', plugin_name='free_waf',
                    status=outcome, operation=operation, stage=stage, message=message,
                    task_id=identity['task_id'],
                    runtime_write=json.loads(os.environ.get('GPT_FIREWALL_RUNTIME_WRITE') or 'null'),
                    runtime_backup_sha256=json.loads(os.environ.get('GPT_FIREWALL_RUNTIME_BACKUP') or '{}').get('sha256'),
                    runtime_changed=changed == 'true', waf_active=loaded == 'true',
                    rollback=rollback, runtime_backup=backup or None,
                    source_profile=os.environ.get('GPT_FIREWALL_SOURCE_PROFILE', 'unidentified'),
                    data_rollback=os.environ.get('GPT_FIREWALL_DATA_ROLLBACK', 'not_needed'),
                    data_migration_backup=Path(backup).name if backup and os.environ.get('GPT_FIREWALL_SOURCE_PROFILE') == DOMESTIC_PROFILE else None,
                    compatibility_warnings=(['使用 GPT 检测引擎，不等同原版 8.4：JSON 正文、上传内容、爬虫验证和旧算术挑战不作等价迁移；普通命中不自动升级封禁，CC 使用 GPT 的限时策略。',
                                             '已有站点别名与 CDN 取值方向保留；未来新增域名需核对站点归属。旧内存封禁与日志不能当作完整活动封禁快照。']
                                            if os.environ.get('GPT_FIREWALL_SOURCE_PROFILE') == DOMESTIC_PROFILE else []),
                    plugin_rollback_available=False, lua_execution_verified=False,
                    warning='面板在安装钩子之前已覆盖后端和界面，钩子没有导入前的旧文件；'
                            '面板也可能忽略安装失败。Nginx 配置测试不等于 Lua 执行验证，'
                            '重载命令成功只确认信号已发出，仍需人工检查工作进程和业务。')
        if outcome == 'failed' and diagnostic:
            detail = json.loads(diagnostic)
            if isinstance(detail, dict) and detail.get('code') in diagnostic_codes:
                data['diagnostic_code'] = detail['code']
                if detail.get('resource') in resources:
                    data['diagnostic_resource'] = detail['resource']
        fd, name = tempfile.mkstemp(prefix='.install-status-', dir=str(plugin))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(data, stream, ensure_ascii=True, indent=2)
                stream.write('\n')
            owner()
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    elif mode == 'active':
        print('true' if active(sys.stdin.read()) else 'false')
    elif mode == 'preflight':
        file(mapped('/www/server/nginx/conf/nginx.conf'))
        include = mapped('/www/server/panel/vhost/nginx/free_waf.conf')
        # Missing integration is allowed only as a code upgrade, never auto-created.
        if include.exists() or include.is_symlink():
            active(file(include).read_text(encoding='utf-8'), required=True)
        if args[0] == 'install':
            runtime = mapped('/www/server/free_waf')
            if runtime.is_symlink() or not runtime.is_dir():
                raise CheckError('runtime_incomplete', '需要完整的既有运行目录，不支持首次安装', 'runtime_directory')
            verify_no_pending_migration(runtime)
            for name in ('init.lua', 'free_waf_main.py', 'report_store.py', 'ban_store.py',
                         'website_statistics.py', 'update_service.py', 'index.html', 'info.json', 'rule.json'):
                file(plugin / name)
            info = load(plugin / 'info.json', dict)
            if info.get('name') != 'free_waf' or info.get('versions') != '0.1.9':
                raise CheckError('package_identity', '需要内部标识为 free_waf、版本为 0.1.9 的兼容升级包', 'info.json')
            load(plugin / 'rule.json', list)
            for name in ('init.lua', 'waf.lua', 'drop_ip.log'):
                path = runtime / name
                if path.is_symlink() or not path.is_file():
                    raise CheckError('missing_resource', '必要的既有运行资源缺失或不安全：' + name, name)
                if name.endswith('.lua'):
                    file(path)
            for path in (plugin / 'init.lua', runtime / 'init.lua'):
                source = path.read_text(encoding='utf-8-sig')
                if not re.search(r'''\bcpath\s*=\s*["']/www/server/free_waf/["']''', source) or not re.search(r'function\s+run_btwaf\s*\(', source):
                    raise CheckError('runtime_entrypoint', '旧版 init.lua 入口不兼容', 'init.lua')
            if not re.search(r'\brun_btwaf\s*\(\s*\)', (runtime / 'waf.lua').read_text(encoding='utf-8-sig')):
                raise CheckError('runtime_entrypoint', '既有 waf.lua 入口不兼容', 'waf.lua')
            config = load(runtime / 'config.json', dict)
            profile = source_profile(runtime)
            candidates = domestic_plan(runtime) if profile == DOMESTIC_PROFILE else {}
            if 'config.json' in candidates:
                config = json.loads(candidates['config.json'])
            load(runtime / 'site.json', dict)
            totals = load(runtime / 'total.json', dict)
            if not isinstance(totals.get('sites'), dict) or not isinstance(totals.get('rules'), dict):
                raise CheckError('json_schema', '旧版统计数据结构不兼容', 'total.json')
            for key in ('open', 'retry', 'retry_time', 'retry_cycle', 'cc', 'scan', 'drop_abroad', 'url_black'):
                if key not in config:
                    raise CheckError('config_incomplete', '旧版配置缺少必要字段', 'config.json')
            if not isinstance(config['cc'], dict):
                raise CheckError('config_incomplete', '旧版 CC 配置不完整', 'config.json')
            for key in ('cycle', 'endtime', 'limit', 'status', 'open'):
                if key not in config['cc']:
                    raise CheckError('config_incomplete', '旧版 CC 配置不完整', 'config.json')
            templates = mapped(config.get('reqfile_path'))
            logs = mapped(config.get('logs_path'))
            if not templates.is_dir() or not logs.is_dir():
                raise CheckError('missing_resource', '既有响应模板或日志目录缺失')
            for key in ('get', 'post', 'cookie', 'user-agent', 'other'):
                item = config.get(key)
                required = ('reqfile', 'status') if key == 'other' else ('reqfile', 'status', 'open')
                if not isinstance(item, dict) or not all(k in item for k in required):
                    raise CheckError('response_template', '响应模板配置不完整', 'config.json')
                name = item['reqfile']
                if not isinstance(name, str) or Path(name).name != name:
                    raise CheckError('unsafe_resource', '响应模板文件名不安全', 'response_template')
                file(templates / name)
            scan_black = load(runtime / 'rule' / 'scan_black.json', dict)
            for key in ('cookie', 'args', 'header'):
                value = scan_black.get(key)
                if not (isinstance(value, str) or
                        isinstance(value, list) and all(isinstance(rule, str) for rule in value)):
                    raise CheckError('scan_rules', '扫描器规则结构不兼容：scan_black.json', 'scan_black.json')
            for name in ('cn', 'ip_black', 'ip_white', 'url_white', 'url_black',
                         'user_agent_white', 'user_agent', 'header', 'post', 'cookie', 'args', 'url', 'head_white'):
                key = 'rule/' + name + '.json'
                if key not in candidates:
                    load(runtime / key, list)
            print(json.dumps({'source_profile': profile,
                              'migration_digest': migration_digest(migration_entries(runtime), runtime) if candidates else ''}))
    else:
        raise ValueError('未知的安装器辅助操作')
except Exception as error:
    print('离线兼容预检或状态记录失败：' + str(error), file=sys.stderr)
    if mode in ('preflight', 'active', 'prepare_storage'):
        print(json.dumps({'code': error.code if isinstance(error, CheckError) else 'preflight_failed',
                          'resource': error.resource if isinstance(error, CheckError) else ''}))
    sys.exit(1)
PY
helper() { "$python" -B "$helper_source" "$root" "$plugin" "$@"; }

stage=preflight
message='升级失败；仅支持已安装的 legacy free_waf，请检查现有运行文件和 Nginx 配置。'
changed=false
loaded=false
rollback=not_needed
backup=
temporary=
locked=false
nested=false
diagnostic=
export GPT_FIREWALL_RUNTIME_WRITE=
export GPT_FIREWALL_RUNTIME_BACKUP=
export GPT_FIREWALL_SOURCE_PROFILE=unidentified
export GPT_FIREWALL_MIGRATION_DIGEST=
export GPT_FIREWALL_DATA_ROLLBACK=not_needed

nginx_test() { "$nginx" -t -p "$nginx_prefix" -c "$nginx_conf"; }
nginx_reload() { "$nginx" -s reload -p "$nginx_prefix" -c "$nginx_conf"; }
fail() { message=$1; diagnostic=${2:-$diagnostic}; printf '%s\n' "$message" >&2; exit 1; }

finish() {
    local code=$? outcome=success
    trap - EXIT INT TERM
    if [[ $code != 0 ]]; then
        outcome=failed
        if [[ -n $backup && -f $backup/compatibility-migration.json ]]; then
            if GPT_FIREWALL_DATA_ROLLBACK=$(helper restore_domestic "$backup"); then
                export GPT_FIREWALL_DATA_ROLLBACK
            else
                export GPT_FIREWALL_DATA_ROLLBACK=conflict_or_failed
                message+=' 数据回退发现冲突或失败，保留同期修改和迁移备份；不再重载，请人工核查。'
            fi
        fi
        if [[ $changed == true ]]; then
            rollback=restore_failed
            if rollback=$(helper restore "$runtime/init.lua" "$backup/init.lua" "$GPT_FIREWALL_RUNTIME_WRITE" "$GPT_FIREWALL_RUNTIME_BACKUP"); then
                if [[ $rollback == conflict ]]; then
                    message+=' 检测到运行文件所有权或摘要冲突，保留同期修改和备份；请人工恢复。'
                elif [[ $rollback == backup_invalid ]]; then
                    message+=' 原始备份缺失或摘要不符，未覆盖运行文件、未重载；请人工恢复。'
                elif [[ $rollback == restored && $GPT_FIREWALL_DATA_ROLLBACK == conflict_or_failed ]]; then
                    rollback=restore_data_conflict
                elif [[ $rollback == restored && $loaded == true ]]; then
                    if ! nginx_test; then rollback=restore_test_failed
                    elif ! nginx_reload; then rollback=restore_reload_failed
                    fi
                fi
            else
                rollback=restore_failed
            fi
        fi
    elif [[ -n $backup ]]; then
        if ! helper commit_domestic "$backup"; then
            code=1
            outcome=failed
            message='更新已执行但迁移完成记录未写入；请核查备份与运行状态，不可直接重试。'
        fi
    fi
    [[ -z $temporary || ! -e $temporary ]] || rm -f -- "$temporary"
    if [[ $locked == true ]]; then
        if ! helper status "$outcome" "$operation" "$stage" "$message" "$changed" "$loaded" "$rollback" "$backup" "$diagnostic"; then
            printf '%s\n' '无法写入 install-status.json；保留安装锁，请人工检查。' >&2
            code=1
        elif [[ $nested == false ]]; then
            helper lock release || code=1
        fi
    fi
    rm -f -- "$helper_source"
    printf '%s\n' "$message"
    exit "$code"
}
trap finish EXIT
trap 'message="升级被中断；请检查 install-status.json 和运行文件备份。"; exit 1' INT TERM

if [[ -n ${GPT_FIREWALL_INSTALL_FD:-}${GPT_FIREWALL_INSTALL_TASK:-}${GPT_FIREWALL_INSTALL_TOKEN:-} ]]; then
    credentials=$(helper lock inherit "$PPID") || fail '无法认证父更新任务的安装锁，未更新运行文件或状态。'
    nested=true
else
    credentials=$(helper lock acquire "$$") || fail '已有安装任务或遗留锁，请先检查后再重试。'
fi
read -r GPT_FIREWALL_INSTALL_TASK GPT_FIREWALL_INSTALL_TOKEN <<< "$credentials"
export GPT_FIREWALL_INSTALL_TASK GPT_FIREWALL_INSTALL_TOKEN
unset credentials
locked=true
[[ $operation == install || $operation == uninstall ]] || fail '仅支持 install（兼容升级）或 uninstall。'
# Repair importer mode 600 without exposing private update/backup directories.
[[ ! -L $plugin/html && ! -L $plugin/docs && ! -L $plugin/docs/images ]] || fail '文档或模板目录包含符号链接，未修复目录权限。'
find "$plugin" -path "$plugin/.gpt-firewall-install.lock" -prune -o -type d -perm 0600 -exec chmod 700 {} \;
for directory in "$plugin/html" "$plugin/docs" "$plugin/docs/images"; do
    if [[ -d $directory && ! -L $directory ]]; then chmod 755 "$directory"; fi
done
helper status running "$operation" "$stage" "$message" false false "$rollback" '' ''
[[ -x $nginx && ! -L $nginx ]] || fail '缺少 aaPanel 自带 Nginx；未更新运行文件。'
if [[ $operation == install && -d $runtime && ! -L $runtime ]] && helper policy_lock supported; then
    command -v flock >/dev/null || fail '缺少配置锁工具，未更新运行文件。'
    helper policy_lock prepare || fail '无法安全准备配置锁，未更新运行文件。'
    exec {policy_descriptor}<>"$runtime/.endpoint-policy.lock"
    flock -n "$policy_descriptor" || fail '站点配置正在修改，未更新运行文件。'
    helper policy_lock verify "$policy_descriptor" || fail '配置锁身份核对失败，未更新运行文件。'
fi
preflight=$(helper preflight "$operation") || { diagnostic=$preflight; exit 1; }
if [[ $operation == install ]]; then
    GPT_FIREWALL_SOURCE_PROFILE=$(printf '%s' "$preflight" | "$python" -c 'import json,sys; print(json.load(sys.stdin)["source_profile"])')
    GPT_FIREWALL_MIGRATION_DIGEST=$(printf '%s' "$preflight" | "$python" -c 'import json,sys; print(json.load(sys.stdin)["migration_digest"])')
fi
nginx_test || fail '现有 Nginx 配置测试失败；未更新运行文件。' '{"code":"nginx_test_failed","resource":"nginx.conf"}'
dump=$("$nginx" -T -p "$nginx_prefix" -c "$nginx_conf" 2>/dev/null) || fail '无法安全读取 Nginx 生效配置；未更新运行文件。'
if loaded=$(printf '%s\n' "$dump" | helper active); then
    diagnostic=
else
    diagnostic=$loaded
    loaded=false
    exit 1
fi

if [[ $operation == uninstall ]]; then
    unset dump
    [[ $loaded == false ]] || fail '防火墙仍被 Nginx 引用，请先手动停用 free_waf include、测试并重载 Nginx 后再卸载；不会删除运行目录或状态。面板可能忽略失败并删除插件目录。'
    stage=complete
    message='插件卸载检查完成；运行代码、配置、规则、日志及封禁状态全部保留，未重载 Nginx。'
    exit 0
fi

stage=backup
backup=$(mktemp -d "$runtime/.gpt-firewall-backup.XXXXXX")
GPT_FIREWALL_RUNTIME_BACKUP=$(helper fingerprint "$runtime/init.lua")
cp -p "$runtime/init.lua" "$backup/init.lua"
helper fingerprint "$backup/init.lua" "$GPT_FIREWALL_RUNTIME_BACKUP" >/dev/null
stage=data_migration
helper migrate_domestic "$backup" || fail '国内版数据迁移失败；将按本次迁移清单回退，请核查备份。'
stage=storage_preparation
diagnostic=$(printf '%s\n' "$dump" | helper prepare_storage "$backup") || fail '无法安全准备运行存储，未替换运行代码；请核查本次备份。' "$diagnostic"
unset dump
diagnostic=
if cmp -s "$plugin/init.lua" "$runtime/init.lua"; then
    stage=complete
    message='兼容升级检查完成；已核对运行存储，init.lua 相同，未覆盖或重载 Nginx。'
    exit 0
fi
temporary=$(mktemp "$runtime/.gpt-firewall-init.XXXXXX")
cp -p "$runtime/init.lua" "$temporary"
cp "$plugin/init.lua" "$temporary"
cmp -s "$backup/init.lua" "$runtime/init.lua" || fail '运行代码在升级期间发生变化；未覆盖，请重试。'
stage=runtime_update
GPT_FIREWALL_RUNTIME_WRITE=$(helper fingerprint "$temporary")
changed=true
mv -f "$temporary" "$runtime/init.lua"
temporary=
stage=nginx_test
nginx_test || fail '更新后的 Nginx 测试失败；将恢复原 init.lua。' '{"code":"nginx_test_failed","resource":"nginx.conf"}'
helper verify_domestic "$backup" || fail '兼容迁移激活前核对失败；将尝试有界回退，请核查数据和备份。'
if [[ $loaded == true ]]; then
    stage=nginx_reload
    nginx_reload || fail 'Nginx 重载失败；将恢复原 init.lua 并尝试测试、重载旧版本。' '{"code":"nginx_reload_failed","resource":"nginx.conf"}'
fi
stage=complete
message='离线兼容升级完成；已更新运行 init.lua 并准备专用统计存储与数据权限，配置、规则内容、站点、日志及封禁状态未改动。'
if [[ $GPT_FIREWALL_SOURCE_PROFILE == bt-free-waf-8.4 ]]; then
    message='国内第三方 8.4 兼容升级完成；仅补齐已核验的缺失字段、域名别名及 CDN 取值方向，保留无歧义的规则例外；原配置与规则已独立备份，检测行为差异请查看安装状态中的兼容提示。'
fi
if [[ $loaded == false ]]; then
    message+=' 防护保持未启用，未创建接入配置、未重载 Nginx；新的 Lua 尚未经活动 Nginx 执行验证。'
fi
