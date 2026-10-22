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
find "$plugin" -type d -exec chmod 755 {} \;
[[ $(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) == "$plugin" ]] || exit 1

python="$root/www/server/panel/pyenv/bin/python"
if [[ ! -x $python ]]; then
    python=$(command -v python3) || {
        printf '%s\n' '缺少 Python 3，无法校验或写入 install-status.json；未更新运行文件。' >&2
        exit 1
    }
fi

# Only JSON/schema checks and status serialization run in Python; no plugin imports.
helper() {
    "$python" -B -c "$(cat <<'PY'
import json, os, re, shlex, sys, tempfile
from pathlib import Path

root, plugin, mode, *args = sys.argv[1:]
plugin = Path(plugin)

def mapped(name):
    if not isinstance(name, str) or not name.startswith('/'):
        raise ValueError('旧运行资源必须使用绝对路径')
    result = Path(root + name)
    if root and os.path.commonpath([str(Path(root).resolve()), str(result.resolve())]) != str(Path(root).resolve()):
        raise ValueError('资源路径超出隔离测试目录')
    return result

def file(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError('必要的既有资源缺失或不安全：' + path.name)
    return path

def load(path, kind):
    data = json.loads(file(path).read_text(encoding='utf-8-sig'))
    if not isinstance(data, kind):
        raise ValueError('JSON 结构不兼容：' + path.name)
    return data

def directives(body):
    lexer = shlex.shlex(body, posix=True, punctuation_chars=';{}')
    lexer.whitespace_split = True
    return list(lexer)

def active(body, required=False):
    tokens = directives(body)
    def values(key):
        return [tokens[i + 1] for i, token in enumerate(tokens[:-1]) if token == key]
    init = '/www/server/free_waf/init.lua'
    access = '/www/server/free_waf/waf.lua'
    relevant = any('/www/server/free_waf/' in token for token in tokens)
    if relevant or required:
        if values('init_by_lua_file') != [init] or values('access_by_lua_file') != [access]:
            raise ValueError('存在未知或冲突的 Lua 入口，不会改写引用配置')
        shared = values('lua_shared_dict')
        if any(shared.count(name) != 1 for name in ('free_waf', 'free_waf_drop_ip', 'free_waf_drop_sum')):
            raise ValueError('旧版 Lua 共享字典缺失或冲突')
    return relevant

try:
    if mode == 'status':
        outcome, operation, stage, message, changed, loaded, rollback, backup = args
        target = plugin / 'install-status.json'
        if target.is_symlink():
            raise ValueError('安装状态文件路径不安全')
        data = dict(product='aapanel GPT Firewall', version='0.1.1', plugin_name='free_waf',
                    status=outcome, operation=operation, stage=stage, message=message,
                    runtime_changed=changed == 'true', waf_active=loaded == 'true',
                    rollback=rollback, runtime_backup=backup or None,
                    plugin_rollback_available=False, lua_execution_verified=False,
                    warning='面板在安装钩子之前已覆盖后端和界面，钩子没有导入前的旧文件；'
                            '面板也可能忽略安装失败。Nginx 配置测试不等于 Lua 执行验证，'
                            '重载命令成功只确认信号已发出，仍需人工检查工作进程和业务。')
        fd, name = tempfile.mkstemp(prefix='.install-status-', dir=str(plugin))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(data, stream, ensure_ascii=True, indent=2)
                stream.write('\n')
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    elif mode == 'active':
        print('true' if active(sys.stdin.read()) else 'false')
    elif mode == 'preflight':
        file(mapped('/www/server/nginx/conf/nginx.conf'))
        include = mapped('/www/server/panel/vhost/nginx/free_waf.conf')
        if include.exists() or args[0] == 'install':
            active(file(include).read_text(encoding='utf-8'), required=True)
        if args[0] == 'install':
            runtime = mapped('/www/server/free_waf')
            if runtime.is_symlink() or not runtime.is_dir():
                raise ValueError('需要完整的既有运行目录，不支持首次安装')
            for name in ('init.lua', 'free_waf_main.py', 'report_store.py', 'ban_store.py',
                         'website_statistics.py', 'update_service.py', 'index.html', 'info.json', 'rule.json'):
                file(plugin / name)
            info = load(plugin / 'info.json', dict)
            if info.get('name') != 'free_waf' or info.get('versions') != '0.1.1':
                raise ValueError('需要内部标识为 free_waf、版本为 0.1.1 的兼容升级包')
            load(plugin / 'rule.json', list)
            for name in ('init.lua', 'waf.lua', 'drop_ip.log'):
                path = runtime / name
                if path.is_symlink() or not path.is_file():
                    raise ValueError('必要的既有运行资源缺失：' + name)
                if name.endswith('.lua'):
                    file(path)
            for path in (plugin / 'init.lua', runtime / 'init.lua'):
                source = path.read_text(encoding='utf-8-sig')
                if not re.search(r'''\bcpath\s*=\s*["']/www/server/free_waf/["']''', source) or not re.search(r'function\s+run_btwaf\s*\(', source):
                    raise ValueError('旧版 init.lua 入口不兼容')
            if not re.search(r'\brun_btwaf\s*\(\s*\)', (runtime / 'waf.lua').read_text(encoding='utf-8-sig')):
                raise ValueError('既有 waf.lua 入口不兼容')
            config = load(runtime / 'config.json', dict)
            load(runtime / 'site.json', dict)
            totals = load(runtime / 'total.json', dict)
            if not isinstance(totals.get('sites'), dict) or not isinstance(totals.get('rules'), dict):
                raise ValueError('旧版统计数据结构不兼容')
            for key in ('open', 'retry', 'retry_time', 'retry_cycle', 'cc', 'scan', 'drop_abroad', 'url_black'):
                if key not in config:
                    raise ValueError('旧版配置缺少字段：' + key)
            for key in ('cycle', 'endtime', 'limit', 'status', 'open'):
                if key not in config['cc']:
                    raise ValueError('旧版 CC 配置不完整')
            templates = mapped(config.get('reqfile_path'))
            logs = mapped(config.get('logs_path'))
            if not templates.is_dir() or not logs.is_dir():
                raise ValueError('既有响应模板或日志目录缺失')
            for key in ('get', 'post', 'cookie', 'user-agent', 'other'):
                item = config.get(key)
                required = ('reqfile', 'status') if key == 'other' else ('reqfile', 'status', 'open')
                if not isinstance(item, dict) or not all(k in item for k in required):
                    raise ValueError('响应模板配置不完整')
                name = item['reqfile']
                if not isinstance(name, str) or Path(name).name != name:
                    raise ValueError('响应模板文件名不安全')
                file(templates / name)
            scan_black = load(runtime / 'rule' / 'scan_black.json', dict)
            for key in ('cookie', 'args', 'header'):
                value = scan_black.get(key)
                if not (isinstance(value, str) or
                        isinstance(value, list) and all(isinstance(rule, str) for rule in value)):
                    raise ValueError('扫描器规则结构不兼容：scan_black.json：' + key)
            for name in ('cn', 'ip_black', 'ip_white', 'url_white', 'url_black',
                         'user_agent_white', 'user_agent', 'header', 'post', 'cookie', 'args', 'url', 'head_white'):
                load(runtime / 'rule' / (name + '.json'), list)
    else:
        raise ValueError('未知的安装器辅助操作')
except Exception as error:
    print('离线兼容预检或状态记录失败：' + str(error), file=sys.stderr)
    sys.exit(1)
PY
)" "$root" "$plugin" "$@"
}

stage=preflight
message='升级失败；仅支持已安装的 legacy free_waf，请检查现有运行文件和 Nginx 配置。'
changed=false
loaded=false
rollback=not_needed
backup=
temporary=
locked=false

nginx_test() { "$nginx" -t -p "$nginx_prefix" -c "$nginx_conf"; }
nginx_reload() { "$nginx" -s reload -p "$nginx_prefix" -c "$nginx_conf"; }
fail() { message=$1; printf '%s\n' "$message" >&2; exit 1; }

finish() {
    local code=$? outcome=success restore=
    trap - EXIT INT TERM
    if [[ $code != 0 ]]; then
        outcome=failed
        if [[ $changed == true ]]; then
            rollback=restore_failed
            restore=$(mktemp "$runtime/.gpt-firewall-restore.XXXXXX") || restore=
            if [[ -n $restore ]] && cp -p "$backup/init.lua" "$restore" && mv -f "$restore" "$runtime/init.lua"; then
                rollback=restored
                if [[ $loaded == true ]]; then
                    if ! nginx_test; then rollback=restore_test_failed
                    elif ! nginx_reload; then rollback=restore_reload_failed
                    fi
                fi
            fi
            [[ -z $restore || ! -e $restore ]] || rm -f -- "$restore"
        fi
    fi
    [[ -z $temporary || ! -e $temporary ]] || rm -f -- "$temporary"
    [[ $locked == false ]] || rmdir -- "$plugin/.gpt-firewall-install.lock"
    if ! helper status "$outcome" "$operation" "$stage" "$message" "$changed" "$loaded" "$rollback" "$backup"; then
        printf '%s\n' '无法写入 install-status.json；请勿将面板提示视为安装成功。' >&2
        code=1
    fi
    printf '%s\n' "$message"
    exit "$code"
}
trap finish EXIT
trap 'message="升级被中断；请检查 install-status.json 和运行文件备份。"; exit 1' INT TERM

[[ $operation == install || $operation == uninstall ]] || fail '仅支持 install（兼容升级）或 uninstall。'
mkdir "$plugin/.gpt-firewall-install.lock" || fail '已有安装任务或遗留锁，请先检查后再重试。'
locked=true
helper status running "$operation" "$stage" "$message" false false "$rollback" ''
[[ -x $nginx && ! -L $nginx ]] || fail '缺少 aaPanel 自带 Nginx；未更新运行文件。'
helper preflight "$operation"
nginx_test || fail '现有 Nginx 配置测试失败；未更新运行文件。'
dump=$("$nginx" -T -p "$nginx_prefix" -c "$nginx_conf" 2>/dev/null) || fail '无法安全读取 Nginx 生效配置；未更新运行文件。'
loaded=$(printf '%s\n' "$dump" | helper active)
unset dump

if [[ $operation == uninstall ]]; then
    [[ $loaded == false ]] || fail '防火墙仍被 Nginx 引用，请先手动停用 free_waf include、测试并重载 Nginx 后再卸载；不会删除运行目录或状态。面板可能忽略失败并删除插件目录。'
    stage=complete
    message='插件卸载检查完成；运行代码、配置、规则、日志及封禁状态全部保留，未重载 Nginx。'
    exit 0
fi

if cmp -s "$plugin/init.lua" "$runtime/init.lua"; then
    stage=complete
    message='兼容升级检查完成；init.lua 相同，未备份、覆盖或重载 Nginx。'
    exit 0
fi
stage=backup
backup=$(mktemp -d "$runtime/.gpt-firewall-backup.XXXXXX")
cp -p "$runtime/init.lua" "$backup/init.lua"
temporary=$(mktemp "$runtime/.gpt-firewall-init.XXXXXX")
cp -p "$runtime/init.lua" "$temporary"
cp "$plugin/init.lua" "$temporary"
cmp -s "$backup/init.lua" "$runtime/init.lua" || fail '运行代码在升级期间发生变化；未覆盖，请重试。'
stage=runtime_update
changed=true
mv -f "$temporary" "$runtime/init.lua"
temporary=
stage=nginx_test
nginx_test || fail '更新后的 Nginx 测试失败；将恢复原 init.lua。'
if [[ $loaded == true ]]; then
    stage=nginx_reload
    nginx_reload || fail 'Nginx 重载失败；将恢复原 init.lua 并尝试测试、重载旧版本。'
fi
stage=complete
message='离线兼容升级完成；只替换运行 init.lua，配置、规则、站点、日志及封禁状态未改动。'
if [[ $loaded == false ]]; then
    message+=' 当前 include 未加载；未重载，新的 Lua 尚未经活动 Nginx 执行验证。'
fi
