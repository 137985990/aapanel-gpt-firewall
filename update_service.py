"""Fixed-source updates; no scheduler, frontend paths, or arbitrary commands."""
import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zipfile

try:
    import fcntl
except ImportError:
    fcntl = None


PLUGIN_VERSION = '0.1.8'
REPOSITORY = '137985990/aapanel-gpt-firewall'
API_URL = 'https://api.github.com/repos/' + REPOSITORY + '/releases'
DOWNLOAD_URL = 'https://github.com/' + REPOSITORY + '/releases/download/'
PRODUCTION_PLUGIN = Path('/www/server/panel/plugin/free_waf')
CACHE_SECONDS = 6 * 3600
FORCE_SECONDS = 60
NETWORK_SECONDS = 10
MAX_JSON = 2 * 1024 * 1024
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_CHECKSUM = 65536
JOB_STALE_SECONDS = 15 * 60
MANAGED_FILES = (
    'info.json', 'install.sh', 'free_waf_main.py', 'index.html', 'init.lua',
    'ban_store.py', 'report_store.py', 'website_statistics.py', 'update_service.py',
    'html/get.html', 'html/post.html', 'html/cookie.html', 'html/user_agent.html',
    'html/other.html', 'README.md', 'NOTICE.md', 'CHANGELOG.md', 'SECURITY.md',
    'docs/UPGRADE.md', 'docs/UPDATES.md', 'docs/images/overview.png',
)
WARNING = ('SHA256SUMS 与资源摘要来自同一 GitHub 发布，不是独立数字签名。'
           '不会重启面板；完成后请关闭并重新打开插件。Nginx 重载成功只确认信号发送，仍需人工验收。')
_LOCAL_LOCKS = {}
INSTALLER_STAGES = ('preflight', 'backup', 'runtime_update', 'nginx_test', 'nginx_reload', 'complete')
INSTALLER_REASONS = {
    'missing_resource': '必要的既有运行资源缺失。',
    'unsafe_resource': '既有资源路径或符号链接不符合安全要求。',
    'invalid_resource': '必要的既有资源为空或不可用。',
    'invalid_json': '既有 JSON 文件无法解析，未重置数据。',
    'json_schema': '既有 JSON 数据结构不兼容，未重写数据。',
    'integration_conflict': 'Nginx 的 Lua 入口或共享字典缺失、冲突或不兼容。',
    'runtime_incomplete': '旧运行目录不完整，不支持首次安装。',
    'package_identity': '升级包内部标识或版本不匹配。',
    'runtime_entrypoint': '既有 Lua 运行入口不兼容。',
    'config_incomplete': '既有防护配置缺少必要字段。',
    'response_template': '既有响应模板配置不完整。',
    'scan_rules': '既有扫描器规则结构不兼容。',
    'storage_permissions': '运行数据存储权限准备未完成，请检查本机迁移记录，未改防护规则。',
    'preflight_failed': '兼容性检查未通过，请检查本机安装状态。',
    'nginx_test_failed': '宝塔 Nginx 配置检查失败，未确认升级生效。',
    'nginx_reload_failed': '宝塔 Nginx 平滑重载失败，请核对回退结果。',
}
INSTALLER_RESOURCES = frozenset(Path(name).name for name in MANAGED_FILES) | frozenset((
    'nginx.conf', 'free_waf.conf', 'waf.lua', 'rule.json', 'drop_ip.log', 'config.json',
    'site.json', 'total.json', 'scan_black.json', 'cn.json', 'ip_black.json', 'ip_white.json',
    'url_white.json', 'url_black.json', 'user_agent_white.json', 'user_agent.json',
    'header.json', 'post.json', 'cookie.json', 'args.json', 'url.json', 'head_white.json',
    'response_template', 'runtime_directory',
))


class UpdateError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def nginx_directives(body):
    # Keep in sync with the standalone installer; never tokenize Lua as shell.
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


def parse_version(value):
    if not isinstance(value, str) or len(value) > 40 or not re.fullmatch(
            r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?', value):
        raise UpdateError('version', '版本标签必须是数字版本，例如 v0.1.1。')
    numbers = [int(part) for part in value.lstrip('v').split('.')]
    return tuple(numbers + [0] * (3 - len(numbers)))


def _version(value):
    return '.'.join(str(part) for part in parse_version(value))


def _url(url, redirect=False):
    if not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 33 for c in url):
        raise UpdateError('source', '发布资源来源不符合固定仓库限制。')
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.username or parsed.password or parsed.fragment
            or parsed.netloc not in ('api.github.com', 'github.com',
                                     'release-assets.githubusercontent.com', 'objects.githubusercontent.com')):
        raise UpdateError('source', '只允许固定 GitHub 仓库的 HTTPS 发布资源。')
    if parsed.hostname == 'api.github.com':
        valid = not redirect and (url == API_URL + '?per_page=100' or
                                 parsed.path.startswith(urllib.parse.urlsplit(API_URL).path + '/tags/'))
        if valid and '/tags/' in parsed.path:
            tag = parsed.path.rsplit('/', 1)[-1]
            parse_version(tag)
            valid = url == API_URL + '/tags/' + tag
    elif parsed.hostname == 'github.com':
        rest = url[len(DOWNLOAD_URL):] if url.startswith(DOWNLOAD_URL) else ''
        pieces = rest.split('/')
        valid = len(pieces) == 2 and not parsed.query
        if valid:
            parse_version(pieces[0])
            valid = bool(re.fullmatch(r'[A-Za-z0-9._-]+', pieces[1]))
    else:
        valid = redirect and parsed.path.startswith('/github-production-release-asset')
    if not valid:
        raise UpdateError('source', '资源路径或重定向不符合固定仓库限制。')
    return url


class ReleaseRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    max_repeats = 2

    def __init__(self, deadline=None):
        self.deadline = deadline

    def redirect_request(self, request, fp, code, message, headers, newurl):
        if urllib.parse.urlsplit(request.full_url).hostname == 'api.github.com':
            raise UpdateError('redirect', '发布 API 重定向已被拒绝。')
        _url(newurl, redirect=True)
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise UpdateError('timeout', '下载重定向超时，请稍后重试。')
            request.timeout = min(request.timeout, remaining)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def _transport(url, *, timeout, max_bytes):
    _url(url)
    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), ReleaseRedirectHandler(deadline=deadline),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={
        'User-Agent': 'aapanel-gpt-firewall/' + PLUGIN_VERSION,
        'Accept': 'application/vnd.github+json' if url.startswith(API_URL) else 'application/octet-stream',
    })
    with opener.open(request, timeout=timeout) as response:
        _url(response.geturl(), redirect=response.geturl() != url)
        length = response.headers.get('Content-Length')
        if length is not None and (not length.isdigit() or int(length) > max_bytes):
            raise UpdateError('size', '发布资源超过允许的大小。')
        chunks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UpdateError('timeout', '下载超时，请稍后重试。')
            # Bound each socket read by the remaining total request deadline.
            socket = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
            if socket is not None:
                socket.settimeout(remaining)
            block = response.read1(min(65536, max_bytes + 1 - size))
            if not block:
                break
            size += len(block)
            if size > max_bytes:
                raise UpdateError('size', '发布资源超过允许的大小。')
            chunks.append(block)
        if length is not None and size != int(length):
            raise UpdateError('size', '发布资源下载不完整。')
        return b''.join(chunks)


def _isolated_transport(url, *, timeout, max_bytes):
    _url(url)
    if (type(max_bytes) is not int or not 0 < max_bytes <= MAX_ARCHIVE
            or type(timeout) not in (int, float) or not 0 < timeout <= NETWORK_SECONDS):
        raise UpdateError('argument', '网络资源限制参数无效。')
    process = subprocess.Popen([
        sys.executable, '-B', str(Path(__file__).absolute()), '--fetch-url', url,
        '--network-timeout', str(timeout), '--max-bytes', str(max_bytes),
    ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True, shell=False)
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise UpdateError('timeout', '连接或下载超时，已结束独立网络进程，请稍后重试。') from None
    except BaseException:
        process.kill()
        process.communicate()
        raise
    if process.returncode != 0:
        raise UpdateError('network', '无法安全读取固定 GitHub 发布资源，请稍后重试。')
    if not isinstance(output, bytes) or len(output) > max_bytes:
        raise UpdateError('size', '发布资源超过允许的大小。')
    return output


class UpdateService:
    """Callbacks: transport(url, timeout=, max_bytes=), spawn(argv, **Popen options), installer(plugin_dir)."""

    def __init__(self, plugin_dir, *, transport=None, spawn=None, installer=None,
                 test_mode=False, clock=None):
        self.plugin = Path(plugin_dir).absolute()
        self.store = self.plugin / 'data/updates'
        self.runtime = self.plugin.parents[2] / 'free_waf'
        self._transport = transport or _isolated_transport
        self._spawn = spawn or subprocess.Popen
        self._installer = installer or self._run_installer
        self._test_mode = test_mode is True
        self._clock = clock or time.time

    @staticmethod
    def _safe(path, *, directory=False, missing=False):
        path = Path(path).absolute()
        current = Path(path.anchor)
        for index, part in enumerate(path.parts[1:]):
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                if missing:
                    continue
                raise UpdateError('path', '必要文件或目录缺失，请先检查既有安装。')
            last = index == len(path.parts) - 2
            if stat.S_ISLNK(info.st_mode) or (not last or directory) and not stat.S_ISDIR(info.st_mode):
                raise UpdateError('path', '文件路径含符号链接或异常父目录，已停止更新。')
            if last and not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise UpdateError('path', '受管文件不是安全的普通文件，已停止更新。')
        return path

    def _mkdir(self, path):
        self._safe(path, directory=True, missing=True)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._safe(path, directory=True)

    def _read(self, path, limit=MAX_FILE):
        self._safe(path)
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise UpdateError('size', '既有文件或状态记录超过安全大小上限。')
        return data

    def _json(self, path):
        data = json.loads(self._read(path, MAX_JSON).decode('utf-8-sig'))
        if not isinstance(data, dict):
            raise UpdateError('schema', '本地更新状态结构异常，请人工检查。')
        return data

    def _atomic_write(self, path, data, *, metadata=None, mode=0o600, preserve_times=True,
                      ownership=None, expected_write=None):
        path = Path(path)
        self._mkdir(path.parent)
        self._safe(path, missing=True)
        descriptor, temporary = tempfile.mkstemp(prefix='.update-', dir=str(path.parent))
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data)
                stream.flush()
                if os.name == 'posix':
                    if metadata is not None:
                        current = os.fstat(stream.fileno())
                        if (current.st_uid, current.st_gid) != (metadata['uid'], metadata['gid']):
                            os.fchown(stream.fileno(), metadata['uid'], metadata['gid'])
                    os.fchmod(stream.fileno(), metadata['mode'] if metadata else mode)
                os.fsync(stream.fileno())
            if metadata is not None and preserve_times:
                os.utime(temporary, ns=(metadata['atime_ns'], metadata['mtime_ns']))
            self._safe(path, missing=True)
            if ownership is not None:
                info = os.stat(temporary, follow_symlinks=False)
                ownership.update(dev=info.st_dev, ino=info.st_ino,
                                 sha256=hashlib.sha256(data).hexdigest())
            if expected_write is not None and not self._owns_write(path, expected_write):
                raise UpdateError('concurrent', '发布或恢复准备期间文件发生变化，已保留同期修改。')
            os.replace(temporary, path)
            if os.name == 'posix':
                directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _save(self, path, data):
        self._atomic_write(path, (json.dumps(data, ensure_ascii=True, indent=2) + '\n').encode())

    @contextmanager
    def _lock(self, blocking=False):
        if fcntl is None and not self._test_mode:
            raise UpdateError('locking', '系统缺少跨进程文件锁支持，已禁止更新。')
        self._mkdir(self.store)
        path = self.store / '.lock'
        self._safe(path, missing=True)
        descriptor = os.open(str(path), os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        local = None
        try:
            if fcntl is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
                except BlockingIOError:
                    raise UpdateError('busy', '已有检查或更新任务，请稍后重试。') from None
            else:
                local = _LOCAL_LOCKS.setdefault(str(path), threading.Lock())
                if not local.acquire(blocking=blocking):
                    local = None
                    raise UpdateError('busy', '已有检查或更新任务，请稍后重试。')
            yield
        finally:
            if local is not None:
                local.release()
            os.close(descriptor)

    def _production(self):
        if not self._test_mode and (fcntl is None or os.name != 'posix' or
                                    self.plugin != PRODUCTION_PLUGIN or os.geteuid() != 0):
            raise UpdateError('environment', '更新只支持具有文件锁的现有 root 面板环境。')

    @contextmanager
    def _install_lock(self, task_id):
        path = self.plugin / '.gpt-firewall-install.lock'
        self._safe(path, directory=True, missing=True)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            raise UpdateError('busy', '已有安装任务或遗留安装锁，未替换代码。') from None
        owner = dict(task_id=task_id, token=uuid.uuid4().hex + uuid.uuid4().hex, pid=os.getpid())
        descriptor = None
        completed = False
        try:
            self._save(path / 'owner.json', owner)
            descriptor = os.open(str(path / 'owner.json'), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            self._install_owner = dict(owner, fd=descriptor)
            yield
            completed = True
        finally:
            self._install_owner = None
            try:
                if descriptor is not None and completed:
                    info = os.fstat(descriptor)
                    current = (path / 'owner.json').lstat()
                    if ((info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)
                            or self._json(path / 'owner.json') != owner):
                        raise UpdateError('locking', '安装锁身份发生变化，保留现场供人工恢复。')
                    if os.name == 'nt':
                        os.close(descriptor)
                        descriptor = None
                    (path / 'owner.json').unlink()
                    path.rmdir()
                # Retain the lock if initialization or final persistence failed.
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    def _owns_write(self, target, ownership):
        if not isinstance(ownership, dict):
            return False
        if ownership == {'existed': False}:
            self._safe(target, missing=True)
            try:
                target.lstat()
            except FileNotFoundError:
                return True
            return False
        try:
            _, info, digest = self._file_snapshot(target)
        except (OSError, UpdateError):
            return False
        return (ownership.get('dev'), ownership.get('ino'), ownership.get('sha256')) == (
            info.st_dev, info.st_ino, digest)

    def _file_snapshot(self, path):
        self._safe(path)
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                             | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise UpdateError('path', '受管文件不再是独占普通文件。')
            data = stream.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise UpdateError('size', '既有文件超过安全大小上限。')
            digest = hashlib.sha256(data).hexdigest()
            after = os.fstat(stream.fileno())
            current = path.lstat()
            # Hash and identity belong to one descriptor; recheck its pathname last.
            if ((info.st_size, info.st_mtime_ns, info.st_ctime_ns) !=
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
                    or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1):
                raise UpdateError('concurrent', '读取校验期间文件被修改或替换，已停止覆盖。')
            return data, info, digest

    def _current(self):
        info = self._json(self.plugin / 'info.json')
        if info.get('name') != 'free_waf':
            raise UpdateError('identity', '既有插件内部标识不匹配，禁止更新。')
        parse_version(info.get('versions'))
        return info['versions']

    def _fetch(self, url, limit):
        _url(url)
        data = self._transport(url, timeout=NETWORK_SECONDS, max_bytes=limit)
        if not isinstance(data, bytes) or len(data) > limit:
            raise UpdateError('size', '发布资源内容或大小不符合限制。')
        return data

    @staticmethod
    def _assets(release):
        tag = release['tag']
        name = 'aapanel-gpt-firewall-' + tag.lstrip('v') + '-upgrade.zip'
        result = []
        assets = release.get('assets')
        if not isinstance(assets, list) or len(assets) > 100:
            raise UpdateError('assets', '该发布缺少可验证的兼容升级资源。')
        for wanted, limit in ((name, MAX_ARCHIVE), ('SHA256SUMS', MAX_CHECKSUM)):
            matches = [item for item in assets if isinstance(item, dict) and item.get('name') == wanted]
            if len(matches) != 1:
                raise UpdateError('assets', '该发布缺少唯一的升级包或 SHA256SUMS。')
            asset = matches[0]
            url = DOWNLOAD_URL + tag + '/' + wanted
            if asset.get('browser_download_url') != url:
                raise UpdateError('source', '发布资源下载地址不符合固定仓库限制。')
            _url(url)
            size = asset.get('size')
            if type(size) is not int or not 0 < size <= limit or asset.get('state', 'uploaded') != 'uploaded':
                raise UpdateError('size', '发布资源尚未上传完成或大小不符合限制。')
            digest = asset.get('digest')
            if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', digest)):
                raise UpdateError('digest', '发布资源摘要格式不受支持。')
            result.append(dict(name=wanted, url=url, size=size, digest=digest, limit=limit))
        return result

    def _release(self, item):
        if not isinstance(item, dict) or item.get('draft') is not False or not item.get('published_at'):
            raise UpdateError('release', '只允许已发布且不是草稿的版本。')
        tag = item.get('tag_name')
        version = _version(tag)
        release = dict(tag=tag, version=version, prerelease=item.get('prerelease') is True,
                       notes=str(item.get('body') or '')[:10000], published_at=str(item['published_at'])[:64],
                       assets=item.get('assets', []))
        try:
            self._assets(release)
            release['available'] = True
        except UpdateError:
            release['available'] = False
        return release

    @staticmethod
    def _public_release(release):
        return {key: release[key] for key in ('tag', 'version', 'prerelease', 'notes', 'published_at', 'available')}

    def _check_result(self, cache, current, cached):
        releases = cache.get('releases', [])
        latest = releases[0] if releases else None
        error = cache.get('error', '')
        return dict(status=not bool(error), current_version=current,
                    latest_version=latest['version'] if latest else current,
                    tag=latest['tag'] if latest else '',
                    available=bool(not error and latest and latest['available'] and
                                   parse_version(latest['version']) > parse_version(current)),
                    prerelease=bool(latest and latest['prerelease']), notes=latest['notes'] if latest else '',
                    releases=[self._public_release(item) for item in releases],
                    checked_at=cache.get('checked_at'),
                    next_check_at=cache.get('attempted_at', 0) + (FORCE_SECONDS if error else CACHE_SECONDS),
                    cached=cached, stale=bool(error and releases), error=error,
                    message=error or '版本检查完成；只有明确确认后才会安装。', warning=WARNING)

    def check(self, force=False):
        current = ''
        try:
            if type(force) is not bool:
                raise UpdateError('argument', '强制检查参数必须是布尔值。')
            current = self._current()
            with self._lock():
                path = self.store / 'check.json'
                cache = self._json(path) if path.exists() or path.is_symlink() else {}
                now = self._clock()
                age = now - cache.get('attempted_at', 0)
                if cache and (age < FORCE_SECONDS or not force and not cache.get('error') and age < CACHE_SECONDS):
                    return self._check_result(cache, current, True)
                try:
                    data = json.loads(self._fetch(API_URL + '?per_page=100', MAX_JSON).decode('utf-8'))
                    if not isinstance(data, list) or len(data) > 100:
                        raise UpdateError('release', 'GitHub 发布列表结构异常。')
                    releases, seen = [], set()
                    for item in data:
                        try:
                            release = self._release(item)
                        except UpdateError:
                            continue
                        if release['version'] in seen:
                            continue
                        seen.add(release['version'])
                        releases.append(release)
                    releases.sort(key=lambda item: parse_version(item['version']), reverse=True)
                    cache = dict(releases=releases, checked_at=now, attempted_at=now, error='')
                except Exception:
                    cache.update(attempted_at=now, error='无法安全连接固定 GitHub 发布源，请稍后重试。')
                self._save(path, cache)
                return self._check_result(cache, current, False)
        except Exception as error:
            message = str(error) if isinstance(error, UpdateError) else '无法读取本地版本或更新缓存，请人工检查。'
            return dict(status=False, current_version=current, latest_version=current, tag='', available=False,
                        prerelease=False, notes='', releases=[], checked_at=None, next_check_at=None,
                        cached=False, stale=False, error=message, message=message, warning=WARNING)

    def _job(self):
        path = self.store / 'job.json'
        if not path.exists() and not path.is_symlink():
            return None
        job = self._json(path)
        if (not re.fullmatch(r'[0-9a-f]{32}', str(job.get('id', ''))) or
                job.get('state') not in ('queued', 'running', 'succeeded', 'failed')):
            raise UpdateError('job', '持久更新任务记录异常，需要人工恢复。')
        parse_version(job.get('target_version'))
        parse_version(job.get('tag'))
        return job

    def _public_job(self, job):
        keys = ('id', 'state', 'stage', 'message', 'tag', 'current_version', 'target_version',
                'created_at', 'updated_at', 'pid', 'rollback', 'error_code', 'failure_stage')
        result = {key: job[key] for key in keys if key in job}
        if isinstance(job.get('installer'), dict):
            detail = job['installer']
            result['installer'] = self._installer_summary(dict(
                stage=detail.get('stage'), diagnostic_code=detail.get('diagnostic_code'),
                diagnostic_resource=detail.get('resource'), waf_active=detail.get('waf_active')),
                detail.get('exit_code'))
        elif job.get('state') == 'succeeded':
            # Old updaters execute the new installer but cannot save new job fields.
            try:
                path = self.plugin / 'install-status.json'
                report = self._json(path)
                if (self._installer_identity(report, job['target_version'])
                        and report.get('status') == 'success' and report.get('stage') == 'complete'
                        and job['created_at'] <= path.stat().st_mtime <= job['updated_at']):
                    result['installer'] = self._installer_summary(report)
            except Exception:
                pass
        if type(result.get('installer', {}).get('waf_active')) is bool:
            result['waf_active'] = result['installer']['waf_active']
        if job['state'] in ('queued', 'running'):
            alive = None
            pid = job.get('pid')
            if os.name == 'posix' and type(pid) is int and pid > 0:
                try:
                    os.kill(pid, 0)
                    alive = True
                except ProcessLookupError:
                    alive = False
                except PermissionError:
                    pass
            if alive is False or self._clock() - job.get('updated_at', 0) > JOB_STALE_SECONDS:
                result.update(state='recovery_required',
                              message='任务进程已退出或状态长时间未更新；不能确认安全结束，请人工检查备份和文件锁后恢复。')
        return result

    @staticmethod
    def _installer_identity(report, target_version):
        return (isinstance(report, dict) and report.get('operation') == 'install'
                and report.get('plugin_name') == 'free_waf'
                and report.get('version') == target_version)

    @staticmethod
    def _installer_summary(report, exit_code=None):
        # Never expose arbitrary installer output, configured paths, or raw messages.
        detail = {}
        if type(exit_code) is int and -255 <= exit_code <= 255:
            detail['exit_code'] = exit_code
        if report.get('stage') in INSTALLER_STAGES:
            detail['stage'] = report['stage']
        code = report.get('diagnostic_code')
        if isinstance(code, str) and code in INSTALLER_REASONS:
            detail.update(diagnostic_code=code, reason=INSTALLER_REASONS[code])
        resource = report.get('diagnostic_resource')
        if isinstance(resource, str) and resource in INSTALLER_RESOURCES:
            detail['resource'] = resource
        if type(report.get('waf_active')) is bool:
            detail['waf_active'] = report['waf_active']
        return detail

    def status(self):
        try:
            job = self._job()
            return dict(status=True, job=self._public_job(job) if job else None, warning=WARNING)
        except Exception:
            return dict(status=False, job=None, error='无法安全读取更新任务，请人工检查，禁止重复启动。', warning=WARNING)

    def start(self, tag):
        try:
            self._production()
            target = _version(tag)
            if parse_version(target) <= parse_version(self._current()):
                raise UpdateError('version', '禁止安装当前版本或降级版本。')
            result = self.check()
            if not result['status']:
                raise UpdateError('check', '无法确认发布信息，未启动更新。')
            release = next((item for item in result['releases'] if item['tag'] == tag), None)
            if not release or not release['available']:
                raise UpdateError('release', '所选版本不在可验证的已发布版本列表中。')
            with self._lock():
                repair_record = self.store / 'integration-repair.json'
                if repair_record.exists() and self._json(repair_record).get('state') not in ('succeeded', 'rolled_back'):
                    raise UpdateError('recovery_required', '接入修复尚未完整结束，请先检查修复记录与备份，未开始更新。')
                previous = self._job()
                if previous and (previous['state'] in ('queued', 'running') or
                                 previous.get('rollback', {}).get('state') == 'failed'):
                    raise UpdateError('busy', '已有更新或未完成恢复的任务，请先人工检查。')
                job = dict(id=uuid.uuid4().hex, state='queued', stage='queued', tag=tag,
                           current_version=self._current(), target_version=target,
                           message='更新已排队，关闭页面不会取消任务。',
                           created_at=self._clock(), updated_at=self._clock(), pid=None,
                           rollback=dict(state='not_needed', errors=[], conflict=False, conflicts=[]))
                self._save(self.store / 'job.json', job)
                try:
                    panel_python = self.plugin.parents[1] / 'pyenv/bin/python'
                    if not self._test_mode:
                        self._safe(panel_python.parent, directory=True)
                        if not panel_python.is_file() or not os.access(panel_python, os.X_OK):
                            raise UpdateError('python', '既有面板 Python 不可用，未启动更新。')
                    module = self.plugin / 'update_service.py'
                    if not self._test_mode:
                        self._safe(module)
                    process = self._spawn([str(panel_python), '-B', str(module), '--job', job['id']],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL, cwd=str(self.plugin),
                                          start_new_session=True, close_fds=True, shell=False)
                except Exception:
                    job.update(state='failed', stage='spawn', message='无法启动独立更新进程；未替换受管代码。')
                    self._save(self.store / 'job.json', job)
                    raise UpdateError('spawn', job['message']) from None
                # Once a child may exist, never publish a terminal/unblocked job on a write error.
                job['pid'] = process.pid
                try:
                    self._save(self.store / 'job.json', job)
                except Exception:
                    raise UpdateError('persistence', '进程可能已启动但状态记录失败；请检查既有任务，不要重复启动。') from None
                return dict(status=True, job_id=job['id'], state='queued', tag=tag,
                            target_version=target, message=job['message'])
        except Exception as error:
            message = str(error) if isinstance(error, UpdateError) else '更新启动失败，未确认安全结束前请勿重复操作。'
            return dict(status=False, error=message, message=message)

    def _phase(self, job, stage, message):
        job.update(state='running', stage=stage, message=message,
                   updated_at=self._clock(), pid=os.getpid())
        self._save(self.store / 'job.json', job)

    def _download(self, asset):
        data = self._fetch(asset['url'], asset['limit'])
        if len(data) != asset['size']:
            raise UpdateError('size', '下载资源大小与发布元数据不一致。')
        if asset['digest'] and hashlib.sha256(data).hexdigest() != asset['digest'].split(':', 1)[1].lower():
            raise UpdateError('digest', '资源摘要不一致，禁止应用升级包。')
        return data

    def _payloads(self, payload, version):
        if len(payload) > MAX_ARCHIVE:
            raise UpdateError('archive', '升级包超过大小限制。')
        result, expanded = {}, 0
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if len(entries) != len(MANAGED_FILES):
                raise UpdateError('archive', '升级包文件数量不符合固定白名单。')
            for entry in entries:
                prefix = 'free_waf/'
                name = entry.filename[len(prefix):] if entry.filename.startswith(prefix) else ''
                mode = entry.external_attr >> 16
                if (name not in MANAGED_FILES or name in result or entry.orig_filename != entry.filename
                        or entry.flag_bits & 1 or entry.is_dir()
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                        or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or entry.file_size > MAX_FILE or entry.file_size < 0
                        or entry.file_size > max(1, entry.compress_size) * 200):
                    raise UpdateError('archive', '升级包含未知、重复、链接、加密或异常压缩文件。')
                expanded += entry.file_size
                if expanded > MAX_EXPANDED:
                    raise UpdateError('archive', '升级包解压大小超过限制。')
                with archive.open(entry) as stream:
                    data = stream.read(MAX_FILE + 1)
                if len(data) != entry.file_size or len(data) > MAX_FILE:
                    raise UpdateError('archive', '升级包文件大小校验失败。')
                result[name] = data
        if set(result) != set(MANAGED_FILES):
            raise UpdateError('archive', '升级包缺少固定白名单文件。')
        info = json.loads(result['info.json'].decode('utf-8-sig'))
        if not isinstance(info, dict) or info.get('name') != 'free_waf' or _version(info.get('versions')) != version:
            raise UpdateError('metadata', '升级包版本或插件标识不匹配。')
        for name, data in result.items():
            if name.endswith('.py'):
                compile(data, name, 'exec', dont_inherit=True)
        return result

    @staticmethod
    def _metadata(path, value=None):
        value = path.stat() if value is None else value
        return dict(mode=stat.S_IMODE(value.st_mode), uid=value.st_uid, gid=value.st_gid,
                    atime_ns=value.st_atime_ns, mtime_ns=value.st_mtime_ns)

    def _backup(self, directory):
        manifest = {}
        for name in MANAGED_FILES:
            path = self.plugin / name
            self._safe(path, missing=True)
            entry = dict(existed=path.exists(), write={'existed': False})
            if entry['existed']:
                data, info, digest = self._file_snapshot(path)
                entry.update(metadata=self._metadata(path, info))
                entry['sha256'] = digest
                entry['write'] = dict(dev=info.st_dev, ino=info.st_ino, sha256=entry['sha256'])
                self._atomic_write(directory / 'plugin' / name, data)
            manifest[name] = entry
        path = self.runtime / 'init.lua'
        self._safe(path)
        data, info, digest = self._file_snapshot(path)
        manifest['runtime'] = dict(metadata=self._metadata(path, info))
        manifest['runtime']['sha256'] = digest
        manifest['runtime']['write'] = dict(dev=info.st_dev, ino=info.st_ino,
                                         sha256=manifest['runtime']['sha256'])
        self._atomic_write(directory / 'runtime/init.lua', data)
        self._save(directory / 'manifest.json', manifest)
        return manifest

    def _rollback(self, backup, manifest, installer_attempted, touched, conflicts):
        errors = []
        conflicts = list(conflicts)
        for name, ownership in touched.items():
            try:
                entry, target = manifest[name], self.plugin / name
                self._safe(target, missing=True)
                current_hash = hashlib.sha256(self._read(target)).hexdigest() if target.exists() else None
                original_hash = entry.get('sha256')
                if current_hash == original_hash:
                    continue
                if not target.exists() or not self._owns_write(target, ownership):
                    conflicts.append(name)
                    continue
                if entry['existed']:
                    data = self._read(backup / 'plugin' / name)
                    if hashlib.sha256(data).hexdigest() != entry['sha256']:
                        raise UpdateError('backup', '备份摘要不一致。')
                    self._atomic_write(target, data, metadata=entry['metadata'], expected_write=ownership)
                elif target.exists():
                    if not self._owns_write(target, ownership):
                        conflicts.append(name)
                        continue
                    target.unlink()
            except Exception as error:
                if isinstance(error, UpdateError) and error.code == 'concurrent':
                    conflicts.append(name)
                else:
                    errors.append('code:' + name)
        reload_needed = False
        runtime_restored = False
        # Only the installer owns runtime writes; do not undo unrelated operator repairs.
        if installer_attempted:
            try:
                data = self._read(backup / 'runtime/init.lua')
                if hashlib.sha256(data).hexdigest() != manifest['runtime']['sha256']:
                    raise UpdateError('backup', '运行文件备份摘要不一致。')
                target = self.runtime / 'init.lua'
                current_hash = hashlib.sha256(self._read(target)).hexdigest()
                if current_hash == manifest['runtime']['sha256']:
                    runtime_restored = True
                else:
                    try:
                        proof = self._json(self.plugin / 'install-status.json')
                    except Exception:
                        proof = {}
                    ownership = proof.get('runtime_write')
                    if (proof.get('task_id') == self._install_owner['task_id']
                            and proof.get('runtime_changed') is True and self._owns_write(target, ownership)):
                        self._atomic_write(target, data, metadata=manifest['runtime']['metadata'],
                                           expected_write=ownership)
                        reload_needed = runtime_restored = True
                    else:
                        conflicts.append('runtime')
            except Exception as error:
                if isinstance(error, UpdateError) and error.code in ('concurrent', 'path'):
                    conflicts.append('runtime')
                else:
                    errors.append('runtime')
            try:
                status_path = self.plugin / 'install-status.json'
                report = self._json(status_path) if status_path.exists() else {}
                reload_needed = reload_needed or (report.get('task_id') == self._install_owner['task_id']
                                                  and report.get('runtime_changed') is True)
            except Exception:
                pass
        if reload_needed and runtime_restored:
            try:
                self._restore_nginx()
            except Exception:
                errors.append('nginx_restore')
        return dict(state='failed' if errors or conflicts else 'restored', errors=errors,
                    conflict=bool(conflicts), conflicts=sorted(set(conflicts)))

    @staticmethod
    def _command(arguments, timeout=30, capture=False, **options):
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, shell=False, start_new_session=True, **options)
        try:
            output, _ = process.communicate(timeout=timeout)
        except BaseException:
            if os.name == 'posix':
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.communicate()
            raise
        if output is not None and len(output) > MAX_JSON:
            raise UpdateError('nginx', 'Nginx 配置输出超过安全限制。')
        return process.returncode, output or b''

    def _run_installer(self, plugin):
        self._production()
        self._safe(plugin / 'install.sh')
        owner = self._install_owner
        environment = os.environ.copy()
        environment.update(GPT_FIREWALL_INSTALL_TASK=owner['task_id'],
                           GPT_FIREWALL_INSTALL_TOKEN=owner['token'],
                           GPT_FIREWALL_INSTALL_FD=str(owner['fd']))
        arguments = ['/bin/bash', str(plugin / 'install.sh'), 'install']
        if self._test_mode:
            environment['GPT_FIREWALL_TEST_ROOT'] = str(self.plugin.parents[4])
            arguments.append('--test-mode')
        code, _ = self._command(arguments, timeout=180, env=environment, pass_fds=(owner['fd'],))
        return code

    def _restore_nginx(self):
        server = self.plugin.parents[2]
        nginx, config = server / 'nginx/sbin/nginx', server / 'nginx/conf/nginx.conf'
        self._safe(nginx)
        self._safe(config)
        options = ['-p', str(server / 'nginx') + '/', '-c', str(config)]
        if self._command([str(nginx), '-t'] + options)[0] != 0:
            raise UpdateError('nginx', '恢复后 Nginx 配置测试失败。')
        code, output = self._command([str(nginx), '-T'] + options, capture=True)
        if code:
            raise UpdateError('nginx', '不能确认恢复后的 Nginx 引用状态。')
        rows = nginx_directives(output.decode('utf-8'))
        hooks = [row[1] for row in rows if len(row) == 2 and row[0] == 'init_by_lua_file']
        if '/www/server/free_waf/init.lua' not in hooks:
            return
        if self._command([str(nginx), '-s', 'reload'] + options)[0] != 0:
            raise UpdateError('nginx', '恢复后的 Nginx 平滑重载失败。')

    def run_job(self, job_id):
        """Worker entry point, not a frontend API; only executes a persisted queued job."""
        try:
            self._production()
            if not isinstance(job_id, str) or not re.fullmatch(r'[0-9a-f]{32}', job_id):
                raise UpdateError('job', '更新任务编号无效。')
            with self._lock(blocking=True), ExitStack() as transaction:
                job = self._job()
                if not job or job['id'] != job_id or job['state'] != 'queued':
                    raise UpdateError('job', '任务不存在、已执行或需要人工恢复。')
                backup, manifest, changes, installer_attempted = None, None, False, False
                touched, conflicts = {}, []
                try:
                    transaction.enter_context(self._install_lock(job_id))
                    self._phase(job, 'verify', '正在核对固定来源、版本与下载资源。')
                    if parse_version(job['target_version']) <= parse_version(self._current()):
                        raise UpdateError('version', '既有版本已改变，禁止重复安装或降级。')
                    raw = json.loads(self._fetch(API_URL + '/tags/' + job['tag'], MAX_JSON).decode('utf-8'))
                    release = self._release(raw)
                    if release['tag'] != job['tag'] or release['version'] != job['target_version']:
                        raise UpdateError('release', '发布信息与已确认任务不一致。')
                    package_asset, checksum_asset = self._assets(release)
                    checksums, package = self._download(checksum_asset), self._download(package_asset)
                    expected, names = None, set()
                    for line in checksums.decode('ascii').splitlines():
                        if not line.strip():
                            continue
                        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *]([A-Za-z0-9._-]+)', line)
                        if not match or match[2] in names:
                            raise UpdateError('checksum', 'SHA256SUMS 内容格式或条目不唯一。')
                        names.add(match[2])
                        if match[2] == package_asset['name']:
                            expected = match[1].lower()
                    if expected != hashlib.sha256(package).hexdigest():
                        raise UpdateError('checksum', '升级包 SHA256SUMS 校验失败。')
                    payloads = self._payloads(package, job['target_version'])
                    self._safe(self.plugin / 'install-status.json', missing=True)
                    self._phase(job, 'stage', '资源与 Python 编译校验通过，正在准备隔离暂存。')
                    directory = self.store / job_id
                    for name, data in payloads.items():
                        self._atomic_write(directory / 'stage' / name, data)
                    self._phase(job, 'backup', '正在备份受管代码与既有运行入口；不会备份或重置业务状态。')
                    backup = directory / 'backup'
                    manifest = self._backup(backup)
                    self._phase(job, 'apply', '正在原子替换受管插件代码。')
                    changes = True
                    for name, data in payloads.items():
                        entry = manifest[name]
                        target = self.plugin / name
                        self._safe(target, missing=True)
                        current_hash = hashlib.sha256(self._read(target)).hexdigest() if target.exists() else None
                        if current_hash != entry.get('sha256'):
                            conflicts.append(name)
                            raise UpdateError('concurrent', '受管代码在更新期间发生变化，已停止覆盖。')
                        touched[name] = {}
                        try:
                            self._atomic_write(target, data, metadata=entry.get('metadata'), preserve_times=False,
                                               mode=0o755 if name == 'install.sh' else 0o644,
                                               ownership=touched[name], expected_write=entry['write'])
                        except UpdateError as error:
                            if error.code == 'concurrent':
                                conflicts.append(name)
                            raise
                    self._phase(job, 'install', '正在执行包内离线兼容安装器。')
                    status_path = self.plugin / 'install-status.json'
                    previous_stat = status_path.stat().st_mtime_ns if status_path.exists() else None
                    if hashlib.sha256(self._read(self.runtime / 'init.lua')).hexdigest() != manifest['runtime']['sha256']:
                        conflicts.append('runtime')
                        raise UpdateError('concurrent', '运行代码在更新期间发生变化，未启动安装器。')
                    installer_attempted = True
                    result = self._installer(self.plugin)
                    code = getattr(result, 'returncode', result)
                    job['installer'] = self._installer_summary({}, code)
                    try:
                        report = self._json(status_path)
                        fresh_report = (self._installer_identity(report, job['target_version'])
                                        and report.get('task_id') == job_id
                                        and status_path.stat().st_mtime_ns != previous_stat)
                    except Exception:
                        raise UpdateError('installer', '安装器没有写入可校验的最新状态。')
                    if fresh_report:
                        job['installer'] = self._installer_summary(report, code)
                    if (code != 0 or not fresh_report or report.get('status') != 'success'
                            or report.get('stage') != 'complete'
                            or _version(self._current()) != job['target_version']):
                        raise UpdateError('installer', '安装器退出码、最新状态或目标版本校验失败。')
                    job.update(state='succeeded', stage='complete', message='升级完成，请关闭并重新打开插件，并人工验收业务。',
                               updated_at=self._clock())
                    if job['installer'].get('waf_active') is False:
                        job.update(waf_active=False, message='代码升级完成；防护保持未启用，未创建接入配置，未重载 Nginx。请关闭并重新打开插件。')
                    self._save(self.store / 'job.json', job)
                except BaseException as error:
                    failure_stage = job.get('stage')
                    if changes and manifest is not None:
                        try:
                            self._phase(job, 'rollback', '更新未完成，正在分别恢复受管代码与运行入口。')
                        except Exception:
                            pass
                        job['rollback'] = self._rollback(backup, manifest, installer_attempted, touched, conflicts)
                    job.update(state='failed', stage='failed', failure_stage=failure_stage,
                               updated_at=self._clock(), error_code=error.code if isinstance(error, UpdateError) else 'internal',
                               message='更新失败；已记录恢复结果，请检查后再操作。')
                    self._save(self.store / 'job.json', job)
                return dict(status=job['state'] == 'succeeded', job=self._public_job(job))
        except BaseException:
            return dict(status=False, error='更新执行或持久记录失败；请人工检查任务与备份，禁止盲目重试。')


def main():
    parser = argparse.ArgumentParser(description='Run one persisted firewall update job.')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--job')
    action.add_argument('--fetch-url')
    action.add_argument('--probe-integration')
    parser.add_argument('--network-timeout', type=float, default=NETWORK_SECONDS)
    parser.add_argument('--max-bytes', type=int, default=MAX_JSON)
    args = parser.parse_args()
    if args.probe_integration:
        if not re.fullmatch(r'[1-9][0-9]{0,9}:[0-9]{1,24}', args.probe_integration):
            return 2
        try:
            proof = IntegrationRepairService._probe_loop(
                Path('/www/server/nginx/sbin/nginx'), args.probe_integration)
            print(json.dumps(proof))
            return 0
        except Exception:
            return 2
    if args.fetch_url:
        if not 0 < args.network_timeout <= NETWORK_SECONDS or not 0 < args.max_bytes <= MAX_ARCHIVE:
            return 2
        try:
            data = _transport(args.fetch_url, timeout=args.network_timeout, max_bytes=args.max_bytes)
            sys.stdout.buffer.write(data)
            return 0
        except Exception:
            return 2
    result = UpdateService(Path(__file__).absolute().parent).run_job(args.job)
    return 0 if result['status'] else 1


class IntegrationRepairService(UpdateService):
    """Explicit missing-include recovery; never edits rules or foreign Lua hooks."""

    INCLUDE = b'''# aapanel GPT Firewall managed integration v1
lua_shared_dict free_waf 10m;
lua_shared_dict free_waf_drop_ip 10m;
lua_shared_dict free_waf_drop_sum 10m;
init_by_lua_file /www/server/free_waf/init.lua;
access_by_lua_file /www/server/free_waf/waf.lua;
server {
    listen 127.0.0.1:39091;
    server_name gpt-firewall-health.invalid;
    access_log off;
    keepalive_timeout 5s;
    keepalive_requests 100;
    location / { root /www/server/free_waf/.health-no-content; }
}
'''
    CONFIRMATION = 'REPAIR_NGINX_INTEGRATION'

    def __init__(self, plugin_dir, *, read_configuration, directives, test_mode=False):
        super().__init__(plugin_dir, test_mode=test_mode)
        self.server = self.plugin.parents[2]
        self.main = self.server / 'nginx/conf/nginx.conf'
        self.include = self.server / 'panel/vhost/nginx/free_waf.conf'
        self.binary = self.server / 'nginx/sbin/nginx'
        self.record = self.store / 'integration-repair.json'
        self._configuration = read_configuration
        self._directives = directives
        self._owned_include = None

    @contextmanager
    def _activation_lock(self):
        with self._lock():
            install_lock = self.plugin / '.gpt-firewall-install.lock'
            self._safe(install_lock, directory=True, missing=True)
            try:
                install_lock.mkdir(mode=0o700)
            except FileExistsError:
                raise UpdateError('busy', '已有安装任务，未开始接入修复。') from None
            try:
                yield
            finally:
                install_lock.rmdir()

    def _snapshot(self):
        self._safe(self.binary)
        self._safe(self.include, missing=True)
        if self.include.exists():
            raise UpdateError('integration_exists', '接入文件已存在，不会覆盖；请先核验，冲突或不完整配置需人工处理。')
        if self.record.exists():
            previous = self._json(self.record)
            if previous.get('state') not in ('succeeded', 'rolled_back'):
                raise UpdateError('recovery_required', '上次修复未完整结束，请先检查本机修复记录和备份，禁止重复操作。')
        main = self._read(self.main)
        if ['include', '/www/server/panel/vhost/nginx/*.conf'] not in self._directives(main.decode('utf-8')):
            raise UpdateError('unsupported_include', '未发现受支持的宝塔 HTTP 站点配置入口，不会自动改写 nginx.conf。')
        configuration = self._configuration()
        rows = self._directives(configuration)
        if ['include', '/www/server/panel/vhost/nginx/*.conf'] not in rows:
            raise UpdateError('unsupported_include', '读取到的宝塔配置未包含受支持的站点入口，请人工核对。')
        if any(row[0].startswith(('init_by_lua', 'access_by_lua')) or
               row[0] == 'lua_shared_dict' and len(row) > 1 and row[1] in
               ('free_waf', 'free_waf_drop_ip', 'free_waf_drop_sum') for row in rows):
            raise UpdateError('integration_conflict', '发现已有 Lua 初始化、访问入口或同名共享字典；不会覆盖其他防护配置。')
        files = {self.main: main}
        for source in re.findall(r'^# configuration file (.+):$', configuration, re.MULTILINE):
            path = Path(source)
            if not path.is_absolute():
                raise UpdateError('unsupported_include', '无法核对配置来源，未修改任何文件。')
            files[path] = self._read(path)
        for name in ('config.json', 'site.json', 'init.lua', 'waf.lua'):
            files[self.runtime / name] = self._read(self.runtime / name)
        if files[self.runtime / 'init.lua'] != self._read(self.plugin / 'init.lua'):
            raise UpdateError('runtime_mismatch', '插件与运行 Lua 版本不一致，请先完成代码升级。')
        if not re.fullmatch(rb'\s*run_btwaf\(\s*\)\s*;?\s*', files[self.runtime / 'waf.lua']):
            raise UpdateError('runtime_entrypoint', '现有访问入口不兼容，未修改任何文件。')
        config = json.loads(files[self.runtime / 'config.json'].decode('utf-8-sig'))
        sites = json.loads(files[self.runtime / 'site.json'].decode('utf-8-sig'))
        if (not isinstance(config, dict) or type(config.get('open')) is not bool or
                not isinstance(config.get('cc'), dict) or
                not all(key in config['cc'] for key in ('cycle', 'limit', 'endtime')) or
                not isinstance(sites, dict)):
            raise UpdateError('runtime_incomplete', '现有运行配置不完整，未重置配置或启用防护。')
        rules = {}
        for name in ('cn', 'ip_black', 'ip_white', 'url_white', 'url_black', 'user_agent_white',
                     'user_agent', 'header', 'post', 'cookie', 'args', 'url', 'head_white', 'scan_black'):
            path = self.runtime / 'rule' / (name + '.json')
            files[path] = self._read(path)
            value = json.loads(files[path].decode('utf-8-sig'))
            if not isinstance(value, dict if name == 'scan_black' else list):
                raise UpdateError('runtime_incomplete', '现有规则结构不完整，未覆盖规则。')
            rules[name] = value
        self._validate_runtime(config, sites, rules)
        logs = config.get('logs_path')
        if not isinstance(logs, str) or not PurePosixPath(logs).is_absolute():
            raise UpdateError('runtime_incomplete', '日志目录配置不兼容，未修改配置。')
        log_path = self.server.parent / logs[5:] if self._test_mode and logs.startswith('/www/') else Path(logs)
        self._safe(log_path, directory=True)
        template = config.get('reqfile_path', '').rstrip('/')
        if template != '/www/server/free_waf/html':
            raise UpdateError('runtime_incomplete', '响应模板不在受支持的运行目录，请人工检查接入。')
        for key in ('get', 'post', 'cookie', 'user-agent', 'other'):
            name = config.get(key, {}).get('reqfile')
            if not isinstance(name, str) or Path(name).name != name:
                raise UpdateError('runtime_incomplete', '响应模板名称不兼容，未修改配置。')
            path = self.runtime / 'html' / name
            files[path] = self._read(path)
        digest = hashlib.sha256(configuration.encode('utf-8'))
        for path, data in sorted(files.items(), key=lambda row: str(row[0])):
            digest.update(str(path).encode('utf-8') + b'\0' + hashlib.sha256(data).digest())
        return dict(files=files, configuration=configuration.rstrip(), revision=digest.hexdigest(), configured_open=config['open'],
                    enabled_sites=sum(isinstance(site, dict) and site.get('open') is True for site in sites.values()))

    @staticmethod
    def _validate_runtime(config, sites, rules):
        def require(condition):
            if not condition:
                raise UpdateError('runtime_incomplete', '现有运行配置或规则缺少必要字段，未重置数据或启用防护；请先完成配置诊断。')

        def integer(value, minimum=1, maximum=2147483647):
            return type(value) is int and minimum <= value <= maximum

        def strings(value):
            return isinstance(value, list) and all(isinstance(item, str) for item in value)

        def patterns(value):
            return isinstance(value, str) or strings(value)

        def ip_ranges(value, expiry=False):
            require(isinstance(value, list))
            for row in value:
                require(isinstance(row, list) and 2 <= len(row) <= (3 if expiry else 2))
                for address in row[:2]:
                    require(isinstance(address, list) and len(address) == 4
                            and all(integer(octet, 0, 255) for octet in address))
                if len(row) > 2:
                    require(integer(row[2], 0, 2 ** 53 - 1))

        def counters(item, cc=False):
            require(isinstance(item, dict))
            for key in (('cycle', 'limit', 'endtime') if cc else ('retry', 'retry_time', 'retry_cycle')):
                require(integer(item.get(key)))
            if cc:
                require(type(item.get('open')) is bool)

        counters(config)
        counters(config.get('cc'), cc=True)
        for key in ('cc', 'scan', 'drop_abroad', 'get', 'post', 'cookie', 'user-agent', 'other'):
            item = config.get(key)
            require(isinstance(item, dict) and integer(item.get('status'), 400, 599))
            if key != 'other':
                require(type(item.get('open')) is bool)
        for site in sites.values():
            require(isinstance(site, dict) and type(site.get('open')) is bool)
            counters(site)
            counters(site.get('cc'), cc=True)
            for key in ('disable_php_path', 'disable_path', 'disable_ext', 'disable_upload_ext'):
                require(strings(site.get(key)))
            if site.get('cdn'):
                require(strings(site.get('cdn_header')))
            if 'cdn_trusted_proxy' in site:
                ip_ranges(site['cdn_trusted_proxy'])
            for key in ('url_white',):
                if key in site:
                    require(patterns(site[key]))
            for key, length in (('url_rule', 2), ('url_tell', 3)):
                require(isinstance(site.get(key), list))
                for row in site[key]:
                    require(isinstance(row, list) and len(row) >= length and isinstance(row[0], str))
                    require(patterns(row[1]) if key == 'url_rule' else all(isinstance(value, str) for value in row[:3]))
            if 'disable_rule' in site:
                require(isinstance(site['disable_rule'], dict))
                for disabled in site['disable_rule'].values():
                    require(isinstance(disabled, list) and all(integer(value, 0) for value in disabled))
        for key in ('cookie', 'args', 'header'):
            require(patterns(rules['scan_black'].get(key)))
        for key in ('user_agent_white', 'user_agent', 'header', 'post', 'cookie', 'args', 'url'):
            for row in rules[key]:
                require(isinstance(row, list) and len(row) >= 2 and type(row[0]) is int
                        and row[0] in (0, 1) and isinstance(row[1], str))
        for key in ('url_white', 'url_black', 'head_white'):
            require(strings(rules[key]))
        for key in ('cn', 'ip_black', 'ip_white'):
            ip_ranges(rules[key], expiry=key == 'ip_black')

    def _assert_files_unchanged(self, snapshot):
        for path, expected in snapshot['files'].items():
            if self._read(path) != expected:
                raise UpdateError('concurrent_edit', '配置或运行文件发生变化，已停止；不会重载其他操作的修改。')

    def _owned_bytes(self, path=None):
        path = self.include if path is None else path
        self._safe(path.parent, directory=True)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or self._owned_include != (info.st_dev, info.st_ino)
                    or info.st_size > len(self.INCLUDE)):
                raise UpdateError('concurrent_edit', '接入文件已被替换，已保留文件并停止自动恢复。')
            data = os.read(descriptor, len(self.INCLUDE) + 1)
            if data != self.INCLUDE:
                raise UpdateError('concurrent_edit', '接入文件已被其他操作修改，已停止自动恢复。')
            return data
        finally:
            os.close(descriptor)

    def _assert_unchanged(self, snapshot, owned=False):
        self._assert_files_unchanged(snapshot)
        if owned:
            self._owned_bytes()
        elif self.include.exists():
            raise UpdateError('concurrent_edit', '出现其他接入文件，未重载配置。')
        body = self._configuration()
        pattern = (r'^# configuration file ' + re.escape(str(self.include)) +
                   r':\n.*?(?=^# configuration file |\Z)')
        sections = re.findall(pattern, body, re.MULTILINE | re.DOTALL)
        if len(sections) > 1 or (sections and (not owned or
                sections[0].split('\n', 1)[1].strip() != self.INCLUDE.decode().strip())):
            raise UpdateError('concurrent_edit', '接入配置来源发生变化，未重载。')
        if owned and not sections and not self._test_mode:
            raise UpdateError('concurrent_edit', '未能在宝塔配置中确认本次接入文件，未重载。')
        body = re.sub(pattern, '', body, flags=re.MULTILINE | re.DOTALL).rstrip()
        if body != snapshot['configuration']:
            raise UpdateError('concurrent_edit', 'Nginx 配置发生变化，已停止；不会重载其他操作的修改。')
        self._assert_files_unchanged(snapshot)
        if owned:
            self._owned_bytes()

    def _quarantine_owned(self, backup):
        self._owned_bytes()
        quarantine = backup / ('removed-include-' + uuid.uuid4().hex + '.conf')
        # Retain the moved inode even on a race; never unlink a pathname after a separate check.
        os.rename(self.include, quarantine)
        try:
            self._owned_bytes(quarantine)
        except Exception:
            try:
                os.link(quarantine, self.include)
            except FileExistsError:
                pass
            raise
        if self.include.exists():
            raise UpdateError('concurrent_edit', '撤销期间出现其他接入文件，已保留双方文件并停止重载。')

    @staticmethod
    def _failure(error):
        if isinstance(error, UpdateError):
            return dict(status=False, can_repair=False, diagnostic_code=error.code, msg=str(error))
        return dict(status=False, can_repair=False, diagnostic_code='repair_failed',
                    msg='接入检查或修复未完成，请核对本机修复记录；未返回配置内容。')

    def preview(self):
        try:
            snapshot = self._snapshot()
            return dict(status=True, can_repair=True, integration='missing',
                        revision=snapshot['revision'], configured_open=snapshot['configured_open'],
                        enabled_sites=snapshot['enabled_sites'],
                        msg='确认后备份并补齐接入、测试和平滑重载宝塔 Nginx；保留原开关和规则。现有已开启规则将开始处理请求。')
        except Exception as error:
            return self._failure(error)

    @staticmethod
    def _check_probe_port():
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            try:
                server.bind(('127.0.0.1', 39091))
            except OSError:
                raise UpdateError('health_port_busy', '本机健康检查端口已占用，未接入；请人工处理端口冲突。') from None

    @staticmethod
    def _process_identity(pid, binary, role):
        process = Path('/proc') / str(pid)
        if not (process / 'exe').samefile(binary):
            raise ValueError('unexpected process')
        if not (process / 'cmdline').read_bytes().startswith(b'nginx: ' + role):
            raise ValueError('unexpected role')
        fields = (process / 'stat').read_text().rsplit(')', 1)[1].split()
        return int(fields[1]), fields[19]

    def _master_identity(self):
        rows = self._directives(self._configuration())
        pid_rows = [row for row in rows if row[0] == 'pid']
        if len(pid_rows) > 1 or pid_rows and len(pid_rows[0]) != 2:
            raise UpdateError('health_process', '无法确认宝塔 Nginx 主进程，未确认接入。')
        path = Path(pid_rows[0][1]) if pid_rows else Path('logs/nginx.pid')
        if not path.is_absolute():
            path = self.server / 'nginx' / path
        pid = self._read(path, limit=32).strip()
        if not re.fullmatch(rb'[1-9][0-9]{0,9}', pid):
            raise UpdateError('health_process', '无法确认宝塔 Nginx 主进程，未确认接入。')
        _, started = self._process_identity(int(pid), self.binary, b'master process')
        return pid.decode('ascii') + ':' + started

    @staticmethod
    def _verify_peer(connection, worker_pid, binary, expected_master, port=39091):
        if connection.sock is None or os.name != 'posix' or type(worker_pid) is not int or worker_pid < 1:
            return False
        import socket
        try:
            master, _ = IntegrationRepairService._process_identity(worker_pid, binary, b'worker process')
            _, started = IntegrationRepairService._process_identity(master, binary, b'master process')
            if str(master) + ':' + started != expected_master:
                return False
            client = connection.sock.getsockname()
            peer = connection.sock.getpeername()
            if client[0] != '127.0.0.1' or peer != ('127.0.0.1', port):
                return False
            def address(value):
                return socket.inet_aton(value[0])[::-1].hex().upper() + ':%04X' % value[1]
            endpoints = (address(peer), address(client))
            inodes = set()
            for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 9 and tuple(fields[1:3]) == endpoints and fields[3] == '01':
                    inodes.add('socket:[' + fields[9] + ']')
            if not inodes:
                return False
            for descriptor in (Path('/proc') / str(worker_pid) / 'fd').iterdir():
                try:
                    if os.readlink(descriptor) in inodes:
                        return True
                except OSError:
                    continue
        except (OSError, ValueError, IndexError):
            pass
        return False

    @staticmethod
    def _probe_loop(binary, expected_master, port=39091):
        import http.client
        nonce = uuid.uuid4().hex
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=0.5)
            try:
                connection.request('GET', '/_gpt_firewall_health/' + nonce,
                                   headers={'Host': 'gpt-firewall-health.invalid', 'Connection': 'keep-alive'})
                response = connection.getresponse()
                payload = response.read(4097)
                if response.status == 200 and len(payload) <= 4096:
                    data = json.loads(payload)
                    if (data.get('product') == 'aapanel GPT Firewall' and data.get('version') == PLUGIN_VERSION
                            and data.get('nonce') == nonce and type(data.get('worker_pid')) is int
                            and IntegrationRepairService._verify_peer(connection, data['worker_pid'], binary, expected_master, port)):
                        return dict(execution_verified=True, worker_pid=data['worker_pid'])
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(0.1)
        raise UpdateError('health_probe_failed', '本机请求未验证 Lua 执行，不能确认接入成功。')

    def _probe(self):
        identity = self._master_identity()
        process = subprocess.Popen([
            sys.executable, '-B', str(Path(__file__).absolute()), '--probe-integration', identity,
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True, shell=False)
        try:
            output, _ = process.communicate(timeout=5)
        except BaseException as error:
            process.kill()
            process.communicate()
            if isinstance(error, subprocess.TimeoutExpired):
                raise UpdateError('health_probe_timeout', '本机验证超时，已结束验证进程；不能确认接入成功。') from None
            raise
        if process.returncode != 0 or len(output) > 4096:
            raise UpdateError('health_probe_failed', '本机请求未验证 Lua 执行，不能确认接入成功。')
        proof = json.loads(output)
        if proof.get('execution_verified') is not True or type(proof.get('worker_pid')) is not int:
            raise UpdateError('health_probe_failed', '本机请求未验证 Lua 执行，不能确认接入成功。')
        return dict(execution_verified=True, worker_pid=proof['worker_pid'])

    def probe_if_managed(self):
        if self._read(self.include) != self.INCLUDE:
            return dict(execution_verified=False)
        return self._probe()

    def _nginx(self, operation):
        arguments = [str(self.binary)] + (['-s', 'reload'] if operation == 'reload' else ['-t'])
        arguments += ['-p', str(self.server / 'nginx') + '/', '-c', str(self.main)]
        if self._command(arguments, timeout=5)[0] != 0:
            raise UpdateError('nginx_' + operation + '_failed', '宝塔 Nginx 检查或重载失败，正在恢复接入前状态。')

    def _create_include(self):
        self._safe(self.include.parent, directory=True)
        descriptor, temporary = tempfile.mkstemp(prefix='.gpt-firewall-', dir=str(self.include.parent))
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(self.INCLUDE)
                stream.flush()
                if os.name == 'posix':
                    os.fchmod(stream.fileno(), 0o644)
                os.fsync(stream.fileno())
            # Publish atomically without ever overwriting an existing/conflicting include.
            info = os.stat(temporary, follow_symlinks=False)
            os.link(temporary, self.include)
            self._owned_include = (info.st_dev, info.st_ino)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def repair(self, revision, confirmation):
        if confirmation != self.CONFIRMATION or not isinstance(revision, str) or not re.fullmatch(r'[a-f0-9]{64}', revision):
            return self._failure(UpdateError('confirmation', '缺少本次修复预览与明确确认，未修改任何配置。'))
        try:
            self._production()
            with self._activation_lock():
                job = self._job()
                if job and (job.get('state') in ('queued', 'running') or
                            job.get('rollback', {}).get('state') in ('recovery_required', 'failed')):
                    raise UpdateError('busy', '已有更新或待恢复任务，未开始接入修复。')
                snapshot = self._snapshot()
                if snapshot['revision'] != revision:
                    raise UpdateError('revision_changed', '配置在预览后发生变化，请重新预览确认，未开始接入。')
                self._check_probe_port()
                backup = self.store / 'integration-backups' / uuid.uuid4().hex
                self._mkdir(backup)
                manifest = []
                for index, (path, data) in enumerate(snapshot['files'].items()):
                    name = str(index) + '.backup'
                    self._atomic_write(backup / name, data)
                    manifest.append(dict(path=str(path), backup=name, sha256=hashlib.sha256(data).hexdigest()))
                self._save(backup / 'manifest.json', dict(revision=revision, files=manifest, include_existed=False))
                # Stop if an administrator edited any input while the backup was written.
                if self._snapshot()['revision'] != revision:
                    raise UpdateError('revision_changed', '备份期间配置发生变化，未创建接入文件，请重新确认。')
                record = dict(state='applying', backup=str(backup), revision=revision, checked_at=int(time.time()))
                self._save(self.record, record)
                self._owned_include = None
                reload_attempted = False
                try:
                    self._create_include()
                    self._assert_unchanged(snapshot, owned=True)
                    self._nginx('test')
                    self._assert_unchanged(snapshot, owned=True)
                    reload_attempted = True
                    self._nginx('reload')
                    proof = self._probe()
                    self._assert_unchanged(snapshot, owned=True)
                    record.update(state='succeeded', **proof)
                    self._save(self.record, record)
                    return dict(status=True, integration='configured', execution_verified=True,
                                verification_scope='local_health_probe', configured_open=snapshot['configured_open'],
                                backup=str(backup), msg='接入修复完成，本机健康请求已执行 Lua；原开关和规则未改动。此验证不代表所有站点及 location 均已覆盖。')
                except Exception as error:
                    rollback = 'restored'
                    try:
                        if self._owned_include is not None:
                            self._assert_files_unchanged(snapshot)
                            self._quarantine_owned(backup)
                            self._assert_unchanged(snapshot)
                            if reload_attempted:
                                self._nginx('test')
                                self._assert_unchanged(snapshot)
                                self._nginx('reload')
                        record.update(state='rolled_back')
                    except Exception:
                        rollback = 'recovery_required'
                        record.update(state='recovery_required')
                    self._save(self.record, record)
                    result = self._failure(error)
                    result.update(rollback=rollback, backup=str(backup), execution_verified=False)
                    result['msg'] += (' 已撤销本次接入文件，保留原配置；重载信号不等于旧工作进程已经完成恢复。'
                                      if rollback == 'restored' else ' 自动恢复未确认，已停止重试；请在本机检查备份与修复记录。')
                    return result
        except Exception as error:
            return self._failure(error)


if __name__ == '__main__':
    raise SystemExit(main())
