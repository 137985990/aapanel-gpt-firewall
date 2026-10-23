"""Fixed-source updates; no scheduler, frontend paths, or arbitrary commands."""
import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
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


PLUGIN_VERSION = '0.1.3'
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

    def _atomic_write(self, path, data, *, metadata=None, mode=0o600, preserve_times=True):
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
    def _metadata(path):
        value = path.stat()
        return dict(mode=stat.S_IMODE(value.st_mode), uid=value.st_uid, gid=value.st_gid,
                    atime_ns=value.st_atime_ns, mtime_ns=value.st_mtime_ns)

    def _backup(self, directory):
        manifest = {}
        for name in MANAGED_FILES:
            path = self.plugin / name
            self._safe(path, missing=True)
            entry = dict(existed=path.exists())
            if entry['existed']:
                entry.update(metadata=self._metadata(path))
                data = self._read(path)
                entry['sha256'] = hashlib.sha256(data).hexdigest()
                self._atomic_write(directory / 'plugin' / name, data)
            manifest[name] = entry
        path = self.runtime / 'init.lua'
        self._safe(path)
        manifest['runtime'] = dict(metadata=self._metadata(path))
        data = self._read(path)
        manifest['runtime']['sha256'] = hashlib.sha256(data).hexdigest()
        self._atomic_write(directory / 'runtime/init.lua', data)
        self._save(directory / 'manifest.json', manifest)
        return manifest

    def _rollback(self, backup, manifest, installer_attempted, touched, conflicts):
        errors = []
        conflicts = list(conflicts)
        for name, candidate_hash in touched.items():
            try:
                entry, target = manifest[name], self.plugin / name
                self._safe(target, missing=True)
                current_hash = hashlib.sha256(self._read(target)).hexdigest() if target.exists() else None
                original_hash = entry.get('sha256')
                if current_hash == original_hash:
                    continue
                if current_hash != candidate_hash:
                    conflicts.append(name)
                    continue
                if entry['existed']:
                    data = self._read(backup / 'plugin' / name)
                    if hashlib.sha256(data).hexdigest() != entry['sha256']:
                        raise UpdateError('backup', '备份摘要不一致。')
                    self._atomic_write(target, data, metadata=entry['metadata'])
                elif target.exists():
                    target.unlink()
            except Exception:
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
                elif current_hash == touched.get('init.lua'):
                    self._atomic_write(target, data, metadata=manifest['runtime']['metadata'])
                    reload_needed = runtime_restored = True
                else:
                    conflicts.append('runtime')
            except Exception:
                errors.append('runtime')
            try:
                status_path = self.plugin / 'install-status.json'
                report = self._json(status_path) if status_path.exists() else {}
                reload_needed = reload_needed or report.get('runtime_changed') is True
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
    def _command(arguments, timeout=30, capture=False):
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, shell=False, start_new_session=True)
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
        code, _ = self._command(['/bin/bash', str(plugin / 'install.sh'), 'install'], timeout=180)
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
        tokens = shlex.split(output.decode('utf-8'), comments=True)
        hooks = [tokens[i + 1].rstrip(';') for i, token in enumerate(tokens[:-1]) if token == 'init_by_lua_file']
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
            with self._lock(blocking=True):
                job = self._job()
                if not job or job['id'] != job_id or job['state'] != 'queued':
                    raise UpdateError('job', '任务不存在、已执行或需要人工恢复。')
                backup, manifest, changes, installer_attempted = None, None, False, False
                touched, conflicts = {}, []
                try:
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
                        touched[name] = hashlib.sha256(data).hexdigest()
                        self._atomic_write(target, data, metadata=entry.get('metadata'), preserve_times=False,
                                           mode=0o755 if name == 'install.sh' else 0o644)
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
    parser.add_argument('--network-timeout', type=float, default=NETWORK_SECONDS)
    parser.add_argument('--max-bytes', type=int, default=MAX_JSON)
    args = parser.parse_args()
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


if __name__ == '__main__':
    raise SystemExit(main())
