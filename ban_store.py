import json
import hashlib
import ipaddress
import os
import re
import stat
import tempfile
import threading
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from urllib.parse import unquote

try:
    import fcntl
except ImportError:
    fcntl = None
    import msvcrt


def _locked_rules(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._transaction():
            return method(self, *args, **kwargs)
    return locked


class BanStore:
    def __init__(self, rule_path, meta_path=None, now_fn=None):
        self.rule_path = Path(rule_path)
        self.meta_path = Path(meta_path) if meta_path else None
        self.now_fn = now_fn or (lambda: int(time.time()))
        self._lock = threading.RLock()
        self._lock_depth = 0

    @contextmanager
    def _transaction(self):
        with self._lock:
            if self._lock_depth:
                yield
                return
            # Lua uses the same permanent inode and Linux flock protocol.
            path = self.rule_path.with_name(self.rule_path.name + '.lock')
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
                                 | getattr(os, 'O_CLOEXEC', 0), 0o600)
            try:
                locked = os.fstat(descriptor)
                named = path.lstat()
                if (not stat.S_ISREG(locked.st_mode) or locked.st_nlink != 1
                        or (locked.st_dev, locked.st_ino) != (named.st_dev, named.st_ino)):
                    raise OSError('unsafe IP blacklist lock inode')
                if fcntl is not None:
                    owner = self.rule_path.stat() if self.rule_path.exists() else self.rule_path.parent.stat()
                    # Grant lock access to the same group/other writers, never to readers alone.
                    mode = 0o600 | (0o060 if owner.st_mode & 0o020 else 0) | (0o006 if owner.st_mode & 0o002 else 0)
                    if (locked.st_uid, locked.st_gid) != (owner.st_uid, owner.st_gid):
                        os.fchown(descriptor, owner.st_uid, owner.st_gid)
                    if stat.S_IMODE(os.fstat(descriptor).st_mode) != mode:
                        os.fchmod(descriptor, mode)
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                else:
                    msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
                self._lock_depth = 1
                try:
                    yield
                finally:
                    self._lock_depth = 0
            finally:
                os.close(descriptor)

    def load_rules(self):
        if not self.rule_path.exists():
            return []
        body = self.rule_path.read_text()
        if not body.strip():
            return []
        rules = json.loads(body)
        if not isinstance(rules, list):
            raise ValueError('invalid IP blacklist')
        return rules

    @_locked_rules
    def save_rules(self, rules):
        body = json.dumps(rules, separators=(",", ":")).encode('utf-8')
        previous = self.rule_path.stat() if self.rule_path.exists() else None
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.rule_path.parent, prefix='.ip-black-', delete=False) as stream:
                temporary = stream.name
                if hasattr(os, 'fchown') and os.geteuid() == 0:
                    owner = previous or self.rule_path.parent.stat()
                    os.fchown(stream.fileno(), owner.st_uid, owner.st_gid)
                os.chmod(temporary, stat.S_IMODE(previous.st_mode) if previous else 0o600)
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.rule_path)
            temporary = None
            if self.rule_path.read_bytes() != body:
                raise OSError('IP blacklist write verification failed')
        finally:
            if temporary is not None:
                os.unlink(temporary)

    @_locked_rules
    def mutate_rules(self, mutator):
        rules = mutator(self.load_rules())
        if not isinstance(rules, list):
            raise ValueError('IP blacklist mutator must return a list')
        self.save_rules(rules)
        return rules

    def _ip_to_arr(self, ip):
        parts = ip.split(".")
        if len(parts) != 4:
            raise ValueError("invalid ip")
        nums = [int(p) for p in parts]
        if any(v < 0 or v > 255 for v in nums):
            raise ValueError("invalid ip")
        return nums

    def _is_exact(self, rule):
        return len(rule) >= 2 and rule[0] == rule[1]

    def _is_expired(self, rule, now):
        return len(rule) >= 3 and int(rule[2]) > 0 and int(rule[2]) <= now

    @_locked_rules
    def prune_and_migrate(self, default_seconds=28800):
        now = int(self.now_fn())
        changed = False
        new_rules = []
        for rule in self.load_rules():
            if self._is_expired(rule, now):
                changed = True
                continue
            if len(rule) < 3 and self._is_exact(rule):
                rule = [rule[0], rule[1], now + int(default_seconds)]
                changed = True
            new_rules.append(rule)
        if changed:
            self.save_rules(new_rules)
        return changed

    def active_exact_ips(self):
        now = int(self.now_fn())
        result = []
        for rule in self.load_rules():
            if self._is_expired(rule, now):
                continue
            if self._is_exact(rule):
                result.append(".".join(map(str, rule[0])))
        return result

    @_locked_rules
    def add_temp_ban(self, ip, seconds, reason="manual_temp"):
        ipn = self._ip_to_arr(ip)
        now = int(self.now_fn())
        rules = []
        for rule in self.load_rules():
            if self._is_expired(rule, now):
                continue
            if self._is_exact(rule) and rule[0] == ipn:
                return False
            rules.append(rule)
        rules.insert(0, [ipn, ipn, now + int(seconds)])
        self.save_rules(rules)
        return True

    @_locked_rules
    def remove_exact_ip(self, ip):
        ipn = self._ip_to_arr(ip)
        removed = False
        new_rules = []
        for rule in self.load_rules():
            if self._is_exact(rule) and rule[0] == ipn:
                removed = True
                continue
            new_rules.append(rule)
        if removed:
            self.save_rules(new_rules)
        return removed

    @_locked_rules
    def clear_exact_ips(self):
        removed = 0
        new_rules = []
        for rule in self.load_rules():
            if self._is_exact(rule):
                removed += 1
                continue
            new_rules.append(rule)
        if removed:
            self.save_rules(new_rules)
        return removed


class BanEscalationStore:
    """Read-only durable escalation snapshot; only Lua mutates runtime state."""

    MAX_BYTES = 1024 * 1024
    MAX_ENTRIES = 4096
    MAX_INTEGER = 9007199254740991
    FIELDS = {'site', 'ip', 'started_at', 'expires_at', 'duration', 'trigger_count',
              'window_seconds', 'threshold', 'reason', 'path'}
    REASONS = {'cc', 'registration_abuse_verify', 'registration_abuse_register',
               'endpoint_limit', '404_flood'}

    def __init__(self, snapshot_path='/www/server/free_waf/repeat_bans.json', now_fn=None):
        self.snapshot_path = Path(os.path.abspath(snapshot_path))
        self.now_fn = now_fn or (lambda: int(time.time()))

    @staticmethod
    def _site(value):
        if (type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_\-][A-Za-z0-9_.\-]{0,252}', value)
                or '..' in value):
            raise ValueError('站点名称不正确')
        return value

    @staticmethod
    def _unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('快照字段重复')
            result[key] = value
        return result

    @staticmethod
    def _no_links(path):
        path = Path(path)
        for current in (path,) + tuple(path.parents):
            info = current.lstat()
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)):
                raise ValueError('快照路径不允许符号链接')

    def _read_bytes(self):
        path = self.snapshot_path
        self._no_links(path.parent)
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('快照不是普通文件')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        if os.open in os.supports_dir_fd and hasattr(os, 'O_NOFOLLOW'):
            directory = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in path.parts[1:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    os.close(directory)
                    directory = child
                descriptor = os.open(path.name, flags, dir_fd=directory)
            finally:
                os.close(directory)
        else:
            descriptor = os.open(str(path), flags | getattr(os, 'O_BINARY', 0))
        try:
            info = os.fstat(descriptor)
            self._no_links(path)
            if (not stat.S_ISREG(info.st_mode)
                    or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)):
                raise ValueError('快照文件已变更')
            if info.st_size > self.MAX_BYTES:
                raise ValueError('快照超过 1 MiB 上限')
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                body = stream.read(self.MAX_BYTES + 1)
            if len(body) > self.MAX_BYTES:
                raise ValueError('快照超过 1 MiB 上限')
            return body
        finally:
            os.close(descriptor)

    def _record(self, row):
        if type(row) is not dict or set(row) != self.FIELDS:
            raise ValueError('长期封禁记录字段不正确')
        self._site(row['site'])
        ip = row['ip']
        if (type(ip) is not str or len(ip) > 45 or '%' in ip
                or str(ipaddress.ip_address(ip)) != ip):
            raise ValueError('长期封禁 IP 必须为规范地址')
        for field, low, high in (('started_at', 1, self.MAX_INTEGER), ('expires_at', 1, self.MAX_INTEGER),
                                 ('duration', 60, 31536000), ('threshold', 2, 1000),
                                 ('trigger_count', 2, 1000), ('window_seconds', 60, 604800)):
            if type(row[field]) is not int or not low <= row[field] <= high:
                raise ValueError('长期封禁记录数值不正确：' + field)
        if row['expires_at'] - row['started_at'] != row['duration'] or row['trigger_count'] < row['threshold']:
            raise ValueError('长期封禁时长或档位证据不一致')
        if type(row['reason']) is not str or row['reason'] not in self.REASONS:
            raise ValueError('长期封禁原因不正确')
        path = row['path']
        if (type(path) is not str or not path.startswith('/') or len(path.encode('utf-8')) > 512
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in path)
                or any(c in path for c in ('?', '#', '\\'))):
            raise ValueError('长期封禁证据路径不正确')
        return dict(row)

    def read_snapshot(self):
        try:
            body = self._read_bytes()
        except FileNotFoundError:
            return dict(version=1, revision='0' * 32, bans=[])
        try:
            snapshot = json.loads(body.decode('utf-8'), object_pairs_hook=self._unique_object)
            if (type(snapshot) is not dict or set(snapshot) != {'version', 'revision', 'bans'}
                    or type(snapshot['version']) is not int or snapshot['version'] != 1
                    or type(snapshot['revision']) is not str
                    or not re.fullmatch(r'[0-9a-f]{32}', snapshot['revision'])
                    or type(snapshot['bans']) is not list or len(snapshot['bans']) > self.MAX_ENTRIES):
                raise ValueError('长期封禁快照格式或容量不正确')
            rows = [self._record(row) for row in snapshot['bans']]
            if len({(row['site'], row['ip']) for row in rows}) != len(rows):
                raise ValueError('长期封禁记录重复')
            return dict(version=1, revision=snapshot['revision'], bans=rows)
        except (ValueError, TypeError, RecursionError, OverflowError) as error:
            raise ValueError('长期封禁快照已损坏，未修改存储') from error

    def active_bans(self, site, now=None):
        site = self._site(site)
        now = int(self.now_fn()) if now is None else now
        rows = [row for row in self.read_snapshot()['bans'] if row['site'] == site and row['expires_at'] > now]
        return sorted(rows, key=lambda row: (-row['expires_at'], row['ip']))


class RiskAdviceAnalyzer:
    """Deterministic positive evidence, never an automatic ban decision."""

    VERSION = 'risk-advice-1'
    MAX_PATH_BYTES = 8192
    _ENV = re.compile(r'\.env(?:\.[A-Za-z0-9_-]+)*\Z')
    _REPOSITORY = re.compile(
        r'(?:^|/)(?:\.git/(?:config|HEAD|index|packed-refs|COMMIT_EDITMSG|info/exclude|'
        r'logs/HEAD|(?:logs/)?refs/(?:heads|tags|remotes)/[A-Za-z0-9_./-]+|'
        r'objects/(?:info/packs|[0-9a-f]{2}/[0-9a-f]{38}))|'
        r'\.svn/(?:entries|wc\.db|format)|\.hg/(?:hgrc|dirstate|requires))\Z')
    _CREDENTIALS = re.compile(
        r'(?:^|/)(?:\.aws/(?:credentials|config)|\.ssh/(?:id_rsa|id_dsa|id_ecdsa|'
        r'id_ed25519|authorized_keys|config|known_hosts)|\.docker/config\.json|'
        r'\.npmrc|\.pypirc|\.git-credentials)\Z')
    _BACKUP = re.compile(
        r'(?:(?:database|db|mysqldump|mysql|postgres|postgresql|dump|backup)'
        r'(?:[-_.][A-Za-z0-9_-]+)?\.(?:sql(?:\.(?:gz|bz2|xz|zip))?|dump)|'
        r'wp-config\.php\.(?:bak|old|save|swp))\Z')

    @staticmethod
    def _ip(value):
        if type(value) is not str or len(value) > 45 or '%' in value:
            raise ValueError('invalid IP address')
        address = ipaddress.ip_address(value)
        return str(getattr(address, 'ipv4_mapped', None) or address)

    @staticmethod
    def _epoch(value):
        if type(value) is not int or not 1 <= value <= BanEscalationStore.MAX_INTEGER:
            raise ValueError('invalid evidence timestamp')
        return value

    @classmethod
    def normalize_path(cls, path):
        if (type(path) is not str or not path.startswith('/')
                or len(path.encode('utf-8')) > cls.MAX_PATH_BYTES):
            raise ValueError('invalid evidence path')
        raw = path.split('?', 1)[0].split('#', 1)[0]
        value = raw
        for _ in range(2):
            if re.search(r'%(?![0-9a-fA-F]{2})', value):
                raise ValueError('invalid percent encoding')
            try:
                decoded = unquote(value, encoding='utf-8', errors='strict')
            except UnicodeError as error:
                raise ValueError('invalid encoded path') from error
            if decoded == value:
                break
            value = decoded
        if (any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
                or any(char in value for char in ('\\', '?', '#'))):
            raise ValueError('ambiguous evidence path')
        parts = []
        for part in value.split('/'):
            if part == '..':
                if parts:
                    parts.pop()
            elif part and part != '.':
                parts.append(part)
        normalized = '/' + '/'.join(parts)
        if value.endswith(('/', '/.', '/..')) and parts:
            normalized += '/'
        return normalized

    @classmethod
    def _family(cls, path):
        leaf = path.rsplit('/', 1)[-1]
        if cls._ENV.fullmatch(leaf) and not any(
                token in {'example', 'sample', 'template', 'dist', 'default'} for token in leaf.split('.')[2:]):
            return 'env'
        if cls._REPOSITORY.search(path):
            return 'repository'
        if cls._CREDENTIALS.search(path) or path in {'/etc/passwd', '/etc/shadow', '/proc/self/environ'}:
            return 'credentials'
        if cls._BACKUP.fullmatch(leaf):
            return 'backup'
        return None

    @staticmethod
    def _window_reaches(events, seconds, tier):
        counts, families, family_rows = Counter(), Counter(), Counter()
        left = 0
        for right, (ts, path, family) in enumerate(events):
            if not counts[path]:
                families[family] += 1
            counts[path] += 1
            family_rows[family] += 1
            while ts - events[left][0] > seconds:
                _, old_path, old_family = events[left]
                counts[old_path] -= 1
                family_rows[old_family] -= 1
                if not counts[old_path]:
                    del counts[old_path]
                    families[old_family] -= 1
                left += 1
            related = right - left + 1
            multi = sum(count >= 2 for count in families.values())
            if tier == 7:
                if related >= 300 and len(counts) >= 150 and multi >= 3:
                    return True
            elif ((related >= 60 and len(counts) >= 25 and multi >= 2)
                  or any(count >= 50 and family_rows[family] >= 100 for family, count in families.items())):
                return True
        return False

    def analyze(self, rows, now=None):
        now = self._epoch(int(time.time()) if now is None else now)
        groups = {}
        for row in rows:
            if (type(row) is not dict or not {'site', 'ip', 'ts', 'path', 'rule_type'} <= set(row)
                    or type(row['rule_type']) is not str):
                raise ValueError('invalid evidence row')
            site = BanEscalationStore._site(row['site'])
            ip = self._ip(row['ip'])
            ts = self._epoch(row['ts'])
            if ts > now:
                raise ValueError('future evidence timestamp')
            path = self.normalize_path(row['path'])
            if ts < now - 86400:
                continue
            group = groups.setdefault((site, ip), {'events': set(), 'raw': set()})
            group['events'].add((ts, path))
            group['raw'].add(row['path'].split('?', 1)[0].split('#', 1)[0])
        result = []
        for (site, ip), group in sorted(groups.items()):
            all_events = sorted(group['events'])
            strong = [(ts, path, self._family(path)) for ts, path in all_events if self._family(path)]
            targets = {path: family for _, path, family in strong}
            family_counts = dict(sorted(Counter(targets.values()).items()))
            recommended = 0
            if self._window_reaches(strong, 3600, 7):
                recommended = 604800
            elif self._window_reaches(strong, 600, 1):
                recommended = 86400
            evidence = [self.VERSION, site, ip, strong, recommended]
            fingerprint = hashlib.sha256(json.dumps(evidence, separators=(',', ':'),
                                                     ensure_ascii=True).encode('ascii')).hexdigest()
            result.append(dict(site=site, ip=ip, fingerprint=fingerprint,
                               name=('\u9ad8\u5f3a\u5ea6\u591a\u7c7b\u8def\u5f84\u626b\u63cf' if recommended == 604800 else
                                     '\u654f\u611f\u6587\u4ef6\u6279\u91cf\u63a2\u6d4b' if recommended else
                                     '\u8bc1\u636e\u4e0d\u8db3\uff0c\u5efa\u8bae\u89c2\u5bdf'),
                               recommended_seconds=recommended, related_rows=len(strong),
                               strong_targets=len(targets), family_counts=family_counts,
                               raw_targets=len(group['raw']), first_seen=all_events[0][0],
                               last_seen=all_events[-1][0], samples=sorted(targets)[:5]))
        return result


class ScopedBanStore(BanEscalationStore):
    """Python-only writer for finite site-scoped manual bans; Lua only reads."""

    FIELDS = {'site', 'ip', 'started_at', 'expires_at', 'duration', 'reason', 'evidence_hash'}

    def __init__(self, snapshot_path, now_fn=None):
        super().__init__(snapshot_path, now_fn=now_fn)
        self._lock = threading.RLock()

    @staticmethod
    def _no_links(path):
        BanEscalationStore._no_links(path)
        info = Path(path).lstat()
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError('manual ban files cannot be hardlinked')

    @staticmethod
    def _hash(value, length):
        if type(value) is not str or not re.fullmatch(r'[0-9a-f]{' + str(length) + '}', value):
            raise ValueError('invalid manual ban revision or evidence hash')
        return value

    def _record(self, row):
        if type(row) is not dict or set(row) != self.FIELDS:
            raise ValueError('invalid manual ban fields')
        self._site(row['site'])
        if RiskAdviceAnalyzer._ip(row['ip']) != row['ip']:
            raise ValueError('manual ban requires canonical IP')
        for field, low, high in (('started_at', 1, self.MAX_INTEGER), ('expires_at', 1, self.MAX_INTEGER),
                                 ('duration', 60, 315360000)):
            if type(row[field]) is not int or not low <= row[field] <= high:
                raise ValueError('invalid manual ban numeric field: ' + field)
        if row['expires_at'] - row['started_at'] != row['duration'] or row['reason'] != 'risk_advice':
            raise ValueError('invalid manual ban duration or reason')
        self._hash(row['evidence_hash'], 64)
        return dict(row)

    def snapshot(self):
        try:
            body = self._read_bytes()
        except FileNotFoundError:
            return dict(version=1, revision='0' * 32, entries=[])
        try:
            value = json.loads(body.decode('utf-8'), object_pairs_hook=self._unique_object)
            if (type(value) is not dict or set(value) != {'version', 'revision', 'entries'}
                    or type(value['version']) is not int or value['version'] != 1
                    or type(value['entries']) is not list or len(value['entries']) > self.MAX_ENTRIES):
                raise ValueError('invalid manual ban snapshot')
            self._hash(value['revision'], 32)
            entries = [self._record(row) for row in value['entries']]
            if len({(row['site'], row['ip']) for row in entries}) != len(entries):
                raise ValueError('duplicate manual site ban')
            return dict(version=1, revision=value['revision'], entries=entries)
        except (ValueError, TypeError, RecursionError, OverflowError) as error:
            raise ValueError('manual ban snapshot corrupt; storage unchanged') from error

    @contextmanager
    def _parent_directory(self):
        self._no_links(self.snapshot_path.parent)
        directory = None
        if os.open in os.supports_dir_fd and hasattr(os, 'O_NOFOLLOW'):
            directory = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in self.snapshot_path.parts[1:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    os.close(directory)
                    directory = child
            except BaseException:
                os.close(directory)
                raise
        try:
            yield directory
        finally:
            if directory is not None:
                os.close(directory)

    def _open_named(self, name, flags, mode, directory):
        flags |= getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0)
        if directory is not None:
            return os.open(name, flags, mode, dir_fd=directory)
        return os.open(str(self.snapshot_path.parent / name), flags, mode)

    def _named_stat(self, name, directory):
        if directory is not None:
            return os.stat(name, dir_fd=directory, follow_symlinks=False)
        return (self.snapshot_path.parent / name).lstat()

    def _check_directory(self, directory):
        self._no_links(self.snapshot_path.parent)
        if directory is not None:
            opened, named = os.fstat(directory), self.snapshot_path.parent.lstat()
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise OSError('manual ban directory changed')

    @contextmanager
    def _transaction(self):
        with self._lock, self._parent_directory() as directory:
            name = self.snapshot_path.name + '.lock'
            try:
                existing = self._named_stat(name, directory)
            except FileNotFoundError:
                existing = None
            if existing is not None and (not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1):
                raise ValueError('unsafe manual ban lock')
            descriptor = self._open_named(name, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NONBLOCK', 0),
                                          0o600, directory)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('unsafe manual ban lock')
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                else:
                    msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
                named = self._named_stat(name, directory)
                self._check_directory(directory)
                if (not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                        or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)):
                    raise ValueError('manual ban lock inode changed')
                yield directory
            finally:
                os.close(descriptor)

    def _expected(self, snapshot, revision):
        if revision is not None and self._hash(revision, 32) != snapshot['revision']:
            raise ValueError('manual ban snapshot changed; reread before applying')

    def _persist(self, snapshot, directory):
        if len(snapshot['entries']) > self.MAX_ENTRIES:
            raise ValueError('manual ban snapshot exceeds 4096 entries')
        body = json.dumps(snapshot, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        if len(body) > self.MAX_BYTES:
            raise ValueError('manual ban snapshot exceeds 1 MiB')
        self._check_directory(directory)
        try:
            old = self._named_stat(self.snapshot_path.name, directory)
        except FileNotFoundError:
            old = None
        if old is not None and (not stat.S_ISREG(old.st_mode) or old.st_nlink != 1):
            raise ValueError('unsafe manual ban destination')
        temporary = '.manual-site-ban-' + uuid.uuid4().hex
        descriptor = self._open_named(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, directory)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                if hasattr(os, 'fchmod'):
                    os.fchmod(stream.fileno(), 0o644)
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            self._check_directory(directory)
            try:
                current = self._named_stat(self.snapshot_path.name, directory)
            except FileNotFoundError:
                current = None
            if ((old is None) != (current is None) or (old is not None and
                    (current.st_dev, current.st_ino, current.st_nlink) != (old.st_dev, old.st_ino, 1))):
                raise OSError('manual ban destination changed')
            if directory is not None:
                os.replace(temporary, self.snapshot_path.name, src_dir_fd=directory, dst_dir_fd=directory)
            else:
                os.replace(str(self.snapshot_path.parent / temporary), str(self.snapshot_path))
            temporary = None
            if directory is not None:
                os.fsync(directory)
            if self._read_bytes() != body:
                raise OSError('manual ban write verification failed')
        finally:
            if temporary is not None:
                if directory is not None:
                    os.unlink(temporary, dir_fd=directory)
                else:
                    os.unlink(str(self.snapshot_path.parent / temporary))
        return snapshot

    def add(self, site, ip, seconds, evidence_hash, expected_revision=None):
        site = self._site(site)
        ip = RiskAdviceAnalyzer._ip(ip)
        evidence_hash = self._hash(evidence_hash, 64)
        if type(seconds) is not int or not 60 <= seconds <= 315360000:
            raise ValueError('manual ban duration must be 60 seconds to 10 years')
        if expected_revision is not None:
            self._hash(expected_revision, 32)
        with self._transaction() as directory:
            snapshot = self.snapshot()
            self._expected(snapshot, expected_revision)
            now = RiskAdviceAnalyzer._epoch(self.now_fn())
            row = self._record(dict(site=site, ip=ip, started_at=now, expires_at=now + seconds,
                                    duration=seconds, reason='risk_advice', evidence_hash=evidence_hash))
            for old in snapshot['entries']:
                if (old['site'], old['ip']) == (site, ip) and old['expires_at'] > now:
                    if (old['expires_at'] >= row['expires_at'] or
                            (old['evidence_hash'] == evidence_hash and old['duration'] >= seconds)):
                        return snapshot
            # Expired history is compacted only with a real explicit add, never on reads or retries.
            entries = [old for old in snapshot['entries']
                       if old['expires_at'] > now and (old['site'], old['ip']) != (site, ip)]
            entries.append(row)
            updated = dict(version=1, revision=uuid.uuid4().hex,
                           entries=sorted(entries, key=lambda entry: (entry['site'], entry['ip'])))
            return self._persist(updated, directory)

    def remove(self, site, ip, expected_revision=None):
        site, ip = self._site(site), RiskAdviceAnalyzer._ip(ip)
        if expected_revision is not None:
            self._hash(expected_revision, 32)
        with self._transaction() as directory:
            snapshot = self.snapshot()
            self._expected(snapshot, expected_revision)
            entries = [row for row in snapshot['entries'] if (row['site'], row['ip']) != (site, ip)]
            if len(entries) == len(snapshot['entries']):
                return snapshot
            return self._persist(dict(version=1, revision=uuid.uuid4().hex, entries=entries), directory)
