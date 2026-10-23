import json
import ipaddress
import os
import re
import stat
import time
from pathlib import Path


class BanStore:
    def __init__(self, rule_path, meta_path=None, now_fn=None):
        self.rule_path = Path(rule_path)
        self.meta_path = Path(meta_path) if meta_path else None
        self.now_fn = now_fn or (lambda: int(time.time()))

    def load_rules(self):
        if not self.rule_path.exists():
            return []
        body = self.rule_path.read_text()
        if not body.strip():
            return []
        return json.loads(body)

    def save_rules(self, rules):
        self.rule_path.write_text(json.dumps(rules, separators=(",", ":")))

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
