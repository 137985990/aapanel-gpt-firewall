"""Read-only, bounded statistics over the available server access logs."""

import datetime as dt
import gzip
import heapq
import ipaddress
import io
import math
import os
import re
import stat
import time
import zlib
from collections import Counter
from contextlib import closing, contextmanager
from pathlib import Path


PLUGIN_VERSION = "0.1.2"

_DEFAULT_BUDGETS = {
    "max_bytes": 32 * 1024 * 1024, "max_seconds": 10.0,
    "max_keys": 50000, "max_files": 256, "max_entries": 4096,
    "max_line_bytes": 16384,
}
_MAX_BUDGETS = {
    "max_bytes": 128 * 1024 * 1024, "max_seconds": 30.0,
    "max_keys": 100000, "max_files": 4096, "max_entries": 16384,
    "max_line_bytes": 65536,
}


class _StopScan(Exception):
    pass


class _FileLimit(Exception):
    pass


class _UnsafePath(OSError):
    pass


class _Budget:
    def __init__(self, limits, coverage):
        self.limits = limits
        self.coverage = coverage
        self.deadline = time.monotonic() + limits["max_seconds"]
        self.keys = 0

    def check(self):
        if time.monotonic() >= self.deadline:
            raise _StopScan("time_budget")

    def reason(self, value):
        if value not in self.coverage["reasons"]:
            self.coverage["reasons"].append(value)


class _LimitedInput(io.RawIOBase):
    """Bound disk reads as well as decompressed bytes, including gzip headers."""

    def __init__(self, stream, size, budget, limit):
        self.stream, self.size, self.budget = stream, size, budget
        self.limit, self.bytes_read = limit, 0

    def readable(self):
        return True

    def read(self, size=-1):
        self.budget.check()
        available = self.size - self.stream.tell()
        if available <= 0:
            return b""
        remaining = self.budget.limits["max_bytes"] - self.budget.coverage["source_bytes_read"]
        if remaining <= 0:
            raise _StopScan("byte_budget")
        file_remaining = self.limit - self.bytes_read
        if file_remaining <= 0:
            raise _FileLimit()
        size = min(65536 if size < 0 else size, remaining, file_remaining, available)
        binary = self.stream.read(size)
        self.bytes_read += len(binary)
        self.budget.coverage["source_bytes_read"] += len(binary)
        return binary


def _is_link(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)

_LOG_NAME = re.compile(
    r"^(?P<base>.+)\.log(?P<rotation>(?:\.[1-9][0-9]*|[.-]\d{4}-?\d{2}-?\d{2})?)(?P<gzip>\.gz)?$"
)
_DATED_BASE = re.compile(r"^(.+)[_.-](\d{4}-?\d{2}-?\d{2})$")
_QUOTED = r'((?:[^"\\]|\\.)*)'
_ACCESS = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"' + _QUOTED +
    r'"\s+(\d{3})\s+(\d+|-)\s+"' + _QUOTED + r'"\s+"' + _QUOTED + r'"\s*$'
)
_STAMP = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
_MONTHS = {month: index for index, month in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_ESCAPE = re.compile(rb'\\(x[0-9a-fA-F]{2}|["\\])')
_DIAGNOSTIC = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^\]]+)\]")
_SPIDERS = (
    ("googlebot", "Googlebot"), ("bingbot", "Bingbot"), ("msnbot", "Bingbot"),
    ("baiduspider", "Baiduspider"), ("yandex", "Yandex"), ("duckduckbot", "DuckDuckBot"),
    ("slurp", "Yahoo"), ("sogou", "Sogou"), ("youdao", "Youdao"), ("yisou", "Yisou"),
    ("360spider", "QH360"), ("sosospider", "Soso"), ("facebot", "Facebot"),
    ("facebookexternalhit", "Facebot"), ("exabot", "Exabot"), ("dnspod", "dnspod"),
)


def _unescape(value):
    binary = _ESCAPE.sub(lambda m: bytes([int(m[1][1:], 16)]) if m[1].startswith(b"x") else m[1],
                         value.encode("utf-8"))
    return binary.decode("utf-8", errors="replace")


def _parse_access(line):
    match = _ACCESS.fullmatch(line)
    if not match:
        return None
    ip, stamp, request, status, size, referer, agent = match.groups()
    parts = _unescape(request).split() if request != "-" else []
    clock = _STAMP.fullmatch(stamp)
    if not clock:
        return None
    try:
        day, month, year, hour, minute, second, sign, offset_hour, offset_minute = clock.groups()
        if int(offset_hour) > 23 or int(offset_minute) > 59:
            return None
        offset = dt.timedelta(hours=int(offset_hour), minutes=int(offset_minute))
        zone = dt.timezone(offset if sign == "+" else -offset)
        moment = dt.datetime(int(year), _MONTHS[month.title()], int(day),
                             int(hour), int(minute), int(second), tzinfo=zone)
        ip = str(ipaddress.ip_address(ip))
        if not 100 <= int(status) <= 599:
            return None
        return {"time": stamp, "time_ts": moment.timestamp(), "ip": ip,
                "method": parts[0] if parts else "", "uri": parts[1] if len(parts) > 1 else "",
                "protocol": parts[2] if len(parts) == 3 and re.fullmatch(r"HTTP/\d+(?:\.\d+)?", parts[2]) else "",
                "status": int(status), "bytes": 0 if size == "-" else int(size),
                "referer": _unescape(referer), "user_agent": _unescape(agent),
                "request_time": None, "raw": line}
    except (ValueError, OverflowError, KeyError):
        return None


def _client_dimensions(agent):
    ua = agent.lower()
    browser = "Unknown"
    for tokens, name in (
        (("edg/", "edge/", "edga/", "edgios/"), "Edge"),
        (("opr/", "opera"), "Opera"), (("micromessenger",), "WeChat"),
        (("qqbrowser",), "QQ"), (("360se", "360ee"), "360"),
        (("samsungbrowser",), "Samsung Internet"), (("chrome/", "crios/"), "Chrome"),
        (("firefox/", "fxios/"), "Firefox"), (("msie", "trident/"), "IE"),
        (("safari/",), "Safari"),
    ):
        if any(token in ua for token in tokens):
            browser = name
            break
    if any(token in ua for token in ("iphone", "ipad", "ipod")):
        operating_system = "iOS"
    elif "android" in ua:
        operating_system = "Android"
    elif "windows" in ua:
        operating_system = "Windows"
    elif "macintosh" in ua or "mac os" in ua:
        operating_system = "Mac"
    elif "linux" in ua:
        operating_system = "Linux"
    else:
        operating_system = "Unknown"
    if "ipad" in ua or "tablet" in ua or ("android" in ua and "mobile" not in ua):
        device = "Tablet"
    elif "mobile" in ua or "iphone" in ua or "ipod" in ua or "android" in ua:
        device = "Mobile"
    elif operating_system in ("Windows", "Mac", "Linux"):
        device = "PC"
    else:
        device = "Unknown"
    return browser, operating_system, device


def _spider(agent):
    ua = agent.lower()
    for token, name in _SPIDERS:
        if token in ua:
            return name
    return "Other" if any(token in ua for token in ("bot", "spider", "crawler")) else ""


def _sample(heap, timestamp, sequence, row, limit):
    candidate = (timestamp, sequence, row)
    if len(heap) < limit:
        heapq.heappush(heap, candidate)
    elif candidate[:2] > heap[0][:2]:
        heapq.heapreplace(heap, candidate)


def _rank(counter, key, limit):
    return [{key: name, "count": count} for name, count in
            sorted(counter.items(), key=lambda pair: (-pair[1], pair[0]))[:limit]]


def _integer(value, default, minimum, maximum):
    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError, OverflowError):
        return default


def _valid_log_date(value):
    digits = value.replace("-", "")
    try:
        dt.date(int(digits[:4]), int(digits[4:6]), int(digits[6:8]))
        return True
    except ValueError:
        return False


def _log_identity(name):
    match = _LOG_NAME.fullmatch(name)
    if not match:
        return None
    rotation = match["rotation"]
    dated_rotation = rotation.startswith("-") or "-" in rotation[1:]
    if dated_rotation and not _valid_log_date(rotation[1:]):
        return None
    base = match["base"]
    dated = _DATED_BASE.fullmatch(base)
    if dated and _valid_log_date(dated[2]):
        base = dated[1]
    diagnostic = base in ("nginx_error", "error") or base.endswith(".error")
    if diagnostic:
        base = base[:-6] if base.endswith(".error") else ""
    if base.endswith(".ssl"):
        base = base[:-4]
    return base, diagnostic


class StatisticsService:
    """Produce JSON-native values; the caller escapes strings at rendering time.

    ``now`` may be a datetime, Unix timestamp, or a callable returning either.
    A timezone-aware datetime supplies the calendar timezone for deterministic
    reports. Otherwise the server's local calendar is used.

    ``budgets`` overrides max_bytes (both disk and decoded input), max_seconds
    (cooperative deadline), max_keys (aggregate cardinality), max_files,
    max_entries, and max_line_bytes. Defaults and hard ceilings are defined
    above. Unreadable, changing, invalid, unsafe, or budget-truncated inputs
    produce partial coverage, never a claim of complete traffic/history.
    """

    def __init__(self, log_directory, now=None, budgets=None):
        self.log_directory = os.path.abspath(os.fspath(log_directory))
        self.now = now
        self.budgets = {}
        for key, default in _DEFAULT_BUDGETS.items():
            try:
                value = float((budgets or {}).get(key, default))
                if not math.isfinite(value) or value <= 0:
                    value = default
            except (TypeError, ValueError, OverflowError):
                value = default
            self.budgets[key] = min(value, _MAX_BUDGETS[key]) if key == "max_seconds" else \
                max(1, int(min(value, _MAX_BUDGETS[key])))

    def _check_directory(self):
        path = Path(self.log_directory)
        for component in reversed([path] + list(path.parents)):
            info = os.lstat(component)
            if _is_link(info):
                raise _UnsafePath("unsafe_directory")
            if not stat.S_ISDIR(info.st_mode):
                raise NotADirectoryError(self.log_directory)

    @contextmanager
    def _root_handle(self):
        self._check_directory()
        descriptor = None
        try:
            if os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY"):
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                descriptor = os.open(os.path.sep, flags)
                for component in Path(self.log_directory).parts[1:]:
                    child = os.open(component, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
            yield descriptor
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _discover(self, budget, root, site_name=""):
        sites, files = set(), []
        with os.scandir(root if root is not None else self.log_directory) as entries:
            for index, entry in enumerate(entries):
                budget.check()
                if index >= budget.limits["max_entries"]:
                    budget.reason("entry_budget")
                    break
                identity = _log_identity(entry.name)
                if not identity:
                    continue
                try:
                    # Windows DirEntry.stat may omit inode/device identifiers.
                    info = os.stat(entry.name, dir_fd=root, follow_symlinks=False) if root is not None else \
                        os.lstat(os.path.join(self.log_directory, entry.name))
                except OSError:
                    budget.reason("file_unavailable")
                    continue
                if _is_link(info) or not stat.S_ISREG(info.st_mode):
                    budget.reason("unsafe_file")
                    continue
                site, diagnostic = identity
                if site:
                    sites.add(site)
                if site_name and site != site_name:
                    continue
                files.append((entry.name, site, diagnostic, info))
        files.sort(key=lambda item: (item[2], item[0].endswith(".gz"), -item[3].st_mtime_ns, item[0]))
        if len(files) > budget.limits["max_files"]:
            budget.reason("file_budget")
        return files[:budget.limits["max_files"]], [{"site": site} for site in sorted(sites)]

    def discover_sites(self):
        """Return bounded metadata-only site options, without opening log content."""
        coverage = {"reasons": []}
        budget = _Budget(self.budgets, coverage)
        try:
            with self._root_handle() as root:
                return self._discover(budget, root)[1]
        except (OSError, _StopScan):
            return []

    def _window(self, days):
        now = self.now() if callable(self.now) else self.now
        system_timezone = now is None or not isinstance(now, dt.datetime) or now.tzinfo is None
        if now is None:
            now = dt.datetime.now().astimezone()
        elif not isinstance(now, dt.datetime):
            now = dt.datetime.fromtimestamp(now).astimezone()
        elif now.tzinfo is None:
            now = now.astimezone()

        def localize(moment):
            return moment.astimezone() if system_timezone else moment.replace(tzinfo=now.tzinfo)

        first = now.date() - dt.timedelta(days=days - 1)
        start = localize(dt.datetime.combine(first, dt.time()))
        trend = []
        if days == 1:
            stop = localize(dt.datetime.combine(first + dt.timedelta(days=1), dt.time()))
            stamp = start.timestamp()
            while stamp < stop.timestamp():
                moment = dt.datetime.fromtimestamp(stamp).astimezone() if system_timezone else \
                    dt.datetime.fromtimestamp(stamp, now.tzinfo)
                trend.append(self._bucket(moment, moment.strftime("%H:%M")))
                stamp += 3600
        else:
            for offset in range(days):
                moment = localize(dt.datetime.combine(first + dt.timedelta(days=offset), dt.time()))
                trend.append(self._bucket(moment, moment.date().isoformat()))
        return now, start, trend, system_timezone

    @staticmethod
    def _bucket(moment, label):
        return {"label": label, "time": moment.isoformat(), "requests": 0,
                "clients": 0, "bytes": 0, "errors": 0}

    def build(self, days=7, site_name="", line_limit=800):
        """Analyze available logs over 1-30 calendar days, including today.

        ``line_limit`` is retained for call compatibility, not an aggregate cap.
        Samples are independently the newest 80 accesses, 120 HTTP 4xx/5xx
        requests (recent_errors), and 120 server diagnostics (server_errors).
        Rotations may overlap or omit history; exact gzip byte-budget boundaries
        conservatively report partial when trailer/EOF cannot be checked.
        Access logs precede diagnostics. Small files are scanned completely when
        their allocation permits; larger plain files use bounded tail samples,
        discarding the first uncertain boundary line. Counts are never scaled
        to estimate omitted data. Gzip stays forward-only and quota-bounded.
        """
        days = _integer(days, 7, 1, 30)
        now, start, trend, system_timezone = self._window(days)
        report = {
            "schema_version": 2, "status": True,
            "checked_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "siteName": str(site_name or "").strip(), "site_options": [],
            "summary": {"days": days, "total_requests": 0, "unique_clients": 0,
                        "total_bytes": 0, "error_requests": 0, "spider_requests": 0,
                        "errors_4xx": 0, "errors_5xx": 0},
            "sites": [], "spiders": [], "clients": [], "status_codes": [],
            "top_uris": [], "referers": [], "common_clients": [],
            "recent_access": [], "recent_errors": [], "server_errors": [],
            "access_logs": [], "error_logs": [], "settings": [], "trend": trend,
            "browsers": [], "operating_systems": [], "devices": [],
            "coverage": {"complete": True, "partial": False, "reasons": [],
                         "files_scanned": 0, "invalid_lines": 0, "bytes_read": 0, "source_bytes_read": 0,
                         "notice": "完整仅表示已处理本次发现的可用日志，不证明全部流量或历史完整；轮转可能缺失或重叠。"},
            "window": {"start": start.isoformat(), "end": now.isoformat(),
                       "timezone": getattr(now.tzinfo, "key", None) or now.tzname()},
        }
        self._aggregate(report, now, start, system_timezone, _Budget(self.budgets, report["coverage"]))
        return report

    def _open_file(self, name, expected, root):
        path = os.path.join(self.log_directory, name)
        if root is None:
            self._check_directory()
        current = os.stat(name, dir_fd=root, follow_symlinks=False) if root is not None else os.lstat(path)
        if _is_link(current) or not stat.S_ISREG(current.st_mode):
            raise _UnsafePath("unsafe_file")
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            raise _UnsafePath("file_changed")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(name, flags, dir_fd=root) if root is not None else os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            after = os.stat(name, dir_fd=root, follow_symlinks=False) if root is not None else os.lstat(path)
            if root is None:
                self._check_directory()
            if _is_link(after) or not stat.S_ISREG(opened.st_mode):
                raise _UnsafePath("unsafe_file")
            if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino) or \
                    (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
                raise _UnsafePath("file_changed")
            return os.fdopen(descriptor, "rb", buffering=0), opened
        except BaseException:
            os.close(descriptor)
            raise

    def _lines(self, stream, source, budget, compressed, discard_first=False):
        pending, discard, decoded = b"", discard_first, 0
        while True:
            budget.check()
            remaining = budget.limits["max_bytes"] - budget.coverage["bytes_read"]
            if remaining <= 0:
                if not compressed and source.stream.tell() >= source.size:
                    break
                raise _StopScan("byte_budget")
            file_remaining = source.limit - decoded
            if file_remaining <= 0:
                if not compressed and source.stream.tell() >= source.size:
                    break
                raise _FileLimit()
            reader = stream.read1 if compressed else stream.read
            chunk = reader(min(65536, remaining, file_remaining))
            decoded += len(chunk)
            budget.coverage["bytes_read"] += len(chunk)
            if not chunk:
                break
            parts = chunk.split(b"\n")
            for index, part in enumerate(parts):
                budget.check()
                terminated = index < len(parts) - 1
                if not discard and len(pending) + len(part) > budget.limits["max_line_bytes"]:
                    budget.coverage["invalid_lines"] += 1
                    budget.reason("line_too_long")
                    discard, pending = True, b""
                if not discard:
                    pending += part
                    if terminated:
                        yield pending
                        pending = b""
                if terminated:
                    discard = False
        if pending and not discard:
            yield pending

    @staticmethod
    def _file_quotas(files, budget):
        # Allocate small files in full, then share the remainder among larger
        # candidates. Diagnostics only receive what access logs did not consume.
        for diagnostic in (False, True):
            group = [item for item in files if item[2] == diagnostic]
            available = max(0, budget.limits["max_bytes"] - max(
                budget.coverage["bytes_read"], budget.coverage["source_bytes_read"]))
            demands = sorted((budget.limits["max_bytes"] if item[0].endswith(".gz") else item[3].st_size,
                              item[0]) for item in group)
            quotas = {}
            for index, (demand, name) in enumerate(demands):
                quota = min(demand, available // (len(demands) - index))
                quotas[name] = quota
                available -= quota
            for item in group:
                yield item, quotas[item[0]]

    def _records(self, report, budget):
        try:
            with self._root_handle() as root:
                files, report["site_options"] = self._discover(budget, root, report["siteName"])
                for (name, site, diagnostic, expected), quota in self._file_quotas(files, budget):
                    budget.check()
                    kind = "error_logs" if diagnostic else "access_logs"
                    report[kind].append(os.path.join(self.log_directory, name))
                    if quota <= 0 and (expected.st_size or name.endswith(".gz")):
                        budget.reason("byte_budget")
                        continue
                    try:
                        stream, initial = self._open_file(name, expected, root)
                        with stream:
                            if (expected.st_size, expected.st_mtime_ns) != (initial.st_size, initial.st_mtime_ns):
                                budget.reason("file_changed")
                            report["coverage"]["files_scanned"] += 1
                            compressed = name.endswith(".gz")
                            offset = 0 if compressed else max(0, initial.st_size - quota)
                            if offset:
                                stream.seek(offset)
                                budget.reason("tail_sampling")
                                budget.reason("byte_budget")
                            source = _LimitedInput(stream, initial.st_size, budget, quota)
                            reader = gzip.GzipFile(fileobj=source, mode="rb") if compressed else source
                            with closing(reader):
                                for binary in self._lines(reader, source, budget, compressed, bool(offset)):
                                    try:
                                        line = binary.decode("utf-8").rstrip("\r")
                                    except UnicodeError:
                                        report["coverage"]["invalid_lines"] += 1
                                        continue
                                    if line.strip():
                                        yield site, diagnostic, line
                            final = os.fstat(stream.fileno())
                            if (initial.st_size, initial.st_mtime_ns) != (final.st_size, final.st_mtime_ns):
                                budget.reason("file_changed")
                    except _UnsafePath as exc:
                        budget.reason(str(exc))
                    except _FileLimit:
                        budget.reason("byte_budget")
                    except (OSError, EOFError, zlib.error):
                        budget.reason("file_unavailable")
        except _UnsafePath as exc:
            budget.reason(str(exc))
        except OSError:
            budget.reason("directory_unavailable")
        except _StopScan as exc:
            budget.reason(str(exc))

    def _aggregate(self, report, now, start, system_timezone, budget):
        summary = report["summary"]
        sites, client_sites = {}, {}
        counters = {key: Counter() for key in ("clients", "spiders", "status_codes", "top_uris",
                                               "referers", "browsers", "operating_systems", "devices")}
        access_heap, error_heap, diagnostic_heap = [], [], []
        bucket_clients = [set() for _ in report["trend"]]
        daily_indices = {row["label"]: i for i, row in enumerate(report["trend"])}
        records = self._records(report, budget)
        for sequence, (site, diagnostic, line) in enumerate(records):
            if diagnostic:
                row = self._parse_diagnostic(line, now, system_timezone)
            else:
                row = _parse_access(line)
            if row is None:
                report["coverage"]["invalid_lines"] += 1
                continue
            if not start.timestamp() <= row["time_ts"] <= now.timestamp():
                continue
            row["site"] = site
            if diagnostic:
                _sample(diagnostic_heap, row["time_ts"], sequence, row, 120)
                continue
            if summary["days"] == 1:
                index = int((row["time_ts"] - start.timestamp()) // 3600)
            else:
                moment = dt.datetime.fromtimestamp(row["time_ts"]).astimezone() if system_timezone else \
                    dt.datetime.fromtimestamp(row["time_ts"], now.tzinfo)
                index = daily_indices[moment.date().isoformat()]
            bucket = report["trend"][index]
            ip, status, size = row["ip"], row["status"], row["bytes"]
            errors = int(400 <= status <= 599)
            spider = _spider(row["user_agent"])
            dimensions = _client_dimensions(row["user_agent"])
            changes = [("clients", ip), ("status_codes", str(status)), ("top_uris", row["uri"])]
            changes.extend(zip(("browsers", "operating_systems", "devices"), dimensions))
            if row["referer"] not in ("", "-"):
                changes.append(("referers", row["referer"]))
            if spider:
                changes.append(("spiders", spider))
            new_keys = sum(name not in counters[key] for key, name in changes)
            new_keys += int(site not in sites) + int(ip not in client_sites)
            new_keys += int(ip not in sites.get(site, {}).get("clients", ()))
            new_keys += int(ip not in bucket_clients[index]) + int(site not in client_sites.get(ip, ()))
            if budget.keys + new_keys > budget.limits["max_keys"]:
                budget.reason("cardinality_budget")
                break
            budget.keys += new_keys
            summary["total_requests"] += 1
            summary["total_bytes"] += size
            summary["error_requests"] += errors
            summary["errors_4xx"] += int(400 <= status <= 499)
            summary["errors_5xx"] += int(500 <= status <= 599)
            item = sites.setdefault(site, {"site": site, "requests": 0, "clients": set(), "bytes": 0, "errors": 0})
            for item_to_update in (item, bucket):
                item_to_update["requests"] += 1
                item_to_update["bytes"] += size
                item_to_update["errors"] += errors
            item["clients"].add(ip)
            bucket_clients[index].add(ip)
            client_sites.setdefault(ip, set()).add(site)
            counters["clients"][ip] += 1
            counters["status_codes"][str(status)] += 1
            counters["top_uris"][row["uri"]] += 1
            if row["referer"] not in ("", "-"):
                counters["referers"][row["referer"]] += 1
            if spider:
                summary["spider_requests"] += 1
                counters["spiders"][spider] += 1
            for key, name in zip(("browsers", "operating_systems", "devices"),
                                 dimensions):
                counters[key][name] += 1
            _sample(access_heap, row["time_ts"], sequence, row, 80)
            if errors:
                _sample(error_heap, row["time_ts"], sequence, row, 120)
        records.close()
        summary["unique_clients"] = len(counters["clients"])
        for bucket, clients in zip(report["trend"], bucket_clients):
            bucket["clients"] = len(clients)
        for item in sites.values():
            item["clients"] = len(item["clients"])
        report["sites"] = sorted(sites.values(), key=lambda item: (-item["requests"], item["site"]))
        for key, field, limit in (("clients", "ip", 50), ("spiders", "spider", 20),
                                  ("status_codes", "status", 20), ("top_uris", "uri", 30),
                                  ("referers", "referer", 30), ("browsers", "name", 50),
                                  ("operating_systems", "name", 50), ("devices", "name", 50)):
            report[key] = _rank(counters[key], field, limit)
        common = [row for row in report["clients"] if len(client_sites[row["ip"]]) > 1 or report["siteName"]]
        report["common_clients"] = [dict(row, sites=", ".join(sorted(client_sites[row["ip"]])))
                                    for row in (common or report["clients"])[:30]]
        for key, heap in (("recent_access", access_heap), ("recent_errors", error_heap),
                          ("server_errors", diagnostic_heap)):
            report[key] = [item[2] for item in sorted(heap, reverse=True)]
        coverage = report["coverage"]
        if coverage["invalid_lines"]:
            coverage["reasons"].append("invalid_lines")
        coverage["reasons"] = sorted(set(coverage["reasons"]))
        coverage["partial"] = bool(coverage["reasons"])
        coverage["complete"] = not coverage["partial"]
        if coverage["partial"]:
            coverage["notice"] = "仅处理了本次发现日志的部分数据；" + coverage["notice"]
        if "tail_sampling" in coverage["reasons"]:
            coverage["notice"] += "大普通日志按候选配额读取尾部，丢弃首个不确定边界行；统计仅覆盖样本，非所选时段全量。"
        if "byte_budget" in coverage["reasons"]:
            coverage["notice"] += "读取配额已限制覆盖；gzip 仅从开头有界读取，可能未读到近期记录；0 请求或空样本不代表没有访问。"
        report["settings"] = [
            {"key": "统计模式", "value": "只读分析已发现日志；不修改 Nginx 或 WAF"},
            {"key": "日志目录", "value": self.log_directory},
            {"key": "统计窗口", "value": "包含今日的最近 %d 个自然日" % summary["days"]},
            {"key": "站点筛选", "value": report["siteName"] or "全部站点"},
            {"key": "指标口径", "value": "独立 IP 不等于 UV；发送字节不含响应头和上传；UA 分类未验证真伪"},
            {"key": "请求耗时", "value": "combined 未采集耗时，不提供推测值"},
            {"key": "覆盖说明", "value": coverage["notice"]},
        ]

    @staticmethod
    def _parse_diagnostic(line, now, system_timezone):
        match = _DIAGNOSTIC.match(line)
        if not match:
            return None
        try:
            moment = dt.datetime.strptime(match[1], "%Y/%m/%d %H:%M:%S")
            moment = moment.astimezone() if system_timezone else moment.replace(tzinfo=now.tzinfo)
        except (ValueError, OverflowError):
            return None
        row = {"time": match[1], "time_ts": moment.timestamp(), "level": match[2], "raw": line}
        for field in ("client", "server", "request"):
            value = re.search(r'\b' + field + r':\s*(?:"' + _QUOTED + r'"|([^,]*))', line)
            row[field] = _unescape(value[1] if value[1] is not None else value[2].strip()) if value else ""
        return row
