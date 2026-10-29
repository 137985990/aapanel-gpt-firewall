"""Read-only, bounded statistics over the available server access logs."""

import datetime as dt
import gzip
import heapq
import ipaddress
import io
import json
import math
import os
import re
import stat
import socket
import subprocess
import sys
import time
import zlib
from collections import Counter
from contextlib import closing, contextmanager
from pathlib import Path


PLUGIN_VERSION = "0.1.12"

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
_IN_APP_BROWSERS = tuple((re.compile(r'(?<![a-z0-9_-])(?:' + pattern + r')'), name)
                         for pattern, name in (
    (r'micromessenger(?:/|\s|$)', 'WeChat'),
    (r'dingtalk(?:/|\s|$)', 'DingTalk'),
    (r'alipayclient(?:/|\s|$)', 'Alipay'),
    (r'qq/', 'QQ'),
    (r'fbav/|fban/', 'Facebook'),
    (r'instagram(?:/|\s|$)', 'Instagram'),
    (r'(?<=;)\s*wv[);]', 'Android WebView'),
))
_API_CLIENTS = tuple((re.compile(r'(?<![a-z0-9_-])(?:' + pattern + r')'), name)
                     for pattern, name in (
    (r'openai(?:/(?:python|js|node|go|java|dotnet)\b|[-_](?:python|node)/)', 'OpenAI SDK'),
    (r'anthropic(?:/(?:python|js|node|go|java)\b|[-_](?:python|node)/)', 'Anthropic SDK'),
    (r'(?:boto3|botocore|aws-sdk(?:-[a-z0-9]+)*)/', 'AWS SDK'),
    (r'curl/', 'curl'), (r'wget/', 'Wget'),
    (r'python-requests/', 'Python Requests'), (r'python-httpx/', 'Python HTTPX'),
    (r'python-urllib/', 'Python urllib'), (r'aiohttp/', 'aiohttp'),
    (r'go-http-client/', 'Go HTTP Client'), (r'okhttp/', 'OkHttp'),
    (r'postmanruntime/', 'Postman'), (r'axios/', 'Axios'),
    (r'node-fetch/', 'node-fetch'), (r'undici(?:/|\s|$)', 'Undici'),
    (r'java/', 'Java'), (r'apache-httpclient/', 'Apache HttpClient'),
))


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


def _in_app_browser(ua):
    for pattern, name in _IN_APP_BROWSERS:
        if pattern.search(ua):
            return name
    return ''


def _client_dimensions(agent):
    ua = agent.lower()
    browser = _in_app_browser(ua) or "Unknown"
    for tokens, name in (
        (("edg/", "edge/", "edga/", "edgios/"), "Edge"),
        (("opr/", "opera", "opios/"), "Opera"), (("micromessenger",), "WeChat"),
        (("qqbrowser",), "QQ"), (("360se", "360ee"), "360"),
        (("samsungbrowser",), "Samsung Internet"), (("ucbrowser/", "ucweb/"), "UC Browser"),
        (("chrome/", "crios/"), "Chrome"),
        (("firefox/", "fxios/"), "Firefox"), (("msie", "trident/"), "IE"),
        (("safari/",), "Safari"),
    ):
        if browser != "Unknown":
            break
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


def _client_profile_dimensions(agent, dimensions, spider):
    """Fixed product labels only, without changing legacy browser counters."""
    browser, operating_system, device = dimensions
    ua = agent.lower()
    # SDK names such as Botocore must precede the legacy generic "bot" match.
    for pattern, name in _API_CLIENTS:
        if pattern.search(ua):
            return name, operating_system, 'Unknown', 'api_tool'
    if spider:
        return spider, operating_system, 'Unknown', 'crawler'
    if _in_app_browser(ua):
        return browser, operating_system, device, 'in_app'
    return browser, operating_system, device, 'browser' if browser != 'Unknown' else 'unknown'


class _ClientProfiles:
    """Keep exact counts for the first 200 observed groups, not estimated top-N."""

    FIELDS = ('country_code', 'country_name', 'browser', 'os', 'device', 'client_type')
    MAX_GROUPS = 200

    def __init__(self, budget):
        self.budget = budget
        self.groups = Counter()
        self.observations = []
        self.position = 0
        self.groups_limited = False
        self.time_limited = False

    def observe(self, dimensions, sequence, observations):
        item = observations.get(dimensions)
        if item is None:
            item = dict(first=sequence, count=0, dimensions=dimensions, country=None)
            observations[dimensions] = item
            # One shared entry per budgeted IP/profile, ordered by first request,
            # not one entry per request or by the later per-IP lookup order.
            self.observations.append(item)
        item['count'] += 1

    def add(self, location, observations):
        if self.time_limited:
            return
        country = ((location['country_code'], location['country_name'])
                   if location['status'] == 'located' else ('', '未知'))
        try:
            for item in observations.values():
                self.budget.check()
                item['country'] = country
            # A late profile of an early IP must wait for all earlier requests'
            # profiles to receive their geography from the same lookup pass.
            while self.position < len(self.observations):
                item = self.observations[self.position]
                if item['country'] is None:
                    break
                self.budget.check()
                key = item['country'] + item['dimensions']
                if key in self.groups or len(self.groups) < self.MAX_GROUPS:
                    self.groups[key] += item['count']
                else:
                    self.groups_limited = True
                self.position += 1
        except _StopScan:
            self.time_limited = True

    def result(self, report):
        rows = [dict(zip(self.FIELDS, key), count=count)
                for key, count in sorted(self.groups.items(), key=lambda item: (-item[1], item[0]))]
        request_count = report['summary']['total_requests']
        represented = sum(row['count'] for row in rows)
        omitted = request_count - represented
        notice = ('按已处理请求的实际地域、浏览器或客户端、系统和设备类型联合统计；'
                  '未知项仍计入请求总数，不代表独立设备或人数。'
                  'UA 为客户端自报信息，可伪造；API/SDK 或爬虫类型不表示恶意。'
                  '地域仅用本地 IP 库近似网络出口，不推断具体机型或系统版本。')
        if self.groups_limited:
            notice += '最多保留先遇到的 200 个联合分组，非全量热门排行；超出分组的请求计入省略数。'
        if self.time_limited:
            notice += '联合分类达到本次统计时间预算；未分类请求仍计入请求总数和省略数。'
        if report['coverage']['partial']:
            notice += '日志覆盖不完整；请求总数仅指本次已处理记录，未读取的请求无法计数。'
        if report['geography']['partial']:
            notice += '本地地域查询不完整；无法定位的请求保留为未知地域。'
        return dict(schema_version=1, rows=rows, request_count=request_count,
                    represented_requests=represented, omitted_requests=omitted,
                    partial=bool(omitted or report['coverage']['partial'] or report['geography']['partial']),
                    notice=notice)


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


_COUNTRY_CODES = frozenset((
    'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ '
    'CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET '
    'FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU '
    'ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY '
    'MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ '
    'OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ '
    'TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'
).split())


def _geo_text(value):
    return re.sub(r'[\x00-\x1f\x7f]', '', value).strip()[:128] if isinstance(value, str) else ''


def _geo_name(value):
    if not isinstance(value, dict):
        return ''
    names = value.get('names')
    names = names if isinstance(names, dict) else {}
    return _geo_text(names.get('zh-CN')) or _geo_text(names.get('en'))


class LocalGeography:
    """Bounded local lookups only; missing databases never trigger downloads."""

    def __init__(self, reader=None, max_lookups=10000, max_seconds=1.5):
        self.reader = reader
        self.cache = {}
        self.max_lookups = _integer(max_lookups, 10000, 1, 10000)
        self.deadline = time.monotonic() + max(0.01, min(1.5, float(max_seconds)))
        if self.reader is None:
            try:
                import maxminddb
                self.reader = maxminddb.open_database('/www/server/panel/config/GeoLite2-City.mmdb')
            except Exception:
                pass
        self.available = self.reader is not None

    @staticmethod
    def describe(ip, record):
        result = dict(country_code='', country_name='', region_code='', region_name='',
                      city_name='', location='未知', status='unknown')
        try:
            address = ipaddress.ip_address(ip)
            address = getattr(address, 'ipv4_mapped', None) or address
        except ValueError:
            result['status'] = 'invalid'
            return result
        if not address.is_global or address.is_multicast:
            result.update(status='private', location='内网或保留地址')
            return result
        country = record.get('country') if isinstance(record, dict) else None
        if not isinstance(country, dict):
            return result
        code = country.get('iso_code') or country.get('en_short_code')
        if not isinstance(code, str) or not re.fullmatch(r'[A-Za-z]{2}', code) or code.upper() not in _COUNTRY_CODES:
            return result
        code = code.upper()
        subdivisions = record.get('subdivisions')
        subdivision = subdivisions[0] if isinstance(subdivisions, list) and subdivisions else {}
        if not isinstance(subdivision, dict):
            subdivision = {}
        country_name = _geo_name(country) or _geo_text(country.get('country')) or code
        region_name = _geo_name(subdivision) or _geo_text(country.get('province'))
        region_code = _geo_text(subdivision.get('iso_code'))
        city_name = _geo_name(record.get('city')) or _geo_text(country.get('city'))
        parts = list(dict.fromkeys(part for part in (country_name, region_name, city_name) if part))
        result.update(country_code=code, country_name=country_name, region_code=region_code,
                      region_name=region_name, city_name=city_name, location=' '.join(parts), status='located')
        return result

    def lookup(self, ip):
        try:
            address = ipaddress.ip_address(ip)
            ip = str(getattr(address, 'ipv4_mapped', None) or address)
        except ValueError:
            return self.describe(ip, None)
        if ip in self.cache:
            return self.cache[ip]
        result = self.describe(ip, None)
        if result['status'] == 'private':
            return result
        if not self.available:
            result['status'] = 'unavailable'
            return result
        if len(self.cache) >= self.max_lookups or time.monotonic() >= self.deadline:
            result['status'] = 'limited'
            return result
        try:
            result = self.describe(ip, self.reader.get(ip))
        except Exception:
            result['status'] = 'lookup_error'
        self.cache[ip] = result
        return result

    def close(self):
        reader, self.reader = self.reader, None
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _geo_counts():
    return dict(clients=0, requests=0, bytes=0, errors=0)


def _visitor_geography(report, activity, profiles=None):
    """Classify every counted IP, retaining unlocated traffic in the denominator."""
    geo = dict(schema_version=1, site=report['siteName'], database_available=False,
               lookup_complete=True, partial=False, reasons=[], countries=[], regions=[], cities=[],
               totals=_geo_counts(), located=_geo_counts(), unlocated=_geo_counts(), private=_geo_counts(),
               regions_truncated=False, cities_truncated=False)
    groups = ({}, {}, {})

    def add_counts(target, item):
        target['clients'] += 1
        for field in ('requests', 'bytes', 'errors'):
            target[field] += item[field]

    def add_group(group, key, metadata, item):
        target = group.setdefault(key, dict(metadata, **_geo_counts(), _days=0))
        add_counts(target, item)
        target['_days'] |= item['days']
        return target

    with LocalGeography() as locator:
        geo['database_available'] = locator.available
        if not locator.available:
            geo['reasons'].append('database_unavailable')
        for ip, item in activity.items():
            location = locator.lookup(ip)
            if profiles is not None:
                profiles.add(location, item['profiles'])
            add_counts(geo['totals'], item)
            if location['status'] != 'located':
                add_counts(geo['unlocated'], item)
                if location['status'] == 'private':
                    add_counts(geo['private'], item)
                reason = {'limited': 'lookup_budget', 'lookup_error': 'lookup_error'}.get(location['status'])
                if reason and reason not in geo['reasons']:
                    geo['reasons'].append(reason)
                continue
            add_counts(geo['located'], item)
            code, name = location['country_code'], location['country_name']
            country = add_group(groups[0], code, dict(code=code, name=name), item)
            if 'trend' not in country:
                country['trend'] = [dict(row, requests=0, clients=0, bytes=0, errors=0) for row in report['trend']]
            for index, bucket in item['buckets'].items():
                target = country['trend'][index]
                target['clients'] += 1
                for field in ('requests', 'bytes', 'errors'):
                    target[field] += bucket[field]
            metadata = dict(country_code=code, country_name=name,
                            region_code=location['region_code'], region_name=location['region_name'])
            region_key = (code, location['region_code'], location['region_name'])
            add_group(groups[1], region_key, metadata, item)
            add_group(groups[2], region_key + (location['city_name'],),
                      dict(metadata, city_name=location['city_name']), item)
    for dimension, group, limit in zip(('countries', 'regions', 'cities'), groups, (249, 200, 500)):
        for row in group.values():
            row['active_days'] = bin(row.pop('_days')).count('1')
        ordered = sorted(group.values(), key=lambda row: (-row['clients'], -row['requests'], -row['bytes'],
                         row.get('code', row.get('country_code', '')), row.get('region_name', ''), row.get('city_name', '')))
        geo[dimension] = ordered[:limit]
        if dimension != 'countries':
            geo[dimension + '_truncated'] = len(ordered) > limit
    geo['lookup_complete'] = not geo['reasons']
    geo['partial'] = not geo['lookup_complete']
    return geo


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
        geography_activity = {}
        profiles = _ClientProfiles(budget)
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
            profile = _client_profile_dimensions(row["user_agent"], dimensions, spider)
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
            new_keys += int(profile not in geography_activity.get(ip, {}).get('profiles', {}))
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
            activity = geography_activity.setdefault(ip, dict(requests=0, bytes=0, errors=0, days=0,
                                                              buckets={}, profiles={}))
            profiles.observe(profile, sequence, activity['profiles'])
            moment = dt.datetime.fromtimestamp(row['time_ts']).astimezone() if system_timezone else \
                dt.datetime.fromtimestamp(row['time_ts'], now.tzinfo)
            activity['days'] |= 1 << max(0, (moment.date() - start.date()).days)
            activity_bucket = activity['buckets'].setdefault(index, dict(requests=0, bytes=0, errors=0))
            for aggregate in (activity, activity_bucket):
                aggregate['requests'] += 1
                aggregate['bytes'] += size
                aggregate['errors'] += errors
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
        report['geography'] = _visitor_geography(report, geography_activity, profiles)
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
        report['client_profiles'] = profiles.result(report)
        report["settings"] = [
            {"key": "统计模式", "value": "只读分析已发现日志；不修改 Nginx 或 WAF"},
            {"key": "日志目录", "value": self.log_directory},
            {"key": "统计窗口", "value": "包含今日的最近 %d 个自然日" % summary["days"]},
            {"key": "站点筛选", "value": report["siteName"] or "全部站点"},
            {"key": "指标口径", "value": "独立 IP 不等于 UV；发送字节不含响应头和上传；UA 分类未验证真伪"},
            {"key": "请求耗时", "value": "combined 未采集耗时，不提供推测值"},
            {"key": "访客地域", "value": "本地 IP 库近似网络出口；独立 IP 不等于人数，包含机器人和 API 请求；不采集停留时长"},
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


# Installed updaters accept exactly 21 files. Keep this independent read-only
# service here until a manifest migration can safely introduce a new module.
class TaskManagerService:
    WORKER_SECONDS = 4
    MAX_OUTPUT_BYTES = 512 * 1024
    WORKER = r'''
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('_gpt_readonly_tasks', sys.argv[1])
module = importlib.util.module_from_spec(spec)
source = spec.loader.get_source(spec.name)
exec(compile(source, sys.argv[1], 'exec', dont_inherit=True), module.__dict__)
request = json.loads(sys.stdin.buffer.read(4097))
params = module.TaskManagerService.validate(request['operation'], request['params'])
result = module._TaskSnapshotReader().collect(request['operation'], params)
body = json.dumps(result, ensure_ascii=True, allow_nan=False).encode('ascii')
if len(body) > module.TaskManagerService.MAX_OUTPUT_BYTES:
    raise ValueError('snapshot limit')
sys.stdout.buffer.write(body)
'''
    STATES = frozenset(('LISTEN', 'ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT',
                        'SYN_RECV', 'FIN_WAIT1', 'FIN_WAIT2', 'LAST_ACK', 'CLOSING', 'CLOSE', 'UNCONN'))

    @staticmethod
    def validate(operation, params):
        if operation not in ('processes', 'detail', 'network') or not isinstance(params, dict):
            raise ValueError('operation')

        def integer(key, default, minimum, maximum):
            value = params.get(key, default)
            if isinstance(value, bool) or not re.fullmatch(r'[0-9]{1,10}', str(value)):
                raise ValueError('number')
            value = int(value)
            if not minimum <= value <= maximum:
                raise ValueError('number')
            return value

        if operation == 'detail':
            identity = params.get('identity', '')
            if not isinstance(identity, str) or not re.fullmatch(r'[0-9]{1,24}', identity):
                raise ValueError('identity')
            return dict(pid=integer('pid', None, 1, 2147483647), identity=identity)
        search = params.get('search', '')
        if not isinstance(search, str) or len(search) > 80 or any(ord(c) < 32 for c in search):
            raise ValueError('search')
        per_page = integer('per_page', 25, 1, 100)
        if per_page not in (25, 50, 100):
            raise ValueError('page size')
        result = dict(page=integer('page', 1, 1, 100000), per_page=per_page, search=search.casefold())
        default_sort = 'cpu_percent' if operation == 'processes' else 'local_port'
        keys = (('cpu_percent', 'rss_bytes', 'read_rate', 'write_rate', 'pid', 'name')
                if operation == 'processes' else ('local_port', 'remote_port', 'state', 'pid'))
        result['sort'] = params.get('sort', default_sort)
        result['order'] = params.get('order', 'desc' if operation == 'processes' else 'asc')
        if result['sort'] not in keys or result['order'] not in ('asc', 'desc'):
            raise ValueError('sort')
        if operation == 'network':
            result['protocol'] = params.get('protocol', 'all')
            result['state'] = params.get('state', 'all')
            if (result['protocol'] not in ('all', 'tcp', 'tcp6', 'udp', 'udp6')
                    or result['state'] not in TaskManagerService.STATES | {'all'}):
                raise ValueError('network filter')
            result['port'] = None if params.get('port', '') in ('', None) else integer('port', None, 0, 65535)
        return result

    @staticmethod
    def error(code):
        messages = {'parameters': '筛选参数不正确，请重新选择。',
                    'unsupported': '任务管理仅支持可读取本机 proc 的 Linux 面板。',
                    'timeout': '本次采集超时，已停止采集；请稍后手动重试。',
                    'unavailable': '本次采集未完成，请稍后手动重试。',
                    'process_changed': '进程已退出或身份发生变化，请刷新进程列表后重试。'}
        return dict(status=False, code=code, msg=messages.get(code, messages['unavailable']))

    def collect(self, operation, params):
        try:
            params = self.validate(operation, params)
        except (ValueError, TypeError):
            return self.error('parameters')
        if os.name != 'posix':
            return self.error('unsupported')
        child = None
        try:
            child = subprocess.Popen([sys.executable, '-I', '-c', self.WORKER, os.path.realpath(__file__)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     close_fds=True)
            request = json.dumps(dict(operation=operation, params=params)).encode('utf-8')
            output, _ = child.communicate(request, timeout=self.WORKER_SECONDS)
            if child.returncode != 0 or len(output) > self.MAX_OUTPUT_BYTES:
                return self.error('unavailable')
            result = json.loads(output)
            if not isinstance(result, dict) or not isinstance(result.get('status'), bool):
                return self.error('unavailable')
            return result
        except subprocess.TimeoutExpired:
            if child is not None:
                child.kill()
                child.communicate()
            return self.error('timeout')
        except Exception:
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate()
            return self.error('unavailable')


class _TaskSnapshotReader:
    MAX_PROCESSES = 2048
    MAX_SOCKET_ROWS = 8192
    MAX_FDS = 8192
    MAX_FDS_PER_PROCESS = 256
    MAX_INTERFACES = 128
    MAX_SECONDS = 2.0
    SAMPLE_SECONDS = .2
    TCP_STATES = {'01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1',
                  '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT',
                  '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING', '0C': 'SYN_RECV'}

    def __init__(self, root='/proc', hz=None, page_size=None, sleep=time.sleep, clock=time.monotonic):
        self.root, self.sleep, self.clock = Path(root), sleep, clock
        self.hz = hz if hz is not None else os.sysconf('SC_CLK_TCK')
        self.page_size = page_size if page_size is not None else os.sysconf('SC_PAGE_SIZE')
        self.deadline = self.clock() + self.MAX_SECONDS
        self.reasons = set()
        self.boot_time = None

    def _budget(self):
        if self.clock() >= self.deadline:
            self.reasons.add('time_limit')
            return False
        return True

    def _read(self, path, maximum=65536):
        with (self.root / path).open('rb') as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError('read limit')
        return raw.decode('utf-8', 'replace')

    @staticmethod
    def _text(value, limit=64):
        return ''.join(c for c in str(value) if c.isprintable())[:limit]

    @staticmethod
    def _numbers(body):
        result = {}
        for line in body.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[1].isdigit():
                result[fields[0].rstrip(':')] = int(fields[1]) * (1024 if len(fields) > 2 and fields[2] == 'kB' else 1)
        return result

    def _pids(self):
        result = []
        with os.scandir(self.root) as entries:
            for index, entry in enumerate(entries):
                if not self._budget() or index >= 8192:
                    self.reasons.add('process_limit')
                    break
                if entry.name.isascii() and entry.name.isdigit():
                    if len(result) >= self.MAX_PROCESSES:
                        self.reasons.add('process_limit')
                        break
                    result.append(int(entry.name))
        return sorted(result)

    def _process(self, pid, with_io=True):
        body = self._read(str(pid) + '/stat', 8192)
        left, right = body.find('('), body.rfind(')')
        if left <= 0 or right <= left or int(body[:left].strip()) != pid:
            raise ValueError('stat')
        fields = body[right + 1:].split()
        if len(fields) < 22:
            raise ValueError('stat')
        started = int(fields[19])
        row = dict(pid=pid, ppid=int(fields[1]), name=self._text(body[left + 1:right]),
                   state=self._text(fields[0], 1), identity=str(started),
                   rss_bytes=max(0, int(fields[21])) * self.page_size, vms_bytes=max(0, int(fields[20])),
                   threads=max(0, int(fields[17])), started_at=None if self.boot_time is None else self.boot_time + started / self.hz,
                   uid=None, cpu_percent=None, read_rate=None, write_rate=None,
                   _ticks=int(fields[11]) + int(fields[12]), _at=self.clock(), _io={})
        try:
            status = self._read(str(pid) + '/status')
            uid = re.search(r'^Uid:\s+([0-9]+)', status, re.M)
            row['uid'] = int(uid[1]) if uid else None
        except (OSError, ValueError):
            self.reasons.add('process_unavailable')
        if with_io:
            try:
                row['_io'] = self._numbers(self._read(str(pid) + '/io', 8192))
                if not {'read_bytes', 'write_bytes'} <= row['_io'].keys():
                    self.reasons.add('io_unavailable')
            except (OSError, ValueError):
                self.reasons.add('io_unavailable')
        verified = self._read(str(pid) + '/stat', 8192)
        verified_fields = verified[verified.rfind(')') + 1:].split()
        if len(verified_fields) < 20 or str(int(verified_fields[19])) != row['identity']:
            self.reasons.add('process_changed')
            raise ValueError('process changed')
        return row

    def _snapshot(self):
        result = {}
        for pid in self._pids():
            if not self._budget():
                break
            try:
                result[pid] = self._process(pid)
            except (OSError, ValueError, IndexError):
                self.reasons.add('process_unavailable')
        return result

    @staticmethod
    def _public_process(row):
        return {key: value for key, value in row.items() if not key.startswith('_')}

    def _sample_processes(self):
        first = self._snapshot()
        start = self.clock()
        self.sleep(self.SAMPLE_SECONDS)
        second = self._snapshot()
        elapsed = self.clock() - start
        result = []
        for pid, row in second.items():
            previous = first.get(pid)
            if previous is None:
                self.reasons.add('process_unavailable')
                continue
            if previous['identity'] != row['identity']:
                self.reasons.add('process_changed')
                continue
            interval = row['_at'] - previous['_at']
            if interval > 0:
                ticks = row['_ticks'] - previous['_ticks']
                if ticks >= 0:
                    row['cpu_percent'] = round(ticks * 100 / self.hz / interval, 2)
                for key, output in (('read_bytes', 'read_rate'), ('write_bytes', 'write_rate')):
                    if key in row['_io'] and key in previous['_io']:
                        delta = row['_io'][key] - previous['_io'][key]
                        row[output] = round(delta / interval, 2) if delta >= 0 else None
            result.append(self._public_process(row))
        if first.keys() != second.keys():
            self.reasons.add('process_unavailable')
        return result, elapsed

    def _system_summary(self):
        result = dict(process_count=0, cpu_count=os.cpu_count(), memory_total_bytes=None, load=[])
        try:
            for line in self._read('stat', 256 * 1024).splitlines():
                if line.startswith('btime '):
                    self.boot_time = int(line.split()[1])
            result['memory_total_bytes'] = self._numbers(self._read('meminfo')).get('MemTotal')
            result['load'] = [float(x) for x in self._read('loadavg', 1024).split()[:3]]
            if (self.boot_time is None or result['memory_total_bytes'] is None or len(result['load']) != 3
                    or not all(math.isfinite(value) for value in result['load'])):
                raise ValueError('load')
        except (OSError, ValueError, IndexError):
            result['load'] = []
            self.reasons.add('system_unavailable')
        return result

    def _page(self, rows, params):
        key = params['sort']
        present = [row for row in rows if row.get(key) is not None]
        missing = [row for row in rows if row.get(key) is None]
        present.sort(key=lambda row: (row[key].casefold() if isinstance(row[key], str) else row[key], row.get('pid') or 0),
                     reverse=params['order'] == 'desc')
        rows = present + missing
        page = min(params['page'], max(1, math.ceil(len(rows) / params['per_page'])))
        offset = (page - 1) * params['per_page']
        return dict(items=rows[offset:offset + params['per_page']], total=len(rows), page=page, per_page=params['per_page'])

    def _detail(self, params):
        pid = params['pid']
        try:
            row = self._process(pid, with_io=False)
            if row['identity'] != params['identity']:
                return TaskManagerService.error('process_changed')
            row.update(pss_bytes=None, uss_bytes=None, swap_bytes=None, fd_count=None)
            try:
                row['swap_bytes'] = self._numbers(self._read(str(pid) + '/status')).get('VmSwap')
                memory = self._numbers(self._read(str(pid) + '/smaps_rollup'))
                row['pss_bytes'] = memory.get('Pss')
                if 'Private_Clean' in memory and 'Private_Dirty' in memory:
                    row['uss_bytes'] = memory['Private_Clean'] + memory['Private_Dirty'] + memory.get('Private_Hugetlb', 0)
                row['swap_bytes'] = memory.get('Swap', row['swap_bytes'])
                if any(row[key] is None for key in ('pss_bytes', 'uss_bytes', 'swap_bytes')):
                    self.reasons.add('memory_unavailable')
            except (OSError, ValueError):
                self.reasons.add('memory_unavailable')
            try:
                count = 0
                with os.scandir(self.root / str(pid) / 'fd') as entries:
                    for _ in entries:
                        count += 1
                        if count > self.MAX_FDS or not self._budget():
                            self.reasons.add('fd_limit')
                            break
                    else:
                        row['fd_count'] = count
            except OSError:
                self.reasons.add('fd_unavailable')
            # Guard PID reuse across all auxiliary reads, not just before them.
            if self._process(pid, with_io=False)['identity'] != row['identity']:
                return TaskManagerService.error('process_changed')
            return dict(process=self._public_process(row))
        except (OSError, ValueError, IndexError):
            return TaskManagerService.error('process_changed')

    @staticmethod
    def _address(value, ipv6):
        address, port = value.split(':')
        if len(address) != (32 if ipv6 else 8):
            raise ValueError('address')
        binary = b''.join(int(address[i:i + 8], 16).to_bytes(4, sys.byteorder) for i in range(0, len(address), 8))
        return socket.inet_ntop(socket.AF_INET6 if ipv6 else socket.AF_INET, binary), int(port, 16)

    def _sockets(self):
        result, count = [], 0
        for protocol in ('tcp', 'tcp6', 'udp', 'udp6'):
            try:
                with (self.root / 'net' / protocol).open('r', encoding='ascii', errors='replace') as stream:
                    stream.readline(1025)
                    while self._budget():
                        line = stream.readline(1025)
                        if not line:
                            break
                        count += 1
                        if count > self.MAX_SOCKET_ROWS:
                            self.reasons.add('socket_limit')
                            return result
                        fields = line.split()
                        try:
                            if len(line) > 1024 or len(fields) < 10:
                                raise ValueError('socket')
                            local, local_port = self._address(fields[1], protocol.endswith('6'))
                            remote, remote_port = self._address(fields[2], protocol.endswith('6'))
                            state = 'UNCONN' if protocol.startswith('udp') and fields[3] == '07' else self.TCP_STATES.get(fields[3])
                            if state is None or not (0 <= local_port <= 65535 and 0 <= remote_port <= 65535):
                                raise ValueError('state')
                            result.append(dict(protocol=protocol, local_address=local, local_port=local_port,
                                               remote_address=remote, remote_port=remote_port, state=state,
                                               uid=int(fields[7]), pid=None, process_name='', _inode=int(fields[9])))
                        except (OSError, ValueError, IndexError):
                            self.reasons.add('socket_unavailable')
            except OSError:
                self.reasons.add('socket_unavailable')
        return result

    def _interfaces(self):
        result = {}
        try:
            for line in self._read('net/dev').splitlines()[2:]:
                if ':' not in line:
                    continue
                name, values = line.rsplit(':', 1)
                fields = values.split()
                if len(fields) < 16:
                    raise ValueError('interface')
                if len(result) >= self.MAX_INTERFACES:
                    self.reasons.add('interface_limit')
                    break
                name = self._text(name.strip())
                result[name] = dict(name=name, received_bytes=int(fields[0]), sent_bytes=int(fields[8]),
                                    receive_rate=None, send_rate=None)
        except (OSError, ValueError):
            self.reasons.add('interface_unavailable')
        return result

    def _owners(self, rows):
        wanted = {row['_inode'] for row in rows if row['_inode']}
        if not wanted:
            return
        owners, inspected = {}, 0
        for pid in self._pids():
            if not self._budget() or inspected >= self.MAX_FDS or wanted <= owners.keys():
                break
            try:
                before = self._process(pid, with_io=False)
                owned = []
                with os.scandir(self.root / str(pid) / 'fd') as entries:
                    for index, entry in enumerate(entries):
                        if index >= self.MAX_FDS_PER_PROCESS or inspected >= self.MAX_FDS or not self._budget():
                            self.reasons.add('ownership_partial')
                            break
                        inspected += 1
                        try:
                            target = os.readlink(entry.path)
                        except OSError:
                            continue
                        match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
                        if match and int(match[1]) in wanted:
                            owned.append(int(match[1]))
                if self._process(pid, with_io=False)['identity'] == before['identity']:
                    for inode in owned:
                        owners.setdefault(inode, (pid, before['name']))
            except (OSError, ValueError, IndexError):
                self.reasons.add('ownership_partial')
        for row in rows:
            if row['_inode'] in owners:
                row['pid'], row['process_name'] = owners[row['_inode']]
        if wanted - owners.keys():
            self.reasons.add('ownership_partial')

    def _network(self, params):
        before, start = self._interfaces(), self.clock()
        self.sleep(self.SAMPLE_SECONDS)
        after, elapsed = self._interfaces(), self.clock() - start
        for name, row in after.items():
            previous = before.get(name)
            if previous is not None and elapsed > 0:
                for key, rate in (('received_bytes', 'receive_rate'), ('sent_bytes', 'send_rate')):
                    delta = row[key] - previous[key]
                    row[rate] = round(delta / elapsed, 2) if delta >= 0 else None
        if before.keys() != after.keys():
            self.reasons.add('interface_unavailable')
        rows = self._sockets()
        summary = dict(socket_count=len(rows), listen_count=sum(row['state'] == 'LISTEN' for row in rows),
                       established_count=sum(row['state'] == 'ESTABLISHED' for row in rows))
        rows = [row for row in rows if (params['protocol'] == 'all' or row['protocol'] == params['protocol'])
                and (params['state'] == 'all' or row['state'] == params['state'])
                and (params['port'] is None or params['port'] in (row['local_port'], row['remote_port']))]
        self._owners(rows)
        if params['search']:
            rows = [row for row in rows if params['search'] in ' '.join(str(row[key]) for key in
                    ('local_address', 'local_port', 'remote_address', 'remote_port', 'pid', 'process_name')).casefold()]
        for row in rows:
            row.pop('_inode', None)
        return dict(self._page(rows, params), interfaces=list(after.values()), sampled_seconds=round(elapsed, 4), summary=summary)

    def collect(self, operation, params):
        if not self.root.is_dir():
            return TaskManagerService.error('unsupported')
        try:
            if operation == 'network':
                result = self._network(params)
            else:
                summary = self._system_summary()
                if operation == 'detail':
                    result = self._detail(params)
                    if result.get('status') is False:
                        return result
                else:
                    rows, elapsed = self._sample_processes()
                    summary['process_count'] = len(rows)
                    if params['search']:
                        rows = [row for row in rows if params['search'] in ('%s %s %s' % (row['pid'], row['name'], row['uid'])).casefold()]
                    result = dict(self._page(rows, params), summary=summary, sampled_seconds=round(elapsed, 4))
            result.update(status=True, partial=bool(self.reasons), reasons=sorted(self.reasons), checked_at=time.time())
            return result
        except (OSError, ValueError, IndexError):
            return TaskManagerService.error('unavailable')
