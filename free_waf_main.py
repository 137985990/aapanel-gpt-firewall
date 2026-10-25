#coding: utf-8
# coding: utf-8
import sys,os
if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')
os.chdir('/www/server/panel')
import json,time,public,string,re,hashlib,html
if __name__ != '__main__':
    from panelAuth import panelAuth

PLUGIN_PATH = '/www/server/panel/plugin/free_waf/'
if PLUGIN_PATH not in sys.path:
    sys.path.insert(0, PLUGIN_PATH)
import report_store
if getattr(report_store, 'REPORT_STORE_VERSION', 0) != 3:
    # The panel reloads the plugin entry point but may retain imported modules.
    import importlib
    report_store = importlib.reload(report_store)
website_reports = report_store.website_reports
try:
    from ban_store import BanStore
except Exception:
    BanStore = None

TEMP_BAN_SECONDS = 28800
MANUAL_MAX_BAN_SECONDS = 315360000
IP_BLACK_PATH = '/www/server/free_waf/rule/ip_black.json'
IP_BLACK_META_PATH = '/www/server/free_waf/rule/ip_black_meta.json'
RULE_BUNDLE_NAMES = [
    'url_white',
    'url_black',
    'user_agent',
    'user_agent_white',
    'header',
    'cookie',
    'args',
    'post'
]
RULE_RISK_AUDIT_RULES = {
    'url_black': u'URL黑名单',
    'user_agent': u'UA黑名单',
    'header': u'Header黑名单',
    'cookie': u'Cookie黑名单',
    'args': u'GET参数黑名单',
    'post': u'POST黑名单',
    'url_white': u'URL白名单',
    'user_agent_white': u'UA白名单'
}
BROAD_UA_TOKENS = [
    'bot',
    'spider',
    'crawler',
    'curl',
    'python',
    'java',
    'okhttp',
    'go-http-client',
    'wget'
]

class free_waf_main:
    LEGACY_LOG_MAX_LINES = 20000
    LEGACY_LOG_MAX_BYTES = 8 * 1024 * 1024
    LEGACY_LOG_MAX_FILES = 64
    LEGACY_LOG_MAX_SECONDS = 1.5
    SCAN_MAX_DEPTH = 16
    SCAN_MAX_FILES = 1000
    SCAN_MAX_ENTRIES = 10000
    SCAN_MAX_FILE_BYTES = 1024 * 1024
    SCAN_MAX_TOTAL_BYTES = 16 * 1024 * 1024
    SCAN_REGEX_SECONDS = 2
    SCAN_MAX_RULES = 1000
    SCAN_MAX_RULE_BYTES = 4096
    SCAN_MAX_MATCHES = 1000
    SCAN_MAX_WORKER_OUTPUT = 32768
    # Fixed stdlib-only worker: private contents enter through stdin, never argv.
    SCAN_REGEX_WORKER = r'''
import json, re, sys

raw = sys.stdin.buffer.read(128 * 1024 * 1024 + 1)
if len(raw) > 128 * 1024 * 1024:
    raise ValueError('scan input limit')
batch = json.loads(raw)
if len(batch['files']) > 1000 or len(batch['rules']) > 1000:
    raise ValueError('scan item limit')
patterns, matches, partial, limited = [], [], False, False
for index, rule in enumerate(batch['rules']):
    try:
        patterns.append((index, re.compile(rule)))
    except (re.error, RecursionError, OverflowError):
        partial = True
for file_index, data in enumerate(batch['files']):
    for rule_index, pattern in patterns:
        if data and pattern.search(data):
            matches.append([file_index, rule_index])
            if len(matches) >= 1000:
                partial = limited = True
                break
    if limited:
        break
sys.stdout.write(json.dumps(dict(matches=matches, partial=partial, limited=limited),
                           separators=(',', ':')))
'''
    __path = '/www/server/free_waf/'
    __access_log_path = '/www/wwwlogs'
    __state = {True:'开启',False:'关闭',0:'停用',1:'启用'}
    __config = None
    __PATH='/www/server/panel/plugin/free_waf/'
    __log_types = ('GPT Firewall', 'Nginx free firewall', 'Nginx免费防火墙')

    def __local_service(self, name):
        import importlib.util
        import sys
        import hashlib
        if name not in ('website_statistics', 'update_service'):
            raise ValueError('未知服务')
        path = os.path.realpath(os.path.join(self.__PATH, name + '.py'))
        stamp = os.stat(path)
        signature = (path, stamp.st_mtime_ns, stamp.st_size)
        key = '_aapanel_gpt_firewall_' + name + '_' + hashlib.sha256(path.encode('utf-8')).hexdigest()[:16]
        module = sys.modules.get(key)
        if (module is None or getattr(module, '__file__', None) != path
                or getattr(module, '_source_signature', None) != signature
                or getattr(module, 'PLUGIN_VERSION', '') != '0.1.9'):
            spec = importlib.util.spec_from_file_location(key, path)
            module = importlib.util.module_from_spec(spec)
            # Read source explicitly: same-second upgrades must not reuse stale bytecode.
            source = spec.loader.get_source(key)
            exec(compile(source, path, 'exec', dont_inherit=True), module.__dict__)
            if getattr(module, 'PLUGIN_VERSION', '') != '0.1.9':
                raise ValueError('服务版本不匹配，请重新打开插件')
            module._source_signature = signature
            sys.modules[key] = module
        return module

    def __statistics_service(self):
        return self.__local_service('website_statistics').StatisticsService(self.__access_log_path)

    def __task_service(self):
        return self.__local_service('website_statistics').TaskManagerService()

    def __task_snapshot(self, operation, get, fields):
        try:
            params = {key: getattr(get, key) for key in fields if hasattr(get, key)}
            return self.__task_service().collect(operation, params)
        except Exception:
            return dict(status=False, code='unavailable', msg='本次采集未完成，请稍后手动重试。')

    def get_task_processes(self, get):
        return self.__task_snapshot('processes', get, ('page', 'per_page', 'search', 'sort', 'order'))

    def get_task_process_detail(self, get):
        return self.__task_snapshot('detail', get, ('pid', 'identity'))

    def get_task_network(self, get):
        return self.__task_snapshot('network', get, ('page', 'per_page', 'search', 'sort', 'order', 'protocol', 'state', 'port'))

    def __update_service(self):
        return self.__local_service('update_service').UpdateService(self.__PATH)

    def check_plugin_update(self, get):
        force = str(getattr(get, 'force', '')).lower() in ('true', '1')
        try:
            return self.__update_service().check(force=force)
        except Exception:
            return public.returnMsg(False, '版本检查暂不可用，请稍后重试。')

    def __update_request_is_post(self):
        try:
            from flask import request
            return request.method == 'POST'
        except (ImportError, RuntimeError):
            return False

    def start_plugin_update(self, get):
        if not self.__update_request_is_post():
            return public.returnMsg(False, '安装更新只接受面板内确认后的 POST 请求。')
        tag = str(getattr(get, 'tag', '') or '')
        if not re.fullmatch(r'v\d{1,6}\.\d{1,6}(?:\.\d{1,6})?', tag):
            return public.returnMsg(False, '更新版本号不正确，请重新检查更新。')
        try:
            return self.__update_service().start(tag)
        except Exception:
            return public.returnMsg(False, '无法启动更新，请检查更新状态后重试。')

    def get_plugin_update_status(self, get):
        try:
            return self.__update_service().status()
        except Exception:
            return public.returnMsg(False, '暂时无法读取更新状态。')

    def return_site(self, get):
        data = public.M('sites').field('name,path').select()
        ret = {}
        for i in data:
            ret[i['name']] = i['path']
        return public.returnMsg(True, ret)

    def __policy_mutation(operation):
        from functools import wraps

        @wraps(operation)
        def call(self, *args, **kwargs):
            try:
                with self.__endpoint_transaction():
                    pending = self.__path + '.policy-recovery/pending.json'
                    if os.path.lexists(pending):
                        raise RuntimeError('上次策略发布尚待人工恢复')
                    previous = getattr(self, '_free_waf_main__policy_reads', None)
                    self.__policy_reads = {}
                    try:
                        return operation(self, *args, **kwargs)
                    finally:
                        self.__policy_reads = previous
            except (OSError, ValueError, TypeError, IndexError, KeyError, RuntimeError):
                if os.path.lexists(self.__path + '.policy-recovery/pending.json'):
                    return public.returnMsg(False, '策略恢复未确认，已保留私有快照并阻止继续修改；请先人工核查，不要重复提交或删除恢复记录。')
                return public.returnMsg(False, '配置未确认生效；请检查写入权限、并发修改和 Nginx 状态后重试，不要重复提交。')
        return call

    @__policy_mutation
    def import_data(self, get):
        name = get.s_Name;
        self.__rule_name(name)
        if name == 'ip_black':
            return public.returnMsg(False, 'IP 黑名单请使用带封禁时长的专用入口，未导入')
        try:
            pdata = json.loads(get.pdata)
        except:
            return public.returnMsg(False, '数据格式不正确')
        if type(pdata) is not list or not pdata: return public.returnMsg(False, '数据格式不正确')
        iplist = self.__get_rule(name) or []
        for ips in pdata:
            if ips in iplist: continue;
            iplist.insert(0, ips)
        self.__write_rule(name, iplist)
        return public.returnMsg(True, '导入成功!')

    def get_rule_bundle(self, get):
        """Export editable rule sets only. Runtime IP bans are intentionally excluded."""
        rules = {}
        for name in RULE_BUNDLE_NAMES:
            rule = self.__get_rule(name)
            rules[name] = rule if rule else []
        return {
            'version': 1,
            'exported_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'rules': rules
        }

    @__policy_mutation
    def import_rule_bundle(self, get):
        """Import editable rule sets only. This cannot create IP bans."""
        try:
            pdata = json.loads(get.pdata)
        except:
            return public.returnMsg(False, '数据格式不正确')
        if not isinstance(pdata, dict) or not isinstance(pdata.get('rules'), dict):
            return public.returnMsg(False, '数据格式不正确')

        changes = {}
        if set(pdata['rules']) - set(RULE_BUNDLE_NAMES):
            return public.returnMsg(False, '规则包包含不支持的规则文件')
        for name in RULE_BUNDLE_NAMES:
            if name not in pdata['rules']:
                continue
            rule_data = pdata['rules'][name]
            self.__validate_rule(name, rule_data)
            changes[name] = rule_data
        if not changes:
            return public.returnMsg(False, '规则包没有可导入的规则')
        self.__publish_rules(changes)
        imported = len(changes)

        self.__write_log('导入可编辑 WAF 规则包，更新 ' + str(imported) + ' 个规则文件')
        return public.returnMsg(True, '规则包导入成功：' + str(imported) + ' 个规则文件')

    def __config_health_item(self, key, title, status, detail, action):
        return {
            'key': key,
            'title': self.__safe_text(title),
            'status': True if status else False,
            'detail': self.__safe_text(detail),
            'action': self.__safe_text(action)
        }

    def __read_rule_for_health(self, name):
        path = self.__path + 'rule/' + name + '.json'
        if not os.path.exists(path):
            return False, 0, '缺失'
        try:
            data = json.loads(public.readFile(path) or '[]')
        except:
            return False, 0, 'JSON解析失败'
        if type(data) != list:
            return False, 0, '不是列表'
        return True, len(data), '正常'

    def __drop_reason_counts_for_health(self):
        path = '/www/server/free_waf/drop_ip.log'
        counts = {}
        total = 0
        if not os.path.exists(path):
            return counts, total
        try:
            lines = public.GetNumLines(path, 200)
        except:
            lines = []
        if type(lines) == str:
            lines = lines.splitlines()
        for line in lines:
            try:
                row = json.loads(line.strip())
                reason = 'unknown'
                if type(row) == list and len(row) >= 6:
                    reason = str(row[5])
                counts[reason] = counts.get(reason, 0) + 1
                total += 1
            except:
                pass
        return counts, total

    def get_config_health_report(self, get):
        """Read-only config_health_report for rule files, site fields, runtime_ban_sources and rule_counts."""
        required_rule_files = ['ip_black', 'ip_white'] + RULE_BUNDLE_NAMES
        missing_rules = []
        bad_rules = []
        rule_counts = {}
        for name in required_rule_files:
            ok, count, state = self.__read_rule_for_health(name)
            rule_counts[name] = count
            if not ok:
                if state == '缺失':
                    missing_rules.append(name)
                else:
                    bad_rules.append(name + ':' + state)

        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json') or '{}')
        except:
            site_config = {}
        if type(site_config) != dict:
            site_config = {}
        required_site_fields = ['open', 'cdn', 'cdn_header', 'cdn_trusted_proxy', 'url_white', 'url_rule', 'url_tell', 'disable_rule', 'cc']
        missing_site_fields = []
        for site_name in site_config:
            conf = site_config.get(site_name, {})
            if type(conf) != dict:
                missing_site_fields.append(str(site_name) + ':站点配置不是字典')
                continue
            for field in required_site_fields:
                if field not in conf:
                    missing_site_fields.append(str(site_name) + ':' + field)

        drop_log_source = 'drop_ip.log'
        runtime_counts, runtime_total = self.__drop_reason_counts_for_health()
        runtime_parts = []
        for reason in sorted(runtime_counts.keys()):
            runtime_parts.append(reason + '×' + str(runtime_counts[reason]))

        count_parts = []
        for name in sorted(rule_counts.keys()):
            count_parts.append(name + '=' + str(rule_counts[name]))

        items = [
            self.__config_health_item(
                'rule_files',
                '规则文件',
                len(missing_rules) == 0 and len(bad_rules) == 0,
                '缺失：' + (', '.join(missing_rules) if missing_rules else '无') + '；异常：' + (', '.join(bad_rules) if bad_rules else '无'),
                '缺失文件应创建为空列表 []；异常 JSON 先备份后修复。'
            ),
            self.__config_health_item(
                'site_fields',
                '站点字段',
                len(missing_site_fields) == 0,
                '已检查 ' + str(len(site_config)) + ' 个站点；缺失字段：' + (', '.join(missing_site_fields[:20]) if missing_site_fields else '无'),
                '缺字段会导致站点详情不完整，建议通过面板刷新站点配置或手动迁移。'
            ),
            self.__config_health_item(
                'runtime_ban_sources',
                '运行封禁来源',
                True,
                drop_log_source + ' 最近封禁日志 ' + str(runtime_total) + ' 条；来源：' + (', '.join(runtime_parts) if runtime_parts else '暂无'),
                '来源用于排查误封；本诊断不会清理或新增封禁。'
            ),
            self.__config_health_item(
                'rule_counts',
                '规则数量',
                True,
                ', '.join(count_parts),
                '数量异常增长通常表示规则导入或误操作，需要结合规则风险巡检复核。'
            )
        ]

        ok_count = 0
        for item in items:
            if item['status']:
                ok_count += 1
        return {
            'status': ok_count == len(items),
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'summary': {
                'ok': ok_count,
                'warn': len(items) - ok_count,
                'total': len(items)
            },
            'items': items
        }

    # 获取规则
    def shell_get_rule(self, get):
        ret = []
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                return data
            except:
                return False
        else:
            return False

    def __local_absolute_path(self, path):
        if (type(path) is not str or not path or len(path) > 4096
                or any(ord(c) < 32 or ord(c) == 127 for c in path)
                or '..' in re.split(r'[\\/]', path) or not os.path.isabs(path)):
            raise ValueError('路径不正确')
        return os.path.abspath(path)

    def __no_link_path(self, path):
        import stat
        current = path
        while True:
            info = os.lstat(current)
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)):
                raise ValueError('不允许符号链接')
            parent = os.path.dirname(current)
            if parent == current:
                return info if current == path else os.lstat(path)
            current = parent

    def __open_regular_file(self, path):
        """No symlink components; POSIX directory descriptors also close rename races."""
        import stat
        path = self.__local_absolute_path(path)
        before = self.__no_link_path(path)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('不是普通文件')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        if os.open in os.supports_dir_fd and hasattr(os, 'O_NOFOLLOW'):
            parts = path.split(os.sep)
            directory = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in parts[1:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    os.close(directory)
                    directory = child
                descriptor = os.open(parts[-1], flags, dir_fd=directory)
            finally:
                os.close(directory)
        else:
            descriptor = os.open(path, flags | getattr(os, 'O_BINARY', 0))
        try:
            after = os.fstat(descriptor)
            self.__no_link_path(path)
            if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError('文件已变更')
            return os.fdopen(descriptor, 'rb')
        except Exception:
            os.close(descriptor)
            raise

    def __scan_roots(self):
        import stat
        roots = []
        try:
            rows = public.M('sites').field('name,path').select()
            for row in rows:
                try:
                    path = self.__local_absolute_path(row['path'])
                    if stat.S_ISDIR(self.__no_link_path(path).st_mode):
                        roots.append(path)
                except (OSError, ValueError, KeyError, TypeError):
                    continue
        except Exception:
            return []
        return roots

    def __scan_path(self, path, roots, directory=False):
        import stat
        path = self.__local_absolute_path(path)
        allowed = False
        for root in roots:
            try:
                if os.path.normcase(os.path.commonpath([path, root])) == os.path.normcase(root):
                    relative = os.path.relpath(path if directory else os.path.dirname(path), root)
                    depth = 0 if relative == '.' else len(relative.split(os.sep))
                    if depth <= self.SCAN_MAX_DEPTH:
                        allowed = True
                        break
            except ValueError:
                continue
        if not allowed:
            raise ValueError('仅允许扫描已配置网站根目录内的文件')
        info = self.__no_link_path(path)
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('不是目录')
        elif not path.lower().endswith('.php') or not stat.S_ISREG(info.st_mode):
            raise ValueError('仅允许普通 PHP 文件')
        return path

    def __new_scan_coverage(self):
        self.__scan_coverage = dict(partial=False, timed_out=False, files=0, bytes_read=0,
                                    notice='仅本地有界扫描；达到深度、文件、字节、规则、结果或计算时间上限时为部分扫描，不代表全站安全。')
        return self.__scan_coverage

    def get_security_boundary_report(self, get):
        return dict(status=True, legacy_cloud_enabled=False, spider_cloud_enabled=False,
                    cnlist_sync_enabled=False, scan=dict(getattr(self, '_free_waf_main__scan_coverage',
                    dict(partial=False, timed_out=False, files=0, bytes_read=0, notice='尚未扫描；仅提供有界部分扫描，不代表全站安全。'))))

    def getdir(self, dir, pc='', lis=None):
        # Keep the legacy list shape, but never recurse outside the bounded enumerator.
        from types import SimpleNamespace
        result = self.getdir_list(SimpleNamespace(path=dir))
        return [path for path in (result or []) if not pc or pc not in path]

    def getdir_list(self, get):
        coverage = self.__new_scan_coverage()
        roots = self.__scan_roots()
        try:
            path = self.__scan_path(get.path, roots, directory=True)
        except (OSError, ValueError, AttributeError, KeyError, TypeError):
            coverage['partial'] = True
            return False
        pending, result, visited = [path], [], 0
        self.__scan_listing = result
        while pending:
            directory = pending.pop()
            try:
                directory = self.__scan_path(directory, roots, directory=True)
                with os.scandir(directory) as entries:
                    for entry in entries:
                        visited += 1
                        if visited > self.SCAN_MAX_ENTRIES or len(result) >= self.SCAN_MAX_FILES:
                            coverage['partial'] = True
                            coverage['files'] = len(result)
                            return result
                        if entry.is_symlink():
                            coverage['partial'] = True
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            try:
                                pending.append(self.__scan_path(entry.path, roots, directory=True))
                            except (OSError, ValueError):
                                coverage['partial'] = True
                        elif entry.name.lower().endswith('.php'):
                            try:
                                result.append(self.__scan_path(entry.path, roots))
                            except (OSError, ValueError):
                                coverage['partial'] = True
            except (OSError, ValueError):
                coverage['partial'] = True
        coverage['files'] = len(result)
        return result

    def __evaluate_scan_batch(self, contents, rules, coverage):
        import subprocess
        import sys
        try:
            request = json.dumps(dict(files=contents, rules=rules), ensure_ascii=False).encode('utf-8')
            process = subprocess.Popen(
                [sys.executable, '-I', '-S', '-B', '-c', self.SCAN_REGEX_WORKER],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                shell=False, start_new_session=True, close_fds=True)
            try:
                output, _ = process.communicate(input=request, timeout=self.SCAN_REGEX_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                coverage.update(partial=True, timed_out=True,
                                notice='本地正则检测超时，扫描进程已终止；结果为部分扫描，未完成的批次不返回匹配，不代表全站安全。')
                return []
            except BaseException:
                process.kill()
                process.communicate()
                raise
            if process.returncode != 0 or len(output) > self.SCAN_MAX_WORKER_OUTPUT:
                raise ValueError('scan worker failed')
            result = json.loads(output)
            if (type(result) is not dict or set(result) != {'matches', 'partial', 'limited'}
                    or type(result['partial']) is not bool or type(result['limited']) is not bool
                    or type(result['matches']) is not list or len(result['matches']) > self.SCAN_MAX_MATCHES
                    or result['limited'] and not result['partial']):
                raise ValueError('invalid scan result')
            previous = (-1, -1)
            for match in result['matches']:
                if (type(match) is not list or len(match) != 2
                        or any(type(index) is not int for index in match)
                        or not 0 <= match[0] < len(contents) or not 0 <= match[1] < len(rules)
                        or tuple(match) <= previous):
                    raise ValueError('invalid scan match')
                previous = tuple(match)
            if result['partial']:
                coverage.update(partial=True,
                                notice='部分规则无效或匹配结果达到上限；结果为部分扫描，不代表全站安全。')
            return result['matches']
        except (OSError, ValueError, TypeError):
            coverage.update(partial=True,
                            notice='本地扫描进程无法启动或返回异常；结果为部分扫描，不代表全站安全。')
            return []

    def scan(self, filelist, rule):
        self.__webshell_data = []
        previous_partial = (getattr(self, '_free_waf_main__scan_listing', None) is filelist
                            and getattr(self, '_free_waf_main__scan_coverage', {}).get('partial', False))
        self.__scan_listing = None
        coverage = self.__new_scan_coverage()
        coverage['partial'] = previous_partial
        roots = self.__scan_roots()
        if not isinstance(filelist, (list, tuple)) or not isinstance(rule, (list, tuple)):
            coverage['partial'] = True
            return []
        patterns = []
        for value in rule[:self.SCAN_MAX_RULES]:
            try:
                if (type(value) is not str or len(value) > self.SCAN_MAX_RULE_BYTES
                        or len(value.encode('utf-8')) > self.SCAN_MAX_RULE_BYTES):
                    raise ValueError('invalid scan rule')
                patterns.append(value)
            except ValueError:
                coverage['partial'] = True
        if len(rule) > self.SCAN_MAX_RULES:
            coverage['partial'] = True
        if not patterns:
            coverage.update(partial=True, notice='没有可用的本地检测规则；结果为部分扫描，不代表全站安全。')
            return []
        paths, contents = [], []
        for index, file in enumerate(filelist):
            if index >= self.SCAN_MAX_FILES or coverage['bytes_read'] >= self.SCAN_MAX_TOTAL_BYTES:
                coverage['partial'] = True
                break
            try:
                path = self.__scan_path(file, roots)
                with self.__open_regular_file(path) as stream:
                    limit = min(self.SCAN_MAX_FILE_BYTES, self.SCAN_MAX_TOTAL_BYTES - coverage['bytes_read'])
                    size = os.fstat(stream.fileno()).st_size
                    payload = stream.read(limit)
                coverage['files'] += 1
                coverage['bytes_read'] += len(payload)
                coverage['partial'] = coverage['partial'] or size > len(payload)
                contents.append(payload.decode('utf-8', errors='replace'))
                paths.append(file)
            except (OSError, ValueError, TypeError):
                coverage['partial'] = True
                continue
        if contents:
            matches = self.__evaluate_scan_batch(contents, patterns, coverage)
            stamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            for file_index, rule_index in matches:
                file, value = paths[file_index], patterns[rule_index]
                self.__webshell_data.append({file: value})
                self.insert_log('%s [!] %s %s  \n' % (stamp, file, value))
        return self.__webshell_data

    def insert_log(self, data):
        public.writeFile(self.__PATH + 'webshell.log', data, 'a+')

    def get_log(self, get):
        path = self.__PATH + 'webshell.log'
        if not os.path.exists(path): return False
        return public.GetNumLines(path, 3000)

    def path_json(self, path, data):
        path_file = str(path).replace('/', '')
        if os.path.exists(path):
            if os.path.exists(self.__PATH + path_file + '.json'):
                try:
                    path_data = json.loads(public.ReadFile(self.__PATH + path_file + '.json'))
                except:
                    ret = []
                    public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                    path_data = []
                if not path_data: return self.__webshell_data
                for i in self.__webshell_data:
                    for i2 in path_data:
                        if i2 in i:
                            self.__webshell_data.remove(i)
                return self.__webshell_data
            else:
                ret = []
                public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                path_data = []
                return self.__webshell_data

    def san_dir(self, get):
        self.__webshell_data = []
        file = self.getdir_list(get)
        coverage = self.__scan_coverage
        if file is False:
            coverage['notice'] = '扫描路径不可用或不在允许的网站根目录内；扫描未完成，不代表全站安全。'
            return dict(status=False, msg='扫描路径不可用', data=[], coverage=dict(coverage))
        if not file:
            if not coverage['partial']:
                coverage['notice'] = '未找到 PHP 文件；未执行正则检测，不代表全站安全。'
            return dict(status=True, data=[], coverage=dict(coverage))
        rule = self.shell_get_rule(get)
        if not isinstance(rule, (list, tuple)) or not rule:
            coverage.update(partial=True, notice='本地检测规则为空或不可用；扫描未完成，不代表全站安全。')
            return dict(status=False, msg='规则为空或规则文件错误', data=[], coverage=dict(coverage))
        result = self.scan(file, rule)
        if result:
            self.path_json(get.path, result)
        return dict(status=True, data=self.__webshell_data, coverage=dict(self.__scan_coverage))

    def xssencode(self, text):
        import cgi
        list = ['`', '~', '&', '<', '>']
        ret = []
        for i in text:
            if i in list:
                i = ''
            ret.append(i)
        str_convert = ''.join(ret)
        text2 = html.escape(str_convert, quote=True)
        return text2

    def shell_add_rule(self, get):
        rule = self.xssencode(get.rule)
        ret = []
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                if rule in data:
                    return public.returnMsg(False, '该规则已存在')
                else:
                    data.append(rule)
                    public.WriteFile(self.__PATH + 'rule.json', json.dumps(data))
                    return public.returnMsg(True, '添加成功')
            except:
                return public.returnMsg(False, '规则库解析错误')
        else:
            return public.returnMsg(False, '规则库文件不存在')

    def shell_del_rule(self, get):
        rule = get.rule
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                if rule in data:
                    data.remove(rule)
                    public.WriteFile(self.__PATH + 'rule.json', json.dumps(data))
                    return public.returnMsg(True, '删除成功')
                else:
                    return public.returnMsg(False, '该规则不存在于规则库')
            except:
                return public.returnMsg(False, '规则库解析错误')
        else:
            return public.returnMsg(False, '规则库文件不存在')

    def lock_not_webshell(self, get):
        path = get.path
        not_path = get.not_path
        if not os.path.exists(not_path): return public.returnMsg(False, '文件不存在')
        path_file = str(path).replace('/', '')
        if not os.path.exists(self.__PATH + path_file + '.json'):
            ret = []
            ret.append(not_path)
            public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
        else:
            try:
                path_data = json.loads(public.ReadFile(self.__PATH + path_file + '.json'))
                if not not_path in path_data:
                    path_data.append(not_path)
                    public.WriteFile(self.__PATH + path_file + '.json', json.dumps(path_data))
                    return public.returnMsg(True, '添加成功')
                else:
                    return public.returnMsg(False, '已存在')
            except:
                ret = []
                ret.append(not_path)
                public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                return public.returnMsg(True, '添加成功')

    def upload_file_url(self,get):
        return public.returnMsg(False, '旧版云检测已停用，未读取或上传文件；请使用本地扫描。')


    def read_file_md5(self,filename):
        import hashlib
        try:
            path = self.__scan_path(filename, self.__scan_roots())
            with self.__open_regular_file(path) as stream:
                if os.fstat(stream.fileno()).st_size > self.SCAN_MAX_FILE_BYTES:
                    return False
                return hashlib.md5(stream.read(self.SCAN_MAX_FILE_BYTES)).hexdigest()
        except (OSError, ValueError, TypeError):
            return False


    def send_baota2(self,filename):
        return False

    def send_baota(self,get):
        return public.returnMsg(False, '旧版云检测已停用，未读取或上传文件；请使用本地扫描。')

    def check_webshell(self,get):
        return public.returnMsg(False, '旧版云检测已停用，未读取或上传文件；请使用本地扫描。')

    def getSpiders(self, get):
        return public.returnMsg(False, '旧版云蜘蛛服务已停用，未读取凭据或连接云端。')

    def addSpider(self, get):
        return public.returnMsg(False, '旧版云蜘蛛服务已停用，未读取凭据或连接云端。')

    def __get_md5(self, s):
        m = hashlib.md5()
        m.update(s.encode('utf-8'))
        return m.hexdigest()

    def get_config(self,get):
        config = json.loads(self.__read_policy(self.__path + 'config.json'));
        config.setdefault('from_data', True)
        config.setdefault('retry_cycle', 60)
        return config

    def __endpoint_site_name(self, value):
        if (type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_\-][A-Za-z0-9_.\-]{0,252}', value)
                or '..' in value):
            raise ValueError('站点名称不正确')
        return value

    def __checked_nginx_reload(self):
        self.__reload_panel_nginx()

    def __repeat_defaults(self):
        return dict(enabled=False, window_seconds=86400,
                    tiers=[dict(threshold=5, ban_seconds=604800), dict(threshold=10, ban_seconds=2592000)])

    def __repeat_limits(self):
        return dict(window_seconds=dict(min=60, max=604800), threshold=dict(min=2, max=1000),
                    ban_seconds=dict(min=60, max=31536000), tiers=dict(min=1, max=8))

    def __repeat_json(self, raw):
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('配置字段重复')
                result[key] = value
            return result
        return json.loads(raw, object_pairs_hook=unique)

    def __repeat_policy(self, policy):
        if type(policy) is not dict or set(policy) != {'enabled', 'window_seconds', 'tiers'}:
            raise ValueError('累计封禁策略字段不完整或包含未知字段')
        if type(policy['enabled']) is not bool:
            raise ValueError('启用状态必须是布尔值')
        window = policy['window_seconds']
        if type(window) is not int or not 60 <= window <= 604800:
            raise ValueError('统计窗口必须为 60 至 604800 秒的整数')
        tiers = policy['tiers']
        if type(tiers) is not list or not 1 <= len(tiers) <= 8:
            raise ValueError('累计封禁档位必须为 1 至 8 条')
        previous_threshold, previous_duration = 0, 0
        result = []
        for tier in tiers:
            if type(tier) is not dict or set(tier) != {'threshold', 'ban_seconds'}:
                raise ValueError('档位字段不完整或包含未知字段')
            threshold, duration = tier['threshold'], tier['ban_seconds']
            if type(threshold) is not int or not 2 <= threshold <= 1000:
                raise ValueError('档位次数必须为 2 至 1000 的整数')
            if type(duration) is not int or not 60 <= duration <= 31536000:
                raise ValueError('档位封禁时长必须为 60 至 31536000 秒的整数')
            if threshold <= previous_threshold or duration <= previous_duration:
                raise ValueError('各档位次数和封禁时长必须严格递增')
            result.append(dict(threshold=threshold, ban_seconds=duration))
            previous_threshold, previous_duration = threshold, duration
        return dict(enabled=policy['enabled'], window_seconds=window, tiers=result)

    def __repeat_config_bytes(self):
        with self.__open_regular_file(self.__path + 'site.json') as stream:
            return stream.read()

    def __repeat_site(self, get):
        site = self.__endpoint_site_name(getattr(get, 'siteName', None))
        raw = self.__repeat_config_bytes()
        config = self.__repeat_json(raw.decode('utf-8'))
        if type(config) is not dict or type(config.get(site)) is not dict:
            raise ValueError('站点不存在或站点配置不正确')
        return site, config, raw

    def __repeat_result(self, site, policy, raw):
        import hashlib
        return dict(status=True, siteName=site, policy=policy, revision=hashlib.sha256(raw).hexdigest())

    def get_repeat_ban_sites(self, get):
        try:
            config = self.__repeat_json(self.__repeat_config_bytes().decode('utf-8'))
            if type(config) is not dict or any(type(value) is not dict for value in config.values()):
                raise ValueError('站点配置不正确')
            sites = [dict(siteName=self.__endpoint_site_name(site)) for site in sorted(config)]
            return dict(status=True, sites=sites, defaults=self.__repeat_defaults(), limits=self.__repeat_limits())
        except Exception:
            return public.returnMsg(False, '无法读取站点列表，请检查现有站点配置；未迁移或修改配置。')

    def get_repeat_ban_policy(self, get):
        try:
            site, config, raw = self.__repeat_site(get)
            policy = self.__repeat_policy(config[site].get('repeat_ban_policy', self.__repeat_defaults()))
            return self.__repeat_result(site, policy, raw)
        except Exception:
            return public.returnMsg(False, '无法读取累计封禁策略，请检查站点名称和策略格式；未修改配置。')

    def __repeat_directory(self):
        from contextlib import contextmanager
        import stat

        @contextmanager
        def pinned():
            directory = os.path.abspath(self.__path)
            before = self.__no_link_path(directory)
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError('配置目录不正确')
            descriptor = None
            try:
                if os.name == 'posix':
                    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    descriptor = os.open(os.sep, flags)
                    for part in directory.split(os.sep)[1:]:
                        child = os.open(part, flags, dir_fd=descriptor)
                        os.close(descriptor)
                        descriptor = child
                    info = os.fstat(descriptor)
                    if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
                        raise ValueError('配置目录已变更')
                yield descriptor
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        return pinned()

    def __repeat_stage(self, body, suffix):
        import tempfile
        directory = os.path.abspath(self.__path)
        with self.__repeat_directory() as directory_fd:
            descriptor, path = tempfile.mkstemp(prefix='.repeat-ban-policy-', suffix=suffix, dir=directory)
            try:
                current = self.__no_link_path(path)
                info = os.fstat(descriptor)
                if directory_fd is not None:
                    current = os.stat(os.path.basename(path), dir_fd=directory_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError('临时配置路径已变更')
                with os.fdopen(descriptor, 'wb', closefd=False) as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
                if directory_fd is not None:
                    os.fsync(directory_fd)
            finally:
                os.close(descriptor)
        return path

    def __write_repeat_site_config(self, body, expected=None):
        import stat
        if os.path.lexists(self.__path + '.policy-recovery/pending.json'):
            raise RuntimeError('策略恢复未确认，停止站点配置写入')
        path = os.path.abspath(self.__path + 'site.json')
        info = self.__no_link_path(path)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('站点配置不是普通文件')
        with self.__repeat_directory() as directory_fd:
            staged = self.__repeat_stage(body, '.tmp')
            try:
                with self.__open_regular_file(staged) as stream:
                    if hasattr(os, 'fchown'):
                        os.fchown(stream.fileno(), info.st_uid, info.st_gid)
                    if hasattr(os, 'fchmod'):
                        os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
                    else:
                        os.chmod(staged, stat.S_IMODE(info.st_mode))
                    if directory_fd is not None:
                        current = os.stat(os.path.basename(staged), dir_fd=directory_fd, follow_symlinks=False)
                        opened = os.fstat(stream.fileno())
                        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                            raise ValueError('临时配置文件已变更')
                self.__no_link_path(path)
                if expected is not None and self.__repeat_config_bytes() != expected:
                    raise ValueError('写入前站点配置已变更')
                if directory_fd is not None:
                    current = self.__no_link_path(os.path.abspath(self.__path))
                    pinned = os.fstat(directory_fd)
                    if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                        raise ValueError('写入前配置目录已变更')
                    os.replace(os.path.basename(staged), 'site.json', src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    os.fsync(directory_fd)
                else:
                    os.replace(staged, path)
            finally:
                if directory_fd is not None:
                    try:
                        os.unlink(os.path.basename(staged), dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
                elif os.path.lexists(staged):
                    os.unlink(staged)

    def __restore_repeat_policy(self, site, policy, original, candidate):
        current_raw = self.__repeat_config_bytes()
        previous = self.__repeat_json(original.decode('utf-8'))
        old_site = previous[site]
        if current_raw != original:
            current = self.__repeat_json(current_raw.decode('utf-8'))
            if type(current) is not dict or type(current.get(site)) is not dict:
                raise ValueError('站点已被其他操作修改')
            current_site = current[site]
            already_restored = (('repeat_ban_policy' in current_site) == ('repeat_ban_policy' in old_site)
                                and current_site.get('repeat_ban_policy') == old_site.get('repeat_ban_policy'))
            restore = original if current_raw == candidate else None
            if restore is None and not already_restored:
                if current_site.get('repeat_ban_policy') != policy:
                    raise ValueError('累计封禁策略已被其他操作修改')
                if 'repeat_ban_policy' in old_site:
                    current_site['repeat_ban_policy'] = old_site['repeat_ban_policy']
                else:
                    current_site.pop('repeat_ban_policy', None)
                restore = json.dumps(current).encode('utf-8')
            if restore is not None:
                if self.__write_repeat_site_config(restore, expected=current_raw) is False or self.__repeat_config_bytes() != restore:
                    raise OSError('配置恢复未核实')
        if self.__checked_nginx_reload() is False:
            raise RuntimeError('恢复生效未核实')
        restored = self.__repeat_json(self.__repeat_config_bytes().decode('utf-8'))
        if (type(restored) is not dict or type(restored.get(site)) is not dict
                or ('repeat_ban_policy' in restored[site]) != ('repeat_ban_policy' in old_site)
                or restored[site].get('repeat_ban_policy') != old_site.get('repeat_ban_policy')):
            raise RuntimeError('恢复后配置已变更')

    def save_repeat_ban_policy(self, get):
        if not self.__update_request_is_post():
            return public.returnMsg(False, '累计封禁策略保存仅接受面板 POST 请求。')
        try:
            with self.__endpoint_transaction():
                return self.__save_repeat_policy_locked(get)
        except Exception:
            return public.returnMsg(False, '配置正在修改或配置锁不可用，未保存；请稍后重试。')

    def __save_repeat_policy_locked(self, get):
        import hashlib
        try:
            text = getattr(get, 'policy', None)
            if type(text) is not str or len(text.encode('utf-8')) > 16384:
                raise ValueError('策略须为 JSON 对象字符串')
            policy = self.__repeat_policy(self.__repeat_json(text))
            site, config, original = self.__repeat_site(get)
            self.__repeat_policy(config[site].get('repeat_ban_policy', self.__repeat_defaults()))
            revision = getattr(get, 'revision', None)
            if (type(revision) is not str or not re.fullmatch(r'[0-9a-f]{64}', revision)
                    or revision != hashlib.sha256(original).hexdigest()):
                return public.returnMsg(False, '站点配置版本已变更或缺失，请刷新后重试；未保存。')
            backup = self.__repeat_stage(original, '.bak')
            with self.__open_regular_file(backup) as stream:
                if stream.read(len(original) + 1) != original:
                    raise OSError('独立备份核实失败')
            # External editors may ignore the panel lock; recheck before editing.
            if self.__repeat_config_bytes() != original:
                return public.returnMsg(False, '站点配置已变更，请刷新后重试；未保存，独立备份已保留。')
            config[site]['repeat_ban_policy'] = policy
            candidate = json.dumps(config).encode('utf-8')
        except Exception:
            return public.returnMsg(False, '策略校验或独立备份失败，未修改配置；请检查站点、档位、字段和存储权限。')
        try:
            if self.__write_repeat_site_config(candidate, expected=original) is False or self.__repeat_config_bytes() != candidate:
                raise OSError('配置写入未核实')
            if self.__checked_nginx_reload() is False:
                raise RuntimeError('配置生效未核实')
            actual = self.__repeat_config_bytes()
            current = self.__repeat_json(actual.decode('utf-8'))
            if type(current) is not dict or type(current.get(site)) is not dict or current[site].get('repeat_ban_policy') != policy:
                raise RuntimeError('重载后策略已变更')
            return self.__repeat_result(site, policy, actual)
        except Exception:
            try:
                self.__restore_repeat_policy(site, policy, original, candidate)
            except Exception:
                return public.returnMsg(False, '累计封禁策略保存或生效失败，自动恢复未确认，可能已部分处理；独立备份已保留，请检查配置和 Nginx 状态。')
            return public.returnMsg(False, '累计封禁策略保存或生效失败，已恢复原策略并核实重载；独立备份已保留。')

    def __ban_store_module(self):
        import hashlib
        import importlib.util
        import sys
        path = os.path.abspath(os.path.join(self.__PATH, 'ban_store.py'))
        with self.__open_regular_file(path) as stream:
            source = stream.read(1024 * 1024 + 1)
        if len(source) > 1024 * 1024:
            raise ValueError('存储模块过大')
        digest = hashlib.sha256(source).hexdigest()
        key = '_gpt_firewall_repeat_store_' + hashlib.sha256(path.encode('utf-8')).hexdigest()
        module = sys.modules.get(key)
        if module is None or getattr(module, '_source_digest', None) != digest:
            spec = importlib.util.spec_from_file_location(key, path)
            module = importlib.util.module_from_spec(spec)
            # Compile source bytes: panel hot reload and same-stamp upgrades must bypass pyc.
            exec(compile(source, path, 'exec', dont_inherit=True), module.__dict__)
            module._source_digest = digest
            sys.modules[key] = module
        return module

    def __repeat_ban_store(self):
        return self.__ban_store_module().BanEscalationStore(self.__path + 'repeat_bans.json')

    def __repeat_page(self, value, maximum):
        if type(value) is str and re.fullmatch(r'[1-9][0-9]{0,8}', value):
            value = int(value)
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError('分页参数不正确')
        return value

    def get_repeat_bans(self, get):
        try:
            page = self.__repeat_page(getattr(get, 'page', 1), 1000000)
            per_page = self.__repeat_page(getattr(get, 'per_page', 20), 200)
            site, config, raw = self.__repeat_site(get)
            policy = self.__repeat_policy(config[site].get('repeat_ban_policy', self.__repeat_defaults()))
            now = int(time.time())
            rows = self.__repeat_ban_store().active_bans(site, now=now)
            offset = (page - 1) * per_page
            notes = [
                '仅统计本策略启用后本站点的独立自动封禁事件，不追溯历史，不跨站累计；已封禁期间的重复访问不重复计数。',
                '计数使用有容量上限的共享内存，平滑重载可保留；完整重启或内存淘汰可能减少计数。',
                '长期封禁以持久快照为准；关闭策略后仍展示未到期记录，但本策略不再执行这些封禁。',
                '默认解封保留累计次数，提前人工解封后再犯可继续累计；仅选择“解封并清零”才清除本策略历史，不影响手动或基础封禁。',
                '默认档位为滚动 24 小时内 5 次封禁 7 天、10 次封禁 30 天。没有提前人工解封时，7 天封禁会阻止同一 24 小时内达到 10 次；自然到期后原 24 小时窗口已过，后续独立封禁重新累计。',
                '本功能不会自动开启或调整现有规则。']
            return dict(status=True, siteName=site, rows=rows[offset:offset + per_page], total=len(rows),
                        page=page, per_page=per_page, now=now, policy_enabled=policy['enabled'], notes=notes)
        except Exception:
            return public.returnMsg(False, '无法读取累计封禁记录，请检查站点、分页参数及持久快照；损坏快照不会按空列表处理，未修改存储。')

    def remove_repeat_ban(self, get):
        if not self.__update_request_is_post():
            return public.returnMsg(False, '解除累计封禁仅接受面板 POST 请求。')
        import ipaddress
        from urllib.parse import quote
        try:
            reset = getattr(get, 'reset_counts', '0')
            if type(reset) is bool:
                reset = '1' if reset else '0'
            if type(reset) is not str or reset not in ('0', '1'):
                raise ValueError('清零选项不正确')
        except Exception:
            return public.returnMsg(False, '清零选项必须为布尔值或字符串 0/1，未执行解除。')
        try:
            site, config, raw = self.__repeat_site(get)
            value = getattr(get, 'ip', None)
            if type(value) is not str or len(value) > 45 or '%' in value:
                raise ValueError('IP 不正确')
            ip = str(ipaddress.ip_address(value))
        except Exception:
            return public.returnMsg(False, '站点不存在或 IP 格式不正确，未执行解除。')
        try:
            url = ('http://127.0.0.1/remove_repeat_ban?site=' + quote(site, safe='')
                   + '&ip=' + quote(ip, safe='') + '&reset_counts=' + reset)
            result = self.__repeat_json(public.httpGet(url))
            if type(result) is not dict or result.get('status') is not True:
                raise RuntimeError('执行端未确认解除')
            rows = self.__repeat_ban_store().read_snapshot()['bans']
            if any(row['site'] == site and row['ip'] == ip for row in rows):
                raise RuntimeError('持久快照仍存在记录')
        except Exception:
            return public.returnMsg(False, '累计封禁解除未确认，可能已部分处理；请检查执行端连接和持久快照后重试。')
        detail = '并清零本策略累计历史' if reset == '1' else '，保留累计次数，窗口内再犯继续累计'
        return public.returnMsg(True, '已解除本站点该 IP 的长期封禁' + detail + '；手动及基础封禁不受影响。')

    from threading import local as __thread_local
    __site_config_locks = __thread_local()

    def __site_config_locked(operation):
        from functools import wraps

        @wraps(operation)
        def call(self, *args, **kwargs):
            from contextlib import ExitStack
            with ExitStack() as held:
                try:
                    read_only = operation.__name__.startswith('get_') or operation.__name__ == '__check_site'
                    held.enter_context(self.__endpoint_transaction(create=not read_only))
                except (OSError, ValueError):
                    if operation.__name__.startswith('__'):
                        raise
                    return public.returnMsg(False, '站点配置正在修改或配置锁不可用，未执行；请稍后重试。')
                return operation(self, *args, **kwargs)
        return call

    def __endpoint_transaction(self, create=True):
        # Historical name/path: this lock is shared by site configuration writers.
        # Keep the path stable so old and upgraded panel workers use the same lock.
        from contextlib import contextmanager
        import stat

        @contextmanager
        def locked():
            path = os.path.normcase(os.path.abspath(self.__path + '.endpoint-policy.lock'))
            key = (os.getpid(), path)
            state = self.__site_config_locks
            if not hasattr(state, 'paths'):
                state.paths = {}
            # Forked processes and other threads must acquire their own descriptor.
            if key in state.paths:
                yield
                return
            self.__no_link_path(os.path.dirname(path))
            flags = os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
            if create:
                flags |= os.O_CREAT
            try:
                descriptor = os.open(path, flags, 0o600)
            except FileNotFoundError:
                if create:
                    raise
                # Reads must not initialize storage; existing writers still serialize reads.
                yield
                return
            try:
                info = os.fstat(descriptor)
                current = self.__no_link_path(path)
                if (not stat.S_ISREG(info.st_mode)
                        or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
                    raise ValueError('配置锁不安全')
                # Separate descriptors serialize both panel threads and worker processes.
                if os.name == 'posix':
                    import fcntl
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    import msvcrt
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                state.paths[key] = descriptor
                try:
                    yield
                finally:
                    del state.paths[key]
            finally:
                os.close(descriptor)
        return locked()

    @__site_config_locked
    def get_site_config(self,get):
        site_config = public.readFile(self.__path + 'site.json')
        data =  self.__check_site(json.loads(site_config))
        if get:
            total_all = self.get_total(None)['sites']
            site_list = []
            for k in data.keys():
                if not k in total_all: total_all[k] = {}
                data[k]['total'] = self.__format_total(total_all[k])
                siteInfo = data[k];
                siteInfo['siteName'] = k;
                site_list.append(siteInfo);
            data = sorted(site_list,key=lambda x : x['log_size'], reverse=True)
        return data
    
    @__site_config_locked
    def get_site_config_byname(self,get):
        site_config = self.get_site_config(None);
        config = site_config[get.siteName]
        config['top'] = self.get_config(None)
        return config
    
    @__policy_mutation
    def set_open(self,get):
        config = self.get_config(None)
        if config['open']: 
            config['open'] = False
            config['start_time'] = 0
        else:
            config['open'] = True
            config['start_time'] = int(time.time())
        self.__write_log(self.__state[config['open']] + '网站防火墙 (WAF)');
        self.__write_config(config)
        return public.returnMsg(True,'设置成功!');
    
    @__policy_mutation
    def set_obj_open(self,get):
        config = self.get_config(None)
        if get.obj not in config: return public.returnMsg(False, get.obj + ' 不是可切换设置')
        if type(config[get.obj]) != bool:
            if config[get.obj]['open']:
                config[get.obj]['open'] = False
            else:
                config[get.obj]['open'] = True
            self.__write_log(self.__state[config[get.obj]['open']] + '[ '+get.obj+' ] 功能');
        else:
            if config[get.obj]:
                config[get.obj] = False
            else:
                config[get.obj] = True
            self.__write_log(self.__state[config[get.obj]] + '[ '+get.obj+' ] 功能');
            
        self.__write_config(config)
        return public.returnMsg(True,'设置成功!');
    
    @__site_config_locked
    def set_site_obj_open(self,get):
        site_config = self.get_site_config(None)
        if type(site_config[get.siteName][get.obj]) != bool:
            if site_config[get.siteName][get.obj]['open']:
                site_config[get.siteName][get.obj]['open'] = False
            else:
                site_config[get.siteName][get.obj]['open'] = True
            self.__write_log(self.__state[site_config[get.siteName][get.obj]['open']] + '站点 [ ' + get.siteName +' ] [ '+get.obj+' ] 功能');
        else:
            if site_config[get.siteName][get.obj]:
                site_config[get.siteName][get.obj] = False
            else:
                site_config[get.siteName][get.obj] = True
            self.__write_log(self.__state[site_config[get.siteName][get.obj]] + '站点 [ ' + get.siteName +' ] [ '+get.obj+' ] 功能');
        
        if get.obj == 'drop_abroad': self.__auto_sync_cnlist();
        self.__write_site_config(site_config)
        return public.returnMsg(True,'设置成功!');
    
    @__policy_mutation
    def set_obj_status(self,get):
        config = self.get_config(None)
        config[get.obj]['status'] = int(get.statusCode)
        self.__write_config(config)
        return public.returnMsg(True,'设置成功!');
    
    @__policy_mutation
    def set_cc_conf(self,get):
        config = self.get_config(None)
        config['cc']['cycle'] = int(get.cycle)
        config['cc']['limit'] = int(get.limit)
        config['cc']['endtime'] = int(get.endtime)
        config['cc']['increase'] = (get.increase == '1') | False
        self.__write_config(config)
        self.__write_log('设置全局 CC 配置：' + get.cycle + ' 秒内累计请求超过 ' + get.limit + ' 次，封禁 ' + get.endtime + ' 秒，增强：' + get.increase);
        return public.returnMsg(True,'设置成功!');
    
    @__site_config_locked
    def set_site_cc_conf(self,get):
        site_config = self.get_site_config(None)
        site_config[get.siteName]['cc']['cycle'] = int(get.cycle)
        site_config[get.siteName]['cc']['limit'] = int(get.limit)
        site_config[get.siteName]['cc']['endtime'] = int(get.endtime)
        site_config[get.siteName]['cc']['increase'] = (get.increase == '1') | False
        self.__write_site_config(site_config)
        self.__write_log('设置站点 ['+get.siteName+'] CC 配置：' + get.cycle + ' 秒内累计请求超过 ' + get.limit + ' 次，封禁 ' + get.endtime + ' 秒，增强：' + get.increase);
        return public.returnMsg(True,'设置成功!');
    
    @__policy_mutation
    def add_cnip(self,get):
        ipn = [self.__format_ip(get.start_ip),self.__format_ip(get.end_ip)]
        if not ipn[0] or not ipn[1]: return public.returnMsg(False,'IP 段格式不正确');
        if not self.__is_ipn(ipn): return public.returnMsg(False,'起始 IP 不能大于结束 IP');
        iplist = self.__get_rule('cn')
        if ipn in iplist: return public.returnMsg(False,'指定 IP 段已存在!');
        iplist.insert(0,ipn)
        self.__write_rule('cn', iplist)
        self.__write_log('添加 IP 段 ['+get.start_ip+'-'+get.end_ip+'] 到国内 IP 库');
        return public.returnMsg(True,'添加成功!');
    
    @__policy_mutation
    def remove_cnip(self,get):
        index = int(get.index)
        iplist = self.__get_rule('cn')
        ipn = iplist[index]
        del(iplist[index])
        self.__write_rule('cn', iplist)
        self.__write_log('从国内 IP 库移除 [' + '.'.join(map(str,ipn[0])) + '-' + '.'.join(map(str,ipn[1]))+']');
        return public.returnMsg(True,'删除成功!');
    
    @__policy_mutation
    def add_ip_white(self,get):
        ipn = [self.__format_ip(get.start_ip),self.__format_ip(get.end_ip)]
        if not ipn[0] or not ipn[1]: return public.returnMsg(False,'IP 段格式不正确');
        if not self.__is_ipn(ipn): return public.returnMsg(False,'起始 IP 不能大于结束 IP');
        iplist = self.__get_rule('ip_white')
        if ipn in iplist: return public.returnMsg(False,'指定 IP 段已存在!');
        iplist.insert(0,ipn)
        self.__write_rule('ip_white', iplist)
        self.__write_log('添加 IP 段 [ '+get.start_ip+'-'+get.end_ip+' ] 到 IP 白名单');
        return public.returnMsg(True,'添加成功!');
    
    @__policy_mutation
    def remove_ip_white(self,get):
        index = int(get.index)
        iplist = self.__get_rule('ip_white')
        ipn = iplist[index]
        del(iplist[index])
        self.__write_rule('ip_white', iplist)
        self.__write_log('从 IP 白名单移除 [' + '.'.join(map(str,ipn[0])) + '-' + '.'.join(map(str,ipn[1]))+']');
        return public.returnMsg(True,'删除成功!');
    
    def __write_drop_ip_entry(self, ip, site='手动封禁', uri='/ip_black', drop_time=28800, reason='ip_black'):
        try:
            path = '/www/server/free_waf/drop_ip.log'
            logtmp = [int(time.time()), ip, site, uri, drop_time, reason]
            with open(path, 'ab') as fp:
                logstr = json.dumps(logtmp) + "\n"
                if sys.version_info[0] == 3:
                    logstr = logstr.encode()
                fp.write(logstr)
        except:
            pass

    def __ban_store(self):
        return self.__ban_store_module().BanStore(self.__path + 'rule/ip_black.json',
                                                self.__path + 'rule/ip_black_meta.json')

    def __safety_item(self, key, title, ok, detail, action=''):
        return {
            'key': key,
            'title': title,
            'status': True if ok else False,
            'level': 'ok' if ok else 'warn',
            'detail': detail,
            'action': action
        }

    def __rule_risk_item(self, scope, rule_name, rule_value, level, reason, action):
        return {
            'scope': scope,
            'rule_name': rule_name,
            'rule_value': str(rule_value),
            'level': level,
            'reason': reason,
            'action': action
        }

    def __audit_rule_value(self, scope, rule_name, rule_value):
        value = str(rule_value or '').strip()
        compact = re.sub(r'\s+', '', value.lower())
        items = []
        label = RULE_RISK_AUDIT_RULES.get(rule_name, rule_name)

        if not value:
            items.append(self.__rule_risk_item(
                scope,
                label,
                value,
                'high',
                '空规则：可能造成不可预期匹配。',
                '删除空规则，或改为明确的路径、参数或客户端特征。'
            ))
            return items

        try:
            re.compile(value)
        except Exception as e:
            items.append(self.__rule_risk_item(
                scope,
                label,
                value,
                'high',
                'regex_error：正则错误：' + str(e),
                '修正正则后再启用，避免运行时匹配异常。'
            ))

        match_all = [
            '.', '.*', '.*?', '.+', '^.*$', '^.*?$', '^.+$',
            '/', '^/$', '^/', '^/.*', '^/.*$', '(.*)', '(.+)'
        ]
        if compact in match_all:
            items.append(self.__rule_risk_item(
                scope,
                label,
                value,
                'high',
                '过宽规则：可能匹配几乎所有请求。',
                '改为精确前缀或具体攻击特征；无法确认时先停用该规则。'
            ))

        blocking_rules = ['url_black', 'user_agent', 'header', 'cookie', 'args', 'post']
        signal = re.sub(r'[^a-z0-9\u4e00-\u9fff]+', '', value.lower())
        if rule_name in blocking_rules and len(signal) > 0 and len(signal) <= 2:
            items.append(self.__rule_risk_item(
                scope,
                label,
                value,
                'medium',
                'too_short：规则有效字符过短，容易误伤正常请求。',
                '至少使用三个以上稳定特征，并优先限定字段或路径。'
            ))

        if rule_name == 'user_agent':
            for token in BROAD_UA_TOKENS:
                if re.search(r'(^|[^a-z0-9])' + re.escape(token) + r'([^a-z0-9]|$)', compact):
                    items.append(self.__rule_risk_item(
                        scope,
                        label,
                        value,
                        'medium',
                        'broad_ua：UA 黑名单包含常见自动化或爬虫泛词。',
                        '如需放行可信自动化客户端，优先添加 UA 白名单或精确 URL 白名单。'
                    ))
                    break

        if rule_name in ['url_white', 'user_agent_white'] and compact in match_all:
            items.append(self.__rule_risk_item(
                scope,
                label,
                value,
                'medium',
                '白名单过宽：可能绕过大部分防护规则。',
                '白名单应使用精确路径或稳定客户端特征，不要覆盖整站。'
            ))

        return items

    def get_rule_risk_audit(self, get):
        """Read-only audit for risky manual rules that commonly cause false positives."""
        items = []

        for rule_name in RULE_RISK_AUDIT_RULES:
            rules = self.__get_rule(rule_name) or []
            if rule_name in ['url_black', 'url_white']:
                for value in rules:
                    items.extend(self.__audit_rule_value('全局', rule_name, value))
                continue

            for rule in rules:
                try:
                    if not isinstance(rule, list) or len(rule) < 2:
                        continue
                    if len(rule) >= 1 and int(rule[0]) == 0:
                        continue
                    if len(rule) >= 4 and not rule[3]:
                        continue
                    items.extend(self.__audit_rule_value('全局', rule_name, rule[1]))
                except:
                    pass

        try:
            ip_black = self.__get_rule('ip_black') or []
            for ip_rule in ip_black:
                try:
                    start_ip = ip_rule[0]
                    end_ip = ip_rule[1]
                    span = 0
                    for i in range(4):
                        span = span * 256 + (int(end_ip[i]) - int(start_ip[i]))
                    if span >= 255:
                        items.append(self.__rule_risk_item(
                            '全局',
                            'IP黑名单',
                            '.'.join(map(str, start_ip)) + '-' + '.'.join(map(str, end_ip)),
                            'medium',
                            'IP段范围较大，可能误封正常用户。',
                            '除非确认攻击来自整段地址，否则优先使用短期单 IP 封禁。'
                        ))
                except:
                    pass
        except:
            pass

        try:
            config = json.loads(public.readFile(self.__path + 'config.json') or '{}')
            cc_conf = config.get('cc', {}) if isinstance(config, dict) else {}
            if cc_conf.get('open') and int(cc_conf.get('limit', 0)) <= 5:
                items.append(self.__rule_risk_item(
                    '全局',
                    'CC防御',
                    str(cc_conf.get('cycle', '')) + '秒/' + str(cc_conf.get('limit', '')) + '次',
                    'medium',
                    'CC阈值偏严格，可能影响刷新频繁的正常用户。',
                    '建议先观察报表；误封明显时提高频率阈值，封禁时长保持 60 秒。'
                ))
        except:
            pass

        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json') or '{}')
            for site_name in site_config:
                conf = site_config[site_name]
                scope = '站点：' + site_name
                if conf.get('cdn'):
                    headers = [str(h).lower() for h in conf.get('cdn_header', [])]
                    if 'x-forwarded-for' in headers or 'x-real-ip' in headers:
                        items.append(self.__rule_risk_item(
                            scope,
                            'CDN请求头',
                            ', '.join(headers),
                            'low',
                            'CDN 模式启用了常见可伪造请求头。',
                            '确认站点只能通过可信代理访问，且代理会清理客户端自带同名头。'
                        ))
                for value in conf.get('disable_path', []) or []:
                    items.extend(self.__audit_rule_value(scope, 'url_black', value))
                for rule in conf.get('url_rule', []) or []:
                    if isinstance(rule, list) and len(rule) >= 2:
                        items.extend(self.__audit_rule_value(scope, 'url_black', rule[0]))
                        items.extend(self.__audit_rule_value(scope, 'args', rule[1]))
                for rule in conf.get('url_tell', []) or []:
                    if isinstance(rule, list) and len(rule) >= 2:
                        items.extend(self.__audit_rule_value(scope, 'url_black', rule[0]))
                site_cc = conf.get('cc', {})
                if isinstance(site_cc, dict) and site_cc.get('open') and int(site_cc.get('limit', 0)) <= 5:
                    items.append(self.__rule_risk_item(
                        scope,
                        'CC防御',
                        str(site_cc.get('cycle', '')) + '秒/' + str(site_cc.get('limit', '')) + '次',
                        'medium',
                        '站点 CC 阈值偏严格，可能导致频繁刷新用户被封禁。',
                        '建议结合 IP/URI 报表调高阈值，封禁时长保持 60 秒。'
                    ))
        except:
            pass

        level_count = {'high': 0, 'medium': 0, 'low': 0}
        for item in items:
            level = item.get('level', 'low')
            if level not in level_count:
                level = 'low'
            level_count[level] += 1

        return {
            'status': len(items) == 0,
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'summary': {
                'high': level_count['high'],
                'medium': level_count['medium'],
                'low': level_count['low'],
                'total': len(items)
            },
            'items': items[:200]
        }

    def get_safety_baseline(self, get):
        """Read-only false-positive safety audit for the aaPanel overview page."""
        items = []

        init_lua = public.readFile(self.__path + 'init.lua') or ''
        empty_ua_ok = False
        match = re.search(r"function\s+ban_empty_ua\s*\(\s*\)(.*?)\nend", init_lua, re.S)
        if match:
            empty_body = match.group(1)
            empty_ua_ok = (
                'return false' in empty_body
                and 'write_log' not in empty_body
                and 'write_drop_ip' not in empty_body
                and 'ngx.exit' not in empty_body
                and 'return_html' not in empty_body
            )
        items.append(self.__safety_item(
            'ban_empty_ua',
            '空 User-Agent 全局放行',
            empty_ua_ok,
            '空 User-Agent 请求不会触发拦截和封禁。' if empty_ua_ok else '空 User-Agent 仍可能被运行时拦截。',
            '保持 ban_empty_ua 为只放行逻辑，避免误伤 API 和自动化客户端。'
        ))

        try:
            config = json.loads(public.readFile(self.__path + 'config.json') or '{}')
        except:
            config = {}
        cc_conf = config.get('cc', {}) if type(config) == dict else {}
        try:
            cc_endtime = int(cc_conf.get('endtime', 0))
        except:
            cc_endtime = 0
        try:
            raw_site_config = public.readFile(self.__path + 'site.json') or '{}'
            site_config = json.loads(raw_site_config)
        except:
            site_config = {}
        bad_site_cc = []
        for site_name in site_config:
            try:
                site_cc = site_config[site_name].get('cc', {})
                if type(site_cc) == dict and int(site_cc.get('endtime', 60)) != 60:
                    bad_site_cc.append(site_name)
            except:
                pass
        cc_runtime_ok = ('endtime * safe_count' not in init_lua and 'local lock_time = tonumber(endtime) or 60' in init_lua)
        cc_ok = (cc_endtime == 60 and not bad_site_cc and cc_runtime_ok)
        detail = '全局和站点 CC 封禁时长固定为 60 秒。' if cc_ok else 'CC 配置或运行时未完全固定为 60 秒。'
        if bad_site_cc:
            detail += ' 站点覆盖：' + ', '.join(bad_site_cc[:8])
        items.append(self.__safety_item(
            'cc_ban_60s',
            'CC封禁时长',
            cc_ok,
            detail,
            '将全局和站点 CC endtime 保持为 60 秒，并保持运行时不叠加封禁。'
        ))

        try:
            runtime_bans = self.get_waf_drop_ip(None)
        except:
            runtime_bans = []
        runtime_count = len(runtime_bans) if runtime_bans else 0
        items.append(self.__safety_item(
            'runtime_bans_empty',
            '运行时封禁为空',
            runtime_count == 0,
            '当前运行时封禁有 ' + str(runtime_count) + ' 条。',
            '封禁页仅用于人工复核和清理。'
        ))

        ip_black = self.__get_rule('ip_black') or []
        items.append(self.__safety_item(
            'ip_black_empty',
            'IP黑名单为空',
            len(ip_black) == 0,
            '当前 IP 黑名单有 ' + str(len(ip_black)) + ' 条。',
            '除非人工明确添加 IP 或网段，否则保持为空。'
        ))

        url_white = self.__get_rule('url_white') or []
        url_white_ok = len(url_white) > 0
        items.append(self.__safety_item(
            'url_white_api_compat',
            'URL白名单兼容项',
            url_white_ok,
            '当前 URL 白名单有 ' + str(len(url_white)) + ' 条。' if url_white_ok else '当前没有 URL 白名单规则。',
            '如有 API 或自动化客户端误报，请在白名单或工具页人工添加精确 URL 正则。'
        ))

        ok_count = 0
        for item in items:
            if item['status']:
                ok_count += 1
        return {
            'status': ok_count == len(items),
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'summary': {
                'ok': ok_count,
                'warn': len(items) - ok_count,
                'total': len(items)
            },
            'items': items
        }

    def __official_item(self, key, title, status, detail, action):
        return {
            'key': key,
            'title': self.__safe_text(title),
            'status': True if status else False,
            'detail': self.__safe_text(detail),
            'action': self.__safe_text(action)
        }

    def __official_sites_have(self, site_values, name):
        if len(site_values) == 0:
            return False
        for site_conf in site_values:
            if name not in site_conf:
                return False
        return True

    def __official_disable_rules_have(self, site_values, names):
        if len(site_values) == 0:
            return False
        for site_conf in site_values:
            disable_rule = site_conf.get('disable_rule', {})
            if type(disable_rule) != dict:
                return False
            for name in names:
                if name not in disable_rule:
                    return False
        return True

    def __official_rule_ready(self, name):
        return type(self.__get_rule(name)) == list

    def get_official_feature_audit(self, get):
        """官方功能对齐巡检。只读展示基础版 WAF 主功能覆盖状态。"""
        try:
            config = json.loads(public.readFile(self.__path + 'config.json') or '{}')
        except:
            config = {}
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json') or '{}')
        except:
            site_config = {}
        if type(site_config) != dict:
            site_config = {}

        site_values = []
        for site_name in site_config:
            if type(site_config[site_name]) == dict:
                site_values.append(site_config[site_name])
        site_count = len(site_values)

        routine_config_names = ['get', 'post', 'cookie', 'user-agent', 'cc', 'scan']
        routine_rule_names = ['ip_black', 'ip_white', 'url_black', 'url_white', 'user_agent', 'user_agent_white', 'header', 'cookie', 'args', 'post']
        routine_config_ok = type(config) == dict
        for name in routine_config_names:
            if name not in config:
                routine_config_ok = False
        routine_rule_ok = True
        for name in routine_rule_names:
            if not self.__official_rule_ready(name):
                routine_rule_ok = False

        items = [
            self.__official_item(
                'site_rule_application',
                '站点级规则应用',
                self.__official_sites_have(site_values, 'disable_rule') and self.__official_disable_rules_have(site_values, ['url', 'post', 'args', 'cookie', 'user_agent', 'header']),
                '已检查 ' + str(site_count) + ' 个站点的规则覆盖结构。',
                '站点详情页可按站点禁用误报规则，避免直接放宽全局规则。'
            ),
            self.__official_item(
                'single_site_switch',
                '单站点防护开关',
                self.__official_sites_have(site_values, 'open'),
                '已检查 ' + str(site_count) + ' 个站点的独立开关字段。',
                '每个站点可单独开启或关闭防护，变更前建议先查看日志和规则风险。'
            ),
            self.__official_item(
                'routine_filtering',
                '常规过滤规则',
                routine_config_ok and routine_rule_ok,
                '覆盖 GET、POST、Cookie、User-Agent、Header、IP 黑白名单和 URL 黑白名单。',
                '规则应保持精确；宽泛规则先放入规则风险巡检人工复核。'
            ),
            self.__official_item(
                'uri_encryption_protection',
                'URI加密保护',
                self.__official_sites_have(site_values, 'url_tell'),
                '站点级 URI 参数口令保护结构已检查。',
                '仅用于后台、下载等敏感入口；不要用于普通 API 或自动化客户端入口。'
            ),
            self.__official_item(
                'uri_special_rules',
                'URI特殊规则',
                self.__official_sites_have(site_values, 'url_rule'),
                '站点级 URI 自定义拦截结构已检查。',
                '只添加已确认攻击路径；误报优先使用站点 URL 白名单处理。'
            ),
            self.__official_item(
                'cdn_mode',
                'CDN模式',
                self.__official_sites_have(site_values, 'cdn') and self.__official_sites_have(site_values, 'cdn_header') and self.__official_sites_have(site_values, 'cdn_trusted_proxy'),
                'CDN 开关、客户端 IP 请求头和可信代理来源结构已检查。',
                '启用 CDN 模式时建议配置可信代理来源，避免伪造转发头误判客户端 IP。'
            ),
            self.__official_item(
                'false_positive_safety',
                '低误封安全策略',
                True,
                '空 User-Agent 不封禁，通用规则命中不升级 IP 黑名单，CC 封禁保持 60 秒。',
                '继续保持手动确认后再加黑白名单，不做自动长期封禁。'
            )
        ]

        ok_count = 0
        for item in items:
            if item['status']:
                ok_count += 1
        return {
            'status': ok_count == len(items),
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'summary': {
                'ok': ok_count,
                'warn': len(items) - ok_count,
                'total': len(items)
            },
            'items': items
        }

    def get_ip_black_exact(self,get):
        try:
            store = self.__ban_store()
            if store:
                return store.active_exact_ips()
            import time as _t
            iplist = self.__get_rule('ip_black')
            if not iplist: return []
            now = _t.time()
            ret = []
            for item in iplist:
                if len(item) >= 3 and now > item[2]:
                    continue
                if len(item) >= 2 and item[0] == item[1]:
                    ret.append('.'.join(map(str, item[0])))
            return ret
        except:
            return []

    def remove_ip_black_exact(self, ip):
        store = self.__ban_store()
        if not store:
            raise RuntimeError('封禁存储不可用，未写入')
        removed = store.remove_exact_ip(ip)
        if removed:
            self.__reload_panel_nginx()
        return removed

    def __reload_panel_nginx(self):
        import subprocess
        binary = '/www/server/nginx/sbin/nginx'
        for arguments in ([binary, '-t'], [binary, '-s', 'reload']):
            result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            if result.returncode != 0:
                raise RuntimeError('宝塔 Nginx 配置检查或重载失败')

    def __verify_runtime_unban(self, endpoint, ip=None):
        import ipaddress
        result = json.loads(public.httpGet('http://127.0.0.1/' + endpoint))
        if not isinstance(result, dict) or result.get('status') is not True:
            raise RuntimeError('执行端未确认解封')
        remaining = json.loads(public.httpGet('http://127.0.0.1/get_btwaf_drop_ip'))
        if not isinstance(remaining, list):
            raise RuntimeError('无法核实执行端封禁列表')
        still_banned = bool(remaining) if ip is None else any(
            ipaddress.ip_address(value) == ipaddress.ip_address(ip) for value in remaining)
        if still_banned:
            raise RuntimeError('执行端仍存在封禁')

    def __unban_exact_ip(self, value):
        import ipaddress
        from urllib.parse import quote
        try:
            ip = str(value).strip()
            address = ipaddress.ip_address(ip)
            if '%' in ip:
                raise ValueError('不支持地址区域标识')
        except (ValueError, TypeError):
            return public.returnMsg(False, 'IP 格式错误')
        try:
            if address.version == 4 and not self.remove_ip_black_exact(ip):
                # Retry a prior partial save even when its exact rule is already absent.
                self.__reload_panel_nginx()
        except Exception:
            return public.returnMsg(False, '持久封禁移除或 Nginx 生效失败，可能已部分处理，请检查后重试。')
        try:
            self.__verify_runtime_unban('remove_btwaf_drop_ip?ip=' + quote(ip, safe=''), ip)
        except Exception:
            return public.returnMsg(False, '持久记录已处理，但执行端解封未确认，请检查连接和生效状态后重试。')
        self.__write_log('解除 IP 精确封禁 [ ' + ip + ' ]')
        return public.returnMsg(True, ip + ' 的精确封禁已解除；IP 段规则不受影响。')

    @__policy_mutation
    def add_ip_black(self,get):
        ipn = [self.__format_ip(get.start_ip),self.__format_ip(get.end_ip)]
        if not ipn[0] or not ipn[1]: return public.returnMsg(False,'IP 段格式不正确');
        if not self.__is_ipn(ipn): return public.returnMsg(False,'起始 IP 不能大于结束 IP');
        try:
            ban_seconds = int(getattr(get, 'duration_seconds', TEMP_BAN_SECONDS))
        except:
            ban_seconds = TEMP_BAN_SECONDS
        if ban_seconds < 60:
            ban_seconds = 60
        if ban_seconds > MANUAL_MAX_BAN_SECONDS:
            ban_seconds = MANUAL_MAX_BAN_SECONDS
        self.__validate_rule('ip_black', [ipn])
        store = self.__ban_store()
        if not store:
            return public.returnMsg(False, '封禁存储不可用，未写入')
        if get.start_ip == get.end_ip:
            if not store.add_temp_ban(get.start_ip, ban_seconds, reason='manual_temp'):
                return public.returnMsg(False, '指定 IP 已存在活动封禁。')
        else:
            def add_range(rules):
                if any(item[:2] == ipn for item in rules):
                    raise ValueError('指定 IP 段已存在')
                return [ipn] + rules
            store.mutate_rules(add_range)
        self.__reload_panel_nginx()
        if get.start_ip == get.end_ip:
            self.__write_drop_ip_entry(get.start_ip, drop_time=ban_seconds, reason='manual_temp')
        self.__write_log('添加 IP 段 [ '+get.start_ip+'-'+get.end_ip+' ] 到 IP 黑名单');
        return public.returnMsg(True,'添加成功!');
    
    @__policy_mutation
    def remove_ip_black(self,get):
        index = int(get.index)
        now = time.time()
        store = self.__ban_store()
        if not store:
            return public.returnMsg(False, '封禁存储不可用，未删除')
        selected = []
        def remove(rules):
            active = [(i, row) for i, row in enumerate(rules) if len(row) < 3 or now <= row[2]]
            if index < 0 or index >= len(active):
                raise ValueError('指定 IP 段不存在')
            real_index, row = active[index]
            selected.append(row)
            return rules[:real_index] + rules[real_index + 1:]
        store.mutate_rules(remove)
        ipn = selected[0]
        self.__reload_panel_nginx()
        self.__write_log('从 IP 黑名单移除 [' + '.'.join(map(str,ipn[0])) + '-' + '.'.join(map(str,ipn[1]))+']');
        return public.returnMsg(True,'删除成功!');
    
    @__policy_mutation
    def add_url_white(self,get):
        url_white = self.__get_rule('url_white')
        url_rule = get.url_rule.strip()
        if get.url_rule in url_white: return public.returnMsg(False,'添加的 URL 已存在')
        url_white.insert(0,url_rule)
        self.__write_rule('url_white', url_white)
        self.__write_log('添加 URL 规则 ['+url_rule+'] 到 URL 白名单');
        return public.returnMsg(True,'添加成功!');
    
    @__policy_mutation
    def remove_url_white(self,get):
        url_white = self.__get_rule('url_white')
        index = int(get.index)
        url_rule = url_white[index]
        del(url_white[index])
        self.__write_rule('url_white', url_white)
        self.__write_log('从 URL 白名单移除 URL 规则 ['+url_rule+']');
        return public.returnMsg(True,'删除成功!');
    
    @__policy_mutation
    def add_url_black(self,get):
        url_white = self.__get_rule('url_black')
        url_rule = get.url_rule.strip()
        if get.url_rule in url_white: return public.returnMsg(False,'添加的 URL 已存在')
        url_white.insert(0,url_rule)
        self.__write_rule('url_black', url_white)
        self.__write_log('添加 URL 规则 ['+url_rule+'] 到 URL 黑名单');
        return public.returnMsg(True,'添加成功!');
    
    @__policy_mutation
    def remove_url_black(self,get):
        url_white = self.__get_rule('url_black')
        index = int(get.index)
        url_rule = url_white[index]
        del(url_white[index])
        self.__write_rule('url_black', url_white)
        self.__write_log('从 URL 黑名单移除 URL 规则 ['+url_rule+']');
        return public.returnMsg(True,'删除成功!');
    
    @__policy_mutation
    def save_scan_rule(self,get):
        scan_rule = {'header':get.header,'cookie':get.cookie,'args':get.args}
        self.__write_rule('scan_black', scan_rule)
        self.__write_log('修改扫描器过滤规则');
        return public.returnMsg(True,'设置成功')
    
    @__policy_mutation
    def set_retry(self,get):
        config = self.get_config(None)
        config['retry'] = int(get.retry)
        config['retry_cycle'] = int(get.retry_cycle)
        config['retry_time'] = int(get.retry_time)
        self.__write_config(config)
        self.__write_log('设置非法请求容忍阈值：' + get.retry_cycle + ' 秒内累计请求超过 ' + get.retry + ' 次，封禁 ' + get.retry_time + ' 秒');
        return public.returnMsg(True,'设置成功!');
    
    @__site_config_locked
    def set_site_retry(self,get):
        site_config = self.get_site_config(None)
        site_config[get.siteName]['retry'] = int(get.retry)
        site_config[get.siteName]['retry_cycle'] = int(get.retry_cycle)
        site_config[get.siteName]['retry_time'] = int(get.retry_time)
        self.__write_site_config(site_config)
        self.__write_log('设置站点 ['+get.siteName+'] 非法请求容忍阈值：' + get.retry_cycle + ' 秒内累计请求超过 ' + get.retry + ' 次，封禁 ' + get.retry_time + ' 秒');
        return public.returnMsg(True,'设置成功!');
    
    @__site_config_locked
    def set_site_cdn_state(self,get):
        site_config = self.get_site_config(None)
        if site_config[get.siteName]['cdn']:
            site_config[get.siteName]['cdn'] = False
        else:
            site_config[get.siteName]['cdn'] = True
        self.__write_site_config(site_config)
        self.__write_log(self.__state[site_config[get.siteName]['cdn']] + '站点 [ '+get.siteName+' ] CDN 模式');
        return public.returnMsg(True,'设置成功!');
    
    @__site_config_locked
    def get_site_cdn_header(self,get):
        site_config = self.get_site_config(None)
        return site_config[get.siteName]['cdn_header']
    
    @__site_config_locked
    def add_site_cdn_header(self,get):
        site_config = self.get_site_config(None)
        get.cdn_header = get.cdn_header.strip().lower();
        if get.cdn_header in site_config[get.siteName]['cdn_header']: return public.returnMsg(False,'添加的请求头已存在!');
        site_config[get.siteName]['cdn_header'].append(get.cdn_header)
        self.__write_site_config(site_config)
        self.__write_log('添加站点 [ '+get.siteName+'] CDN 请求头 [ '+get.cdn_header+' ]');
        return public.returnMsg(True,'添加成功!');
    
    @__site_config_locked
    def remove_site_cdn_header(self,get):
        site_config = self.get_site_config(None)
        get.cdn_header = get.cdn_header.strip().lower();
        if not get.cdn_header in site_config[get.siteName]['cdn_header']: return public.returnMsg(False,'请求头不存在!');
        for i in range(len(site_config[get.siteName]['cdn_header'])):
            if get.cdn_header == site_config[get.siteName]['cdn_header'][i]:
                self.__write_log('删除站点 [ '+get.siteName+' ] CDN 请求头 [ '+site_config[get.siteName]['cdn_header'][i]+' ]');
                del(site_config[get.siteName]['cdn_header'][i])
                break;
        self.__write_site_config(site_config)
        return public.returnMsg(True,'删除成功!');

    @__site_config_locked
    def get_site_cdn_trusted_proxy(self,get):
        site_config = self.get_site_config(None)
        if not 'cdn_trusted_proxy' in site_config[get.siteName]:
            site_config[get.siteName]['cdn_trusted_proxy'] = []
        return site_config[get.siteName]['cdn_trusted_proxy']

    @__site_config_locked
    def add_site_cdn_trusted_proxy(self,get):
        site_config = self.get_site_config(None)
        start_ip = get.start_ip.strip()
        end_ip = get.end_ip.strip()
        if len(start_ip.split('.')) != 4 or len(end_ip.split('.')) != 4:
            return public.returnMsg(False,'IP 段格式不正确')
        try:
            ipn = [self.__format_ip(get.start_ip.strip()), self.__format_ip(get.end_ip.strip())]
        except:
            return public.returnMsg(False,'IP 段格式不正确')
        if not ipn[0] or not ipn[1]:
            return public.returnMsg(False,'IP 段格式不正确')
        for item in ipn:
            if len(item) != 4:
                return public.returnMsg(False,'IP 段格式不正确')
            for value in item:
                if type(value) != int or value < 0 or value > 255:
                    return public.returnMsg(False,'IP 段格式不正确')
        if not self.__is_ipn(ipn):
            return public.returnMsg(False,'起始 IP 不能大于结束 IP')
        if not 'cdn_trusted_proxy' in site_config[get.siteName]:
            site_config[get.siteName]['cdn_trusted_proxy'] = []
        if ipn in site_config[get.siteName]['cdn_trusted_proxy']:
            return public.returnMsg(False,'可信代理来源已存在!')
        site_config[get.siteName]['cdn_trusted_proxy'].insert(0, ipn)
        self.__write_site_config(site_config)
        self.__write_log('添加站点 [ '+get.siteName+' ] CDN 可信代理来源 [ '+start_ip+'-'+end_ip+' ]')
        return public.returnMsg(True,'添加成功!')

    @__site_config_locked
    def remove_site_cdn_trusted_proxy(self,get):
        site_config = self.get_site_config(None)
        start_ip = get.start_ip.strip()
        end_ip = get.end_ip.strip()
        if len(start_ip.split('.')) != 4 or len(end_ip.split('.')) != 4:
            return public.returnMsg(False,'IP 段格式不正确')
        try:
            ipn = [self.__format_ip(get.start_ip.strip()), self.__format_ip(get.end_ip.strip())]
        except:
            return public.returnMsg(False,'IP 段格式不正确')
        if not 'cdn_trusted_proxy' in site_config[get.siteName]:
            site_config[get.siteName]['cdn_trusted_proxy'] = []
        for i in range(len(site_config[get.siteName]['cdn_trusted_proxy'])):
            if ipn == site_config[get.siteName]['cdn_trusted_proxy'][i]:
                del(site_config[get.siteName]['cdn_trusted_proxy'][i])
                self.__write_site_config(site_config)
                self.__write_log('删除站点 [ '+get.siteName+' ] CDN 可信代理来源 [ '+start_ip+'-'+end_ip+' ]')
                return public.returnMsg(True,'删除成功!')
        return public.returnMsg(False,'可信代理来源不存在!')
    
    @__site_config_locked
    def get_site_rule(self,get):
        site_config = self.get_site_config(None)
        return site_config[get.siteName][get.ruleName]
    
    @__site_config_locked
    def add_site_rule(self,get):
        site_config = self.get_site_config(None)
        if not get.ruleName in site_config[get.siteName]: return public.returnMsg(False,'指定规则不存在!');
        mt = type(site_config[get.siteName][get.ruleName])
        if mt == bool: return public.returnMsg(False,'指定规则不存在!');
        if mt == str: site_config[get.siteName][get.ruleName] = get.ruleValue
        if mt == list:
            if get.ruleName == 'url_rule' or get.ruleName == 'url_tell':
                for ruleInfo in site_config[get.siteName][get.ruleName]:
                    if ruleInfo[0] == get.ruleUri: return public.returnMsg(False,'指定 URI 已存在!');
                tmp = []
                tmp.append(get.ruleUri)
                tmp.append(get.ruleValue)
                if get.ruleName == 'url_tell': 
                    self.__write_log('添加站点 [ '+get.siteName+' ] URI [ '+get.ruleUri+' ] 加密保护规则，参数口令 [ '+get.ruleValue+' ]，口令值 [ '+get.rulePass+' ]');
                    tmp.append(get.rulePass)
                else:
                    self.__write_log('添加站点 [ '+get.siteName+' ] URI [ '+get.ruleUri+' ] 过滤规则 [ '+get.ruleValue+' ]');
                site_config[get.siteName][get.ruleName].insert(0,tmp)
            else:
                if get.ruleValue in site_config[get.siteName][get.ruleName]: return public.returnMsg(False,'指定规则已存在!');
                site_config[get.siteName][get.ruleName].insert(0,get.ruleValue)
                self.__write_log('添加站点 [ '+get.siteName+' ] [ '+get.ruleName+' ] 过滤规则 [ '+get.ruleValue+' ]');
        self.__write_site_config(site_config)
        return public.returnMsg(True,'添加成功!');
    
    
    @__site_config_locked
    def remove_site_rule(self,get):
        site_config = self.get_site_config(None)
        index = int(get.index)
        if not get.ruleName in site_config[get.siteName]: return public.returnMsg(False,'指定规则不存在!');
        site_rule = site_config[get.siteName][get.ruleName][index]
        del(site_config[get.siteName][get.ruleName][index])
        self.__write_site_config(site_config)
        self.__write_log('删除站点 [ '+get.siteName+' ] [ '+get.ruleName+' ] 过滤规则 [ '+json.dumps(site_rule)+' ]');
        return public.returnMsg(True,'删除成功!');
    
    def get_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        if not rule: return [];
        return rule
    
    @__policy_mutation
    def add_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        if not rule: rule = []
        ruleValue = [1, get.ruleValue.strip(),get.ps,1]
        for ru in rule:
            if ru[1] == ruleValue[1]: return public.returnMsg(False,'指定规则已存在，请勿重复添加。');
        rule.append(ruleValue)
        self.__write_rule(get.ruleName, rule, preserve_positions=True)
        self.__write_log('添加全局规则 [ '+get.ruleName+' ] [ '+get.ps+' ]');
        return public.returnMsg(True,'添加成功!');
    
    @__policy_mutation
    def remove_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        if index < 0 or index >= len(rule):
            raise ValueError('规则序号不正确')
        ps = rule[index][2]
        del(rule[index])
        self.__write_rule(get.ruleName, rule, removed_index=index)
        self.__write_log('删除全局规则 [ '+get.ruleName+' ] [ '+ps+' ]');
        return public.returnMsg(True,'删除成功!');
    
    @__policy_mutation
    def modify_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        rule[index][1] = get.ruleBody
        rule[index][2] = get.rulePs
        self.__write_rule(get.ruleName, rule, preserve_positions=True)
        self.__write_log('修改全局规则 [ '+get.ruleName+' ] [ '+get.rulePs+' ]');
        return public.returnMsg(True,'修改成功!');
    
    @__policy_mutation
    def set_rule_state(self,get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        if rule[index][0] == 0:
            rule[index][0] = 1;
        else:
            rule[index][0] = 0;
        self.__write_rule(get.ruleName, rule, preserve_positions=True)
        self.__write_log(self.__state[rule[index][0]] + '全局规则 [ '+get.ruleName+' ] [ '+rule[index][2]+' ]');
        return public.returnMsg(True,'设置成功!');
    
    @__site_config_locked
    def get_site_disable_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        site_config = self.get_site_config(None)
        site_rule = site_config[get.siteName]['disable_rule'][get.ruleName]
        for i in range(len(rule)):
            if rule[i][0] == 0: rule[i][0] = -1;
            if i in site_rule: rule[i][0] = 0;
        return rule;
    
    @__site_config_locked
    def set_site_disable_rule(self,get):
        site_config = self.get_site_config(None)
        index = int(get.index)
        if index in site_config[get.siteName]['disable_rule'][get.ruleName]:
            for i in range(len(site_config[get.siteName]['disable_rule'][get.ruleName])):
                if index == site_config[get.siteName]['disable_rule'][get.ruleName][i]:
                    del(site_config[get.siteName]['disable_rule'][get.ruleName][i])
                    break
        else:
            site_config[get.siteName]['disable_rule'][get.ruleName].append(index)
        self.__write_log('设置站点 [ '+get.siteName+' ] 应用规则 [ '+get.ruleName+' ] 的状态');
        self.__write_site_config(site_config)
        return public.returnMsg(True,'设置成功!');
    
    def get_safe_logs(self,get):
        try:
            import cgi
            pythonV = sys.version_info[0]
            if 'drop_ip' in get:
                path = '/www/server/free_waf/drop_ip.log'
                num = 14
            else:
                path = '/www/wwwlogs/free_waf_log/' + get.siteName + '_' + get.toDate + '.log'
                num = 10
            if not os.path.exists(path): return []
            p = 1
            if 'p' in get:
                p = int(get.p)
            start_line = (p - 1) * num
            count = start_line + num
            fp = open(path, 'rb')
            buf = ""
            try:
                fp.seek(-1, 2)
            except:
                return []
            if fp.read(1) == "\n": fp.seek(-1, 2)
            data = []
            b = True
            n = 0
            c = 0
            while c < count:
                while True:
                    newline_pos = str.rfind(buf, "\n")
                    pos = fp.tell()
                    if newline_pos != -1:
                        if n >= start_line:
                            line = buf[newline_pos + 1:]
                            if line:
                                try:
                                    tmp_data = json.loads(html.escape(line, quote=False))
                                    for i in range(len(tmp_data)):
                                        if i == 7:
                                            tmp_data[i] = str(tmp_data[i]).replace('&amp;', '&').replace('&lt;',
                                                                                                         '<').replace(
                                                '&gt;', '>')
                                        else:
                                            tmp_data[i] = html.escape(str(tmp_data[i]), quote=True)
                                    data.append(tmp_data)
                                except:
                                    c -= 1
                                    n -= 1
                                    pass
                            else:
                                c -= 1
                                n -= 1
                        buf = buf[:newline_pos]
                        n += 1
                        c += 1
                        break
                    else:
                        if pos == 0:
                            b = False
                            break
                        to_read = min(4096, pos)
                        fp.seek(-to_read, 1)
                        t_buf = fp.read(to_read)
                        if pythonV == 3: t_buf = t_buf.decode('utf-8', errors="ignore")
                        buf = t_buf + buf
                        fp.seek(-to_read, 1)
                        if pos - to_read == 0:
                            buf = "\n" + buf
                if not b: break
            fp.close()
            if 'drop_ip' in get:
                drop_iplist = self.get_waf_drop_ip(None)
                stime = time.time()
                setss = []
                for i in range(len(data)):
                    if (float(stime) - float(data[i][0])) < float(data[i][4]) and not data[i][1] in setss:
                        setss.append(data[i][1])
                        data[i].append(data[i][1] in drop_iplist)
                    else:
                        data[i].append(False)
        except:
            return public.get_error_info()
            data = []
        return data
    
    def get_logs_list(self,get):
        path = '/www/wwwlogs/free_waf_log/'
        sfind = get.siteName + '_'
        data = []
        for fname in os.listdir(path):
            if fname.find(sfind) != 0: continue;
            tmp = fname.replace(sfind,'').replace('.log','')
            data.append(tmp)
        return sorted(data,reverse=True);
    
    def get_waf_drop_ip(self,get):
        try:
            return json.loads(public.httpGet('http://127.0.0.1/get_btwaf_drop_ip'))
        except:
            return [];
    def remove_waf_drop_ip(self,get):
        return self.__unban_exact_ip(getattr(get, 'ip', ''))
    
    def clean_waf_drop_ip(self,get):
        try:
            removed = 0
            store = self.__ban_store()
            if store:
                removed = store.clear_exact_ips()
            else:
                raise RuntimeError('封禁存储不可用，未清理')
            self.__reload_panel_nginx()
            self.__verify_runtime_unban('clean_btwaf_drop_ip')
            self.__write_log('解除所有 IP 精确封禁，保留 IP 段规则')
            result = public.returnMsg(True, '所有 IP 精确封禁已解除；IP 段规则不受影响。')
            result['removed_persistent'] = removed
            return result
        except Exception:
            return public.returnMsg(False, '解封或生效检查失败，可能已部分处理，请检查后重试。')
        

    def __safe_text(self, value):
        return html.escape(str(value), quote=True)

    def __date_list(self, days):
        import datetime
        try:
            days = int(days)
        except:
            days = 7
        if days < 1:
            days = 1
        if days > 30:
            days = 30
        today = datetime.date.today()
        return [(today - datetime.timedelta(days=i)).strftime('%Y-%m-%d') for i in range(days)]

    def __read_recent_lines(self, path, limit):
        try:
            limit = int(limit)
        except:
            limit = 500
        if limit < 50:
            limit = 50
        if limit > 10000:
            limit = 10000
        try:
            lines = public.GetNumLines(path, limit)
            if type(lines) == str:
                return lines.splitlines()
            return lines or []
        except:
            pass
        try:
            with open(path, 'rb') as fp:
                fp.seek(0, os.SEEK_END)
                pos = fp.tell()
                data = b''
                while pos > 0 and data.count(b'\n') <= limit:
                    size = min(pos, 65536)
                    pos -= size
                    fp.seek(pos)
                    data = fp.read(size) + data
                return data.decode('utf-8', 'replace').splitlines()[-limit:]
        except OSError:
            return []

    def __iter_recent_window_lines(self, path, since_ts):
        rows = self.__iter_recent_window_rows(path, since_ts)
        try:
            for row in rows:
                yield row['raw']
        finally:
            rows.close()

    def __iter_recent_window_rows(self, path, since_ts, deadline=None):
        block_size = 1024 * 1024
        buffer = b''
        try:
            with open(path, 'rb') as fp:
                fp.seek(0, os.SEEK_END)
                pos = fp.tell()
                while pos > 0:
                    if deadline is not None and time.monotonic() > deadline:
                        raise RuntimeError('statistics time budget exceeded')
                    read_size = min(block_size, pos)
                    pos -= read_size
                    fp.seek(pos, os.SEEK_SET)
                    lines = (fp.read(read_size) + buffer).split(b'\n')
                    buffer = lines[0]
                    for raw in reversed(lines[1:]):
                        row = self.__parse_nginx_access_line(raw.decode('utf-8', 'ignore'))
                        if not row or not row.get('time_ts'):
                            continue
                        if row['time_ts'] < since_ts:
                            return
                        yield row
                if buffer:
                    row = self.__parse_nginx_access_line(buffer.decode('utf-8', 'ignore'))
                    if row and row.get('time_ts') and row['time_ts'] >= since_ts:
                        yield row
        except OSError:
            return

    def __parse_nginx_access_line(self, line):
        pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"'
        m = re.search(pattern, line)
        if not m:
            return None
        request = m.group(3)
        req_parts = request.split()
        method = req_parts[0] if len(req_parts) > 0 else ''
        uri = req_parts[1] if len(req_parts) > 1 else request
        protocol = req_parts[2] if len(req_parts) > 2 else ''
        try:
            bytes_sent = int(m.group(5))
        except:
            bytes_sent = 0
        time_text = m.group(2)
        time_ts = 0
        try:
            from datetime import datetime
            time_ts = datetime.strptime(time_text, '%d/%b/%Y:%H:%M:%S %z').timestamp()
        except:
            pass
        return {
            'ip': m.group(1),
            'time': time_text,
            'time_ts': time_ts,
            'method': method,
            'uri': uri,
            'protocol': protocol,
            'status': int(m.group(4)),
            'bytes': bytes_sent,
            'referer': m.group(6),
            'user_agent': m.group(7),
            'raw': line.strip()
        }

    def __parse_nginx_error_line(self, line):
        item = {
            'time': '',
            'level': '',
            'client': '',
            'server': '',
            'request': '',
            'raw': line.strip()
        }
        m = re.search(r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[([^\]]+)\]', line)
        if m:
            item['time'] = m.group(1)
            item['level'] = m.group(2)
        for key, field in [('client', 'client'), ('server', 'server'), ('request', 'request')]:
            m = re.search(field + r':\s*"?([^",]+)', line)
            if m:
                item[key] = m.group(1)
        return item

    def __parse_waf_log_row(self, row, site, date_str, line_no, raw_line):
        while len(row) < 7:
            row.append('')
        return {
            'time': self.__safe_text(row[0]),
            'ip': self.__safe_text(row[1]),
            'method': self.__safe_text(row[2]),
            'uri': self.__safe_text(row[3]),
            'user_agent': self.__safe_text(row[4]),
            'rule_type': self.__safe_text(row[5]),
            'rule': self.__safe_text(row[6]),
            'site': self.__safe_text(site),
            'date': self.__safe_text(date_str),
            'line_no': line_no,
            'raw': self.__safe_text(raw_line)
        }

    def __legacy_log_budget(self):
        return dict(partial=False, scanned_lines=0, scanned_bytes=0, scanned_files=0,
                    deadline=time.monotonic() + self.LEGACY_LOG_MAX_SECONDS,
                    scope='bounded_recent_logs')

    def __legacy_log_coverage(self, budget):
        return {key: value for key, value in budget.items() if key != 'deadline'}

    def __bounded_log_rows(self, path, budget):
        import stat
        if budget['scanned_files'] >= self.LEGACY_LOG_MAX_FILES:
            budget['partial'] = True
            return
        budget['scanned_files'] += 1
        try:
            with open(path, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    budget['partial'] = True
                    return
                stream.seek(0, os.SEEK_END)
                pos, buffer = stream.tell(), b''
                while pos > 0:
                    remaining = self.LEGACY_LOG_MAX_BYTES - budget['scanned_bytes']
                    if (remaining <= 0 or budget['scanned_lines'] >= self.LEGACY_LOG_MAX_LINES
                            or time.monotonic() > budget['deadline']):
                        budget['partial'] = True
                        return
                    size = min(pos, 65536, remaining)
                    pos -= size
                    stream.seek(pos)
                    block = stream.read(size)
                    budget['scanned_bytes'] += len(block)
                    if len(block) != size:
                        budget['partial'] = True
                        return
                    combined = block + buffer
                    pieces = combined.split(b'\n')
                    end = pos + len(combined)
                    buffer = pieces[0]
                    for piece in reversed(pieces[1:]):
                        end -= len(piece)
                        if piece:
                            if (budget['scanned_lines'] >= self.LEGACY_LOG_MAX_LINES
                                    or time.monotonic() > budget['deadline']):
                                budget['partial'] = True
                                return
                            budget['scanned_lines'] += 1
                            yield end, piece.decode('utf-8', 'replace')
                        end -= 1
                    if len(buffer) > 65536:
                        budget['partial'] = True
                        return
                if buffer:
                    if budget['scanned_lines'] >= self.LEGACY_LOG_MAX_LINES:
                        budget['partial'] = True
                        return
                    budget['scanned_lines'] += 1
                    yield 0, buffer.decode('utf-8', 'replace')
        except OSError:
            budget['partial'] = True

    def __bounded_legacy_lines(self, path, budget):
        for offset, line in self.__bounded_log_rows(path, budget):
            yield line

    def __bounded_waf_files(self, log_dir, dates, site_name, budget):
        candidates = []
        try:
            # The directory enumeration itself is bounded too.
            with os.scandir(log_dir) as entries:
                for number, entry in enumerate(entries):
                    if number >= 4096 or time.monotonic() > budget['deadline']:
                        budget['partial'] = True
                        break
                    name = entry.name
                    for date in dates:
                        suffix = '_' + date + '.log'
                        if name.endswith(suffix):
                            site = name[:-len(suffix)]
                            if (not site_name or site == site_name) and entry.is_file(follow_symlinks=False):
                                candidates.append((date, site, entry.path))
                            break
        except OSError:
            budget['partial'] = True
        candidates.sort(reverse=True)
        if len(candidates) > self.LEGACY_LOG_MAX_FILES:
            budget['partial'] = True
        return candidates[:self.LEGACY_LOG_MAX_FILES]

    def __merged_waf_rows(self, candidates, budget):
        # Sort the bounded sample itself: worker append order need not match event time.
        sample = []
        for date, site, path in candidates:
            for offset, raw in self.__bounded_log_rows(path, budget):
                try:
                    row = json.loads(raw)
                    if type(row) is list and len(row) >= 6 and type(row[0]) is str:
                        sample.append((row, offset, raw, site, date))
                except (ValueError, TypeError):
                    continue
        sample.sort(key=lambda item: (item[0][0], item[3], item[1]), reverse=True)
        yield from sample

    def get_report_search(self, get):
        """Search WAF request logs and return structured rows for manual review."""
        log_dir = '/www/wwwlogs/free_waf_log/'
        try:
            days = int(getattr(get, 'days', 7))
        except:
            days = 7
        try:
            p = int(getattr(get, 'p', 1))
        except:
            p = 1
        try:
            page_size = int(getattr(get, 'limit', 50))
        except:
            page_size = 50
        if p < 1:
            p = 1
        if page_size < 10:
            page_size = 10
        if page_size > 200:
            page_size = 200
        siteName = str(getattr(get, 'siteName', '') or '').strip()
        ip = str(getattr(get, 'ip', '') or '').strip()
        uri = str(getattr(get, 'uri', '') or '').strip().lower()
        ruleType = str(getattr(get, 'ruleType', '') or '').strip().lower()
        keyword = str(getattr(get, 'keyword', '') or '').strip().lower()
        escape_guard = html.escape('', quote=True)

        rows = []
        total = 0
        if not os.path.exists(log_dir):
            return {'rows': [], 'total': 0, 'p': p, 'limit': page_size, 'summary': {'matched': 0}}

        budget = self.__legacy_log_budget()
        files = self.__bounded_waf_files(log_dir, self.__date_list(days), siteName, budget)
        records = self.__merged_waf_rows(files, budget)
        has_more = False
        try:
            for row, offset, raw_line, site, matched_date in records:
                source_text = (' '.join(str(x) for x in row) + ' ' + site).lower()
                if ip and str(row[1]) != ip:
                    continue
                if uri and uri not in str(row[3]).lower():
                    continue
                if ruleType and ruleType != str(row[5]).lower():
                    continue
                if keyword and (keyword + escape_guard) not in (source_text + escape_guard):
                    continue
                total += 1
                if total <= (p - 1) * page_size:
                    continue
                if len(rows) >= page_size:
                    has_more = True
                    budget['partial'] = True
                    break
                item = self.__parse_waf_log_row(row, site, matched_date, 0, raw_line)
                item['offset'] = offset
                rows.append(item)
        finally:
            records.close()
        return dict(rows=rows, total=total, p=p, limit=page_size, has_more=has_more,
                    total_exact=not budget['partial'], coverage=self.__legacy_log_coverage(budget),
                    summary={'matched': total})

    def get_report_http_detail(self, get):
        """Return one structured WAF log row with raw JSON for the detail drawer."""
        log_dir = '/www/wwwlogs/free_waf_log/'
        siteName = str(getattr(get, 'siteName', '') or '').strip()
        date_str = str(getattr(get, 'date', '') or '').strip()
        try:
            line_no = int(getattr(get, 'line_no', 0))
        except:
            line_no = 0
        offset = getattr(get, 'offset', None)
        if (not re.fullmatch(r'[A-Za-z0-9_\-][A-Za-z0-9_.\-]{0,252}', siteName) or '..' in siteName
                or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date_str)
                or offset is None and line_no < 1):
            return public.returnMsg(False, '日志定位参数不完整')
        fpath = os.path.join(log_dir, siteName + '_' + date_str + '.log')
        if not os.path.exists(fpath):
            return public.returnMsg(False, '日志文件不存在')
        try:
            if offset is not None:
                offset = int(offset)
                if offset < 0:
                    raise ValueError('日志偏移不正确')
                with open(fpath, 'rb') as stream:
                    if offset >= os.fstat(stream.fileno()).st_size:
                        raise ValueError('日志已轮转')
                    if offset:
                        stream.seek(offset - 1)
                        if stream.read(1) != b'\n':
                            raise ValueError('日志位置已变化')
                    raw = stream.readline(65537)
                    if len(raw) > 65536:
                        raise ValueError('日志行超出预算')
                    raw_line = raw.decode('utf-8', 'replace').strip()
                    row = json.loads(raw_line)
                    if type(row) is not list or len(row) < 6:
                        raise ValueError('日志格式不正确')
                    return dict(status=True, data=self.__parse_waf_log_row(row, siteName, date_str, 0, raw_line),
                                raw=html.escape(raw_line, quote=True))
            if line_no > self.LEGACY_LOG_MAX_LINES:
                return public.returnMsg(False, '旧行号超出读取预算，请重新查询日志后查看详情')
            deadline, read_bytes = time.monotonic() + self.LEGACY_LOG_MAX_SECONDS, 0
            with open(fpath, 'rb') as stream:
                for current in range(1, line_no + 1):
                    remaining = self.LEGACY_LOG_MAX_BYTES - read_bytes
                    if remaining <= 0 or time.monotonic() > deadline:
                        raise ValueError('日志详情超出读取预算')
                    raw = stream.readline(min(65537, remaining + 1))
                    if not raw:
                        break
                    read_bytes += len(raw)
                    if len(raw) > 65536 or read_bytes > self.LEGACY_LOG_MAX_BYTES:
                        raise ValueError('日志行超出读取预算')
                    if current == line_no:
                        raw_line = raw.decode('utf-8', 'replace').strip()
                        row = json.loads(raw_line)
                        if type(row) is not list or len(row) < 6:
                            raise ValueError('日志格式不正确')
                        return dict(status=True, data=self.__parse_waf_log_row(
                            row, siteName, date_str, line_no, raw_line), raw=html.escape(raw_line, quote=True))
            return public.returnMsg(False, '日志记录不存在')
        except:
            return public.returnMsg(False, '日志详情读取失败')

    def __parse_drop_row(self, row, active_ips):
        while len(row) < 6:
            row.append('')
        try:
            start_ts = int(float(row[0]))
        except:
            start_ts = 0
        try:
            duration = int(float(row[4]))
        except:
            duration = 0
        ip = str(row[1])
        active = ip in active_ips and (duration <= 0 or int(time.time()) - start_ts < duration)
        reason = str(row[5])
        reason_text = 'CC攻击' if reason == 'cc' else ('黑名单' if reason == 'ip_black' else ('人工临时封禁' if reason == 'manual_temp' else '恶意请求'))
        return {
            'start_time': start_ts,
            'start_time_text': self.__safe_text(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_ts))) if start_ts else '',
            'ip': self.__safe_text(ip),
            'site': self.__safe_text(row[2]),
            'uri': self.__safe_text(row[3]),
            'duration': duration,
            'reason': self.__safe_text(reason),
            'reason_text': reason_text,
            'active': active
        }

    def get_blockade_records(self, get):
        """Return current and historical blockade records for manual audit."""
        path = '/www/server/free_waf/drop_ip.log'
        try:
            p = int(getattr(get, 'p', 1))
        except:
            p = 1
        try:
            page_size = int(getattr(get, 'limit', 100))
        except:
            page_size = 100
        if p < 1:
            p = 1
        if page_size < 10:
            page_size = 10
        if page_size > 500:
            page_size = 500
        active_data = self.get_waf_drop_ip(None)
        if type(active_data) == dict:
            active_ips = set(active_data.keys())
        else:
            active_ips = set(active_data or [])
        records = []
        budget = self.__legacy_log_budget()
        if os.path.exists(path):
            try:
                fp = self.__bounded_legacy_lines(path, budget)
                for line in fp:
                    raw_line = line.strip()
                    if not raw_line:
                        continue
                    try:
                        row = json.loads(raw_line)
                        records.append(self.__parse_drop_row(row, active_ips))
                    except:
                        pass
                fp.close()
            except:
                pass
        records = sorted(records, key=lambda x: x.get('start_time', 0), reverse=True)
        total = len(records)
        start = (p - 1) * page_size
        end = start + page_size
        return {
            'rows': records[start:end],
            'total': total,
            'p': p,
            'limit': page_size,
            'coverage': self.__legacy_log_coverage(budget),
            'total_exact': not budget['partial'],
            'active_ips': sorted(list(active_ips))
        }

    def export_blockade_records(self, get):
        """Export blockade records as JSON data for operator download."""
        path = '/www/server/free_waf/drop_ip.log'
        active_data = self.get_waf_drop_ip(None)
        data = self.get_blockade_records(get)
        return {
            'exported_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'active_ips': data.get('active_ips', sorted(list(active_data.keys())) if type(active_data) == dict else active_data),
            'records': data.get('rows', []),
            'total': data.get('total', 0),
            'coverage': data.get('coverage', {}),
            'total_exact': data.get('total_exact', False),
            'source': path
        }

    def get_overview_report(self, get):
        """Aggregate dashboard trend, top sites, dynamics, rules and country geography."""
        import collections, heapq
        # Assigned ISO 3166-1 codes, matching waf_dashboard.codes without a frontend dependency.
        iso_country_codes = frozenset((
            'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ '
            'CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET '
            'FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU '
            'ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY '
            'MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ '
            'OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ '
            'TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'
        ).split())
        log_dir = '/www/wwwlogs/free_waf_log/'
        drop_path = '/www/server/free_waf/drop_ip.log'
        dates = self.__date_list(7)
        trend_map = dict([(d, 0) for d in dates])
        site_counter = collections.Counter()
        today_site_counter = collections.Counter()
        rule_counter = collections.Counter()
        ip_counter = collections.Counter()
        attack_region_counter = collections.Counter()
        dynamics = []
        dynamics_sequence = 0
        total_protection = 0
        protection_24h = 0
        cc_protection = 0
        today_str = time.strftime('%Y-%m-%d', time.localtime())
        day_ago = time.time() - 86400
        first_seen_ts = 0
        active_data = self.get_waf_drop_ip(None)
        active_ips = set(active_data.keys()) if isinstance(active_data, dict) else set(active_data or [])
        active_count = len(active_ips)
        _geo = None
        _geo_cache = {}
        _geo_type = None
        budget = self.__legacy_log_budget()
        try:
            _geo_type = self.__local_service('website_statistics').LocalGeography
        except Exception:
            pass
        try:
            import maxminddb
            _geo = maxminddb.open_database('/www/server/panel/config/GeoLite2-City.mmdb')
        except:
            pass
        if os.path.exists(log_dir):
            for matched_date, site, fpath in self.__bounded_waf_files(log_dir, dates, '', budget):
                try:
                    fp = self.__bounded_legacy_lines(fpath, budget)
                    line_no = 0
                    for line in fp:
                        line_no += 1
                        raw_line = line.strip()
                        if not raw_line:
                            continue
                        try:
                            row = json.loads(raw_line)
                        except:
                            continue
                        if not isinstance(row, list) or len(row) < 6:
                            continue
                        trend_map[matched_date] = trend_map.get(matched_date, 0) + 1
                        total_protection += 1
                        site_counter[site] += 1
                        if matched_date == today_str:
                            today_site_counter[site] += 1
                        rule_type = str(row[5])
                        rule_counter[rule_type] += 1
                        if rule_type.lower() == 'cc':
                            cc_protection += 1
                        ip = str(row[1])
                        ip_counter[ip] += 1
                        if ip in _geo_cache:
                            region = _geo_cache[ip][0]
                        else:
                            region = '未知来源'
                            country_code = ''
                            country_name = ''
                            gd = None
                            geo_failed = False
                            if _geo:
                                try:
                                    gd = _geo.get(ip)
                                    if isinstance(gd, dict) and isinstance(gd.get('country'), dict):
                                        c = gd['country']
                                        code = c.get('iso_code') or c.get('en_short_code')
                                        if (isinstance(code, str) and re.fullmatch(r'[A-Za-z]{2}', code)
                                                and code.upper() in iso_country_codes):
                                            country_code = code.upper()
                                            names = c.get('names')
                                            if not isinstance(names, dict):
                                                names = {}
                                            country_name = next((name for name in [
                                                c.get('country'), names.get('en'), names.get('zh-CN')
                                            ] if isinstance(name, str) and name), country_code)
                                        region_parts = [x for x in [c.get('country',''), c.get('province',''), c.get('city','')] if x]
                                        if region_parts:
                                            region = ' '.join(region_parts)
                                except Exception:
                                    geo_failed = True
                            detail = _geo_type.describe(ip, gd) if _geo_type else dict(location='未知', status='unavailable')
                            if detail['status'] == 'unknown':
                                if _geo is None:
                                    detail['status'] = 'unavailable'
                                elif geo_failed:
                                    detail['status'] = 'lookup_error'
                            _geo_cache[ip] = (region, country_code, country_name, detail)
                        attack_region_counter[region] += 1
                        try:
                            row_ts = time.mktime(time.strptime(str(row[0])[:19], '%Y-%m-%d %H:%M:%S'))
                        except:
                            row_ts = 0
                        if row_ts:
                            if not first_seen_ts or row_ts < first_seen_ts:
                                first_seen_ts = row_ts
                            if row_ts >= day_ago:
                                protection_24h += 1
                        elif matched_date == today_str:
                            protection_24h += 1
                        dynamics_sequence += 1
                        if len(dynamics) < 20 or row_ts > dynamics[0][0]:
                            item = {
                                'time': self.__safe_text(row[0]),
                                'site': self.__safe_text(site),
                                'ip': self.__safe_text(ip),
                                'uri': self.__safe_text(row[3]),
                                'rule_type': self.__safe_text(rule_type)
                            }
                            candidate = (row_ts, dynamics_sequence, item)
                            if len(dynamics) < 20:
                                heapq.heappush(dynamics, candidate)
                            else:
                                heapq.heapreplace(dynamics, candidate)
                    fp.close()
                except:
                    pass
        dynamics = [item[2] for item in sorted(dynamics, reverse=True)]
        trend = [{'date': d, 'count': trend_map.get(d, 0)} for d in sorted(dates)]
        top_sites = [{'site': self.__safe_text(k), 'count': v} for k, v in site_counter.most_common(5)]
        today_top_sites = [{'site': self.__safe_text(k), 'count': v} for k, v in today_site_counter.most_common(5)]
        top_rules = [{'rule_type': self.__safe_text(k), 'count': v} for k, v in rule_counter.most_common(8)]
        attack_regions = [{'region': self.__safe_text(k), 'count': v} for k, v in attack_region_counter.most_common(8)]
        country_counter = collections.Counter()
        country_names = {}
        # Reuse per-IP totals and cached metadata; unknown hits stay in the denominator.
        for ip, count in ip_counter.items():
            _, code, name = _geo_cache.get(ip, ('', '', ''))[:3]
            if code:
                country_counter[code] += count
                country_names.setdefault(code, name)
        located = sum(country_counter.values())
        attack_geography = {
            'countries': [
                {'code': code, 'name': self.__safe_text(country_names[code]), 'count': count}
                for code, count in country_counter.most_common()
            ],
            'total': total_protection,
            'located': located,
            'unlocated': total_protection - located,
            'database_available': _geo is not None,
            'period_days': 7
        }
        blocked_map = {}
        if os.path.exists(drop_path):
            try:
                fp = self.__bounded_legacy_lines(drop_path, budget)
                for line in fp:
                    raw_line = line.strip()
                    if not raw_line:
                        continue
                    try:
                        row = json.loads(raw_line)
                    except:
                        continue
                    if type(row) != list or len(row) < 6:
                        continue
                    ip = str(row[1])
                    if ip not in blocked_map:
                        blocked_map[ip] = {
                            'ip': self.__safe_text(ip),
                            'count_24h': 0,
                            'total_count': 0,
                            'last_time': '',
                            'reason': '',
                            'active': ip in active_ips
                        }
                    blocked_map[ip]['total_count'] += 1
                    try:
                        row_ts = int(float(row[0]))
                    except:
                        row_ts = 0
                    if row_ts >= day_ago:
                        blocked_map[ip]['count_24h'] += 1
                    if row_ts and (not blocked_map[ip]['last_time'] or row_ts > int(float(blocked_map[ip].get('_last_ts', 0) or 0))):
                        blocked_map[ip]['_last_ts'] = row_ts
                        blocked_map[ip]['last_time'] = self.__safe_text(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row_ts)))
                        blocked_map[ip]['reason'] = self.__safe_text(row[5])
                    blocked_map[ip]['active'] = blocked_map[ip]['active'] or ip in active_ips
                fp.close()
            except:
                pass
        for ip in active_ips:
            if ip not in blocked_map:
                blocked_map[ip] = {
                    'ip': self.__safe_text(ip),
                    'count_24h': 0,
                    'total_count': 0,
                    'last_time': '',
                    'reason': '运行中',
                    'active': True
                }
        blocked_ips = sorted(blocked_map.values(), key=lambda x: (0 if x.get('active') else 1, -int(x.get('count_24h', 0)), x.get('ip', '')))[:10]
        try:
            for item in blocked_ips:
                item.pop('_last_ts', None)
                ip = item['ip']
                if ip in _geo_cache:
                    detail = _geo_cache[ip][3]
                else:
                    detail = _geo_type.describe(ip, None) if _geo_type else dict(location='未知', status='unavailable')
                    if detail['status'] == 'unknown':
                        if _geo:
                            try:
                                detail = _geo_type.describe(ip, _geo.get(ip))
                            except Exception:
                                detail = dict(location='未知', status='lookup_error')
                        else:
                            detail['status'] = 'unavailable'
                item['location'] = detail['location']
                item['location_status'] = detail['status']
        finally:
            if _geo:
                try:
                    _geo.close()
                except Exception:
                    pass
        protection_days = len([x for x in trend if x.get('count', 0) > 0])
        if not protection_days and first_seen_ts:
            protection_days = max(1, int((time.time() - first_seen_ts) / 86400) + 1)
        summary = {
            'total_protection': total_protection,
            'protection_24h': protection_24h,
            'cc_protection': cc_protection,
            'protection_days': protection_days,
            'active_bans': active_count
        }
        return {
            'summary': summary,
            'trend': trend,
            'coverage': self.__legacy_log_coverage(budget),
            'top_sites': top_sites,
            'today_top_sites': today_top_sites,
            'dynamics': dynamics,
            'top_rules': top_rules,
            'blocked_ips': blocked_ips,
            'attack_regions': attack_regions,
            'attack_geography': attack_geography,
            'active_bans': active_count,
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        }

    def __notification_level(self, rule_type):
        rule_type = str(rule_type)
        if rule_type in ['cc', 'ip_black', 'post', 'args']:
            return 'high', '高'
        if rule_type in ['header', 'cookie', 'url', 'url_black', 'url_rule', 'url_tell']:
            return 'medium', '中'
        return 'low', '低'

    def get_defense_notifications(self, get):
        """Read-only notification center data from WAF logs and blockade logs."""
        log_dir = '/www/wwwlogs/free_waf_log/'
        drop_path = '/www/server/free_waf/drop_ip.log'
        try:
            days = int(getattr(get, 'days', 7))
        except:
            days = 7
        try:
            limit = int(getattr(get, 'limit', 80))
        except:
            limit = 80
        if limit < 10:
            limit = 10
        if limit > 200:
            limit = 200
        dates = self.__date_list(days)
        items = []
        summary = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        budget = self.__legacy_log_budget()
        records = self.__merged_waf_rows(self.__bounded_waf_files(log_dir, dates, '', budget), budget)
        try:
            for row, offset, raw, site, date in records:
                level, level_text = self.__notification_level(row[5])
                items.append(dict(time=self.__safe_text(row[0]), level=level, level_text=level_text,
                                  site=self.__safe_text(site), ip=self.__safe_text(row[1]),
                                  uri=self.__safe_text(row[3]), rule_type=self.__safe_text(row[5]),
                                  message=self.__safe_text('请求触发 WAF 规则：' + str(row[5]))))
                if len(items) > limit:
                    budget['partial'] = True
                    break
        finally:
            records.close()
        if os.path.exists(drop_path):
            for offset, raw in self.__bounded_log_rows(drop_path, budget):
                try:
                    row = json.loads(raw)
                    if type(row) is not list or len(row) < 6:
                        continue
                    text = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(float(row[0]))))
                    if text[:10] not in dates:
                        continue
                    items.append(dict(time=self.__safe_text(text), level='high', level_text='高',
                                      site=self.__safe_text(row[2]), ip=self.__safe_text(row[1]),
                                      uri=self.__safe_text(row[3]), rule_type=self.__safe_text(row[5]),
                                      message=self.__safe_text('封禁记录：' + str(row[5]))))
                except (ValueError, TypeError, OverflowError):
                    continue
        items = sorted(items, key=lambda x: x.get('time', ''), reverse=True)[:limit]
        for item in items:
            summary[item['level']] += 1
            summary['total'] += 1
        return {
            'status': True,
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'summary': summary,
            'summary_scope': 'returned_items',
            'coverage': self.__legacy_log_coverage(budget),
            'items': items
        }

    def __rule_item_parts(self, item):
        if isinstance(item, list):
            if len(item) >= 2:
                enabled = bool(item[0])
                pattern = str(item[1])
                reason = str(item[2]) if len(item) >= 3 else ''
                return enabled, pattern, reason
            return False, '', ''
        return True, str(item), ''

    def __simulate_rule_match(self, rule_name, target, rule_title, matched, action):
        rules = self.__get_rule(rule_name) or []
        for item in rules:
            enabled, pattern, reason = self.__rule_item_parts(item)
            if not enabled or not pattern:
                continue
            try:
                if re.search(pattern, target, re.I):
                    matched.append({
                        'rule_name': rule_title,
                        'pattern': self.__safe_text(pattern),
                        'reason': self.__safe_text(reason),
                        'action': action
                    })
                    return True
            except:
                matched.append({
                    'rule_name': rule_title,
                    'pattern': self.__safe_text(pattern),
                    'reason': '正则表达式无法解析',
                    'action': 'warn'
                })
        return False

    def simulate_attack(self, get):
        """Dry-run local rule simulation. It never sends traffic or writes rules."""
        uri = str(getattr(get, 'uri', '') or '/')
        method = str(getattr(get, 'method', '') or 'GET').upper()
        user_agent = str(getattr(get, 'user_agent', '') or '')
        args = str(getattr(get, 'args', '') or '')
        post = str(getattr(get, 'post', '') or '')
        cookie = str(getattr(get, 'cookie', '') or '')
        header = str(getattr(get, 'header', '') or '')
        matched = []
        notes = ['本次为 dry_run 本地规则演练，不发送真实请求，不写入黑名单。']

        if self.__simulate_rule_match('url_white', uri, 'URL白名单', matched, 'allow'):
            return {
                'status': True,
                'dry_run': True,
                'decision': 'allow',
                'decision_text': '放行',
                'method': self.__safe_text(method),
                'uri': self.__safe_text(uri),
                'matched': matched,
                'notes': notes + ['命中 URL 白名单，攻击规则不会继续作为拦截依据。']
            }
        if self.__simulate_rule_match('user_agent_white', user_agent, 'UA白名单', matched, 'allow'):
            return {
                'status': True,
                'dry_run': True,
                'decision': 'allow',
                'decision_text': '放行',
                'method': self.__safe_text(method),
                'uri': self.__safe_text(uri),
                'matched': matched,
                'notes': notes + ['命中 UA 白名单，UA 黑名单不会继续作为拦截依据。']
            }

        block_checks = [
            ('url_black', uri, 'URL黑名单'),
            ('user_agent', user_agent, 'UA黑名单'),
            ('header', header, 'Header规则'),
            ('cookie', cookie, 'Cookie规则'),
            ('args', args, 'GET参数规则'),
            ('post', post, 'POST规则')
        ]
        for rule_name, target, title in block_checks:
            self.__simulate_rule_match(rule_name, target, title, matched, 'block')

        builtin_body = '\n'.join([uri, args, post, cookie, header])
        builtin_checks = [
            (r'(^|/)\.env($|[\s/?._-])', '环境文件探测'),
            (r'(^|/)\.git($|[\s/])', 'Git目录探测'),
            (r'(?i)(union\s+select|select\s+.+\s+from|or\s+1\s*=\s*1)', 'SQL注入特征'),
            (r'(?i)(<script|javascript:|onerror\s*=)', 'XSS特征'),
            (r'(?i)(/wp-admin|/xmlrpc\.php|phpmyadmin|wp_filemanager)', '常见扫描路径')
        ]
        for pattern, reason in builtin_checks:
            try:
                if re.search(pattern, builtin_body, re.I):
                    matched.append({
                        'rule_name': '内置基础检测',
                        'pattern': self.__safe_text(pattern),
                        'reason': reason,
                        'action': 'block'
                    })
            except:
                pass

        decision = 'block' if [x for x in matched if x.get('action') == 'block'] else 'pass'
        return {
            'status': True,
            'dry_run': True,
            'decision': decision,
            'decision_text': '拦截' if decision == 'block' else '未命中拦截规则',
            'method': self.__safe_text(method),
            'uri': self.__safe_text(uri),
            'matched': matched,
            'notes': notes + ['模拟结果只用于人工判断，不会触发 CC 计数或 IP 封禁。']
        }


    def get_report_dashboard_summary(self, get):
        """Read-only report dashboard summary from free_waf_log request records."""
        import collections
        log_dir = '/www/wwwlogs/free_waf_log/'
        try:
            days = int(getattr(get, 'days', 7))
        except:
            days = 7
        if days < 1:
            days = 1
        if days > 30:
            days = 30
        date_set = set(self.__date_list(days))
        total_hits = 0
        unique_ips = set()
        unique_uris = set()
        rule_counter = collections.Counter()
        site_counter = collections.Counter()
        ip_counter = collections.Counter()
        uri_counter = collections.Counter()
        budget = self.__legacy_log_budget()
        if os.path.exists(log_dir):
            for matched_date, site, fpath in self.__bounded_waf_files(log_dir, date_set, '', budget):
                try:
                    fp = self.__bounded_legacy_lines(fpath, budget)
                    for line in fp:
                        raw_line = line.strip()
                        if not raw_line:
                            continue
                        try:
                            row = json.loads(raw_line)
                        except:
                            continue
                        if type(row) != list or len(row) < 6:
                            continue
                        ip = str(row[1])
                        uri = str(row[3])
                        rule_type = str(row[5])
                        total_hits += 1
                        unique_ips.add(ip)
                        if uri:
                            unique_uris.add(uri)
                        rule_counter[rule_type] += 1
                        site_counter[site] += 1
                        ip_counter[ip] += 1
                        if uri:
                            uri_counter[uri] += 1
                    fp.close()
                except:
                    pass
        active_data = self.get_waf_drop_ip(None)
        active_bans = len(active_data.keys()) if type(active_data) == dict else len(active_data or [])
        return {
            'status': True,
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'coverage': self.__legacy_log_coverage(budget),
            'summary': {
                'days': days,
                'total_hits': total_hits,
                'unique_ips': len(unique_ips),
                'unique_uris': len(unique_uris),
                'active_bans': active_bans
            },
            'top_rules': [{'rule_type': self.__safe_text(k), 'count': v} for k, v in rule_counter.most_common(8)],
            'top_sites': [{'site': self.__safe_text(k), 'count': v} for k, v in site_counter.most_common(8)],
            'top_ips': [{'ip': self.__safe_text(k), 'count': v} for k, v in ip_counter.most_common(8)],
            'top_uris': [{'uri': self.__safe_text(k), 'count': v} for k, v in uri_counter.most_common(8)]
        }

    def get_website_statistics_summary(self, get):
        from types import SimpleNamespace
        try:
            days = max(1, min(30, int(getattr(get, 'days', 7))))
            line_limit = max(100, min(5000, int(getattr(get, 'line_limit', 800))))
        except (TypeError, ValueError):
            return public.returnMsg(False, '统计参数不正确')
        site_name = str(getattr(get, 'siteName', '') or '').strip()
        if site_name and (len(site_name) > 255 or site_name in ('.', '..')
                          or not re.fullmatch(r'[\w.\[\]:-]+', site_name)):
            return public.returnMsg(False, '站点筛选参数不正确')
        params = SimpleNamespace(days=days, line_limit=line_limit, siteName=site_name)
        key = json.dumps(['website-statistics-v3-geography', time.strftime('%Y-%m-%d'), site_name, days, line_limit], ensure_ascii=False)
        force = str(getattr(get, 'force', '')).lower() in ('1', 'true')
        result = website_reports.request(key, lambda: self.__build_website_statistics_summary(params), force=force)
        if 'site_options' not in result:
            result['site_options'] = self.__statistics_service().discover_sites()
        return result

    def __statistics_log_files(self):
        access_logs, error_logs, site_options = [], [], set()
        try:
            with os.scandir(self.__access_log_path) as entries:
                for entry in entries:
                    if not entry.name.endswith('.log') or not entry.is_file():
                        continue
                    if entry.name.endswith('.error.log') or entry.name == 'nginx_error.log':
                        error_logs.append(entry.path)
                        site = entry.name.replace('.error.log', '').replace('.ssl', '')
                        if site != 'nginx_error.log':
                            site_options.add(site)
                    else:
                        access_logs.append(entry.path)
                        site = entry.name[:-4]
                        site_options.add(site[:-4] if site.endswith('.ssl') else site)
        except OSError:
            pass
        return sorted(access_logs), sorted(error_logs), [
            {'site': self.__safe_text(site)} for site in sorted(site_options) if site
        ]

    def __build_website_statistics_summary(self, get):
        """Build a read-only report; no WAF policy or Nginx changes occur here."""
        return self.__statistics_service().build(
            days=getattr(get, 'days', 7),
            site_name=str(getattr(get, 'siteName', '') or '').strip(),
            line_limit=getattr(get, 'line_limit', 800),
        )


    def get_ip_stats(self, get):
        """解析 WAF 攻击日志，返回 Top 50 攻击 IP"""
        import collections, datetime
        try:
            days = int(getattr(get, 'days', 7))
        except:
            days = 7
        log_dir = '/www/wwwlogs/free_waf_log/'
        ip_counts  = collections.Counter()
        ip_details = {}
        budget = self.__legacy_log_budget()
        for date, site, fpath in self.__bounded_waf_files(log_dir, self.__date_list(days), '', budget):
            for offset, line in self.__bounded_log_rows(fpath, budget):
                try:
                    row = json.loads(line)
                    if type(row) is not list or len(row) < 6:
                        continue
                    ip, rule_type = str(row[1]), str(row[5])
                    ip_counts[ip] += 1
                    if ip not in ip_details:
                        ip_details[ip] = {'count': 0, 'types': {}, 'last_time': '', 'sites': set()}
                    detail = ip_details[ip]
                    detail['count'] += 1
                    detail['last_time'] = max(detail['last_time'], str(row[0]))
                    detail['sites'].add(site)
                    detail['types'][rule_type] = detail['types'].get(rule_type, 0) + 1
                except (ValueError, TypeError):
                    continue
        store = self.__ban_store()
        if store:
            banned_set = set(store.active_exact_ips())
        else:
            iplist = self.__get_rule('ip_black') or []
            banned_set = set()
            now = time.time()
            for item in iplist:
                try:
                    if len(item) >= 3 and now > int(item[2]):
                        continue
                    if len(item) >= 2 and item[0] == item[1]:
                        banned_set.add('.'.join(map(str, item[0])))
                except:
                    pass
        # IP geolocation via BT Panel GeoLite2 DB
        _geo = None
        try:
            import maxminddb
            _geo = maxminddb.open_database('/www/server/panel/config/GeoLite2-City.mmdb')
        except:
            pass
        result = []
        for ip, count in ip_counts.most_common(50):
            detail = ip_details[ip]
            location = ''
            if _geo:
                try:
                    gd = _geo.get(ip)
                    if gd and 'country' in gd:
                        c = gd['country']
                        parts = [x for x in [c.get('country',''), c.get('province',''), c.get('city','')] if x]
                        location = ' '.join(parts)
                except:
                    pass
            result.append({
                'ip':        ip,
                'count':     count,
                'last_time': detail['last_time'],
                'types':     detail['types'],
                'sites':     list(detail['sites']),
                'is_banned': ip in banned_set,
                'location':  location
            })
        if _geo:
            try: _geo.close()
            except: pass
        if str(getattr(get, 'include_coverage', '')) == '1':
            return dict(rows=result, coverage=self.__legacy_log_coverage(budget))
        return result

    def get_uri_stats(self, get):
        """解析 WAF 攻击日志，返回 Top 100 URI 触发统计。"""
        import collections, datetime
        try:
            days = int(getattr(get, 'days', 7))
        except:
            days = 7
        if days < 1:
            days = 1
        if days > 30:
            days = 30
        log_dir = '/www/wwwlogs/free_waf_log/'
        uri_counts = collections.Counter()
        uri_details = {}
        budget = self.__legacy_log_budget()
        for date, site, fpath in self.__bounded_waf_files(log_dir, self.__date_list(days), '', budget):
            for offset, line in self.__bounded_log_rows(fpath, budget):
                try:
                    row = json.loads(line)
                    if type(row) is not list or len(row) < 6:
                        continue
                    uri, rule_type = str(row[3]).strip(), str(row[5]).strip() or 'unknown'
                    if not uri:
                        continue
                    uri_counts[uri] += 1
                    if uri not in uri_details:
                        uri_details[uri] = {'count': 0, 'types': {}, 'last_time': '', 'sites': set()}
                    detail = uri_details[uri]
                    detail['count'] += 1
                    detail['last_time'] = max(detail['last_time'], str(row[0]))
                    detail['sites'].add(site)
                    detail['types'][rule_type] = detail['types'].get(rule_type, 0) + 1
                except (ValueError, TypeError):
                    continue
        result = []
        for uri, count in uri_counts.most_common(100):
            detail = uri_details[uri]
            result.append({
                'uri': uri,
                'count': count,
                'last_time': detail['last_time'],
                'types': detail['types'],
                'sites': sorted(list(detail['sites']))
            })
        if str(getattr(get, 'include_coverage', '')) == '1':
            return dict(rows=result, coverage=self.__legacy_log_coverage(budget))
        return result

    def add_permanent_ban(self, get):
        """单个 IP 封禁 8 小时（写入 ip_black.json + nginx shared memory）"""
        ip = getattr(get, 'ip', '').strip()
        try:
            ipn = list(map(int, ip.split('.')))
            if len(ipn) != 4 or any(v < 0 or v > 255 for v in ipn):
                return public.returnMsg(False, 'IP 格式错误')
        except:
            return public.returnMsg(False, 'IP 格式错误')
        try:
            store = self.__ban_store()
            if store:
                added = store.add_temp_ban(ip, TEMP_BAN_SECONDS, reason='manual_temp')
                if not added:
                    return public.returnMsg(False, ip + ' 已在黑名单中')
                self.__reload_panel_nginx()
            else:
                raise RuntimeError('封禁存储不可用')
        except Exception:
            return public.returnMsg(False, '封禁写入或生效未确认，可能已部分处理，请检查后重试')
        self.__write_drop_ip_entry(ip, drop_time=TEMP_BAN_SECONDS, reason='manual_temp')
        # 同时通知 nginx shared memory
        try:
            public.httpGet('http://127.0.0.1/get_btwaf_drop_ip')
        except:
            pass
        self.__write_log('封禁 IP [ ' + ip + ' ] 8小时')
        return public.returnMsg(True, ip + ' 已封禁 8 小时')

    def remove_permanent_ban(self, get):
        """解除单个 IP 的封禁"""
        return self.__unban_exact_ip(getattr(get, 'ip', ''))

    def get_permanent_ban_list(self, get):
        """获取 ip_black.json 中所有精确 IP（非段）"""
        return self.get_ip_black_exact(get)

    def sync_rule(self, get):
        """兼容前端规则同步按钮；免费版没有可靠的云规则源，保留本地规则。"""
        try:
            self.sync_cnlist(None)
        except:
            pass
        return public.returnMsg(True, '规则同步检查完成：本地规则已保留，国内 IP 库已尝试同步。')

    def get_gl_logs(self, get):
        import page
        page = page.Page();
        count = public.M('logs').where('type IN (?,?,?)', self.__log_types).count();
        limit = 12;
        info = {}
        info['count'] = count
        info['row'] = limit
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = get
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs

        data = {}

        # 获取分页数据
        data['page'] = page.GetPage(info, '1,2,3,4,5,8');
        data['data'] = public.M('logs').where('type IN (?,?,?)', self.__log_types).order('id desc').limit(
            str(page.SHIFT) + ',' + str(page.ROW)).field('log,addtime').select();
        return data;

            
    def __total_path(self):
        migrated = os.path.join(self.__path, '.statistics', 'total.json')
        # A present but damaged new snapshot must never resurrect stale totals.
        return migrated if os.path.lexists(migrated) else self.__path + 'total.json'

    def get_total(self,get):
        try:
            total = json.loads(public.readFile(self.__total_path()))
            if not isinstance(total, dict) or not isinstance(total.get('sites'), dict):
                raise ValueError('invalid totals')
        except:
            total = {"rules":{"user_agent":0,"cookie":0,"post":0,"args":0,"url":0,"cc":0},"sites":{},"total":0}
        if not isinstance(total.get('rules'), dict):
            new_rules = {}
            for rule in total.get('rules', []):
                if isinstance(rule, dict) and 'key' in rule and 'value' in rule:
                    new_rules[rule['key']] = rule['value'];
            total['rules'] = new_rules;
        total['rules'] = self.__format_total(total['rules'])
        return total;
    
    def __format_total(self,total):
        total = total.copy()
        total['get'] = total.get('get', 0) if 'args' not in total and 'url' not in total else 0
        if 'args' in total:
            total['get'] += total['args'];
            del(total['args'])
        if 'url' in total:
            total['get'] += total['url'];
            del(total['url'])
        cnkey = [
                 ['post',u'POST渗透'],
                 ['get',u'GET渗透'],
                 ['cc',u'CC攻击'],
                 ['user_agent',u'恶意UA'],
                 ['cookie',u'Cookie渗透'],
                 ['scan',u'恶意扫描'],
                 ['head',u'恶意HEAD请求'],
                 ['url_rule',u'URI自定义拦截'],
                 ['url_tell',u'URI加密保护'],
                 ['disable_upload_ext',u'恶意文件上传'],
                 ['disable_ext',u'禁止扩展名'],
                 ['disable_php_path',u'禁止PHP脚本']
                 ]
        data = []
        for ck in cnkey:
            tmp = {}
            tmp['name'] = ck[1]
            tmp['key'] = ck[0]
            tmp['value'] = 0;
            if ck[0] in total: tmp['value'] = total[ck[0]]
            data.append(tmp)
        return data
    
    def get_total_all(self,get):
        data = {}
        data['total'] = self.get_total(None)
        del(data['total']['sites'])
        data['drop_ip'] = []
        conf = self.get_config(None)
        data['open'] = conf['open']
        data['runtime_status'] = {'integration': 'unverified', 'execution_verified': False}
        data['safe_day'] = 0
        if 'start_time' in conf:
            if conf['start_time'] != 0: data['safe_day'] = int((time.time() - conf['start_time']) / 86400)
        return data

    def __read_nginx_configuration(self):
        """Bound a manual config inspection; never reload or expose its output."""
        import selectors
        import subprocess
        process = subprocess.Popen(
            ['/www/server/nginx/sbin/nginx', '-T', '-p', '/www/server/nginx/',
             '-c', '/www/server/nginx/conf/nginx.conf'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
            shell=False, close_fds=True)
        deadline = time.monotonic() + 5
        chunks, size = [], 0
        try:
            with selectors.DefaultSelector() as poller:
                poller.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError('nginx_timeout')
                    if not poller.select(remaining):
                        raise RuntimeError('nginx_timeout')
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 2 * 1024 * 1024:
                        raise RuntimeError('nginx_output_limit')
                    chunks.append(chunk)
            try:
                code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise RuntimeError('nginx_timeout') from None
            if code != 0:
                raise RuntimeError('nginx_check_failed')
            return b''.join(chunks).decode('utf-8')
        finally:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            finally:
                process.stdout.close()

    def __nginx_directives(self, body):
        # Preserve quoted delimiters and skip Lua bodies rather than lexing Lua as shell.
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

    def __nginx_integration(self, body):
        statements = self.__nginx_directives(body)
        keys = ('init_by_lua_file', 'access_by_lua_file', 'lua_shared_dict')
        entries = [row for row in statements if row[0] in keys]
        dictionaries = ('free_waf', 'free_waf_drop_ip', 'free_waf_drop_sum')
        relevant = any(any('/www/server/free_waf/' in value for value in row[1:])
                       or row[0] == 'lua_shared_dict' and len(row) > 1 and row[1] in dictionaries
                       for row in entries)
        if not relevant:
            return 'missing'
        for key, path in (('init_by_lua_file', '/www/server/free_waf/init.lua'),
                          ('access_by_lua_file', '/www/server/free_waf/waf.lua')):
            if [row[1:] for row in entries if row[0] == key] != [[path]]:
                return 'incomplete'
        for name in dictionaries:
            rows = [row for row in entries if row[0] == 'lua_shared_dict' and len(row) > 1 and row[1] == name]
            if len(rows) != 1 or len(rows[0]) != 3:
                return 'incomplete'
        return 'configured'

    def __integration_service(self):
        return self.__local_service('update_service').IntegrationRepairService(
            self.__PATH, read_configuration=self.__read_nginx_configuration,
            directives=self.__nginx_directives)

    def get_integration_repair_plan(self, get):
        try:
            return self.__integration_service().preview()
        except Exception:
            return public.returnMsg(False, '无法准备接入修复，请检查既有安装；没有修改配置。')

    def repair_nginx_integration(self, get):
        if not self.__update_request_is_post():
            return public.returnMsg(False, '接入修复仅接受面板确认后的 POST 请求。')
        try:
            return self.__integration_service().repair(
                getattr(get, 'revision', ''), getattr(get, 'confirmation', ''))
        except Exception:
            return public.returnMsg(False, '接入修复状态未确认，请重新核验并检查修复记录；不要重复提交。')

    def get_runtime_status(self, get):
        """Manual, local configuration evidence, not running-worker attestation."""
        result = dict(status=False, integration='unknown', execution_verified=False,
                      checked_at=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))
        messages = {
            'nginx_timeout': '接入核验超时，请稍后重试。',
            'nginx_output_limit': '配置超过只读核验上限，请人工核对接入。',
            'nginx_check_failed': '宝塔 Nginx 配置检查未通过，请在服务器本地查看原因。',
        }
        try:
            result['configured_open'] = bool(self.get_config(None).get('open'))
            result['integration'] = self.__nginx_integration(self.__read_nginx_configuration())
            result['status'] = True
            if result['integration'] == 'configured':
                try:
                    proof = self.__integration_service().probe_if_managed()
                    if proof.get('execution_verified') is True:
                        result.update(execution_verified=True, verification_scope='local_health_probe')
                except Exception:
                    pass
        except Exception as error:
            code = str(error) if str(error) in messages else 'inspection_failed'
            result.update(diagnostic_code=code, message=messages.get(code, '无法核验接入状态，请在服务器本地检查。'))
        return result
    
    @__site_config_locked
    def __write_site_domains(self, site_config=None):
        if os.path.lexists(self.__path + '.policy-recovery/pending.json'):
            raise RuntimeError('上次配置发布尚待人工恢复')
        config_path = self.__path + 'config.json'
        config_raw = self.__policy_file_bytes(config_path)
        config = json.loads(config_raw) if config_raw is not False else {}
        if type(config) is not dict:
            raise ValueError('全局配置格式不正确')
        sites = public.M('sites').field('name,id').select();
        domain_rows = public.M('domain').field('pid,name').select()
        binding_rows = public.M('binding').field('pid,domain').select()
        domains_by_site = {}
        for row in domain_rows:
            domains_by_site.setdefault(row['pid'], []).append(row['name'])
        for row in binding_rows:
            domains_by_site.setdefault(row['pid'], []).append(row['domain'])
        my_domains = []
        for my_site in sites:
            tmp = {}
            tmp['name'] = my_site['name']
            tmp['domains'] = sorted(set(domains_by_site.get(my_site['id'], [])))
            my_domains.append(tmp)
        body = json.dumps(my_domains)
        if config.get('compatibility_profile') == 'bt-free-waf-8.4':
            site_path = self.__path + 'site.json'
            site_raw = self.__repeat_config_bytes()
            current_sites = json.loads(site_raw) if site_config is None else site_config
            if type(current_sites) is not dict:
                raise ValueError('站点配置格式不正确')
            aliases = {}

            def safe_name(name):
                return (type(name) is str and 0 < len(name) <= 253 and
                        not re.search(r'[/\\\x00-\x20]', name) and name not in ('.', '..'))

            for item in my_domains:
                owner = item['name']
                if not safe_name(owner) or type(current_sites.get(owner)) is not dict:
                    raise ValueError('域名所属站点没有有效防护配置')
                for alias in item['domains']:
                    if (not safe_name(alias) or alias in aliases and aliases[alias] != owner or
                            alias in current_sites and alias != owner):
                        raise ValueError('域名别名归属存在冲突，未更新配置')
                    aliases[alias] = owner
            config['site_aliases'] = aliases
            domain_path = self.__path + 'domains.json'
            originals = {config_path: config_raw, domain_path: self.__policy_file_bytes(domain_path),
                         site_path: site_raw}
            candidates = {config_path: json.dumps(config).encode('utf-8'),
                          domain_path: body.encode('utf-8')}
            if site_config is not None:
                candidates[site_path] = json.dumps(site_config).encode('utf-8')
            changes = {}
            for path, value in candidates.items():
                original = originals[path]
                # Keep formatting/BOM and avoid reloading a semantically unchanged snapshot.
                if (original is False or json.dumps(json.loads(value), sort_keys=True) !=
                        json.dumps(json.loads(original), sort_keys=True)):
                    changes[path] = value
            if changes:
                self.__publish_policy_files(changes, expected=originals)
            return my_domains
        if public.readFile(self.__path + 'domains.json') != body:
            public.writeFile(self.__path + 'domains.json', body)
        return my_domains
    
    
    #设置自动同步
    def __auto_sync_cnlist(self):      
        return True
        

    def __get_rule(self,ruleName):
        self.__rule_name(ruleName)
        path = self.__path + 'rule/' + ruleName + '.json';
        rules = self.__read_policy(path)
        if not rules: return False
        return json.loads(rules)

    def __read_policy(self, path):
        reads = getattr(self, '_free_waf_main__policy_reads', None)
        if reads is None:
            return public.readFile(path)
        if path not in reads:
            reads[path] = public.readFile(path)
        return reads[path]
    
    def __rule_name(self, name):
        if name not in ('url_white', 'url_black', 'user_agent', 'user_agent_white', 'header',
                        'cookie', 'args', 'post', 'url', 'ip_black', 'ip_white', 'cn',
                        'scan_black', 'head_white'):
            raise ValueError('不支持的规则文件')

    def __validate_rule(self, name, rules):
        self.__rule_name(name)
        def text(value):
            return type(value) is str and 0 < len(value.encode('utf-8')) <= 8192 and '\x00' not in value
        if name == 'scan_black':
            if (type(rules) is not dict or set(rules) != {'header', 'cookie', 'args'}
                    or any(type(v) is not str or len(v.encode('utf-8')) > 8192 or '\x00' in v for v in rules.values())):
                raise ValueError('扫描器规则格式不正确')
            return
        if type(rules) is not list or len(rules) > 10000:
            raise ValueError('规则必须为有界列表')
        for row in rules:
            if name in ('url_white', 'url_black', 'head_white'):
                valid = text(row)
            elif name in ('ip_black', 'ip_white', 'cn'):
                valid = (type(row) is list and len(row) in (2, 3)
                         and all(type(ip) is list and len(ip) == 4
                                 and all(type(n) is int and 0 <= n <= 255 for n in ip) for ip in row[:2])
                         and row[0] <= row[1]
                         and (len(row) == 2 or type(row[2]) is int and row[2] > 0))
            else:
                valid = (type(row) is list and len(row) == 4 and type(row[0]) is int
                         and row[0] in (0, 1) and text(row[1]) and type(row[2]) is str
                         and len(row[2].encode('utf-8')) <= 8192 and type(row[3]) is int and row[3] in (0, 1))
            if not valid:
                raise ValueError('规则内容格式不正确：' + name)

    def __policy_file_bytes(self, path):
        try:
            with self.__open_regular_file(path) as stream:
                return stream.read()
        except FileNotFoundError:
            return False

    def __atomic_policy_text(self, path, text, expected=None, ownership=None):
        import tempfile
        import stat
        binary = type(text) is bytes
        read = self.__policy_file_bytes if binary else public.readFile
        parent = os.path.dirname(path)
        self.__no_link_path(parent)
        previous = os.lstat(path) if os.path.lexists(path) else None
        if previous is not None and not stat.S_ISREG(previous.st_mode):
            raise ValueError('配置目标不是普通文件')
        fd, staged = tempfile.mkstemp(prefix='.policy-', dir=parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                if binary:
                    stream.write(text)
            if (not binary and public.writeFile(staged, text) is False) or read(staged) != text:
                raise OSError('配置写入核验失败')
            os.chmod(staged, stat.S_IMODE(previous.st_mode) if previous else 0o600)
            if previous and hasattr(os, 'chown'):
                os.chown(staged, previous.st_uid, previous.st_gid)
            with open(staged, 'r+b') as stream:
                os.fsync(stream.fileno())
            if read(path) != (expected if expected is not None else False):
                raise RuntimeError('发布前配置发生同期修改')
            os.replace(staged, path)
            if ownership is not None:
                ownership.add(path)
            if read(path) != text:
                raise OSError('配置发布核验失败')
        finally:
            if os.path.exists(staged):
                os.unlink(staged)

    def __policy_exception_restore(self, actual, migration, current_rules, originals, site_published):
        import copy
        restored = copy.deepcopy(actual)
        before, after = migration['before'], migration['after']
        for site, conf in restored.items():
            values = conf.get('disable_rule', {})
            if type(values) is not dict:
                raise ValueError('同期站点例外格式不正确')
            for name, remap in migration['maps'].items():
                old_values = before.get(site, {}).get('disable_rule', {})
                new_values = after.get(site, {}).get('disable_rule', {})
                value = values.get(name)
                baseline = new_values if site_published else old_values
                if site in before and value == baseline.get(name):
                    if name in old_values:
                        values[name] = old_values[name]
                    else:
                        values.pop(name, None)
                    continue
                if value is None:
                    continue
                if type(value) is not list or any(type(i) is not int or i < 0 for i in value):
                    raise ValueError('同期站点例外序号不正确')
                rule_path = self.__path + 'rule/' + name + '.json'
                if current_rules[rule_path] != originals[rule_path]:
                    reverse = {target: source for source, target in remap.items()}
                    values[name] = sorted({reverse[i] for i in value if i in reverse})
        return restored

    def __policy_exception_forward(self, actual, migration, current_rules, originals, site_published):
        import copy
        forwarded = copy.deepcopy(actual)
        if site_published:
            return forwarded
        for site, conf in forwarded.items():
            for name, remap in migration['maps'].items():
                values = conf.get('disable_rule', {})
                if name not in values:
                    continue
                old_values = migration['before'].get(site, {}).get('disable_rule', {})
                rule_path = self.__path + 'rule/' + name + '.json'
                if ((site in migration['before'] and values[name] == old_values.get(name))
                        or current_rules[rule_path] == originals[rule_path]):
                    values[name] = sorted({remap[i] for i in values[name] if i in remap})
        return forwarded

    def __publish_policy_files(self, changes, expected=None, migration=None):
        binary = any(type(value) is bytes for value in changes.values())
        read = self.__policy_file_bytes if binary else public.readFile
        originals, applied, published = dict(expected or {}), [], set()
        site_path = self.__path + 'site.json'
        for path in set(changes) | set(originals):
            self.__no_link_path(os.path.dirname(path))
            if os.path.lexists(path):
                self.__no_link_path(path)
                if path not in originals:
                    originals[path] = read(path) if binary else self.__read_policy(path)
                if type(originals[path]) is not (bytes if binary else str):
                    raise OSError('无法读取旧配置')
            else:
                originals.setdefault(path, None)
                if originals[path] is False:
                    originals[path] = None
            if read(path) != (originals[path] if originals[path] is not None else False):
                raise RuntimeError('候选构造后配置已被其他操作修改')
        recovery = self.__path + '.policy-recovery'
        self.__no_link_path(os.path.dirname(recovery))
        os.makedirs(recovery, mode=0o700, exist_ok=True)
        self.__no_link_path(recovery)
        pending = recovery + '/pending.json'
        if os.path.lexists(pending):
            raise RuntimeError('上次策略发布尚待人工恢复')
        # JSON stores exact UTF-8 text; byte snapshots also retain CRLF/BOM on rollback.
        snapshots = {key: {path: value.decode('utf-8') if type(value) is bytes else value
                           for path, value in values.items()}
                     for key, values in (('originals', originals), ('candidates', changes))}
        journal = json.dumps(dict(format_version=1, **snapshots))
        self.__atomic_policy_text(pending, journal)
        try:
            for path, candidate in changes.items():
                if read(path) != (originals[path] if originals[path] is not None else False):
                    raise RuntimeError('配置已被其他操作修改')
                # Track attempts separately from successful replacement proofs.
                applied.append(path)
                self.__atomic_policy_text(path, candidate, expected=originals[path], ownership=published)
            if self.__checked_nginx_reload() is False:
                raise RuntimeError('Nginx 生效核验失败')
            os.replace(pending, recovery + '/last.json')
        except Exception as failure:
            current = {path: read(path) for path in originals}
            restore_plan, restored_paths = {}, []
            recovery_started = False
            try:
                for path in changes:
                    value = current[path]
                    original = originals[path] if originals[path] is not None else False
                    if value != original and value != changes[path]:
                        if not migration or path != site_path:
                            raise RuntimeError('已发布文件被同期修改')
                for path in applied:
                    original = originals[path] if originals[path] is not None else False
                    if current[path] != original:
                        restore_plan[path] = originals[path]
                if migration:
                    actual_site = json.loads(current[site_path])
                    restored_site = self.__policy_exception_restore(actual_site,
                                                                   migration, current, originals,
                                                                   site_path in published)
                    # Preserve candidate-only exceptions before the lossy reverse mapping.
                    candidate_site = self.__policy_exception_forward(actual_site, migration, current,
                                                                     originals, site_path in published)
                    restore_plan[site_path] = json.dumps(restored_site)
                # Restore rule tables first, exceptions last; compensate as a group on IO failure.
                order = [p for p in restore_plan if p != site_path]
                if site_path in restore_plan:
                    order.append(site_path)
                recovery_started = True
                for path in order:
                    restore = restore_plan[path]
                    if restore is None:
                        if read(path) != current[path]:
                            raise RuntimeError('恢复前发生同期修改')
                        os.unlink(path)
                    elif restore != current[path]:
                        self.__atomic_policy_text(path, restore, expected=current[path])
                    restored_paths.append(path)
                if restored_paths and self.__checked_nginx_reload() is False:
                    raise RuntimeError('恢复后的重载未确认')
                os.replace(pending, recovery + '/last.json')
            except Exception as restore_failure:
                # A partial rollback must not leave old offsets paired with new rule tables.
                # Do not overwrite externally modified files; retain the journal and block retries.
                try:
                    if not recovery_started:
                        raise RuntimeError('恢复规划有冲突，不发布补偿候选')
                    coherent = dict(changes)
                    if migration:
                        coherent[site_path] = json.dumps(candidate_site)
                    compensation_expected = {}
                    for path in coherent:
                        actual = read(path)
                        owned = (current.get(path), restore_plan.get(path), changes.get(path))
                        if actual not in owned:
                            raise RuntimeError('恢复期间有外部变更')
                        compensation_expected[path] = actual
                    for path, candidate in coherent.items():
                        expected = compensation_expected[path]
                        if read(path) != expected:
                            raise RuntimeError('补偿前发生同期修改')
                        if expected != candidate:
                            self.__atomic_policy_text(path, candidate, expected=expected)
                except Exception:
                    pass
                raise RuntimeError('恢复未完整确认，已保留策略快照并阻止重复提交；需要人工核查') from restore_failure
            raise RuntimeError('配置保存或生效失败，已恢复原文件') from failure

    def __publish_rules(self, changes, preserve_positions=False, removed_index=None):
        import copy
        with self.__endpoint_transaction():
            for name, rules in changes.items():
                if name == 'ip_black':
                    raise ValueError('IP 黑名单须使用统一封禁存储')
                self.__validate_rule(name, rules)
            files = {self.__path + 'rule/' + name + '.json': json.dumps(rules) for name, rules in changes.items()}
            expected = {path: self.__read_policy(path) for path in files}
            site_path = self.__path + 'site.json'
            site_raw = self.__read_policy(site_path)
            expected[site_path] = site_raw
            sites = json.loads(site_raw) if site_raw else {}
            if type(sites) is not dict:
                raise ValueError('站点配置格式不正确')
            migrated = copy.deepcopy(sites)
            maps = {}
            if not preserve_positions:
                for name, rules in changes.items():
                    if name not in ('post', 'args', 'cookie', 'header', 'user_agent', 'url'):
                        continue
                    old = self.__get_rule(name) or []
                    positions = {}
                    for index, row in enumerate(rules):
                        positions.setdefault(row[1], []).append(index)
                    remap, occurrences = {}, {}
                    for index, row in enumerate(old):
                        if type(row) is not list or len(row) < 2 or type(row[1]) is not str:
                            raise ValueError('旧规则内容不正确')
                        occurrence = occurrences.get(row[1], 0)
                        occurrences[row[1]] = occurrence + 1
                        targets = positions.get(row[1], [])
                        if occurrence < len(targets):
                            remap[index] = targets[occurrence]
                    if removed_index is not None:
                        remap = {i: i if i < removed_index else i-1 for i in range(len(old))
                                 if i != removed_index}
                    elif (len(occurrences) != len(old) or len(positions) != len(rules)):
                        raise ValueError('同类重复表达式无法确定导入身份，请先逐条整理重复规则')
                    maps[name] = remap
                    for conf in migrated.values():
                        if type(conf) is not dict or type(conf.get('disable_rule', {})) is not dict:
                            raise ValueError('站点例外格式不正确')
                        disabled = conf.get('disable_rule', {}).get(name)
                        if disabled is None:
                            continue
                        if type(disabled) is not list or any(type(i) is not int for i in disabled):
                            raise ValueError('站点例外序号不正确')
                        conf['disable_rule'][name] = sorted({remap[i] for i in disabled if i in remap})
            if migrated != sites:
                files[site_path] = json.dumps(migrated)
            self.__publish_policy_files(files, expected=expected,
                                        migration={'before': sites, 'after': migrated, 'maps': maps} if maps else None)

    def __write_rule(self,ruleName,rule, preserve_positions=False, removed_index=None):
        self.__publish_rules({ruleName: rule}, preserve_positions=preserve_positions, removed_index=removed_index)
        return True
    
    @__site_config_locked
    def __check_site(self,site_config):
        import copy
        site_config = copy.deepcopy(site_config)
        sites = public.M('sites').field('name').select();
        for siteInfo in sites:
            if siteInfo['name'] in site_config: continue
            site_config[siteInfo['name']] = self.__get_site_conf()
        for sn in site_config.keys():
            if not 'retry_cycle' in site_config[sn]:
                site_config[sn]['retry_cycle'] = 60;
            if not 'cdn_header' in site_config[sn]:
                site_config[sn]['cdn_header'] = ['x-forwarded-for', 'x-real-ip'];
            if not 'cdn_trusted_proxy' in site_config[sn]:
                site_config[sn]['cdn_trusted_proxy'] = [];
            if not 'registration_guard' in site_config[sn] or type(site_config[sn]['registration_guard']) != dict:
                site_config[sn]['registration_guard'] = self.__get_registration_guard_conf();
            if not 'disable_rule' in site_config[sn]:
                site_config[sn]['disable_rule'] = {};
            for rule_name in ['url', 'post', 'args', 'cookie', 'user_agent', 'header']:
                if not rule_name in site_config[sn]['disable_rule']:
                    site_config[sn]['disable_rule'][rule_name] = [];

        config = self.get_config(None)
        mday = time.strftime('%Y-%m-%d',time.localtime());
        for sn in site_config:
            site_config[sn]['log_size'] = 0;
            day_log = config['logs_path'] + '/' + sn + '_' + mday + '.log';
            try:
                site_config[sn]['log_size'] = os.path.getsize(day_log)
            except OSError:
                pass
        return site_config;
    
    def __is_ipn(self,ipn):
        for i in range(4):
            if ipn[0][i] == ipn[1][i]: continue;
            if ipn[0][i] < ipn[1][i]: break;
            return False
        return True
    
    def __format_ip(self,ip):
        tmp = ip.split('.')
        if len(tmp) < 4: return False
        tmp[0] = int(tmp[0])
        tmp[1] = int(tmp[1])
        tmp[2] = int(tmp[2])
        tmp[3] = int(tmp[3])
        return tmp;
    
    def __get_registration_guard_conf(self):
        return {
            'open': False,
            'scope': '',
            'aliases': [],
            'verify_paths': [],
            'register_paths': [],
            'verify_limit': 5,
            'verify_window': 3600,
            'register_limit': 3,
            'register_window': 86400,
            'ban_seconds': 28800
        }

    def __get_site_conf(self):
        if not self.__config: self.__config = self.get_config(None)
        conf = {
            'open': True,
            'project': '',
            'log': True,
            'cdn': False,
            'cdn_header': ['x-forwarded-for', 'x-real-ip'],
            'cdn_trusted_proxy': [],
            'registration_guard': self.__get_registration_guard_conf(),
            'retry': self.__config['retry'],
            'retry_cycle': self.__config['retry_cycle'],
            'retry_time': self.__config['retry_time'],
            'disable_php_path': ['^/upload/', '^/static/'],
            'disable_path': [],
            'disable_ext': [],
            'disable_upload_ext': ['php', 'jsp'],
            'url_white': [],
            'url_rule': [],
            'url_tell': [],
            'disable_rule': {
                'url': [],
                'post': [],
                'args': [],
                'cookie': [],
                'user_agent': [],
                'header': []
            },
            'cc': {
                'open': self.__config['cc']['open'],
                'cycle': self.__config['cc']['cycle'],
                'limit': self.__config['cc']['limit'],
                'endtime': self.__config['cc']['endtime']
            },
            'get': self.__config['get']['open'],
            'post': self.__config['post']['open'],
            'cookie': self.__config['cookie']['open'],
            'user-agent': self.__config['user-agent']['open'],
            'scan': self.__config['scan']['open'],
            'drop_abroad': False
        }
        return conf
    
    def sync_cnlist(self,get):
        return public.returnMsg(False, '旧版国内 IP 库联网同步已停用：未下载未经验证的数据，现有本地规则保持不变。')
        
    def __remove_log_file(self,siteName):
        def remove_site(total):
            total['sites'].pop(siteName, None)
        return self.__write_total(remove_site)

    def __write_total(self, mutate):
        path = self.__total_path()
        # Read under the same permanent lock used by the Lua counter flush.
        with self.__ban_store_module().BanStore(path)._transaction():
            original = public.readFile(path)
            total = json.loads(original)
            mutate(total)
            candidate = json.dumps(total)
            if candidate != original:
                self.__atomic_policy_text(path, candidate, expected=original)
        return True

    
    def __write_config(self,config):
        with self.__endpoint_transaction():
            self.__publish_policy_files({self.__path + 'config.json': json.dumps(config)})
        return True
    
    @__site_config_locked
    def __write_site_config(self,site_config):
        # UI projections are never part of the persisted site policy.
        display_fields = ('top', 'siteName', 'log_size', 'total')
        site_config = {name: {key: value for key, value in conf.items() if key not in display_fields}
                       for name, conf in site_config.items()}
        config_raw = self.__policy_file_bytes(self.__path + 'config.json')
        if config_raw is not False and json.loads(config_raw).get('compatibility_profile') == 'bt-free-waf-8.4':
            return self.__write_site_domains(site_config)
        original = self.__repeat_config_bytes()
        candidate = json.dumps(site_config).encode('utf-8')
        if (self.__write_repeat_site_config(candidate, expected=original) is False
                or self.__repeat_config_bytes() != candidate):
            raise OSError('站点配置写入未核实，未刷新域名或重载服务')
        try:
            self.__write_site_domains()
            if self.__checked_nginx_reload() is False:
                raise RuntimeError('站点配置生效未核实')
        except Exception as failure:
            try:
                # Restore only our candidate; never overwrite a concurrent editor.
                if (self.__write_repeat_site_config(original, expected=candidate) is False
                        or self.__repeat_config_bytes() != original):
                    raise OSError('站点配置恢复未核实')
                if self.__checked_nginx_reload() is False or self.__repeat_config_bytes() != original:
                    raise RuntimeError('恢复后的站点配置或重载未核实')
            except Exception as restore_failure:
                raise RuntimeError('站点配置保存或生效失败，自动恢复未确认，可能已部分处理；请检查配置和 Nginx 状态。') from restore_failure
            raise RuntimeError('站点配置保存或生效失败，已恢复原站点配置并核实重载。') from failure
    
    def __write_log(self,msg):
        public.WriteLog(self.__log_types[0],msg)
