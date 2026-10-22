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
if getattr(report_store, 'REPORT_STORE_VERSION', 0) != 2:
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
    __path = '/www/server/free_waf/'
    __access_log_path = '/www/wwwlogs'
    __state = {True:'开启',False:'关闭',0:'停用',1:'启用'}
    __config = None
    __PATH='/www/server/panel/plugin/free_waf/'
    __log_types = ('GPT Firewall', 'Nginx free firewall')
    

    def return_site(self, get):
        data = public.M('sites').field('name,path').select()
        ret = {}
        for i in data:
            ret[i['name']] = i['path']
        return public.returnMsg(True, ret)

    def import_data(self, get):
        name = get.s_Name;
        try:
            pdata = json.loads(get.pdata)
        except:
            return public.returnMsg(False, '数据格式不正确')
        if not pdata: return public.returnMsg(False, '数据格式不正确')
        iplist = self.__get_rule(name)
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

    def import_rule_bundle(self, get):
        """Import editable rule sets only. This cannot create IP bans."""
        try:
            pdata = json.loads(get.pdata)
        except:
            return public.returnMsg(False, '数据格式不正确')
        if not isinstance(pdata, dict) or not isinstance(pdata.get('rules'), dict):
            return public.returnMsg(False, '数据格式不正确')

        imported = 0
        for name in RULE_BUNDLE_NAMES:
            if name not in pdata['rules']:
                continue
            rule_data = pdata['rules'][name]
            if not isinstance(rule_data, list):
                return public.returnMsg(False, '规则数据不正确：' + name)
            self.__write_rule(name, rule_data)
            imported += 1

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

    # 查询站点跟目录
    def getdir(self, dir, pc='', lis=None):
        if lis is None: lis = []
        list = os.listdir(dir)
        for l in list:
            if os.path.isdir(dir + '/' + l):
                lis = self.getdir(dir + '/' + l, pc, lis)
            elif str(l.lower())[-4:] == '.php' and str(dir + '/' + l).find(pc) == -1:
                print (dir + '/' + l)
                lis.append(dir + '/' + l)
        return lis

    # 目录
    def getdir_list(self, get):
        path = get.path
        if os.path.exists(path):
            pc = 'hackcnm'
            rs = self.getdir(path, pc)
            return rs
        else:
            return False

    def scan(self, filelist, rule):
        self.__webshell_data=[]
        import time
        time_data = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        ret = []
        for file in filelist:
            data = ''
            try:
                with open(file, encoding='utf-8', errors='replace') as stream:
                    data = stream.read()
            except:
                pass
            for r in rule:
                if data and re.compile(r).findall(data):
                    result = {}
                    result[file] = r
                    self.__webshell_data.append(result)
                    log_entry = ("%s [!] %s %s  \n" % (time_data, file, r))
                    self.insert_log(log_entry)
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
        file = self.getdir_list(get)
        if not file: return public.returnMsg(False, "未找到 PHP 文件")
        rule = self.shell_get_rule(get)
        if not rule: return public.returnMsg(False, "规则为空或规则文件错误")
        self.__webshell_data = []
        result = self.scan(file, rule)
        result = self.path_json(get.path, result)
        return self.__webshell_data

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
        if os.path.exists(filename):
            with open(filename, 'rb') as fp:
                data = fp.read()
            file_md5 = hashlib.md5(data).hexdigest()
            return file_md5
        else:
            return False


    def send_baota2(self,filename):
        return False

    def send_baota(self,get):
        return public.returnMsg(False, '旧版云检测已停用，未读取或上传文件；请使用本地扫描。')

    def check_webshell(self,get):
        return public.returnMsg(False, '旧版云检测已停用，未读取或上传文件；请使用本地扫描。')

    def __get_md5(self, s):
        m = hashlib.md5()
        m.update(s.encode('utf-8'))
        return m.hexdigest()

    def get_config(self,get):
        config = json.loads(public.readFile(self.__path + 'config.json'));
        config.setdefault('from_data', True)
        config.setdefault('retry_cycle', 60)
        return config
    
    def get_site_config(self,get):
        if not os.path.exists('/www/wwwlogs/free_waf_log'):os.mkdir('/www/wwwlogs/free_waf_log')
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
    
    def get_site_config_byname(self,get):
        site_config = self.get_site_config(None);
        config = site_config[get.siteName]
        config['top'] = self.get_config(None)
        return config
    
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
    
    def set_obj_status(self,get):
        config = self.get_config(None)
        config[get.obj]['status'] = int(get.statusCode)
        self.__write_config(config)
        return public.returnMsg(True,'设置成功!');
    
    def set_cc_conf(self,get):
        config = self.get_config(None)
        config['cc']['cycle'] = int(get.cycle)
        config['cc']['limit'] = int(get.limit)
        config['cc']['endtime'] = int(get.endtime)
        config['cc']['increase'] = (get.increase == '1') | False
        self.__write_config(config)
        self.__write_log('设置全局 CC 配置：' + get.cycle + ' 秒内累计请求超过 ' + get.limit + ' 次，封禁 ' + get.endtime + ' 秒，增强：' + get.increase);
        return public.returnMsg(True,'设置成功!');
    
    def set_site_cc_conf(self,get):
        site_config = self.get_site_config(None)
        site_config[get.siteName]['cc']['cycle'] = int(get.cycle)
        site_config[get.siteName]['cc']['limit'] = int(get.limit)
        site_config[get.siteName]['cc']['endtime'] = int(get.endtime)
        site_config[get.siteName]['cc']['increase'] = (get.increase == '1') | False
        self.__write_site_config(site_config)
        self.__write_log('设置站点 ['+get.siteName+'] CC 配置：' + get.cycle + ' 秒内累计请求超过 ' + get.limit + ' 次，封禁 ' + get.endtime + ' 秒，增强：' + get.increase);
        return public.returnMsg(True,'设置成功!');
    
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
    
    def remove_cnip(self,get):
        index = int(get.index)
        iplist = self.__get_rule('cn')
        ipn = iplist[index]
        del(iplist[index])
        self.__write_rule('cn', iplist)
        self.__write_log('从国内 IP 库移除 [' + '.'.join(map(str,ipn[0])) + '-' + '.'.join(map(str,ipn[1]))+']');
        return public.returnMsg(True,'删除成功!');
    
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
        if not BanStore:
            return None
        return BanStore(IP_BLACK_PATH, IP_BLACK_META_PATH)

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
        if store:
            removed = store.remove_exact_ip(ip)
        else:
            ipn = list(map(int, ip.split('.')))
            iplist = self.__get_rule('ip_black')
            if not isinstance(iplist, list):
                raise ValueError('无法读取 IP 黑名单')
            new_list = [item for item in iplist if not (
                len(item) >= 2 and item[0] == ipn and item[1] == ipn)]
            removed = len(new_list) != len(iplist)
            if removed:
                if public.writeFile(self.__path + 'rule/ip_black.json', json.dumps(new_list)) is not True:
                    raise OSError('IP 黑名单保存失败')
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
        if get.start_ip == get.end_ip:
            store = self.__ban_store()
            if store:
                try:
                    added = store.add_temp_ban(get.start_ip, ban_seconds, reason='manual_temp')
                    if not added:
                        return public.returnMsg(False, '指定 IP 已存在活动封禁。');
                    self.__write_drop_ip_entry(get.start_ip, drop_time=ban_seconds, reason='manual_temp')
                    public.serviceReload()
                    self.__write_log('添加 IP [ '+get.start_ip+' ] 到 IP 黑名单，时长 '+str(ban_seconds)+' 秒');
                    return public.returnMsg(True,'添加成功!');
                except:
                    pass
        iplist = self.__get_rule('ip_black')
        for item in iplist:
            if len(item) >= 2 and item[0] == ipn[0] and item[1] == ipn[1]:
                return public.returnMsg(False,'指定 IP 段已存在!');
        if get.start_ip == get.end_ip:
            import time as _t
            iplist.insert(0, ipn + [int(_t.time()) + ban_seconds])
        else:
            iplist.insert(0, ipn)
        self.__write_rule('ip_black', iplist)
        if get.start_ip == get.end_ip:
            self.__write_drop_ip_entry(get.start_ip, drop_time=ban_seconds, reason='manual_temp')
        self.__write_log('添加 IP 段 [ '+get.start_ip+'-'+get.end_ip+' ] 到 IP 黑名单');
        return public.returnMsg(True,'添加成功!');
    
    def remove_ip_black(self,get):
        index = int(get.index)
        iplist = self.__get_rule('ip_black')
        now = time.time()
        active_items = []
        for i,item in enumerate(iplist):
            if len(item) >= 3 and now > item[2]:
                continue
            active_items.append((i,item))
        if index < 0 or index >= len(active_items):
            return public.returnMsg(False,'指定 IP 段不存在。');
        real_index, ipn = active_items[index]
        del(iplist[real_index])
        self.__write_rule('ip_black', iplist)
        self.__write_log('从 IP 黑名单移除 [' + '.'.join(map(str,ipn[0])) + '-' + '.'.join(map(str,ipn[1]))+']');
        return public.returnMsg(True,'删除成功!');
    
    def add_url_white(self,get):
        url_white = self.__get_rule('url_white')
        url_rule = get.url_rule.strip()
        if get.url_rule in url_white: return public.returnMsg(False,'添加的 URL 已存在')
        url_white.insert(0,url_rule)
        self.__write_rule('url_white', url_white)
        self.__write_log('添加 URL 规则 ['+url_rule+'] 到 URL 白名单');
        return public.returnMsg(True,'添加成功!');
    
    def remove_url_white(self,get):
        url_white = self.__get_rule('url_white')
        index = int(get.index)
        url_rule = url_white[index]
        del(url_white[index])
        self.__write_rule('url_white', url_white)
        self.__write_log('从 URL 白名单移除 URL 规则 ['+url_rule+']');
        return public.returnMsg(True,'删除成功!');
    
    def add_url_black(self,get):
        url_white = self.__get_rule('url_black')
        url_rule = get.url_rule.strip()
        if get.url_rule in url_white: return public.returnMsg(False,'添加的 URL 已存在')
        url_white.insert(0,url_rule)
        self.__write_rule('url_black', url_white)
        self.__write_log('添加 URL 规则 ['+url_rule+'] 到 URL 黑名单');
        return public.returnMsg(True,'添加成功!');
    
    def remove_url_black(self,get):
        url_white = self.__get_rule('url_black')
        index = int(get.index)
        url_rule = url_white[index]
        del(url_white[index])
        self.__write_rule('url_black', url_white)
        self.__write_log('从 URL 黑名单移除 URL 规则 ['+url_rule+']');
        return public.returnMsg(True,'删除成功!');
    
    def save_scan_rule(self,get):
        scan_rule = {'header':get.header,'cookie':get.cookie,'args':get.args}
        self.__write_rule('scan_black', scan_rule)
        self.__write_log('修改扫描器过滤规则');
        return public.returnMsg(True,'设置成功')
    
    def set_retry(self,get):
        config = self.get_config(None)
        config['retry'] = int(get.retry)
        config['retry_cycle'] = int(get.retry_cycle)
        config['retry_time'] = int(get.retry_time)
        self.__write_config(config)
        self.__write_log('设置非法请求容忍阈值：' + get.retry_cycle + ' 秒内累计请求超过 ' + get.retry + ' 次，封禁 ' + get.retry_time + ' 秒');
        return public.returnMsg(True,'设置成功!');
    
    def set_site_retry(self,get):
        site_config = self.get_site_config(None)
        site_config[get.siteName]['retry'] = int(get.retry)
        site_config[get.siteName]['retry_cycle'] = int(get.retry_cycle)
        site_config[get.siteName]['retry_time'] = int(get.retry_time)
        self.__write_site_config(site_config)
        self.__write_log('设置站点 ['+get.siteName+'] 非法请求容忍阈值：' + get.retry_cycle + ' 秒内累计请求超过 ' + get.retry + ' 次，封禁 ' + get.retry_time + ' 秒');
        return public.returnMsg(True,'设置成功!');
    
    def set_site_cdn_state(self,get):
        site_config = self.get_site_config(None)
        if site_config[get.siteName]['cdn']:
            site_config[get.siteName]['cdn'] = False
        else:
            site_config[get.siteName]['cdn'] = True
        self.__write_site_config(site_config)
        self.__write_log(self.__state[site_config[get.siteName]['cdn']] + '站点 [ '+get.siteName+' ] CDN 模式');
        return public.returnMsg(True,'设置成功!');
    
    def get_site_cdn_header(self,get):
        site_config = self.get_site_config(None)
        return site_config[get.siteName]['cdn_header']
    
    def add_site_cdn_header(self,get):
        site_config = self.get_site_config(None)
        get.cdn_header = get.cdn_header.strip().lower();
        if get.cdn_header in site_config[get.siteName]['cdn_header']: return public.returnMsg(False,'添加的请求头已存在!');
        site_config[get.siteName]['cdn_header'].append(get.cdn_header)
        self.__write_site_config(site_config)
        self.__write_log('添加站点 [ '+get.siteName+'] CDN 请求头 [ '+get.cdn_header+' ]');
        return public.returnMsg(True,'添加成功!');
    
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

    def get_site_cdn_trusted_proxy(self,get):
        site_config = self.get_site_config(None)
        if not 'cdn_trusted_proxy' in site_config[get.siteName]:
            site_config[get.siteName]['cdn_trusted_proxy'] = []
        return site_config[get.siteName]['cdn_trusted_proxy']

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
    
    def get_site_rule(self,get):
        site_config = self.get_site_config(None)
        return site_config[get.siteName][get.ruleName]
    
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
    
    def add_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        if not rule: rule = []
        ruleValue = [1, get.ruleValue.strip(),get.ps,1]
        for ru in rule:
            if ru[1] == ruleValue[1]: return public.returnMsg(False,'指定规则已存在，请勿重复添加。');
        rule.append(ruleValue)
        self.__write_rule(get.ruleName, rule)
        self.__write_log('添加全局规则 [ '+get.ruleName+' ] [ '+get.ps+' ]');
        return public.returnMsg(True,'添加成功!');
    
    def remove_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        ps = rule[index][2]
        del(rule[index])
        self.__write_rule(get.ruleName, rule)
        self.__write_log('删除全局规则 [ '+get.ruleName+' ] [ '+ps+' ]');
        return public.returnMsg(True,'删除成功!');
    
    def modify_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        rule[index][1] = get.ruleBody
        rule[index][2] = get.rulePs
        self.__write_rule(get.ruleName, rule)
        self.__write_log('修改全局规则 [ '+get.ruleName+' ] [ '+get.rulePs+' ]');
        return public.returnMsg(True,'修改成功!');
    
    def set_rule_state(self,get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        if rule[index][0] == 0:
            rule[index][0] = 1;
        else:
            rule[index][0] = 0;
        self.__write_rule(get.ruleName, rule)
        self.__write_log(self.__state[rule[index][0]] + '全局规则 [ '+get.ruleName+' ] [ '+rule[index][2]+' ]');
        return public.returnMsg(True,'设置成功!');
    
    def get_site_disable_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        site_config = self.get_site_config(None)
        site_rule = site_config[get.siteName]['disable_rule'][get.ruleName]
        for i in range(len(rule)):
            if rule[i][0] == 0: rule[i][0] = -1;
            if i in site_rule: rule[i][0] = 0;
        return rule;
    
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
                iplist = self.__get_rule('ip_black')
                if not isinstance(iplist, list):
                    raise ValueError('无法读取 IP 黑名单')
                new_list = []
                for item in iplist:
                    try:
                        if len(item) >= 2 and item[0] == item[1]:
                            removed += 1
                            continue
                    except:
                        pass
                    new_list.append(item)
                if removed:
                    if public.writeFile(self.__path + 'rule/ip_black.json', json.dumps(new_list)) is not True:
                        raise OSError('IP 黑名单保存失败')
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

        date_set = set(self.__date_list(days))
        try:
            files = sorted(os.listdir(log_dir), reverse=True)
        except:
            files = []
        for fname in files:
            if not fname.endswith('.log'):
                continue
            matched_date = ''
            for date_str in date_set:
                if fname.endswith('_' + date_str + '.log'):
                    matched_date = date_str
                    break
            if not matched_date:
                continue
            site = fname[: fname.rfind('_' + matched_date)]
            if siteName and site != siteName:
                continue
            fpath = os.path.join(log_dir, fname)
            try:
                fp = open(fpath, 'r', errors='ignore')
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
                    if len(row) < 6:
                        continue
                    source_text = (' '.join([str(x) for x in row]) + ' ' + site).lower()
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
                        continue
                    rows.append(self.__parse_waf_log_row(row, site, matched_date, line_no, raw_line))
                fp.close()
            except:
                pass
        return {'rows': rows, 'total': total, 'p': p, 'limit': page_size, 'summary': {'matched': total}}

    def get_report_http_detail(self, get):
        """Return one structured WAF log row with raw JSON for the detail drawer."""
        log_dir = '/www/wwwlogs/free_waf_log/'
        siteName = str(getattr(get, 'siteName', '') or '').strip()
        date_str = str(getattr(get, 'date', '') or '').strip()
        try:
            line_no = int(getattr(get, 'line_no', 0))
        except:
            line_no = 0
        if not siteName or not date_str or line_no < 1:
            return public.returnMsg(False, '日志定位参数不完整')
        fpath = os.path.join(log_dir, siteName + '_' + date_str + '.log')
        if not os.path.exists(fpath):
            return public.returnMsg(False, '日志文件不存在')
        try:
            fp = open(fpath, 'r', errors='ignore')
            current = 0
            for line in fp:
                current += 1
                if current != line_no:
                    continue
                raw_line = line.strip()
                row = json.loads(raw_line)
                safe_raw = html.escape(raw_line, quote=True)
                fp.close()
                return {
                    'status': True,
                    'data': self.__parse_waf_log_row(row, siteName, date_str, line_no, raw_line),
                    'raw': safe_raw
                }
            fp.close()
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
        if os.path.exists(path):
            try:
                fp = open(path, 'r', errors='ignore')
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
        _geo = None
        _geo_cache = {}
        try:
            import maxminddb
            _geo = maxminddb.open_database('/www/server/panel/config/GeoLite2-City.mmdb')
        except:
            pass
        if os.path.exists(log_dir):
            try:
                files = sorted(os.listdir(log_dir), reverse=True)
            except:
                files = []
            for fname in files:
                if not fname.endswith('.log'):
                    continue
                matched_date = ''
                for date_str in dates:
                    if fname.endswith('_' + date_str + '.log'):
                        matched_date = date_str
                        break
                if not matched_date:
                    continue
                site = fname[: fname.rfind('_' + matched_date)]
                fpath = os.path.join(log_dir, fname)
                try:
                    fp = open(fpath, 'r', errors='ignore')
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
                                except:
                                    pass
                            _geo_cache[ip] = (region, country_code, country_name)
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
        if _geo:
            try:
                _geo.close()
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
            _, code, name = _geo_cache.get(ip, ('', '', ''))
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
        active_data = self.get_waf_drop_ip(None)
        if type(active_data) == dict:
            active_ips = set(active_data.keys())
        else:
            active_ips = set(active_data or [])
        active_count = len(active_ips)
        blocked_map = {}
        if os.path.exists(drop_path):
            try:
                fp = open(drop_path, 'r', errors='ignore')
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
        for item in blocked_ips:
            if '_last_ts' in item:
                del(item['_last_ts'])
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

        if os.path.exists(log_dir):
            try:
                files = sorted(os.listdir(log_dir), reverse=True)
            except:
                files = []
            for fname in files:
                if len(items) >= limit:
                    break
                matched_date = ''
                for date_str in dates:
                    if fname.endswith('_' + date_str + '.log'):
                        matched_date = date_str
                        break
                if not matched_date:
                    continue
                site = fname[: fname.rfind('_' + matched_date)]
                fpath = os.path.join(log_dir, fname)
                try:
                    fp = open(fpath, 'r', errors='ignore')
                    for line in fp:
                        if len(items) >= limit:
                            break
                        raw_line = line.strip()
                        if not raw_line:
                            continue
                        try:
                            row = json.loads(raw_line)
                        except:
                            continue
                        if len(row) < 6:
                            continue
                        level, level_text = self.__notification_level(row[5])
                        summary[level] += 1
                        summary['total'] += 1
                        items.append({
                            'time': self.__safe_text(row[0]),
                            'level': level,
                            'level_text': level_text,
                            'site': self.__safe_text(site),
                            'ip': self.__safe_text(row[1]),
                            'uri': self.__safe_text(row[3]),
                            'rule_type': self.__safe_text(row[5]),
                            'message': self.__safe_text('请求触发 WAF 规则：' + str(row[5]))
                        })
                    fp.close()
                except:
                    pass

        if os.path.exists(drop_path) and len(items) < limit:
            try:
                fp = open(drop_path, 'r', errors='ignore')
                for line in fp:
                    if len(items) >= limit:
                        break
                    raw_line = line.strip()
                    if not raw_line:
                        continue
                    try:
                        row = json.loads(raw_line)
                    except:
                        continue
                    while len(row) < 6:
                        row.append('')
                    try:
                        ts = int(float(row[0]))
                        time_text = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
                    except:
                        time_text = ''
                    summary['high'] += 1
                    summary['total'] += 1
                    items.append({
                        'time': self.__safe_text(time_text),
                        'level': 'high',
                        'level_text': '高',
                        'site': self.__safe_text(row[2]),
                        'ip': self.__safe_text(row[1]),
                        'uri': self.__safe_text(row[3]),
                        'rule_type': self.__safe_text(row[5]),
                        'message': self.__safe_text('封禁记录：' + str(row[5]))
                    })
                fp.close()
            except:
                pass

        items = sorted(items, key=lambda x: x.get('time', ''), reverse=True)[:limit]
        return {
            'status': True,
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'summary': summary,
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
        if os.path.exists(log_dir):
            try:
                files = sorted(os.listdir(log_dir), reverse=True)
            except:
                files = []
            for fname in files:
                if not fname.endswith('.log'):
                    continue
                matched_date = ''
                for date_str in date_set:
                    if fname.endswith('_' + date_str + '.log'):
                        matched_date = date_str
                        break
                if not matched_date:
                    continue
                site = fname[: fname.rfind('_' + matched_date)]
                fpath = os.path.join(log_dir, fname)
                try:
                    fp = open(fpath, 'r', errors='ignore')
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
        params = SimpleNamespace(days=days, line_limit=line_limit, siteName=site_name)
        key = json.dumps([site_name, days, line_limit], ensure_ascii=False)
        force = str(getattr(get, 'force', '')).lower() in ('1', 'true')
        result = website_reports.request(key, lambda: self.__build_website_statistics_summary(params), force=force)
        if 'site_options' not in result:
            result['site_options'] = self.__statistics_log_files()[2]
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
        """Read-only Website Statistics basic dashboard from Nginx access_logs and error_logs."""
        import collections, heapq
        log_dir = self.__access_log_path
        siteName = str(getattr(get, 'siteName', '') or '').strip()
        try:
            days = int(getattr(get, 'days', 7))
        except:
            days = 7
        if days < 1:
            days = 1
        if days > 30:
            days = 30
        try:
            line_limit = int(getattr(get, 'line_limit', 800))
        except:
            line_limit = 800
        if line_limit < 100:
            line_limit = 100
        if line_limit > 5000:
            line_limit = 5000
        since_ts = time.time() - days * 86400
        access_logs, error_logs, site_options = self.__statistics_log_files()
        deadline = time.monotonic() + 120

        site_stats = {}
        unique_clients = set()
        total_requests = 0
        total_bytes = 0
        error_requests = 0
        spider_requests = 0
        spider_counter = collections.Counter()
        client_counter = collections.Counter()
        status_counter = collections.Counter()
        uri_counter = collections.Counter()
        referer_counter = collections.Counter()
        client_sites = {}
        recent_access = []
        access_sequence = 0
        spider_tokens = ['bot', 'spider', 'crawler', 'slurp', 'baiduspider', 'googlebot', 'bingbot', 'yandex', 'duckduckbot']

        for path in access_logs:
            fname = os.path.basename(path)
            site = fname[:-4] if fname.endswith('.log') else fname
            if site.endswith('.ssl'):
                site = site[:-4]
            if siteName and site != siteName:
                continue
            for row in self.__iter_recent_window_rows(path, since_ts, deadline=deadline):
                total_requests += 1
                total_bytes += row.get('bytes', 0)
                unique_clients.add(row.get('ip', ''))
                client_counter[row.get('ip', '')] += 1
                if row.get('ip', ''):
                    if row.get('ip', '') not in client_sites:
                        client_sites[row.get('ip', '')] = set()
                    client_sites[row.get('ip', '')].add(site)
                status = int(row.get('status', 0))
                status_counter[str(status)] += 1
                if status >= 400:
                    error_requests += 1
                uri = row.get('uri', '')
                if uri:
                    uri_counter[uri] += 1
                referer = row.get('referer', '')
                if referer and referer != '-':
                    referer_counter[referer] += 1
                if site not in site_stats:
                    site_stats[site] = {'requests': 0, 'clients': set(), 'bytes': 0, 'errors': 0}
                site_stats[site]['requests'] += 1
                site_stats[site]['clients'].add(row.get('ip', ''))
                site_stats[site]['bytes'] += row.get('bytes', 0)
                if status >= 400:
                    site_stats[site]['errors'] += 1
                ua_lower = (row.get('user_agent', '') or '').lower()
                spider_name = ''
                for token in spider_tokens:
                    if token in ua_lower:
                        spider_name = token
                        break
                if spider_name:
                    spider_requests += 1
                    spider_counter[spider_name] += 1
                if len(recent_access) < 80 or row['time_ts'] > recent_access[0][0]:
                    access_sequence += 1
                    item = {
                        'time': self.__safe_text(row.get('time', '')),
                        'site': self.__safe_text(site),
                        'ip': self.__safe_text(row.get('ip', '')),
                        'method': self.__safe_text(row.get('method', '')),
                        'uri': self.__safe_text(uri),
                        'status': status,
                        'bytes': row.get('bytes', 0),
                        'user_agent': self.__safe_text(row.get('user_agent', '')),
                        'raw': self.__safe_text(row.get('raw', ''))
                    }
                    candidate = (row['time_ts'], access_sequence, item)
                    if len(recent_access) < 80:
                        heapq.heappush(recent_access, candidate)
                    else:
                        heapq.heapreplace(recent_access, candidate)

        sites = []
        for site in sorted(site_stats.keys()):
            item = site_stats[site]
            sites.append({
                'site': self.__safe_text(site),
                'requests': item['requests'],
                'clients': len(item['clients']),
                'bytes': item['bytes'],
                'errors': item['errors']
            })
        sites = sorted(sites, key=lambda x: x.get('requests', 0), reverse=True)[:50]
        recent_access = [item[2] for item in sorted(recent_access, reverse=True)]

        recent_errors = []
        error_sequence = 0
        for path in error_logs:
            fname = os.path.basename(path)
            site = fname.replace('.error.log', '').replace('.ssl', '')
            if siteName and site != siteName:
                continue
            for line in self.__read_recent_lines(path, min(line_limit, 300)):
                row = self.__parse_nginx_error_line(line)
                try:
                    row_ts = time.mktime(time.strptime(row.get('time', ''), '%Y/%m/%d %H:%M:%S'))
                except (ValueError, OverflowError):
                    continue
                if row_ts < since_ts:
                    continue
                error_sequence += 1
                item = {
                    'time': self.__safe_text(row.get('time', '')),
                    'site': self.__safe_text(site),
                    'level': self.__safe_text(row.get('level', '')),
                    'client': self.__safe_text(row.get('client', '')),
                    'server': self.__safe_text(row.get('server', '')),
                    'request': self.__safe_text(row.get('request', '')),
                    'raw': self.__safe_text(row.get('raw', ''))
                }
                candidate = (row_ts, error_sequence, item)
                if len(recent_errors) < 120:
                    heapq.heappush(recent_errors, candidate)
                elif row_ts > recent_errors[0][0]:
                    heapq.heapreplace(recent_errors, candidate)
        recent_errors = [item[2] for item in sorted(recent_errors, reverse=True)]

        common_clients = []
        for ip, count in client_counter.most_common(50):
            if not ip:
                continue
            sites_for_ip = sorted(client_sites.get(ip, set()))
            if len(sites_for_ip) > 1 or siteName:
                common_clients.append({
                    'ip': self.__safe_text(ip),
                    'count': count,
                    'sites': self.__safe_text(', '.join(sites_for_ip))
                })
            if len(common_clients) >= 30:
                break
        if not common_clients:
            for ip, count in client_counter.most_common(30):
                if not ip:
                    continue
                sites_for_ip = sorted(client_sites.get(ip, set()))
                common_clients.append({
                    'ip': self.__safe_text(ip),
                    'count': count,
                    'sites': self.__safe_text(', '.join(sites_for_ip))
                })

        settings = [
            {'key': '统计模式', 'value': '后台只读统计，页面展示最近完成的结果'},
            {'key': '日志目录', 'value': log_dir},
            {'key': '统计窗口', 'value': '近 ' + str(days) + ' 天'},
            {'key': '站点筛选', 'value': siteName if siteName else '全部站点'},
            {'key': '汇总统计', 'value': '按统计窗口流式汇总，结果缓存 5 分钟，可手动刷新'},
            {'key': '最近日志展示', 'value': '跨站点按时间展示最近 80 条访问和 120 条错误记录'}
        ]
        return {
            'status': True,
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'siteName': self.__safe_text(siteName),
            'site_options': site_options,
            'access_logs': [self.__safe_text(x) for x in access_logs],
            'error_logs': [self.__safe_text(x) for x in error_logs],
            'summary': {
                'days': days,
                'total_requests': total_requests,
                'unique_clients': len([x for x in unique_clients if x]),
                'total_bytes': total_bytes,
                'error_requests': error_requests,
                'spider_requests': spider_requests
            },
            'sites': sites,
            'spiders': [{'spider': self.__safe_text(k), 'count': v} for k, v in spider_counter.most_common(20)],
            'clients': [{'ip': self.__safe_text(k), 'count': v} for k, v in client_counter.most_common(50)],
            'status_codes': [{'status': self.__safe_text(k), 'count': v} for k, v in status_counter.most_common(20)],
            'top_uris': [{'uri': self.__safe_text(k), 'count': v} for k, v in uri_counter.most_common(30)],
            'referers': [{'referer': self.__safe_text(k), 'count': v} for k, v in referer_counter.most_common(30)],
            'common_clients': common_clients,
            'recent_access': recent_access,
            'recent_errors': recent_errors,
            'settings': [{'key': self.__safe_text(x['key']), 'value': self.__safe_text(x['value'])} for x in settings]
        }


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
        today = datetime.date.today()
        for i in range(days):
            d = today - datetime.timedelta(days=i)
            date_str = d.strftime('%Y-%m-%d')
            try:
                for fname in os.listdir(log_dir):
                    if not fname.endswith('_' + date_str + '.log'):
                        continue
                    site = fname[: fname.rfind('_' + date_str)]
                    fpath = os.path.join(log_dir, fname)
                    try:
                        with open(fpath, 'r', errors='ignore') as fp:
                            for line in fp:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    row = json.loads(line)
                                    if len(row) < 6:
                                        continue
                                    ip        = row[1]
                                    rule_type = row[5]
                                    ip_counts[ip] += 1
                                    if ip not in ip_details:
                                        ip_details[ip] = {'count': 0, 'types': {}, 'last_time': '', 'sites': set()}
                                    ip_details[ip]['count']    += 1
                                    ip_details[ip]['last_time']  = row[0]
                                    ip_details[ip]['sites'].add(site)
                                    ip_details[ip]['types'][rule_type] = ip_details[ip]['types'].get(rule_type, 0) + 1
                                except:
                                    pass
                    except:
                        pass
            except:
                pass
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
        today = datetime.date.today()
        for i in range(days):
            d = today - datetime.timedelta(days=i)
            date_str = d.strftime('%Y-%m-%d')
            try:
                for fname in os.listdir(log_dir):
                    if not fname.endswith('_' + date_str + '.log'):
                        continue
                    site = fname[: fname.rfind('_' + date_str)]
                    fpath = os.path.join(log_dir, fname)
                    try:
                        with open(fpath, 'r', errors='ignore') as fp:
                            for line in fp:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    row = json.loads(line)
                                    if len(row) < 6:
                                        continue
                                    uri = str(row[3]).strip()
                                    if not uri:
                                        continue
                                    rule_type = str(row[5]).strip() or 'unknown'
                                    uri_counts[uri] += 1
                                    if uri not in uri_details:
                                        uri_details[uri] = {'count': 0, 'types': {}, 'last_time': '', 'sites': set()}
                                    uri_details[uri]['count'] += 1
                                    if row[0] > uri_details[uri]['last_time']:
                                        uri_details[uri]['last_time'] = row[0]
                                    uri_details[uri]['sites'].add(site)
                                    uri_details[uri]['types'][rule_type] = uri_details[uri]['types'].get(rule_type, 0) + 1
                                except:
                                    pass
                    except:
                        pass
            except:
                pass
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
        store = self.__ban_store()
        if store:
            try:
                added = store.add_temp_ban(ip, TEMP_BAN_SECONDS, reason='manual_temp')
                if not added:
                    return public.returnMsg(False, ip + ' 已在黑名单中')
                public.serviceReload()
            except:
                return public.returnMsg(False, '写入封禁列表失败')
        else:
            iplist = self.__get_rule('ip_black') or []
            for item in iplist:
                if len(item) >= 3 and item[0] == ipn and item[1] == ipn and item[2] > int(__import__("time").time()):
                    return public.returnMsg(False, ip + ' 已在黑名单中')
            import time as _t
            iplist.insert(0, [ipn, ipn, int(_t.time()) + TEMP_BAN_SECONDS])
            self.__write_rule('ip_black', iplist)
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
        count = public.M('logs').where('type IN (?,?)', self.__log_types).count();
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
        data['data'] = public.M('logs').where('type IN (?,?)', self.__log_types).order('id desc').limit(
            str(page.SHIFT) + ',' + str(page.ROW)).field('log,addtime').select();
        return data;

            
    def get_total(self,get):
        try:
            total = json.loads(public.readFile(self.__path + 'total.json'))
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
        nginxconf = '/www/server/nginx/conf/nginx.conf';
        if not os.path.exists(nginxconf): return public.returnMsg(False,'仅支持 Nginx 服务器');
        if public.readFile(nginxconf).find('luawaf.conf') == -1: return public.returnMsg(False,'当前 Nginx 不支持防火墙，请重新安装 Nginx');
        data = {}
        data['total'] = self.get_total(None)
        del(data['total']['sites'])
        data['drop_ip'] = []
        conf = self.get_config(None)
        data['open'] = conf['open']
        data['safe_day'] = 0
        if 'start_time' in conf:
            if conf['start_time'] != 0: data['safe_day'] = int((time.time() - conf['start_time']) / 86400)
        return data
    
    def __write_site_domains(self):
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
        if public.readFile(self.__path + 'domains.json') != body:
            public.writeFile(self.__path + 'domains.json', body)
        return my_domains
    
    
    #设置自动同步
    def __auto_sync_cnlist(self):      
        return True
        

    def __get_rule(self,ruleName):
        path = self.__path + 'rule/' + ruleName + '.json';
        rules = public.readFile(path)
        if not rules: return False
        return json.loads(rules)
    
    def __write_rule(self,ruleName,rule):
        path = self.__path + 'rule/' + ruleName + '.json';
        public.writeFile(path,json.dumps(rule))
        public.serviceReload();
    
    def __check_site(self,site_config):
        sites = public.M('sites').field('name').select();
        siteNames = []
        n = 0
        for siteInfo in sites:
            siteNames.append(siteInfo['name'])
            if siteInfo['name'] in site_config: continue
            site_config[siteInfo['name']] = self.__get_site_conf()
            n += 1
        old_site_config = site_config.copy()
        for sn in site_config.keys():
            if sn in siteNames: 
                if not 'retry_cycle' in site_config[sn]:
                    site_config[sn]['retry_cycle'] = 60;
                    n += 1;
                if not 'cdn_header' in site_config[sn]:
                    site_config[sn]['cdn_header'] = ['x-forwarded-for', 'x-real-ip'];
                    n += 1;
                if not 'cdn_trusted_proxy' in site_config[sn]:
                    site_config[sn]['cdn_trusted_proxy'] = [];
                    n += 1;
                if not 'registration_guard' in site_config[sn] or type(site_config[sn]['registration_guard']) != dict:
                    site_config[sn]['registration_guard'] = self.__get_registration_guard_conf();
                    n += 1;
                if not 'disable_rule' in site_config[sn]:
                    site_config[sn]['disable_rule'] = {};
                    n += 1;
                for rule_name in ['url', 'post', 'args', 'cookie', 'user_agent', 'header']:
                    if not rule_name in site_config[sn]['disable_rule']:
                        site_config[sn]['disable_rule'][rule_name] = [];
                        n += 1;
                continue
            del(old_site_config[sn])
            self.__remove_log_file(sn)
            n += 1
        
        if n > 0: 
            site_config = old_site_config.copy()
            self.__write_site_config(site_config)
        
        config = self.get_config(None)
        logList = os.listdir(config['logs_path'])
        mday = time.strftime('%Y-%m-%d',time.localtime());
        for sn in siteNames:
            site_config[sn]['log_size'] = 0;
            day_log = config['logs_path'] + '/' + sn + '_' + mday + '.log';
            if os.path.exists(day_log):
                site_config[sn]['log_size'] = os.path.getsize(day_log)
            
            tmp = []
            for logName in logList:
                if logName.find(sn + '_') != 0: continue;
                tmp.append(logName)
            
            length = len(tmp) - config['log_save'];
            if length > 0:
                tmp = sorted(tmp)
                for i in range(length):
                    filename = config['logs_path'] + '/' + tmp[i];
                    if not os.path.exists(filename): continue
                    os.remove(filename)
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
        if not get:
            self.get_config(None)
            self.get_site_config(None)
        rcnlist = public.httpGet(public.get_url() + '/cnlist.json')
        if not rcnlist: return public.returnMsg(False,'连接云端失败')
        cloudList = json.loads(rcnlist)
        cnlist = self.__get_rule('cn')
        n = 0
        for ipd in cloudList:
            if ipd in cnlist: continue;
            cnlist.append(ipd)
            n += 1
        self.__write_rule('cn', cnlist)
        if get: return public.returnMsg(True,'同步成功，本次共新增 ' + str(n) + ' 个 IP 段')
        
    def __remove_log_file(self,siteName):
        total = json.loads(public.readFile(self.__path + 'total.json'))
        if siteName in total['sites']:
            del(total['sites'][siteName])
            self.__write_total(total)
        return True
            
    def __write_total(self,total):
        return public.writeFile(self.__path + 'total.json',json.dumps(total))

    
    def __write_config(self,config):
        public.writeFile(self.__path + 'config.json',json.dumps(config))
        public.serviceReload();
    
    def __write_site_config(self,site_config):
        public.writeFile(self.__path + 'site.json',json.dumps(site_config))
        self.__write_site_domains()
        public.serviceReload();
    
    def __write_log(self,msg):
        public.WriteLog(self.__log_types[0],msg)
        
    def __check_cjson(self):
        cjson = '/usr/local/lib/lua/5.1/cjson.so'
        if os.path.exists(cjson): 
            if os.path.exists('/usr/lib64/lua/5.1'):
                if not os.path.exists('/usr/lib64/lua/5.1/cjson.so'):
                    public.ExecShell("ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so");
            if os.path.exists('/usr/lib/lua/5.1'):
                if not os.path.exists('/usr/lib/lua/5.1/cjson.so'):
                    public.ExecShell("ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so");
            return True
        
        c = '''wget -O lua-cjson-2.1.0.tar.gz http://download.bt.cn/install/src/lua-cjson-2.1.0.tar.gz -T 20
tar xvf lua-cjson-2.1.0.tar.gz
rm -f lua-cjson-2.1.0.tar.gz
cd lua-cjson-2.1.0
make
make install
cd ..
rm -rf lua-cjson-2.1.0
ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so
ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so
/etc/init.d/nginx reload
'''
        public.writeFile('/root/install_cjson.sh',c)
        public.ExecShell('cd /root && bash install_cjson.sh')
        return True
    
