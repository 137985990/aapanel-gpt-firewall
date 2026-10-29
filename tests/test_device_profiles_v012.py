import datetime as dt
import ipaddress
import json
import sys
import tempfile
import types
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import Mock, patch

import website_statistics as statistics


NOW = dt.datetime(2026, 10, 29, 12, tzinfo=dt.timezone.utc)
CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0 Safari/537.36'
ANDROID = 'Mozilla/5.0 (Linux; Android 14; Model-X) Chrome/130.0.0.0 Mobile Safari/537.36'
SAFARI = 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) Version/17.0 Safari/604.1'
UNKNOWN = '\u672a\u77e5'
PROFILE_FIELDS = ('country_code', 'country_name', 'browser', 'os', 'device', 'client_type')


class DeviceProfileTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.records = {
            '8.8.8.8': self.country('US', '\u7f8e\u56fd'),
            '1.1.1.1': self.country('CN', '\u4e2d\u56fd'),
            '2606:4700:4700::1111': self.country('US', '\u7f8e\u56fd'),
        }
        self.reader = types.SimpleNamespace(
            get=Mock(side_effect=lambda ip: self.records.get(ip)), close=Mock())
        self.maxmind = types.SimpleNamespace(open_database=Mock(return_value=self.reader))
        self.addCleanup(patch.stopall)
        patch.dict(sys.modules, {'maxminddb': self.maxmind}).start()
        patch('socket.create_connection', side_effect=AssertionError('network access')).start()
        patch('socket.getaddrinfo', side_effect=AssertionError('DNS lookup')).start()

    @staticmethod
    def country(code, name):
        return {'country': {'iso_code': code, 'names': {'zh-CN': name}}}

    @staticmethod
    def line(ip='8.8.8.8', ua=CHROME, moment=NOW, status=200):
        stamp = moment.strftime('%d/Oct/%Y:%H:%M:%S %z')
        return '%s - - [%s] "GET / HTTP/1.1" %d 10 "-" "%s"\n' % (ip, stamp, status, ua)

    def log(self, site, rows):
        (self.root / (site + '.log')).write_text(''.join(rows), encoding='utf-8')

    def build(self, budgets=None, **kwargs):
        self.reader.get.reset_mock()
        self.reader.close.reset_mock()
        self.maxmind.open_database.reset_mock()
        report = statistics.StatisticsService(self.root, now=NOW, budgets=budgets).build(**kwargs)
        self.assertIn('client_profiles', report.keys(), 'A separate joint-request profile contract is required')
        profiles = report['client_profiles']
        self.assertEqual(set(profiles), {
            'schema_version', 'rows', 'request_count', 'represented_requests',
            'omitted_requests', 'partial', 'notice',
        })
        self.assertEqual(profiles['schema_version'], 1)
        self.assertIs(type(profiles['partial']), bool)
        self.assertIsInstance(profiles['notice'], str)
        self.assertRegex(profiles['notice'], '[\u4e00-\u9fff]')
        self.assertEqual(profiles['request_count'], report['summary']['total_requests'])
        self.assertLessEqual(len(profiles['rows']), 200)
        for row in profiles['rows']:
            self.assertEqual(set(row), set(PROFILE_FIELDS) | {'count'})
            for field in PROFILE_FIELDS:
                self.assertIsInstance(row[field], str)
            self.assertIn(row['client_type'], {'browser', 'in_app', 'api_tool', 'crawler', 'unknown'})
            self.assertIs(type(row['count']), int)
            self.assertGreater(row['count'], 0)
        for field in ('request_count', 'represented_requests', 'omitted_requests'):
            self.assertIs(type(profiles[field]), int)
            self.assertGreaterEqual(profiles[field], 0)
        self.assertEqual(sum(row['count'] for row in profiles['rows']), profiles['represented_requests'])
        self.assertEqual(profiles['represented_requests'] + profiles['omitted_requests'], profiles['request_count'])
        self.assertEqual(report['geography']['totals']['requests'], profiles['request_count'])
        self.assertEqual(report['geography']['totals']['clients'], report['summary']['unique_clients'])
        self.assertEqual(report['geography']['totals']['bytes'], report['summary']['total_bytes'])
        self.assertEqual(report['geography']['totals']['errors'], report['summary']['error_requests'])
        self.maxmind.open_database.assert_called_once()
        if self.maxmind.open_database.side_effect is None:
            self.reader.close.assert_called_once()
        json.dumps(profiles, ensure_ascii=False, allow_nan=False)
        return report

    @staticmethod
    def joint_counts(report):
        return {tuple(row[field] for field in PROFILE_FIELDS): row['count']
                for row in report['client_profiles']['rows']}

    def test_runtime_version_is_012(self):
        self.assertEqual(statistics.PLUGIN_VERSION, '0.1.12')

    def test_empty_schema_is_stable_and_does_not_change_legacy_lists(self):
        report = self.build()
        self.assertEqual(report['client_profiles']['rows'], [])
        self.assertEqual(report['client_profiles']['request_count'], 0)
        self.assertFalse(report['client_profiles']['partial'])
        for key in ('browsers', 'operating_systems', 'devices'):
            self.assertEqual(report[key], [])
        self.assertNotIn('unique_devices', report['summary'])
        self.assertIn('\u8bf7\u6c42', report['client_profiles']['notice'])
        self.assertIn('\u72ec\u7acb\u8bbe\u5907', report['client_profiles']['notice'])

    def test_joint_groups_are_observed_requests_not_marginal_products(self):
        self.log('a.example', [
            self.line(ua=CHROME), self.line(ua=CHROME, status=404),
            self.line(ua='curl/8.10.0'),
            self.line(ip='1.1.1.1', ua=ANDROID + ' MicroMessenger/8.0.49'),
        ])
        self.log('b.example', [
            self.line(ip='1.1.1.1', ua=SAFARI, status=503),
            self.line(ua=CHROME),
            self.line(ip='2606:4700:4700::1111', ua=CHROME),
        ])
        report = self.build()
        self.assertEqual(self.joint_counts(report), {
            ('US', '\u7f8e\u56fd', 'Chrome', 'Windows', 'PC', 'browser'): 4,
            ('US', '\u7f8e\u56fd', 'curl', 'Unknown', 'Unknown', 'api_tool'): 1,
            ('CN', '\u4e2d\u56fd', 'WeChat', 'Android', 'Mobile', 'in_app'): 1,
            ('CN', '\u4e2d\u56fd', 'Safari', 'iOS', 'Tablet', 'browser'): 1,
        })
        self.assertFalse(report['client_profiles']['partial'])
        self.assertEqual(report['summary']['unique_clients'], 3)
        self.assertEqual(self.reader.get.call_count, 3)
        self.assertEqual(report['client_profiles']['rows'][0]['count'], 4)

    def test_site_and_calendar_filters_are_applied_before_joint_aggregation(self):
        self.log('a.example', [
            self.line(ua=CHROME),
            self.line(ua=SAFARI, moment=NOW - dt.timedelta(days=1)),
            self.line(ua=SAFARI, moment=NOW + dt.timedelta(seconds=1)),
        ])
        self.log('b.example', [self.line(ip='1.1.1.1', ua=SAFARI)] * 4)
        self.log('a.example.error', ['2026/10/29 11:00:00 [error] diagnostic only\n'])
        report = self.build(site_name='a.example', days=1)
        self.assertEqual(self.joint_counts(report), {
            ('US', '\u7f8e\u56fd', 'Chrome', 'Windows', 'PC', 'browser'): 1,
        })
        self.reader.get.assert_called_once_with('8.8.8.8')
        self.assertEqual(len(report['server_errors']), 1)

    def test_profiles_are_not_derived_from_recent_access_or_top_ip_samples(self):
        rows = [self.line(ip=str(ipaddress.ip_address('8.8.9.1') + i), ua='curl/8.10')
                for i in range(100)]
        self.records.update({str(ipaddress.ip_address('8.8.9.1') + i): self.records['8.8.8.8']
                             for i in range(100)})
        self.log('a.example', rows)
        report = self.build(line_limit=1)
        self.assertEqual(len(report['recent_access']), 80)
        self.assertEqual(len(report['clients']), 50)
        self.assertEqual(len(report['client_profiles']['rows']), 1)
        self.assertEqual(report['client_profiles']['rows'][0]['count'], 100)
        self.assertEqual(self.reader.get.call_count, 100)

    def test_known_browser_and_wrapper_tokens_precede_shared_engine_tokens(self):
        cases = [
            (CHROME + ' Edg/130.0', ('Edge', 'Windows', 'PC')),
            (ANDROID + ' EdgA/130.0', ('Edge', 'Android', 'Mobile')),
            (SAFARI + ' EdgiOS/130.0', ('Edge', 'iOS', 'Tablet')),
            (CHROME + ' OPR/115.0', ('Opera', 'Windows', 'PC')),
            (SAFARI + ' OPiOS/3.5', ('Opera', 'iOS', 'Tablet')),
            (ANDROID + ' SamsungBrowser/26.0', ('Samsung Internet', 'Android', 'Mobile')),
            (ANDROID + ' UCBrowser/15.0', ('UC Browser', 'Android', 'Mobile')),
            (ANDROID + ' MQQBrowser/13.0', ('QQ', 'Android', 'Mobile')),
            (CHROME + ' Edg/130.0 MicroMessenger/8.0', ('WeChat', 'Windows', 'PC')),
            (ANDROID + ' MQQBrowser/13.0 MicroMessenger/8.0', ('WeChat', 'Android', 'Mobile')),
            (ANDROID + ' DingTalk/7.0', ('DingTalk', 'Android', 'Mobile')),
            (SAFARI + ' CriOS/130.0', ('Chrome', 'iOS', 'Tablet')),
            (SAFARI + ' FxiOS/131.0', ('Firefox', 'iOS', 'Tablet')),
            ('Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko', ('IE', 'Windows', 'PC')),
        ]
        for ua, expected in cases:
            with self.subTest(ua=ua):
                self.assertEqual(statistics._client_dimensions(ua), expected)

    def test_tools_and_sdks_are_named_without_reclassifying_legacy_browser_lists(self):
        cases = [
            ('curl/8.10.0', 'curl'),
            ('Wget/1.21.4', 'Wget'),
            ('python-requests/2.32.3', 'Python Requests'),
            ('python-httpx/0.27.2', 'Python HTTPX'),
            ('Python-urllib/3.12', 'Python urllib'),
            ('aiohttp/3.10.0', 'aiohttp'),
            ('Go-http-client/1.1', 'Go HTTP Client'),
            ('okhttp/4.12.0', 'OkHttp'),
            ('PostmanRuntime/7.42.0', 'Postman'),
            ('axios/1.7.7', 'Axios'),
            ('node-fetch/3.3.2', 'node-fetch'),
            ('undici', 'Undici'),
            ('Java/21.0.5', 'Java'),
            ('Apache-HttpClient/4.5.14', 'Apache HttpClient'),
            ('OpenAI/Python 1.54.0', 'OpenAI SDK'),
            ('OpenAI/JS 4.71.0', 'OpenAI SDK'),
            ('Anthropic/Python 0.39.0', 'Anthropic SDK'),
            ('Anthropic/JS 0.30.1', 'Anthropic SDK'),
            ('Boto3/1.35.0 Botocore/1.35.0', 'AWS SDK'),
            ('aws-sdk-go-v2/1.32.0', 'AWS SDK'),
        ]
        for ua, name in cases:
            with self.subTest(ua=ua):
                self.log('a.example', [self.line(ua=ua)])
                report = self.build()
                self.assertEqual(self.joint_counts(report), {
                    ('US', '\u7f8e\u56fd', name, 'Unknown', 'Unknown', 'api_tool'): 1,
                })
                self.assertEqual(report['browsers'], [{'name': 'Unknown', 'count': 1}])
                self.assertNotRegex(json.dumps(report['client_profiles']), 'malicious|attack|risk|ban')

    def test_in_app_crawler_browser_and_unknown_have_distinct_types(self):
        cases = [
            (CHROME, 'Chrome', 'browser'),
            (ANDROID + ' MQQBrowser/13.0', 'QQ', 'browser'),
            (ANDROID + ' QQ/9.0.0', 'QQ', 'in_app'),
            (ANDROID + ' MicroMessenger/8.0', 'WeChat', 'in_app'),
            (ANDROID + ' DingTalk/7.0', 'DingTalk', 'in_app'),
            (ANDROID + ' AlipayClient/10.6.0', 'Alipay', 'in_app'),
            (ANDROID + ' [FBAN/FB4A;FBAV/480.0]', 'Facebook', 'in_app'),
            (ANDROID + ' Instagram 350.0', 'Instagram', 'in_app'),
            (ANDROID.replace('; Android 14; Model-X', '; Android 14; Model-X; wv'),
             'Android WebView', 'in_app'),
            (CHROME + ' (compatible; Googlebot/2.1)', 'Googlebot', 'crawler'),
            ('bingbot/2.0', 'Bingbot', 'crawler'),
            ('randomcrawler/1.0', 'Other', 'crawler'),
            ('-', 'Unknown', 'unknown'),
            ('', 'Unknown', 'unknown'),
            ('custom-private-client/1.0', 'Unknown', 'unknown'),
        ]
        for ua, browser, kind in cases:
            with self.subTest(ua=ua):
                self.log('a.example', [self.line(ua=ua)])
                row = self.build()['client_profiles']['rows'][0]
                self.assertEqual((row['browser'], row['client_type']), (browser, kind))

    def test_unknown_and_private_geography_are_explicit_and_in_denominator(self):
        self.log('a.example', [
            self.line(ua='-'), self.line(ip='9.9.9.9', ua='-'),
            self.line(ip='10.0.0.1', ua='-'), self.line(ip='192.0.2.1', ua='-'),
        ])
        report = self.build()
        self.assertEqual(self.joint_counts(report), {
            ('US', '\u7f8e\u56fd', 'Unknown', 'Unknown', 'Unknown', 'unknown'): 1,
            ('', UNKNOWN, 'Unknown', 'Unknown', 'Unknown', 'unknown'): 3,
        })
        self.assertEqual(self.reader.get.call_count, 2)
        self.assertFalse(report['client_profiles']['partial'])

    def test_missing_database_keeps_unknown_requests_without_network_fallback(self):
        self.maxmind.open_database.side_effect = OSError('missing local database')
        self.log('a.example', [self.line(), self.line(ip='1.1.1.1')])
        profiles = self.build()['client_profiles']
        self.assertEqual(profiles['rows'], [dict(zip(PROFILE_FIELDS, (
            '', UNKNOWN, 'Chrome', 'Windows', 'PC', 'browser')), count=2)])
        self.assertTrue(profiles['partial'])
        self.assertEqual(profiles['omitted_requests'], 0)
        self.reader.get.assert_not_called()

    def test_lookup_error_is_cached_once_and_never_exposed(self):
        self.reader.get.side_effect = OSError('private database path or key')
        self.log('a.example', [self.line(), self.line(ua='curl/8.10')])
        report = self.build()
        self.assertTrue(report['client_profiles']['partial'])
        self.assertEqual(report['client_profiles']['represented_requests'], 2)
        self.assertTrue(all(row['country_code'] == '' for row in report['client_profiles']['rows']))
        self.reader.get.assert_called_once_with('8.8.8.8')
        self.assertNotIn('private database path or key', json.dumps(report['client_profiles']))

    def test_existing_lookup_cap_does_not_drop_or_double_count_geo_requests(self):
        self.log('a.example', [
            self.line(), self.line(ua='curl/8.10'),
            self.line(ip='1.1.1.1', ua=SAFARI), self.line(ip='1.1.1.1', ua=SAFARI),
        ])
        original = statistics.LocalGeography
        with patch.object(statistics, 'LocalGeography',
                          side_effect=lambda: original(max_lookups=1)):
            report = self.build()
        self.assertEqual(report['client_profiles']['request_count'], 4)
        self.assertEqual(report['client_profiles']['represented_requests'], 4)
        self.assertTrue(report['client_profiles']['partial'])
        self.assertEqual(report['geography']['unlocated']['requests'], 2)
        self.assertEqual(sum(row['count'] for row in report['client_profiles']['rows']
                             if row['country_code'] == ''), 2)
        self.reader.get.assert_called_once_with('8.8.8.8')

    def test_ipv4_mapped_ipv6_uses_existing_per_ip_cache(self):
        self.log('a.example', [
            self.line(), self.line(ip='::ffff:8.8.8.8'),
            self.line(ip='::ffff:8.8.8.8', ua='curl/8.10'),
        ])
        report = self.build()
        self.assertEqual(len(report['client_profiles']['rows']), 2)
        self.assertEqual(report['client_profiles']['represented_requests'], 3)
        self.reader.get.assert_called_once_with('8.8.8.8')

    def test_group_cap_keeps_real_groups_and_counts_repeats_without_other_bucket(self):
        countries = sorted(statistics._COUNTRY_CODES)[:201]
        rows = [self.line(ip='10.0.0.1', ua='-')]
        observed = Counter({('', UNKNOWN, 'Unknown', 'Unknown', 'Unknown', 'unknown'): 1})
        for index, code in enumerate(countries):
            ip = str(ipaddress.ip_address('8.9.0.1') + index)
            self.records[ip] = self.country(code, code)
            rows.append(self.line(ip=ip))
            observed[(code, code, 'Chrome', 'Windows', 'PC', 'browser')] += 1
        rows += [self.line(ip='8.9.0.1')] * 3
        rows += [self.line(ip=str(ipaddress.ip_address('8.9.0.1') + 200))] * 5
        rows += [self.line(ip='10.0.0.1', ua='-')] * 2
        observed[(countries[0], countries[0], 'Chrome', 'Windows', 'PC', 'browser')] += 3
        observed[(countries[-1], countries[-1], 'Chrome', 'Windows', 'PC', 'browser')] += 5
        observed[('', UNKNOWN, 'Unknown', 'Unknown', 'Unknown', 'unknown')] += 2
        self.log('a.example', rows)
        report = self.build()
        profiles = report['client_profiles']
        self.assertEqual(len(profiles['rows']), 200)
        self.assertEqual(profiles['request_count'], 212)
        self.assertEqual(profiles['represented_requests'], 205)
        self.assertEqual(profiles['omitted_requests'], 7)
        self.assertTrue(profiles['partial'])
        self.assertIn('200', profiles['notice'])
        self.assertTrue(report['coverage']['complete'])
        self.assertEqual(self.reader.get.call_count, 201)
        for key, count in self.joint_counts(report).items():
            self.assertEqual(count, observed[key])
        self.assertEqual(self.joint_counts(report)[('', UNKNOWN, 'Unknown', 'Unknown', 'Unknown', 'unknown')], 3)
        self.assertEqual(report['client_profiles'], self.build()['client_profiles'])

    def test_unknown_after_group_cap_is_still_in_request_and_omission_totals(self):
        rows = []
        for index, code in enumerate(sorted(statistics._COUNTRY_CODES)[:200]):
            ip = str(ipaddress.ip_address('8.9.0.1') + index)
            self.records[ip] = self.country(code, code)
            rows.append(self.line(ip=ip))
        rows += [self.line(ip='10.0.0.1', ua='-')] * 3
        self.log('a.example', rows)
        profiles = self.build()['client_profiles']
        self.assertEqual((profiles['request_count'], profiles['represented_requests'],
                          profiles['omitted_requests']), (203, 200, 3))
        self.assertTrue(profiles['partial'])

    def test_group_cap_uses_first_request_order_not_ip_group_order(self):
        countries = sorted(statistics._COUNTRY_CODES)[:200]
        ips = [str(ipaddress.ip_address('8.9.0.1') + index) for index in range(200)]
        for ip, code in zip(ips, countries):
            self.records[ip] = self.country(code, code)
        last_group = (countries[-1], countries[-1], 'Chrome', 'Windows', 'PC', 'browser')
        late_group = (countries[0], countries[0], 'curl', 'Unknown', 'Unknown', 'api_tool')
        for repeats in (False, True):
            with self.subTest(repeats=repeats):
                rows = [self.line(ip=ip) for ip in ips]
                rows.append(self.line(ip=ips[0], ua='curl/8.10'))
                expected = {(code, code, 'Chrome', 'Windows', 'PC', 'browser'): 1
                            for code in countries}
                if repeats:
                    # Matching traffic after the cap still belongs to the retained group,
                    # including a later first occurrence from another IP in that country.
                    self.records['8.10.0.1'] = self.country(countries[-1], countries[-1])
                    rows += [self.line(ip=ips[-1])] * 3
                    rows += [self.line(ip='8.10.0.1')] * 2
                    rows += [self.line(ip=ips[0], ua='curl/8.11')] * 2
                    expected[last_group] += 5
                self.log('a.example', rows)
                report = self.build()
                counts = self.joint_counts(report)
                self.assertTrue(last_group in counts, 'The 200th first-seen group must be retained')
                self.assertFalse(late_group in counts, 'The 201st group must not jump ahead with its IP')
                self.assertEqual(counts, expected)
                profiles = report['client_profiles']
                self.assertEqual(profiles['request_count'], 208 if repeats else 201)
                self.assertEqual(profiles['represented_requests'], 205 if repeats else 200)
                self.assertEqual(profiles['omitted_requests'], 3 if repeats else 1)
                self.assertTrue(profiles['partial'])
                self.assertEqual(self.reader.get.call_count, 201 if repeats else 200)

    def test_profile_keys_obey_existing_cardinality_budget_before_accepting_rows(self):
        self.log('a.example', [
            self.line(ua='curl/8.10'), self.line(ua='curl/8.11'), self.line(ua='Wget/1.21'),
        ])
        report = self.build(budgets={'max_keys': 12})
        self.assertIn('cardinality_budget', report['coverage']['reasons'])
        self.assertEqual(report['summary']['total_requests'], 2)
        self.assertEqual(report['client_profiles']['represented_requests'], 2)
        self.assertEqual(report['client_profiles']['omitted_requests'], 0)
        self.assertTrue(report['client_profiles']['partial'])
        for key in ('browsers', 'operating_systems', 'devices'):
            self.assertEqual(report[key], [{'name': 'Unknown', 'count': 2}])

    def test_no_row_is_counted_when_first_row_exceeds_cardinality_budget(self):
        self.log('a.example', [self.line()])
        profiles = self.build(budgets={'max_keys': 1})['client_profiles']
        self.assertEqual(profiles['request_count'], 0)
        self.assertTrue(profiles['partial'])
        self.reader.get.assert_not_called()

    def test_post_scan_time_budget_preserves_all_accepted_request_totals(self):
        clock = [0.0]
        self.log('a.example', [
            self.line(), self.line(),
            self.line(ip='1.1.1.1'),
            self.line(ip='2606:4700:4700::1111'), self.line(ip='2606:4700:4700::1111'),
        ])

        def lookup(ip):
            clock[0] += 0.02
            return self.records[ip]

        self.reader.get.side_effect = lookup
        with patch.object(statistics.time, 'monotonic', side_effect=lambda: clock[0]):
            report = self.build(budgets={'max_seconds': 0.05})
        profiles = report['client_profiles']
        self.assertEqual(profiles['request_count'], 5)
        self.assertEqual(profiles['represented_requests'], 3)
        self.assertEqual(profiles['omitted_requests'], 2)
        self.assertTrue(profiles['partial'])
        self.assertIn('\u65f6\u95f4', profiles['notice'])
        self.assertEqual(report['geography']['located']['requests'], 5)
        self.assertEqual(self.reader.get.call_count, 3)

    def test_scan_deadline_does_not_lose_already_accepted_rows(self):
        clock = [0.0]
        original = statistics._parse_access
        parsed = [0]

        def parse(line):
            result = original(line)
            parsed[0] += 1
            if parsed[0] == 2:
                clock[0] = 1.0
            return result

        self.log('a.example', [self.line()] * 10)
        with patch.object(statistics.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(statistics, '_parse_access', side_effect=parse):
            report = self.build(budgets={'max_seconds': 0.5})
        profiles = report['client_profiles']
        self.assertEqual(profiles['request_count'], 2)
        self.assertEqual(profiles['represented_requests'], 0)
        self.assertEqual(profiles['omitted_requests'], 2)
        self.assertIn('time_budget', report['coverage']['reasons'])
        self.assertTrue(profiles['partial'])

    def test_byte_sampling_and_invalid_lines_are_reported_as_partial(self):
        self.log('a.example', [self.line()] * 100)
        report = self.build(budgets={'max_bytes': 2048})
        self.assertTrue(report['client_profiles']['partial'])
        self.assertGreater(report['client_profiles']['request_count'], 0)
        self.assertLess(report['client_profiles']['request_count'], 100)
        self.assertEqual(report['client_profiles']['omitted_requests'], 0)
        self.log('a.example', [self.line(), 'not an access record\n'])
        report = self.build()
        self.assertEqual(report['client_profiles']['request_count'], 1)
        self.assertTrue(report['client_profiles']['partial'])

    def test_output_never_contains_raw_agents_ips_models_or_unique_device_estimates(self):
        ua = ANDROID.replace('Model-X', 'Secret-Model-123') + ' private-token-456'
        self.log('a.example', [self.line(ua=ua), self.line(ua=CHROME)] * 3)
        report = self.build()
        encoded = json.dumps(report['client_profiles'])
        for private in ('8.8.8.8', ua, 'Secret-Model-123', 'private-token-456', 'user_agent',
                        'Windows 10', 'Windows 11', 'unique_devices', 'fingerprint'):
            self.assertNotIn(private, encoded)
        self.assertEqual(report['summary']['unique_clients'], 1)
        self.assertEqual(report['client_profiles']['request_count'], 6)
        self.assertEqual(len(report['client_profiles']['rows']), 2)


if __name__ == '__main__':
    unittest.main()
