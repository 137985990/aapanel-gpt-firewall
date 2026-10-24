import datetime as dt
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import website_statistics as statistics


NOW = dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc)


class LocalGeographyTest(unittest.TestCase):
    def locator(self, records=None, **kwargs):
        reader = types.SimpleNamespace(get=Mock(side_effect=lambda ip: (records or {}).get(ip)), close=Mock())
        locator = statistics.LocalGeography(reader=reader, **kwargs)
        self.addCleanup(locator.close)
        return locator, reader

    def test_standard_records_prefer_chinese_and_keep_parent_codes(self):
        locator, reader = self.locator({'8.8.8.8': {
            'country': {'iso_code': 'us', 'names': {'en': 'United States', 'zh-CN': '美国'}},
            'subdivisions': [{'iso_code': 'CA', 'names': {'en': 'California', 'zh-CN': '加利福尼亚州'}}],
            'city': {'names': {'en': 'Mountain View', 'zh-CN': '山景城'}},
        }})
        result = locator.lookup('8.8.8.8')
        self.assertEqual(result, dict(country_code='US', country_name='美国', region_code='CA',
                                     region_name='加利福尼亚州', city_name='山景城',
                                     location='美国 加利福尼亚州 山景城', status='located'))
        self.assertEqual(locator.lookup('::ffff:8.8.8.8'), result)
        reader.get.assert_called_once_with('8.8.8.8')
        locator.close()
        locator.close()
        reader.close.assert_called_once_with()

    def test_panel_custom_record_and_unicode_are_supported(self):
        locator, _ = self.locator({'1.1.1.1': {'country': {
            'en_short_code': 'CN', 'country': '中国', 'province': '广东省', 'city': '广州市',
        }}})
        self.assertEqual(locator.lookup('1.1.1.1')['location'], '中国 广东省 广州市')

    def test_private_invalid_and_reserved_addresses_never_query_database(self):
        locator, reader = self.locator()
        for ip in ('10.0.0.1', '127.0.0.1', '192.168.1.1', '100.64.0.1', '::1', 'fe80::1', 'fc00::1', '192.0.2.1'):
            self.assertEqual(locator.lookup(ip)['status'], 'private', ip)
        self.assertEqual(locator.lookup('not-an-ip')['status'], 'invalid')
        reader.get.assert_not_called()

    def test_registered_country_is_not_a_location_and_bad_codes_are_unknown(self):
        for record in ({'registered_country': {'iso_code': 'US'}},
                       {'country': {'iso_code': 'ZZ', 'country': 'Somewhere'}},
                       {'country': ['US']}, [], None):
            result = statistics.LocalGeography.describe('8.8.8.8', record)
            self.assertEqual(result['status'], 'unknown')
            self.assertEqual(result['country_code'], '')

    def test_names_are_plain_bounded_text_and_malformed_subdivisions_do_not_raise(self):
        result = statistics.LocalGeography.describe('8.8.8.8', {
            'country': {'iso_code': 'US', 'names': {'zh-CN': '<country>\x00' + 'x' * 500}},
            'subdivisions': ['bad'], 'city': {'names': ['bad']},
        })
        self.assertTrue(result['country_name'].startswith('<country>'))
        self.assertLessEqual(len(result['country_name']), 128)
        self.assertNotIn('\x00', result['location'])
        self.assertEqual(result['city_name'], '')

    def test_lookup_count_and_deadline_are_bounded_without_unbounded_cache(self):
        locator, reader = self.locator(max_lookups=1)
        self.assertEqual(locator.lookup('8.8.8.8')['status'], 'unknown')
        self.assertEqual(locator.lookup('1.1.1.1')['status'], 'limited')
        self.assertEqual(locator.lookup('9.9.9.9')['status'], 'limited')
        self.assertEqual(reader.get.call_count, 1)
        self.assertLessEqual(len(locator.cache), 1)
        deadline, other = self.locator()
        deadline.deadline = 0
        self.assertEqual(deadline.lookup('8.8.8.8')['status'], 'limited')
        other.get.assert_not_called()

    def test_lookup_error_does_not_escape_and_is_cached(self):
        locator, reader = self.locator()
        reader.get.side_effect = ValueError('private database error')
        first = locator.lookup('8.8.8.8')
        self.assertEqual(first['status'], 'lookup_error')
        self.assertEqual(locator.lookup('8.8.8.8'), first)
        reader.get.assert_called_once()
        self.assertNotIn('private database error', json.dumps(first))

    def test_missing_local_database_does_not_attempt_online_fallback(self):
        module = types.SimpleNamespace(open_database=Mock(side_effect=OSError('missing')))
        with patch.dict(sys.modules, {'maxminddb': module}), \
                patch('socket.create_connection', side_effect=AssertionError('network lookup')):
            with statistics.LocalGeography() as locator:
                self.assertFalse(locator.available)
                self.assertEqual(locator.lookup('8.8.8.8')['status'], 'unavailable')
        module.open_database.assert_called_once_with('/www/server/panel/config/GeoLite2-City.mmdb')


class VisitorGeographyTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.records = {
            '8.8.8.8': {'country': {'iso_code': 'US', 'names': {'zh-CN': '美国'}},
                        'subdivisions': [{'iso_code': 'CA', 'names': {'zh-CN': '加州'}}],
                        'city': {'names': {'zh-CN': '山景城'}}},
            '1.1.1.1': {'country': {'en_short_code': 'CN', 'country': '中国', 'province': '广东', 'city': '广州'}},
            '2606:4700:4700::1111': {'country': {'iso_code': 'US', 'names': {'zh-CN': '美国'}}},
        }
        self.reader = types.SimpleNamespace(get=Mock(side_effect=lambda ip: self.records.get(ip)), close=Mock())

    def log(self, site, entries):
        rows = []
        for ip, offset, size, status in entries:
            moment = NOW - dt.timedelta(hours=offset)
            stamp = moment.strftime('%d/Oct/%Y:%H:%M:%S %z')
            rows.append('%s - - [%s] "GET / HTTP/1.1" %s %s "-" "browser"\n' % (ip, stamp, status, size))
        (self.root / (site + '.log')).write_text(''.join(rows), encoding='utf-8')

    def report(self, **kwargs):
        self.reader.close.reset_mock()
        maxmind = types.SimpleNamespace(open_database=Mock(return_value=self.reader))
        with patch.dict(sys.modules, {'maxminddb': maxmind}):
            report = statistics.StatisticsService(self.root, now=NOW).build(**kwargs)
        self.reader.close.assert_called_once()
        geo = report['geography']
        self.assertEqual(geo['schema_version'], 1)
        self.assertEqual(geo['totals']['clients'], report['summary']['unique_clients'])
        self.assertEqual(geo['totals']['requests'], report['summary']['total_requests'])
        self.assertEqual(geo['totals']['bytes'], report['summary']['total_bytes'])
        for key in ('clients', 'requests', 'bytes', 'errors'):
            self.assertEqual(geo['located'][key] + geo['unlocated'][key], geo['totals'][key])
            self.assertEqual(sum(row[key] for row in geo['countries']), geo['located'][key])
        json.dumps(report, allow_nan=False)
        return report

    def test_unique_ips_are_per_window_and_site_not_sum_of_daily_or_site_counts(self):
        self.log('one.example', [('8.8.8.8', 0, 10, 200), ('8.8.8.8', 24, 20, 404), ('1.1.1.1', 0, 30, 200)])
        self.log('two.example', [('8.8.8.8', 0, 40, 200), ('2606:4700:4700::1111', 0, 50, 503)])
        whole = self.report()
        self.assertEqual(whole['geography']['totals']['clients'], 3)
        us = next(row for row in whole['geography']['countries'] if row['code'] == 'US')
        self.assertEqual((us['clients'], us['requests'], us['bytes'], us['errors'], us['active_days']), (2, 4, 120, 2, 2))
        self.assertEqual(sum(row['clients'] for row in us['trend']), 3)
        self.assertEqual(sum(row['requests'] for row in us['trend']), 4)
        self.assertEqual(self.reader.get.call_count, 3)
        self.reader.get.reset_mock()
        one = self.report(site_name='one.example')
        self.assertEqual(one['geography']['site'], 'one.example')
        self.assertEqual(one['geography']['totals']['clients'], 2)
        self.assertEqual(sum(row['requests'] for row in one['geography']['countries']), 3)
        self.assertEqual(self.reader.get.call_count, 2)

    def test_all_unique_ips_are_classified_not_only_top_50_clients(self):
        ips = ['8.8.8.%d' % index for index in range(1, 81)]
        self.records.update({ip: self.records['8.8.8.8'] for ip in ips})
        self.log('one.example', [(ip, 0, 1, 200) for ip in ips])
        report = self.report()
        self.assertEqual(len(report['clients']), 50)
        self.assertEqual(report['geography']['countries'][0]['clients'], 80)
        self.assertEqual(self.reader.get.call_count, 80)

    def test_unknown_private_and_ipv6_do_not_disappear_from_denominator(self):
        self.log('one.example', [(ip, 0, 10, 200) for ip in
                                ('8.8.8.8', '10.1.1.1', '9.9.9.9', '2606:4700:4700::1111')])
        geo = self.report()['geography']
        self.assertEqual((geo['located']['clients'], geo['unlocated']['clients'], geo['private']['clients']), (2, 2, 1))
        self.assertTrue(geo['lookup_complete'])
        self.assertNotIn('10.1.1.1', [call.args[0] for call in self.reader.get.call_args_list])

    def test_country_and_city_groups_keep_parent_identity_and_unknown_city(self):
        self.records['9.9.9.9'] = {'country': {'en_short_code': 'AU', 'country': '澳大利亚', 'province': '广东', 'city': '广州'}}
        self.log('one.example', [(ip, 0, 1, 200) for ip in self.records])
        geo = self.report()['geography']
        guangzhou = [row for row in geo['cities'] if row['city_name'] == '广州']
        self.assertEqual({row['country_code'] for row in guangzhou}, {'CN', 'AU'})
        self.assertTrue(any(row['country_code'] == 'US' and not row['city_name'] for row in geo['cities']))

    def test_missing_database_and_empty_logs_return_honest_metadata(self):
        self.log('one.example', [('8.8.8.8', 0, 7, 200)])
        maxmind = types.SimpleNamespace(open_database=Mock(side_effect=OSError('missing')))
        with patch.dict(sys.modules, {'maxminddb': maxmind}):
            result = statistics.StatisticsService(self.root, now=NOW).build()
        self.assertFalse(result['geography']['database_available'])
        self.assertTrue(result['geography']['partial'])
        self.assertEqual(result['geography']['unlocated']['requests'], 1)
        self.assertTrue(result['coverage']['complete'])
        (self.root / 'one.example.log').unlink()
        empty = self.report()['geography']
        self.assertEqual(empty['countries'], [])
        self.assertEqual(empty['totals']['clients'], 0)

    def test_lookup_limits_keep_full_traffic_totals_and_report_partial(self):
        self.log('one.example', [('8.8.8.8', 0, 10, 200), ('1.1.1.1', 0, 20, 200)])
        original = statistics.LocalGeography
        factory = lambda: original(reader=self.reader, max_lookups=1)
        with patch.object(statistics, 'LocalGeography', side_effect=factory):
            report = statistics.StatisticsService(self.root, now=NOW).build()
        geo = report['geography']
        self.assertFalse(geo['lookup_complete'])
        self.assertTrue(geo['partial'])
        self.assertIn('lookup_budget', geo['reasons'])
        self.assertEqual(geo['totals']['requests'], 2)
        self.assertEqual(geo['unlocated']['clients'], 1)
        self.assertTrue(report['coverage']['complete'])

    def test_region_and_city_top_limits_are_explicit_not_silent_totals_loss(self):
        entries = []
        for index in range(1, 230):
            ip = '8.8.%d.%d' % (index // 250, index % 250 + 1)
            self.records[ip] = {'country': {'en_short_code': 'US', 'country': '美国',
                                           'province': 'region-%03d' % index, 'city': 'city-%03d' % index}}
            entries.append((ip, 0, 1, 200))
        self.log('one.example', entries)
        geo = self.report()['geography']
        self.assertEqual(geo['countries'][0]['clients'], len(entries))
        self.assertLessEqual(len(geo['regions']), 200)
        self.assertTrue(geo['regions_truncated'])
        self.assertFalse(geo['cities_truncated'])
        self.assertTrue(geo['lookup_complete'])

    def test_city_cap_does_not_reduce_country_totals_or_hide_truncation(self):
        entries = []
        for index in range(520):
            ip = '8.9.%d.%d' % (index // 250, index % 250 + 1)
            self.records[ip] = {'country': {'en_short_code': 'US', 'country': '美国',
                                           'province': '同一省份', 'city': 'city-%03d' % index}}
            entries.append((ip, 0, 2, 200))
        self.log('one.example', entries)
        geo = self.report()['geography']
        self.assertEqual(geo['totals']['clients'], 520)
        self.assertEqual(geo['countries'][0]['requests'], 520)
        self.assertEqual(len(geo['cities']), 500)
        self.assertTrue(geo['cities_truncated'])
        self.assertFalse(geo['regions_truncated'])

    def test_log_sampling_is_separate_from_geolocation_completeness(self):
        self.log('one.example', [('8.8.8.8', 0, 100, 200)] * 80)
        maxmind = types.SimpleNamespace(open_database=Mock(return_value=self.reader))
        with patch.dict(sys.modules, {'maxminddb': maxmind}):
            report = statistics.StatisticsService(self.root, now=NOW, budgets={'max_bytes': 1024}).build()
        self.assertTrue(report['coverage']['partial'])
        self.assertTrue(report['geography']['lookup_complete'])
        self.assertFalse(report['geography']['partial'])
        self.assertEqual(report['geography']['totals']['requests'], report['summary']['total_requests'])
        self.assertLess(report['summary']['total_requests'], 80)

    def test_active_days_and_trends_follow_report_timezone_not_log_offset(self):
        self.log('one.example', [('8.8.8.8', 9, 10, 200), ('8.8.8.8', 7, 20, 200)])
        local_now = NOW.astimezone(dt.timezone(dt.timedelta(hours=-4)))
        maxmind = types.SimpleNamespace(open_database=Mock(return_value=self.reader))
        with patch.dict(sys.modules, {'maxminddb': maxmind}):
            report = statistics.StatisticsService(self.root, now=local_now).build(days=3)
        country = report['geography']['countries'][0]
        self.assertEqual(country['active_days'], 2)
        self.assertEqual([row['requests'] for row in country['trend']], [0, 1, 1])
        self.assertEqual([row['bytes'] for row in country['trend']], [0, 10, 20])
        self.assertEqual(country['clients'], 1)


if __name__ == '__main__':
    unittest.main()
