import copy
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock

from tests.test_panel_performance import load_backend


class CCConfigValidationTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            readFile=Mock(), writeFile=Mock(), WriteLog=Mock())
        self.backend = load_backend(self.public)
        self.backend._free_waf_main__path = str(self.root) + os.sep
        self.config = dict(cc=dict(open=True, cycle=300, limit=200, endtime=120,
                                   increase=True, operator_note='keep'), other='keep')
        self.sites = {'fixture.example': copy.deepcopy(self.config),
                      'other.example': copy.deepcopy(self.config)}
        self.backend.get_config = Mock(return_value=self.config)
        self.backend.get_site_config = Mock(return_value=self.sites)
        self.backend._free_waf_main__write_config = Mock(return_value=True)
        self.backend._free_waf_main__write_site_config = Mock(return_value=True)
        for name, value in (('config.json', self.config), ('site.json', self.sites)):
            (self.root / name).write_text(json.dumps(value), encoding='utf-8')

    def args(self, **changes):
        values = dict(siteName='fixture.example', cycle='60', limit='100',
                      endtime='30', increase='0')
        values.update(changes)
        return types.SimpleNamespace(**values)

    def snapshot(self):
        return {path.name: path.read_bytes() for path in self.root.iterdir()}

    def reject(self, endpoint, arguments):
        files = self.snapshot()
        config, sites = copy.deepcopy(self.config), copy.deepcopy(self.sites)
        try:
            result = getattr(self.backend, endpoint)(arguments)
        except Exception as error:
            self.fail('%s raised %s instead of returning a validation error' %
                      (endpoint, type(error).__name__))
        self.assertIs(result.get('status'), False)
        self.assertRegex(result.get('msg', ''), r'[\u4e00-\u9fff]')
        self.assertEqual(self.config, config)
        self.assertEqual(self.sites, sites)
        self.assertEqual(self.snapshot(), files, 'invalid requests must not even create a lock file')
        self.backend.get_config.assert_not_called()
        self.backend.get_site_config.assert_not_called()
        self.backend._free_waf_main__write_config.assert_not_called()
        self.backend._free_waf_main__write_site_config.assert_not_called()
        self.public.writeFile.assert_not_called()
        self.public.WriteLog.assert_not_called()

    def test_numeric_fields_reject_coercible_nonintegers_and_noncanonical_strings(self):
        invalid = (True, False, 1.0, 1.5, None, [], {}, b'1', '', ' 1', '1 ',
                   '+1', '-1', '01', '1.0', '1e1', '1_0', '\u0661', '\uff11', '1\n')
        for endpoint in ('set_cc_conf', 'set_site_cc_conf'):
            for field in ('cycle', 'limit', 'endtime', 'increase'):
                for value in invalid:
                    with self.subTest(endpoint=endpoint, field=field, value=repr(value)):
                        self.reject(endpoint, self.args(**{field: value}))

    def test_ranges_and_increase_switch_are_strict(self):
        for endpoint in ('set_cc_conf', 'set_site_cc_conf'):
            for field, values in (('cycle', (0, -1, 86401, '86401', '9' * 10000)),
                                  ('limit', (0, -1, 1000001, '1000001')),
                                  ('endtime', (0, -1, 61, '61', 120)),
                                  ('increase', (-1, 2, '2', 'true', 'false', '00', '01'))):
                for value in values:
                    with self.subTest(endpoint=endpoint, field=field, value=str(value)[:30]):
                        self.reject(endpoint, self.args(**{field: value}))

    def test_missing_arguments_are_validation_errors_not_exceptions(self):
        for endpoint in ('set_cc_conf', 'set_site_cc_conf'):
            for field in ('cycle', 'limit', 'endtime', 'increase'):
                with self.subTest(endpoint=endpoint, field=field):
                    arguments = self.args()
                    delattr(arguments, field)
                    self.reject(endpoint, arguments)
            with self.subTest(endpoint=endpoint, arguments=None):
                self.reject(endpoint, None)

    def test_valid_integer_and_string_boundaries_preserve_other_settings(self):
        for endpoint in ('set_cc_conf', 'set_site_cc_conf'):
            for cycle, limit, endtime, increase in ((1, 1, 1, 0),
                                                   (86400, 1000000, 60, 1),
                                                   ('60', '100', '30', '1')):
                with self.subTest(endpoint=endpoint, cycle=cycle, increase=increase):
                    config, sites = copy.deepcopy(self.config), copy.deepcopy(self.sites)
                    result = getattr(self.backend, endpoint)(self.args(
                        cycle=cycle, limit=limit, endtime=endtime, increase=increase))
                    self.assertIs(result.get('status'), True)
                    updated = self.config if endpoint == 'set_cc_conf' else self.sites['fixture.example']
                    self.assertEqual(updated['cc'], dict(open=True, cycle=int(cycle), limit=int(limit),
                                                        endtime=int(endtime), increase=bool(int(increase)),
                                                        operator_note='keep'))
                    self.assertIsInstance(updated['cc']['increase'], bool)
                    self.assertEqual(updated['other'], 'keep')
                    if endpoint == 'set_cc_conf':
                        self.assertEqual(self.sites, sites)
                    else:
                        self.assertEqual(self.config, config)
                        self.assertEqual(self.sites['other.example'], sites['other.example'])

    def test_reading_legacy_cc_does_not_normalize_or_persist_it(self):
        raw = '{"cc":{"cycle":0,"limit":-2,"endtime":7200,"increase":true}}\r\n'
        self.public.readFile.return_value = raw
        before = self.snapshot()
        result = type(self.backend).get_config(self.backend, None)
        self.assertEqual(result['cc'], json.loads(raw)['cc'])
        self.assertEqual(self.snapshot(), before)
        self.backend._free_waf_main__write_config.assert_not_called()
        self.backend._free_waf_main__write_site_config.assert_not_called()
        self.public.writeFile.assert_not_called()

    def reject_site_state(self, arguments):
        # Reuse the normal writer lock while checking that policy files stay unchanged.
        (self.root / '.endpoint-policy.lock').touch()
        files, sites = self.snapshot(), copy.deepcopy(self.backend.get_site_config.return_value)
        try:
            result = self.backend.set_site_cc_conf(arguments)
        except Exception as error:
            self.fail('invalid site state raised %s instead of returning an error' % type(error).__name__)
        self.assertIs(result.get('status'), False)
        self.assertRegex(result.get('msg', ''), r'[\u4e00-\u9fff]')
        self.assertEqual(self.snapshot(), files)
        self.assertEqual(self.backend.get_site_config.return_value, sites)
        self.backend._free_waf_main__write_site_config.assert_not_called()
        self.backend._free_waf_main__write_config.assert_not_called()
        self.public.writeFile.assert_not_called()
        self.public.WriteLog.assert_not_called()

    def test_unknown_site_returns_chinese_failure_without_policy_writes(self):
        self.reject_site_state(self.args(siteName='unknown.example'))

    def test_missing_site_cc_table_returns_chinese_failure_without_repair(self):
        del self.sites['fixture.example']['cc']
        self.reject_site_state(self.args())

    def test_malformed_site_cc_table_returns_chinese_failure_without_repair(self):
        for value in (None, [], 'bad', 1, True):
            with self.subTest(value=value):
                self.sites['fixture.example']['cc'] = value
                self.reject_site_state(self.args())

    def test_malformed_site_state_returns_chinese_failure_without_policy_writes(self):
        for value in (None, [], 'bad', 1, True):
            with self.subTest(value=value):
                self.backend.get_site_config.return_value = {'fixture.example': value}
                self.reject_site_state(self.args())

    def test_site_config_parse_errors_return_chinese_failure_without_policy_writes(self):
        for error in (ValueError('invalid json'), TypeError('invalid site entry'),
                      AttributeError('invalid site field'), KeyError('missing site field')):
            with self.subTest(error=type(error).__name__):
                self.backend.get_site_config.side_effect = error
                self.reject_site_state(self.args())


if __name__ == '__main__':
    unittest.main()
