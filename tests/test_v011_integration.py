import ast
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tests.test_panel_performance import load_backend


ROOT = Path(__file__).resolve().parents[1]


class V011IntegrationTest(unittest.TestCase):
    def setUp(self):
        self.backend = load_backend(types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg)))
        self.backend._free_waf_main__update_request_is_post = Mock(return_value=True)

    def test_update_start_rejects_non_post_before_service_creation(self):
        self.backend._free_waf_main__update_request_is_post.return_value = False
        service = Mock()
        service.return_value.start.return_value = {'status': True}
        self.backend._free_waf_main__update_service = service
        self.assertTrue(hasattr(self.backend, 'start_plugin_update'))
        self.assertFalse(self.backend.start_plugin_update(types.SimpleNamespace(tag='v0.1.2'))['status'])
        service.assert_not_called()

    def test_update_endpoints_exist_without_adding_an_external_installer(self):
        for name in ('check_plugin_update', 'start_plugin_update', 'get_plugin_update_status'):
            self.assertTrue(callable(getattr(self.backend, name, None)), name)

    def test_update_check_only_passes_a_boolean_force(self):
        self.assertTrue(hasattr(self.backend, 'check_plugin_update'))
        service = Mock()
        service.check.return_value = {'status': True, 'current_version': '0.1.2'}
        self.backend._free_waf_main__update_service = Mock(return_value=service)
        actual = self.backend.check_plugin_update(types.SimpleNamespace(
            force='true', url='https://untrusted.invalid/package.zip'))
        service.check.assert_called_once_with(force=True)
        self.assertEqual(actual['current_version'], '0.1.2')

    def test_update_start_accepts_only_a_version_tag(self):
        self.assertTrue(hasattr(self.backend, 'start_plugin_update'))
        service = Mock()
        service.start.return_value = {'status': True, 'job_id': 'fixture'}
        self.backend._free_waf_main__update_service = Mock(return_value=service)
        self.assertTrue(self.backend.start_plugin_update(
            types.SimpleNamespace(tag='v0.1.2', url='/tmp/arbitrary'))['status'])
        service.start.assert_called_once_with('v0.1.2')
        service.start.reset_mock()
        for invalid in ('../../etc/passwd', 'v0.1.2; reboot', '', 'x' * 500):
            result = self.backend.start_plugin_update(types.SimpleNamespace(tag=invalid))
            self.assertFalse(result['status'])
        service.start.assert_not_called()

    def test_update_status_is_read_only(self):
        self.assertTrue(hasattr(self.backend, 'get_plugin_update_status'))
        service = Mock()
        service.status.return_value = {'status': True, 'job': None}
        self.backend._free_waf_main__update_service = Mock(return_value=service)
        self.assertEqual(self.backend.get_plugin_update_status(None), {'status': True, 'job': None})
        service.status.assert_called_once_with()
        service.start.assert_not_called()

    def test_statistics_uses_isolated_schema_cache_and_raw_site_name(self):
        service = Mock()
        service.discover_sites.return_value = [{'site': 'fixture.invalid'}]
        self.backend._free_waf_main__statistics_service = Mock(return_value=service)
        report = Mock()
        report.request.return_value = {'status': True, 'loading': True}
        method = self.backend.get_website_statistics_summary
        with patch.dict(method.__func__.__globals__, website_reports=report):
            result = method(types.SimpleNamespace(days='7', siteName='fixture.invalid', force='false'))
        key = json.loads(report.request.call_args[0][0])
        self.assertEqual(key[0], 'website-statistics-v3-geography')
        self.assertEqual(result['site_options'], [{'site': 'fixture.invalid'}])
        self.assertFalse(report.request.call_args[1]['force'])

    def test_statistics_rejects_path_input_before_scheduling(self):
        report = Mock()
        report.request.return_value = {'status': True, 'loading': True}
        method = self.backend.get_website_statistics_summary
        with patch.dict(method.__func__.__globals__, website_reports=report):
            result = method(types.SimpleNamespace(siteName='../secret'))
        self.assertFalse(result['status'])
        report.request.assert_not_called()

    def test_statistics_builder_delegates_without_security_side_effects(self):
        service = Mock()
        service.build.return_value = {'status': True, 'schema_version': 2}
        self.backend._free_waf_main__statistics_service = Mock(return_value=service)
        result = self.backend._free_waf_main__build_website_statistics_summary(
            types.SimpleNamespace(days=3, siteName='fixture.invalid', line_limit=800))
        service.build.assert_called_once_with(days=3, site_name='fixture.invalid', line_limit=800)
        self.assertEqual(result['schema_version'], 2)

    def test_version_metadata_is_v011(self):
        self.assertEqual(json.loads((ROOT / 'info.json').read_text(encoding='utf-8'))['versions'], '0.1.10')

    def test_local_service_ignores_other_plugins_global_module_cache(self):
        foreign = types.ModuleType('update_service')
        foreign.__file__ = '/other-plugin/update_service.py'
        foreign.PLUGIN_VERSION = '0.1.10'
        foreign.origin = 'foreign'
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'update_service.py').write_text(
                "PLUGIN_VERSION = '0.1.10'\norigin = 'local'\n", encoding='utf-8')
            self.backend._free_waf_main__PATH = directory
            with patch.dict(sys.modules, update_service=foreign):
                service = self.backend._free_waf_main__local_service('update_service')
                self.assertEqual(service.origin, 'local')
                self.assertIs(sys.modules['update_service'], foreign)

    def test_local_service_reloads_changed_source_without_restarting_the_panel(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'website_statistics.py'
            path.write_text("PLUGIN_VERSION = '0.1.10'\norigin = 'before'\n", encoding='utf-8')
            self.backend._free_waf_main__PATH = directory
            first = self.backend._free_waf_main__local_service('website_statistics')
            self.assertIs(first, self.backend._free_waf_main__local_service('website_statistics'))
            stamp = path.stat().st_mtime_ns
            path.write_text("PLUGIN_VERSION = '0.1.10'\norigin = 'after_'\n", encoding='utf-8')
            os.utime(path, ns=(stamp + 1000000000, stamp + 1000000000))
            second = self.backend._free_waf_main__local_service('website_statistics')
            self.assertEqual(second.origin, 'after_')
            self.assertIsNot(first, second)


if __name__ == '__main__':
    unittest.main()
