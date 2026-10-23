from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock

from tests.test_panel_performance import load_backend


ROOT = Path(__file__).resolve().parents[1]


class Args(dict):
    __getattr__ = dict.__getitem__


class ReleasePrivacyTest(unittest.TestCase):
    def setUp(self):
        self.public = types.SimpleNamespace(
            returnMsg=lambda status, msg: dict(status=status, msg=msg),
            httpPost=Mock(side_effect=AssertionError('cloud request attempted')),
            ExecShell=Mock(side_effect=AssertionError('external upload attempted')),
            ReadFile=Mock(side_effect=AssertionError('file content read for upload')),
            M=Mock(),
        )
        self.backend = load_backend(self.public)

    def test_local_scan_never_calls_upload_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.php'
            path.write_text('fixture-malware-marker')
            self.public.M.return_value.field.return_value.select.return_value = [
                dict(name='fixture.example', path=directory)]
            self.backend.send_baota2 = Mock(side_effect=AssertionError('automatic upload attempted'))
            self.backend.insert_log = Mock()
            result = self.backend.scan([str(path)], ['fixture-malware-marker'])
            self.assertEqual(len(result), 1)
            self.backend.send_baota2.assert_not_called()

    def test_legacy_cloud_endpoints_fail_closed_without_reading_or_sending_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private.php'
            path.write_text('private fixture')
            for method in ('send_baota', 'upload_file_url', 'check_webshell'):
                with self.subTest(method=method):
                    result = getattr(self.backend, method)(Args(filename=str(path)))
                    self.assertFalse(result['status'])
                    self.assertIn('停用', result['msg'])
            self.assertFalse(self.backend.send_baota2(str(path)))
        self.public.httpPost.assert_not_called()
        self.public.ReadFile.assert_not_called()
        self.public.ExecShell.assert_not_called()

    def test_disabled_cloud_methods_do_not_even_inspect_private_file_arguments(self):
        class PrivateArgs:
            def __getattribute__(self, name):
                raise AssertionError('private argument inspected: ' + name)
        for method in ('send_baota', 'upload_file_url', 'check_webshell'):
            self.assertFalse(getattr(self.backend, method)(PrivateArgs())['status'])
        self.assertFalse(self.backend.send_baota2(PrivateArgs()))

    def test_false_positive_action_does_not_upload_or_add_global_bypass(self):
        source = (ROOT / 'index.html').read_text(encoding='utf-8')
        body = source.split('render_site_logs:function', 1)[1].split('//', 1)[0]
        self.assertTrue('add_waf_logs' not in source, 'legacy telemetry is still present')
        self.assertTrue('add_url_white(' not in body, 'false-positive action adds a global bypass')
        self.assertTrue('rdata.msg' not in body, 'callback uses an undefined response variable')


if __name__ == '__main__':
    unittest.main()
