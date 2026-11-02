import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from update_service import IntegrationRepairService, PLUGIN_VERSION, UpdateError


class IntegrationProbeTest(unittest.TestCase):
    def test_a_nonce_echo_from_an_unowned_listener_is_not_execution_evidence(self):
        self.assertTrue(hasattr(IntegrationRepairService, '_probe_loop'))
        response = Mock(status=200)
        response.read.return_value = json.dumps({'product': 'aapanel GPT Firewall',
            'version': PLUGIN_VERSION, 'nonce': 'a' * 32, 'worker_pid': 123}).encode()
        connection = Mock()
        connection.getresponse.return_value = response
        with patch('http.client.HTTPConnection', return_value=connection), \
                patch('update_service.uuid.uuid4', return_value=Mock(hex='a' * 32)), \
                patch.object(IntegrationRepairService, '_verify_peer', return_value=False), \
                patch('update_service.time.monotonic', side_effect=[0, 0, 6]):
            with self.assertRaises(UpdateError):
                IntegrationRepairService._probe_loop(Path('/expected/nginx'), '1:100')

    def test_probe_timeout_kills_worker_instead_of_retaining_a_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = IntegrationRepairService(Path(temporary) / 'www/server/panel/plugin/free_waf',
                read_configuration=lambda: '', directives=lambda body: [], test_mode=True)
            service._master_identity = Mock(return_value='1:100')
            worker = Mock(returncode=None)
            worker.communicate.side_effect = [subprocess.TimeoutExpired('probe', 5), (b'', None)]
            with patch('update_service.subprocess.Popen', return_value=worker) as spawn:
                with self.assertRaises(UpdateError):
                    service._probe()
            self.assertEqual(worker.communicate.call_args_list[0][1]['timeout'], 5)
            worker.kill.assert_called_once()
            self.assertIs(spawn.call_args[1]['shell'], False)
            self.assertIs(spawn.call_args[1]['close_fds'], True)

    def test_process_identity_alone_cannot_replace_socket_ownership(self):
        self.assertTrue(hasattr(IntegrationRepairService, '_verify_peer'))
        connection = Mock(sock=None)
        self.assertFalse(IntegrationRepairService._verify_peer(connection, 123, Path('/expected/nginx'), '1:100'))

    def test_replacement_master_is_not_used_as_the_expected_probe_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = IntegrationRepairService(Path(temporary) / 'www/server/panel/plugin/free_waf',
                read_configuration=lambda: '', directives=lambda body: [], test_mode=True)
            service._previous_master = '10:100'
            service._master_identity = Mock(return_value='20:200')
            worker = Mock(returncode=0)
            worker.communicate.return_value = (b'{"execution_verified":true,"worker_pid":200}', None)
            with patch('update_service.subprocess.Popen', return_value=worker) as spawn:
                with self.assertRaises(UpdateError):
                    service._probe()
            spawn.assert_not_called()

    def test_old_worker_cannot_prove_a_repair_reload_succeeded(self):
        response = Mock(status=200)
        response.read.return_value = json.dumps({'product': 'aapanel GPT Firewall',
            'version': PLUGIN_VERSION, 'nonce': 'a' * 32, 'worker_pid': 123}).encode()
        connection = Mock()
        connection.getresponse.return_value = response
        with patch('http.client.HTTPConnection', return_value=connection), \
                patch('update_service.uuid.uuid4', return_value=Mock(hex='a' * 32)), \
                patch.object(IntegrationRepairService, '_verify_peer', return_value=True), \
                patch('update_service.time.monotonic', side_effect=[0, 0, 6]):
            with self.assertRaises(UpdateError):
                IntegrationRepairService._probe_loop(Path('/expected/nginx'), '1:100', previous_workers=(123,))

    def dependency_service(self, root):
        service = IntegrationRepairService(root / 'www/server/panel/plugin/free_waf',
            read_configuration=lambda: '', directives=lambda body: [], test_mode=True)
        backup = root / 'backup'
        backup.mkdir()
        return service, backup

    def test_dependency_probe_uses_an_isolated_config_without_a_listener(self):
        with tempfile.TemporaryDirectory() as temporary:
            service, backup = self.dependency_service(Path(temporary))
            def command(args, **kwargs):
                config = Path(args[args.index('-c') + 1]).read_text()
                self.assertNotIn('listen ', config)
                self.assertNotIn('init_by_lua_file', config)
                self.assertIn('require("resty.core")', config)
                self.assertIn('require("cjson")', config)
                self.assertNotIn('/etc/init.d/', ' '.join(args))
                self.assertNotIn('-t', args)
                self.assertLessEqual(kwargs['timeout'], 4)
                self.assertTrue(kwargs['capture'])
                return 0, b'gpt-firewall-dependencies-' + b'a' * 32
            service._command = command
            with patch('update_service.uuid.uuid4', return_value=Mock(hex='a' * 32)):
                self.assertTrue(service._verify_dependencies(backup))
            self.assertEqual(list(backup.iterdir()), [])

    def test_dependency_probe_requires_success_and_its_exact_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            service, backup = self.dependency_service(Path(temporary))
            for result in ((0, b'wrong result'), (1, b'private diagnostic')):
                with self.subTest(result=result):
                    service._command = Mock(return_value=result)
                    with self.assertRaises(UpdateError) as raised:
                        service._verify_dependencies(backup)
                    self.assertEqual(raised.exception.code, 'lua_dependency_failed')
                    self.assertNotIn('private diagnostic', str(raised.exception))
            self.assertEqual(list(backup.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
