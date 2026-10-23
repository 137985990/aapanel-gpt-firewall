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
            self.assertEqual(worker.communicate.call_args_list[0].kwargs['timeout'], 5)
            worker.kill.assert_called_once()
            self.assertIs(spawn.call_args.kwargs['shell'], False)
            self.assertIs(spawn.call_args.kwargs['close_fds'], True)

    def test_process_identity_alone_cannot_replace_socket_ownership(self):
        self.assertTrue(hasattr(IntegrationRepairService, '_verify_peer'))
        connection = Mock(sock=None)
        self.assertFalse(IntegrationRepairService._verify_peer(connection, 123, Path('/expected/nginx'), '1:100'))


if __name__ == '__main__':
    unittest.main()
