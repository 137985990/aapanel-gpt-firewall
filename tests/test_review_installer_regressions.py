"""Installer review regressions, using temporary trees only (never production)."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import unittest
from unittest import mock

import update_service as updater
import test_offline_installer as offline
import test_update_service as online


@contextmanager
def fixture(kind):
    case = kind()
    try:
        case.setUp()
        yield case
    finally:
        case.doCleanups()


class InstallerReviewRegressions(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: 1)() == 0,
                         'Ownership race requires Linux root')
    def test_storage_metadata_race_cannot_chown_program_through_symlink(self):
        import pwd
        try:
            account = pwd.getpwnam('www')
        except KeyError:
            self.skipTest('requires an actual www account')
        for name in ('rule/ip_black.json', '.statistics/total.json'):
            with self.subTest(name=name), fixture(offline.OfflineInstallerTest) as t:
                program = t.runtime / 'init.lua'
                target = t.runtime / name
                if name.startswith('.statistics'):
                    t.write(target, (t.runtime / 'total.json').read_text())
                    os.chown(target.parent, account.pw_uid, account.pw_gid)
                    os.chown(target, account.pw_uid, account.pw_gid)
                dump = t.root / 'nginx-dump.txt'
                t.write(dump, 'user www;\n' + dump.read_text())
                python = t.root / 'www/server/panel/pyenv/bin/python'
                python.unlink()
                bootstrap = '''import os, sys
from pathlib import Path
source = Path(sys.argv.pop(1)).read_text(encoding='utf-8')
fixture_root = Path(sys.argv[1]) / 'www/server/free_waf'
fixture_target = fixture_root / ''' + repr(name) + '''
fixture_victim = fixture_root / 'init.lua'
fixture_identity = fixture_target.stat()
chown, fchown = os.chown, os.fchown
done = []
def swap():
    if not done:
        fixture_target.unlink()
        fixture_target.symlink_to(fixture_victim)
        (fixture_root / 'race-injected').touch()
        done.append(True)
def by_path(path, *args, **kwargs):
    if Path(path) == fixture_target: swap()
    return chown(path, *args, **kwargs)
def by_fd(fd, *args, **kwargs):
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino) == (fixture_identity.st_dev, fixture_identity.st_ino): swap()
    return fchown(fd, *args, **kwargs)
os.chown, os.fchown = by_path, by_fd
exec(source)
'''
                executable = '"' + Path(sys.executable).as_posix() + '"'
                t.write(python, '#!/bin/bash\nif [[ ${5:-} == prepare_storage ]]; then\n'
                        'exec ' + executable + ' -B -c ' + shlex.quote(bootstrap) + ' "$2" "${@:3}"\n'
                        'fi\nexec ' + executable + ' "$@"\n')
                python.chmod(0o755)
                owner = program.stat().st_uid
                result = t.run_installer()
                self.assertTrue((t.runtime / 'race-injected').exists(), result.stdout + result.stderr)
                self.assertEqual(program.stat().st_uid, owner)

    @unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: 1)() == 0,
                         'Worker permissions require Linux root')
    def test_actual_worker_can_write_data_but_cannot_replace_program(self):
        import pwd
        import subprocess
        try:
            account = pwd.getpwnam('www')
        except KeyError:
            self.skipTest('requires an actual www account')
        with fixture(offline.OfflineInstallerTest) as t:
            t.root.chmod(0o755)
            t.runtime.chmod(0o755)
            (t.runtime / 'rule').chmod(0o777)
            blacklist = t.runtime / 'rule/ip_black.json'
            blacklist.chmod(0o666)
            original = blacklist.read_bytes()
            dump = t.root / 'nginx-dump.txt'
            t.write(dump, 'user www;\n' + dump.read_text())
            result = t.run_installer()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(blacklist.read_bytes(), original)
            self.assertEqual(blacklist.stat().st_uid, account.pw_uid)
            script = '''import os, sys
from pathlib import Path
from ban_store import BanStore
root = Path(sys.argv[1])
os.setgroups([])
os.setgid(int(sys.argv[3]))
os.setuid(int(sys.argv[2]))
assert not os.access(root, os.W_OK)
for name in ('rule/ip_black.json', '.statistics/total.json'):
    store = BanStore(root / name)
    with store._transaction():
        body = (root / name).read_bytes()
        temporary = root / (name + '.fixture')
        temporary.write_bytes(body)
        os.replace(temporary, root / name)
'''
            result = subprocess.run([sys.executable, '-B', '-c', script, str(t.runtime),
                                     str(account.pw_uid), str(account.pw_gid)],
                                    cwd=offline.PLUGIN_SOURCE,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_storage_migration_preserves_policy_bytes_and_does_not_expose_program_directory(self):
        import stat
        with fixture(offline.OfflineInstallerTest) as t:
            original = (t.runtime / 'rule/ip_black.json').read_bytes()
            totals = (t.runtime / 'total.json').read_bytes()
            program_mode = stat.S_IMODE(t.runtime.stat().st_mode)
            self.assertEqual(t.run_installer().returncode, 0)
            self.assertEqual((t.runtime / '.statistics/total.json').read_bytes(), totals)
            self.assertEqual((t.runtime / 'total.json').read_bytes(), totals)
            self.assertEqual((t.runtime / 'rule/ip_black.json').read_bytes(), original)
            self.assertEqual(stat.S_IMODE(t.runtime.stat().st_mode), program_mode)
            self.assertTrue((t.runtime / '.statistics/total.json.lock').is_file())
            self.assertTrue((t.runtime / 'rule/ip_black.json.lock').is_file())

    def test_existing_migrated_statistics_are_never_replaced_by_legacy_snapshot(self):
        with fixture(offline.OfflineInstallerTest) as t:
            body = json.dumps({'total': 19, 'sites': {}, 'rules': {}})
            t.write(t.runtime / '.statistics/total.json', body)
            self.assertEqual(t.run_installer().returncode, 0)
            self.assertEqual((t.runtime / '.statistics/total.json').read_text(), body)

    @unittest.skipUnless(os.name == 'posix', 'Symlink and directory modes require POSIX')
    def test_installer_refuses_symlink_parent_before_repairing_child_modes(self):
        import stat
        with fixture(offline.OfflineInstallerTest) as t:
            external = t.root / 'private-external'
            (external / 'images').mkdir(parents=True)
            external.chmod(0o700)
            (external / 'images').chmod(0o700)
            (t.plugin / 'docs').symlink_to(external, target_is_directory=True)
            self.assertNotEqual(t.run_installer().returncode, 0)
            self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((external / 'images').stat().st_mode), 0o700)

    @unittest.skipUnless(os.name == 'posix', 'Private directory modes require POSIX')
    def test_installer_preserves_private_update_and_backup_directory_modes(self):
        import stat
        with fixture(offline.OfflineInstallerTest) as t:
            private = t.plugin / 'data/updates/private-backup'
            private.mkdir(parents=True)
            for path in (private, private.parent, private.parent.parent):
                path.chmod(0o700)
            self.assertEqual(t.run_installer().returncode, 0)
            for path in (private, private.parent, private.parent.parent):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_lagrange_apply_rechecks_original_after_preparing_candidate(self):
        for action in ('edit', 'same_content_replace', 'create_missing'):
            with self.subTest(action=action), fixture(online.UpdateServiceTest) as t:
                name = 'website_statistics.py' if action == 'create_missing' else 'index.html'
                target = t.plugin / name
                write, sync = t.service._atomic_write, os.fsync
                original = target.read_bytes() if target.exists() else None
                external = original if action == 'same_content_replace' else b'operator repair\n'
                injected = []

                def racing_write(path, data, **kwargs):
                    if path != target or data != b'# new managed code\n':
                        return write(path, data, **kwargs)

                    def prepare(descriptor):
                        if not injected:
                            if action == 'same_content_replace':
                                replacement = target.with_suffix('.operator')
                                replacement.write_bytes(external)
                                os.replace(replacement, target)
                            else:
                                t.write(target, external)
                            injected.append(target.stat().st_ino)
                        return sync(descriptor)

                    with mock.patch.object(updater.os, 'fsync', side_effect=prepare):
                        return write(path, data, **kwargs)

                with mock.patch.object(t.service, '_atomic_write', side_effect=racing_write):
                    job = t.run_job()
                self.assertTrue(injected)
                self.assertEqual(job['state'], 'failed', job)
                self.assertEqual(target.read_bytes(), external)
                self.assertEqual(target.stat().st_ino, injected[0])
                self.assertIn(name, job['rollback']['conflicts'])
                self.assertFalse(t.install_calls)

    def test_lagrange_ownership_cannot_mix_old_stat_with_new_open(self):
        with fixture(online.UpdateServiceTest) as t:
            target = t.plugin / 'index.html'
            data, info = target.read_bytes(), target.stat()
            proof = dict(dev=info.st_dev, ino=info.st_ino, sha256=hashlib.sha256(data).hexdigest())
            replacement = target.with_suffix('.operator')
            replacement.write_bytes(data)
            opened = os.open
            injected = []

            def swap_on_open(path, flags, *args, **kwargs):
                if Path(path) == target and not injected:
                    os.replace(replacement, target)
                    injected.append(True)
                return opened(path, flags, *args, **kwargs)

            with mock.patch.object(updater.os, 'open', side_effect=swap_on_open):
                owned = t.service._owns_write(target, proof)
            self.assertTrue(injected)
            self.assertFalse(owned, 'An old inode cannot authenticate bytes read from a new inode')

    @unittest.skipUnless(os.name == 'posix', 'Replacing an open file requires POSIX')
    def test_lagrange_restore_rechecks_path_identity_after_fd_read(self):
        with fixture(online.UpdateServiceTest) as t:
            target = t.plugin / 'index.html'
            data, info = target.read_bytes(), target.stat()
            proof = dict(dev=info.st_dev, ino=info.st_ino, sha256=hashlib.sha256(data).hexdigest())
            replacement = target.with_suffix('.operator')
            replacement.write_bytes(data)
            external_ino = replacement.stat().st_ino
            fdopen = os.fdopen
            injected = []

            class SwapAfterRead:
                def __init__(self, stream):
                    self.stream = stream

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.stream.__exit__(*args)

                def fileno(self):
                    return self.stream.fileno()

                def read(self, *args):
                    value = self.stream.read(*args)
                    if not injected:
                        os.replace(replacement, target)
                        injected.append(True)
                    return value

            def intercepted(descriptor, mode, *args, **kwargs):
                stream = fdopen(descriptor, mode, *args, **kwargs)
                opened = os.fstat(descriptor)
                if mode == 'rb' and (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino):
                    return SwapAfterRead(stream)
                return stream

            with mock.patch.object(updater.os, 'fdopen', side_effect=intercepted):
                try:
                    t.service._atomic_write(target, b'restored old version\n', expected_write=proof)
                except updater.UpdateError as error:
                    self.assertEqual(error.code, 'concurrent')
                else:
                    self.fail('Restore overwrote an external replacement during final ownership verification')
            self.assertTrue(injected)
            self.assertEqual(target.read_bytes(), data)
            self.assertEqual(target.stat().st_ino, external_ino)

    def test_lagrange_offline_refuses_tampered_backup_without_reload(self):
        with fixture(offline.OfflineInstallerTest) as t:
            needle = 'if $candidate && [ -e "$root/fail-candidate-test" ]; then exit 1; fi'
            command = ('if $candidate; then for backup in '
                       '"$root"/www/server/free_waf/.gpt-firewall-backup.*/init.lua; do '
                       'printf "tampered backup\\n" > "$backup"; done; exit 1; fi')
            t.write(t.nginx, offline.MOCK_NGINX.replace(needle, command))
            t.nginx.chmod(0o755)
            result = t.run_installer()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(t.status()['rollback'], 'backup_invalid')
            self.assertEqual(t.status()['runtime_backup_sha256'], hashlib.sha256(offline.OLD_LUA.encode()).hexdigest())
            self.assertEqual((t.runtime / 'init.lua').read_text(), offline.NEW_LUA)
            self.assertFalse(any('-s reload' in call for call in t.calls()))
            self.assertEqual(Path(t.status()['runtime_backup'], 'init.lua').read_text(), 'tampered backup\n')

    def test_lagrange_offline_rechecks_copy_after_backup_digest_was_validated(self):
        with fixture(offline.OfflineInstallerTest) as t:
            python = t.root / 'www/server/panel/pyenv/bin/python'
            python.unlink()
            bootstrap = '''import shutil, sys
from pathlib import Path
source = Path(sys.argv.pop(1)).read_text(encoding='utf-8')
copy = shutil.copy2
def tamper(path, target, *args, **kwargs):
    Path(path).write_bytes(b"backup changed during restore copy\\n")
    return copy(path, target, *args, **kwargs)
shutil.copy2 = tamper
exec(source)
'''
            executable = '"' + Path(sys.executable).as_posix() + '"'
            t.write(python, '#!/bin/bash\nif [[ ${5:-} == restore ]]; then\n'
                    '  exec ' + executable + ' -B -c ' + shlex.quote(bootstrap) + ' "$2" "${@:3}"\n'
                    'fi\nexec ' + executable + ' "$@"\n')
            python.chmod(0o755)
            t.write(t.root / 'fail-candidate-test', '1')
            result = t.run_installer()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(t.status()['rollback'], 'backup_invalid')
            self.assertEqual((t.runtime / 'init.lua').read_text(), offline.NEW_LUA)
            self.assertFalse(any('-s reload' in call for call in t.calls()))

    def real_update(self, t):
        """Use real worker, subprocess and installer, but synthetic release/Nginx."""
        with fixture(online.UpdateServiceTest) as package:
            payload = package.archive({
                'install.sh': (t.plugin / 'install.sh').read_bytes(),
                'init.lua': offline.NEW_LUA.encode(),
                'info.json': b'{"name":"free_waf","versions":"0.1.10"}',
            })
            package.payload = payload
            package.configure_release()
            release = json.loads(json.dumps(package.release).replace('0.1.1', '0.1.10'))
            asset = online.ASSET.replace('0.1.1', '0.1.10')
            checksums = (hashlib.sha256(payload).hexdigest() + '  ' + asset + '\n').encode()
            release['assets'][1]['size'] = len(checksums)
            download = updater.DOWNLOAD_URL + 'v0.1.10/'
            responses = {
                updater.API_URL + '?per_page=100': json.dumps([release]).encode(),
                updater.API_URL + '/tags/v0.1.10': json.dumps(release).encode(),
                download + asset: payload, download + 'SHA256SUMS': checksums,
            }
        t.write_json(t.plugin / 'info.json', {'name': 'free_waf', 'versions': '0.1.7'})
        service = updater.UpdateService(t.plugin, test_mode=True,
            transport=lambda url, **kwargs: responses[url], spawn=lambda *a, **k: mock.Mock(pid=123456))
        started = service.start('v0.1.10')
        self.assertTrue(started['status'], started)
        return service, started['job_id']

    @unittest.skipUnless(os.name == 'posix', 'Authenticated descriptor inheritance requires POSIX')
    def test_r05_real_nested_installer_shares_lock_until_online_completion(self):
        with fixture(offline.OfflineInstallerTest) as t:
            service, job_id = self.real_update(t)
            result = service.run_job(job_id)
            self.assertTrue(result['status'], result)
            self.assertEqual(t.status()['task_id'], job_id)
            self.assertIsInstance(t.status()['runtime_write'], dict)
            self.assertEqual((t.runtime / 'init.lua').read_text(), offline.NEW_LUA)
            self.assertFalse((t.plugin / '.gpt-firewall-install.lock').exists())

    @unittest.skipUnless(os.name == 'posix', 'Authenticated descriptor inheritance requires POSIX')
    def test_r06_real_nested_failure_cannot_undo_operator_repair(self):
        with fixture(offline.OfflineInstallerTest) as t:
            operator = offline.OLD_LUA.replace('existing runtime', 'operator recovery')
            t.write(t.root / 'operator.lua', operator)
            needle = 'if $candidate && [ -e "$root/fail-candidate-test" ]; then exit 1; fi'
            t.write(t.nginx, offline.MOCK_NGINX.replace(needle,
                    'if $candidate; then cp "$root/operator.lua" '
                    '"$root/www/server/free_waf/init.lua"; exit 1; fi'))
            t.nginx.chmod(0o755)
            service, job_id = self.real_update(t)
            with mock.patch.object(service, '_restore_nginx') as reload:
                result = service.run_job(job_id)
            self.assertFalse(result['status'], result)
            self.assertEqual(t.status()['rollback'], 'conflict')
            self.assertIn('runtime', result['job']['rollback']['conflicts'])
            self.assertEqual((t.runtime / 'init.lua').read_text(), operator)
            reload.assert_not_called()
            self.assertFalse((t.plugin / '.gpt-firewall-install.lock').exists())

    def test_r05_existing_offline_lock_prevents_all_online_publication(self):
        with fixture(online.UpdateServiceTest) as t:
            lock = t.plugin / '.gpt-firewall-install.lock'
            lock.mkdir()
            marker = lock / 'foreign-owner'
            marker.write_bytes(b'other installer')
            before = t.snapshot()
            with mock.patch.object(t.service, '_backup', wraps=t.service._backup) as backup:
                job = t.run_job()
            self.assertEqual(job['state'], 'failed')
            self.assertEqual(job.get('error_code'), 'busy')
            backup.assert_not_called()
            self.assertFalse(t.install_calls)
            self.assertEqual(t.snapshot(), before)
            self.assertEqual(marker.read_bytes(), b'other installer')

    def test_r05_online_lock_covers_verify_backup_install_rollback_and_final_status(self):
        with fixture(online.UpdateServiceTest) as t:
            lock = t.plugin / '.gpt-firewall-install.lock'
            phases = []
            phase = t.service._phase
            save = t.service._save

            def checked_phase(job, stage, message):
                self.assertTrue(lock.is_dir(), stage)
                phases.append(stage)
                return phase(job, stage, message)

            def checked_save(path, value):
                if path == t.service.store / 'job.json' and value['state'] == 'failed':
                    self.assertTrue(lock.is_dir(), 'final status must precede unlock')
                return save(path, value)

            def failing(plugin):
                self.assertTrue(lock.is_dir())
                t.installer(plugin)
                return 1

            t.service._installer = failing
            with mock.patch.object(t.service, '_phase', side_effect=checked_phase), \
                    mock.patch.object(t.service, '_save', side_effect=checked_save), \
                    mock.patch.object(t.service, '_restore_nginx'):
                job = t.run_job()
            self.assertEqual(job['rollback']['state'], 'restored', job)
            self.assertEqual(phases, ['verify', 'stage', 'backup', 'apply', 'install', 'rollback'])
            self.assertFalse(lock.exists())

    def test_r11_online_final_status_failure_retains_lock_for_recovery(self):
        with fixture(online.UpdateServiceTest) as t:
            save = t.service._save

            def broken(path, value):
                if path == t.service.store / 'job.json' and value['state'] in ('succeeded', 'failed'):
                    raise OSError('fixture terminal status failure')
                return save(path, value)

            started = t.service.start('v0.1.1')
            with mock.patch.object(t.service, '_save', side_effect=broken), \
                    mock.patch.object(t.service, '_restore_nginx'):
                result = t.service.run_job(started['job_id'])
            self.assertFalse(result['status'])
            self.assertTrue((t.plugin / '.gpt-firewall-install.lock').is_dir())

    def test_r06_plugin_same_content_replacement_is_not_owned_by_update(self):
        with fixture(online.UpdateServiceTest) as t:
            target = t.plugin / 'index.html'

            def failing(plugin):
                t.installer(plugin)
                replacement = target.with_suffix('.operator')
                replacement.write_bytes(target.read_bytes())
                os.replace(replacement, target)
                return 1

            t.service._installer = failing
            with mock.patch.object(t.service, '_restore_nginx'):
                job = t.run_job()
            self.assertIn('index.html', job['rollback']['conflicts'])
            self.assertEqual(target.read_bytes(), b'# new managed code\n')

    def test_r06_operator_edit_during_restore_preparation_is_not_overwritten(self):
        with fixture(online.UpdateServiceTest) as t:
            target = t.plugin / 'index.html'
            write = t.service._atomic_write

            def restore_race(path, data, **kwargs):
                if path == target and data == b'# old managed code\n':
                    t.write(target, b'operator repair during restore\n')
                return write(path, data, **kwargs)

            def failing(plugin):
                t.installer(plugin)
                return 1

            t.service._installer = failing
            with mock.patch.object(t.service, '_atomic_write', side_effect=restore_race), \
                    mock.patch.object(t.service, '_restore_nginx'):
                job = t.run_job()
            self.assertEqual(target.read_bytes(), b'operator repair during restore\n')
            self.assertIn('index.html', job['rollback']['conflicts'])

    def test_r06_runtime_without_installer_ownership_proof_is_not_rolled_back(self):
        with fixture(online.UpdateServiceTest) as t:
            def failed_before_write(plugin):
                # An unrelated writer publishes bytes equal to the candidate.
                t.write(t.runtime / 'init.lua', (plugin / 'init.lua').read_bytes())
                t.write(plugin / 'install-status.json', json.dumps({
                    'operation': 'install', 'plugin_name': 'free_waf', 'version': '0.1.1',
                    'status': 'failed', 'stage': 'preflight', 'runtime_changed': False,
                }).encode())
                return 1

            t.service._installer = failed_before_write
            with mock.patch.object(t.service, '_restore_nginx') as reload:
                job = t.run_job()
            self.assertIn('runtime', job['rollback']['conflicts'])
            self.assertEqual((t.runtime / 'init.lua').read_bytes(), b'new runtime\n')
            reload.assert_not_called()

    def test_r06_offline_rollback_preserves_operator_edit_or_replacement(self):
        for action in ('edit', 'replace_same_bytes', 'remove'):
            with self.subTest(action=action), fixture(offline.OfflineInstallerTest) as t:
                target = t.runtime / 'init.lua'
                operator = offline.OLD_LUA.replace('existing runtime', 'operator recovery')
                t.write(t.root / 'operator.lua', operator)
                command = {
                    'edit': 'cp "$root/operator.lua" "$root/www/server/free_waf/init.lua"',
                    'replace_same_bytes': 'cp "$root/www/server/free_waf/init.lua" "$root/other.lua"; '
                                          'mv "$root/other.lua" "$root/www/server/free_waf/init.lua"',
                    'remove': 'rm "$root/www/server/free_waf/init.lua"',
                }[action]
                needle = 'if $candidate && [ -e "$root/fail-candidate-test" ]; then exit 1; fi'
                t.write(t.nginx, offline.MOCK_NGINX.replace(needle,
                        'if $candidate; then ' + command + '; exit 1; fi'))
                t.nginx.chmod(0o755)
                result = t.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(t.status()['rollback'], 'conflict')
                self.assertTrue(Path(t.status()['runtime_backup'], 'init.lua').is_file())
                if action == 'remove':
                    self.assertFalse(target.exists())
                else:
                    self.assertEqual(target.read_text(), operator if action == 'edit' else offline.NEW_LUA)
                self.assertFalse(any('-s reload' in call for call in t.calls()))

    def test_r11_contender_cannot_overwrite_status(self):
        with fixture(offline.OfflineInstallerTest) as t:
            lock = t.plugin / '.gpt-firewall-install.lock'
            lock.mkdir()
            status = t.plugin / 'install-status.json'
            t.write(status, '{"status":"running","task_id":"foreign-task","runtime_backup":"private"}')
            before = status.read_bytes()
            self.assertNotEqual(t.run_installer().returncode, 0)
            self.assertEqual(status.read_bytes(), before)
            self.assertTrue(lock.is_dir())
            self.assertFalse(t.calls())

    def test_r11_final_status_is_written_while_lock_owned_and_has_task_identity(self):
        with fixture(offline.OfflineInstallerTest) as t:
            python = t.root / 'www/server/panel/pyenv/bin/python'
            python.unlink()
            t.write(python, '#!/bin/bash\n'
                    'if [[ ${6:-} == status && ${7:-} != running ]]; then\n'
                    '  [[ -d "${5}/.gpt-firewall-install.lock" ]] || exit 97\n'
                    'fi\nexec "' + Path(sys.executable).as_posix() + '" "$@"\n')
            python.chmod(0o755)
            result = t.run_installer()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(t.status().get('task_id', ''), r'^[a-f0-9]{32}$')
            self.assertFalse((t.plugin / '.gpt-firewall-install.lock').exists())

    def test_r11_environment_only_cannot_impersonate_nested_installer(self):
        with fixture(offline.OfflineInstallerTest) as t:
            lock = t.plugin / '.gpt-firewall-install.lock'
            lock.mkdir()
            t.write_json(lock / 'owner.json', {'task_id': 'a' * 32, 'token': 'b' * 64})
            status = t.plugin / 'install-status.json'
            t.write(status, '{"status":"running","task_id":"foreign"}')
            before = status.read_bytes()
            with mock.patch.dict(os.environ, {'GPT_FIREWALL_INSTALL_TASK': 'a' * 32,
                                             'GPT_FIREWALL_INSTALL_TOKEN': 'b' * 64,
                                             'GPT_FIREWALL_INSTALL_FD': '199'}):
                self.assertNotEqual(t.run_installer().returncode, 0)
            self.assertEqual(status.read_bytes(), before)

    def test_r12_lua_comments_quotes_tables_and_long_strings_are_not_shell_syntax(self):
        with fixture(offline.OfflineInstallerTest) as t:
            body = r'''log_by_lua_block {
    -- administrator's "unfinished shell quote } {
    --[==[ ' } init_by_lua_file /foreign/init.lua; ]==]
    local text = [=[ } access_by_lua_file /foreign/waf.lua; { ]=]
    local nested = { data = { "escaped\"quote", 'text}' } }
    if ban_404_accumulate then ban_404_accumulate() end
}
'''
            include = offline.WAF_INCLUDE.split('log_by_lua_block')[0] + body
            t.write(t.include, include)
            t.set_active(True)
            result = t.run_installer()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(t.status()['waf_active'])
            self.assertEqual(t.include.read_text(), include)

    def test_r12_restore_parser_also_ignores_lua_comment_quotes(self):
        with fixture(online.UpdateServiceTest) as t:
            nginx = t.root / 'www/server/nginx/sbin/nginx'
            t.write(nginx, b'fixture')
            t.write(t.root / 'www/server/nginx/conf/nginx.conf', b'http {}')
            dump = (b'init_by_lua_file /www/server/free_waf/init.lua;\n'
                    b'log_by_lua_block { -- administrator\'s counter\n local x = {} }\n')
            with mock.patch.object(t.service, '_command', return_value=(0, dump)) as command:
                try:
                    t.service._restore_nginx()
                except ValueError as error:
                    self.fail('Legal Lua must not be parsed as shell: ' + str(error))
            self.assertEqual([call.args[0][1] for call in command.call_args_list], ['-t', '-T', '-s'])


class DomesticMigrationCrashRegressions(unittest.TestCase):
    def test_rollback_rechecks_owned_snapshot_before_restoring_each_entry(self):
        with fixture(offline.DomesticInstallerTest) as t:
            python = t.root / 'www/server/panel/pyenv/bin/python'
            python.unlink()
            bootstrap = """import os, sys
from pathlib import Path
source = Path(sys.argv.pop(1)).read_text(encoding='utf-8')
target = Path(sys.argv[1]) / 'www/server/free_waf/config.json'
original_open = os.open
observations = []

def injected(path, flags, *args, **kwargs):
    if Path(path) == target:
        observations.append(True)
        if len(observations) == 2:
            target.write_text('{"concurrent":true}\\n', encoding='utf-8')
    return original_open(path, flags, *args, **kwargs)
os.open = injected
exec(source)
"""
            executable = '"' + Path(sys.executable).as_posix() + '"'
            t.write(python, '#!/bin/bash\nif [[ ${5:-} == restore_domestic ]]; then\n'
                    'exec ' + executable + ' -B -c ' + shlex.quote(bootstrap) + ' "$2" "${@:3}"\n'
                    'fi\nexec ' + executable + ' "$@"\n')
            python.chmod(0o755)
            t.write(t.root / 'fail-candidate-test', '1')
            result = t.run_installer()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads((t.runtime / 'config.json').read_text()), {'concurrent': True})
            self.assertEqual(t.status()['data_rollback'], 'conflict_or_failed')
            journal = t.runtime / t.status()['data_migration_backup'] / 'compatibility-migration.json'
            self.assertEqual(json.loads(journal.read_text())['state'], 'applying')
            self.assertFalse(any('-s reload' in call for call in offline.OfflineInstallerTest.calls(t)))

    def test_write_ahead_identity_restores_a_published_file_if_journal_update_fails(self):
        with fixture(offline.DomesticInstallerTest) as t:
            python = t.root / 'www/server/panel/pyenv/bin/python'
            python.unlink()
            bootstrap = """import os, sys
from pathlib import Path
source = Path(sys.argv.pop(1)).read_text(encoding='utf-8')
runtime = Path(sys.argv[1]) / 'www/server/free_waf'
replace = os.replace
failed = []
def injected(source, destination):
    if (Path(destination).name == 'compatibility-migration.json'
            and (runtime / 'rule/cookie.json').exists() and not failed):
        failed.append(True)
        raise OSError('fixture journal failure after publication')
    return replace(source, destination)
os.replace = injected
exec(source)
"""
            executable = '"' + Path(sys.executable).as_posix() + '"'
            t.write(python, '#!/bin/bash\nif [[ ${5:-} == migrate_domestic ]]; then\n'
                    'exec ' + executable + ' -B -c ' + shlex.quote(bootstrap) + ' "$2" "${@:3}"\n'
                    'fi\nexec ' + executable + ' "$@"\n')
            python.chmod(0o755)
            before = {p.name: p.read_bytes() for p in (t.runtime / 'rule').glob('*.json')}
            result = t.run_installer()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(t.status()['data_rollback'], 'restored')
            self.assertEqual((t.runtime / 'config.json').read_bytes(), t.original_config)
            for name, body in before.items():
                self.assertEqual((t.runtime / 'rule' / name).read_bytes(), body)
            self.assertFalse((t.runtime / 'rule/cookie.json').exists())


if __name__ == '__main__':
    unittest.main()
