import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]


class ReleasePackageTest(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'tools/build_release.py'
        self.assertTrue(path.is_file(), 'release builder is missing')
        spec = importlib.util.spec_from_file_location('release_builder', path)
        self.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.builder)

    def test_v011_packages_local_services_and_regressions(self):
        self.assertEqual(self.builder.VERSION, '0.1.10')
        for name in ('website_statistics.py', 'update_service.py', 'docs/UPDATES.md'):
            self.assertIn(name, self.builder.PLUGIN_FILES)
        for name in ('tests/test_website_statistics.py', 'tests/test_update_service.py',
                     'tests/test_v011_integration.py', 'tests/test_statistics_v011.js',
                     'tests/test_plugin_update_ui.js'):
            self.assertIn(name, self.builder.SOURCE_FILES)

    def test_release_archive_matches_the_updaters_managed_files(self):
        spec = importlib.util.spec_from_file_location('release_update_service', ROOT / 'update_service.py')
        updater = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(updater)
        self.assertEqual(set(self.builder.PLUGIN_FILES), set(updater.MANAGED_FILES))
        self.assertEqual(len(self.builder.PLUGIN_FILES), len(updater.MANAGED_FILES))
        with tempfile.TemporaryDirectory() as directory:
            result = self.builder.build(ROOT, Path(directory) / 'output')
            service = updater.UpdateService(Path(directory) / 'panel/plugin/free_waf', test_mode=True)
            payloads = service._payloads(Path(result['archive']).read_bytes(), self.builder.VERSION)
            self.assertEqual(set(payloads), set(self.builder.PLUGIN_FILES))

    def test_forum_regressions_ship_only_in_the_source_snapshot(self):
        names = ('tests/test_forum_regressions.py', 'tests/test_post_forwarding_runtime.py')
        for name in names:
            self.assertIn(name, self.builder.SOURCE_FILES)
            self.assertNotIn(name, self.builder.PLUGIN_FILES)
        self.assertEqual(len(self.builder.PLUGIN_FILES), 21)
        with tempfile.TemporaryDirectory() as directory:
            result = self.builder.build(ROOT, Path(directory) / 'output')
            for name in names:
                self.assertEqual((Path(result['source']) / name).read_bytes(), (ROOT / name).read_bytes())

    def test_existing_defect_regressions_do_not_expand_runtime_payload(self):
        for name in ('tests/test_cc_scope.py', 'tests/test_report_pagination_ui.js',
                     'tests/test_cc_config_validation.py', 'tests/test_report_backend_regressions.py'):
            self.assertIn(name, self.builder.SOURCE_FILES)
            self.assertNotIn(name, self.builder.PLUGIN_FILES)
        self.assertEqual(len(self.builder.PLUGIN_FILES), 21)

    def test_agent_entrypoint_ships_in_source_without_expanding_upgrade_manifest(self):
        self.assertIn('AGENTS.md', self.builder.SOURCE_FILES)
        self.assertNotIn('AGENTS.md', self.builder.PLUGIN_FILES)
        self.assertEqual(len(self.builder.PLUGIN_FILES), 21)
        with tempfile.TemporaryDirectory() as directory:
            result = self.builder.build(ROOT, Path(directory) / 'output')
            entrypoint = (Path(result['source']) / 'AGENTS.md').read_text(encoding='utf-8')
            self.assertIn('docs/UPGRADE.md#agent-安装升级清单', entrypoint)
            with zipfile.ZipFile(result['archive']) as archive:
                guide = archive.read('free_waf/docs/UPGRADE.md').decode('utf-8')
                readme = archive.read('free_waf/README.md').decode('utf-8')
                self.assertIn('## Agent 安装升级清单', guide)
                self.assertIn('docs/UPGRADE.md#agent-安装升级清单', readme)
                self.assertNotIn('free_waf/AGENTS.md', archive.namelist())

    def test_release_excludes_private_docs_and_unknown_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            output = Path(directory) / 'output'
            for name in self.builder.SOURCE_FILES:
                source = ROOT / name
                self.assertTrue(source.is_file(), 'missing public source: ' + name)
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            (root / 'private.log').write_text('private content')
            (root / '.env').write_text('PRIVATE_KEY=fixture')
            (root / 'docs/plans').mkdir(parents=True)
            (root / 'docs/plans/secret.md').write_text('private server details')
            result = self.builder.build(root, output)
            self.assertFalse((output / 'source/private.log').exists())
            self.assertFalse((output / 'source/docs/plans').exists())
            self.assertFalse((output / 'source/.env').exists())
            with zipfile.ZipFile(result['archive']) as archive:
                names = archive.namelist()
                self.assertEqual(set(names), {'free_waf/' + name for name in self.builder.PLUGIN_FILES})
                self.assertTrue(all('..' not in name.split('/') and not name.startswith('/') for name in names))
                metadata = json.loads(archive.read('free_waf/info.json'))
                self.assertEqual(metadata['versions'], '0.1.10')
                self.assertIn('install.sh', ' '.join(names))
            self.assertTrue((output / 'SHA256SUMS').is_file())

    def test_build_is_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.builder.build(ROOT, Path(directory) / 'first')
            second = self.builder.build(ROOT, Path(directory) / 'second')
            self.assertEqual(Path(first['archive']).read_bytes(), Path(second['archive']).read_bytes())

    def test_private_key_marker_in_allowed_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            for name in self.builder.SOURCE_FILES:
                source = ROOT / name
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            with (root / 'README.md').open('a', encoding='utf-8') as stream:
                stream.write('\n-----BEGIN OPENSSH PRIVATE KEY-----\n')
            with self.assertRaises(ValueError):
                self.builder.build(root, Path(directory) / 'output')

    def test_version_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            for name in self.builder.SOURCE_FILES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            metadata = json.loads((root / 'info.json').read_text(encoding='utf-8'))
            metadata['versions'] = '5.0'
            (root / 'info.json').write_text(json.dumps(metadata), encoding='utf-8')
            with self.assertRaises(ValueError):
                self.builder.build(root, Path(directory) / 'output')

    def test_release_notes_reject_local_user_paths_without_echoing_them(self):
        validator = getattr(self.builder, 'validate_public_text', None)
        self.assertTrue(callable(validator), 'release notes need an explicit privacy gate')
        paths = ['C:' + '/Users/' + 'fixture-person/private.txt',
                 'C:' + '\\Users\\' + 'fixture-person\\private.txt',
                 '/' + 'home/' + 'fixture-person/private.txt',
                 '/' + 'Users/' + 'fixture-person/private.txt']
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ValueError) as failure:
                validator('Update evidence: ' + path, 'release notes', public_document=True)
            self.assertNotIn(path, str(failure.exception))
            self.assertNotIn('fixture-person', str(failure.exception))

    def test_external_private_terms_cover_notes_without_entering_public_source(self):
        validator = getattr(self.builder, 'validate_public_text', None)
        self.assertTrue(callable(validator), 'private terms must be checked outside the public source')
        private = 'private-fixture-' + 'node'
        with self.assertRaises(ValueError) as failure:
            validator('Do not deploy ' + private.upper() + '.', 'release notes',
                      private_terms=[private], public_document=True)
        self.assertNotIn(private, str(failure.exception).lower())
        with self.assertRaises(ValueError):
            validator('ssh_' + private + ': private alias', 'release notes', private_terms=[private])
        validator('private-fixture-nodes is a different word', 'release notes',
                  private_terms=[private], public_document=True)
        validator('Use the BaoTa Nginx path /www/server/nginx/sbin/nginx.',
                  'release notes', public_document=True)

    def test_private_term_file_is_strict_bounded_and_never_reported_in_errors(self):
        loader = getattr(self.builder, 'load_private_terms', None)
        self.assertTrue(callable(loader), 'private audit terms require a local-only loader')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'terms.json'
            path.write_text(json.dumps(['private-fixture-node']), encoding='utf-8')
            self.assertEqual(loader(path), ['private-fixture-node'])
            for value in ({'hostname': 'private-fixture-node'}, [], [''], [1],
                          ['x' * 257], ['x'] * 257, ['line\nbreak']):
                path.write_text(json.dumps(value), encoding='utf-8')
                with self.subTest(value=type(value).__name__), self.assertRaises(ValueError) as failure:
                    loader(path)
                self.assertNotIn(str(path), str(failure.exception))

    def test_source_text_also_rejects_user_home_paths(self):
        validator = getattr(self.builder, 'validate_public_text', None)
        self.assertTrue(callable(validator))
        with self.assertRaises(ValueError):
            validator('input_path = "C:' + '/Users/' + 'fixture-person/config.json"', 'fixture.py')

    def _private_home_path_cases(self):
        slash = '\\'
        return (
            ('escaped_windows', 'C:' + slash * 2 + 'Users' + slash * 2
             + 'fixture-person' + slash * 2 + 'private.txt'),
            ('unc_users', slash * 2 + 'fixture-workstation' + slash + 'Users'
             + slash + 'fixture-person' + slash + 'private.txt'),
            ('escaped_unc_profiles', slash * 4 + 'fixture-workstation' + slash * 2
             + 'Profiles' + slash * 2 + 'fixture-person' + slash * 2 + 'private.txt'),
            ('root_ssh', '/' + 'root/' + '.ssh/id_rsa'),
            ('root_codex', '/' + 'root/' + '.codex/config.toml'),
            ('root_desktop', '/' + 'root/' + 'Desktop/fixture-person.txt'),
            ('root_documents', '/' + 'root/' + 'Documents/fixture-person.txt'),
        )

    def test_private_home_notes_are_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            for case, path in self._private_home_path_cases():
                with self.subTest(case=case):
                    output = Path(directory) / case
                    with self.assertRaises(ValueError) as failure:
                        self.builder.build(ROOT, output, release_notes='Evidence: ' + path,
                                           private_terms=['excluded-' + 'fixture-host'])
                    self.assertIn('本地用户目录', str(failure.exception))
                    self.assertNotIn(path, str(failure.exception))
                    self.assertNotIn('fixture-person', str(failure.exception))
                    self.assertFalse(output.exists())

    def test_private_home_source_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            for name in self.builder.SOURCE_FILES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            target = root / 'tools/check.py'
            original = target.read_text(encoding='utf-8')
            for case, path in self._private_home_path_cases():
                with self.subTest(case=case):
                    target.write_text(original + '\n# Evidence: ' + path + '\n', encoding='utf-8')
                    output = Path(directory) / case
                    with self.assertRaises(ValueError) as failure:
                        self.builder.build(root, output)
                    self.assertIn('本地用户目录', str(failure.exception))
                    self.assertNotIn(path, str(failure.exception))
                    self.assertNotIn('fixture-person', str(failure.exception))
                    self.assertFalse(output.exists())

    def test_generic_backup_and_vendor_paths_remain_public(self):
        # Generic root backup instructions are not personalized profile paths.
        paths = ('/root/gpt-firewall-backups/20261027-120000',
                 '/www/server/nginx/sbin/nginx',
                 'C:' + '\\ProgramData\\Vendor\\config.json',
                 'https://vendor.example/Users/guide')
        for path in paths:
            with self.subTest(path=path):
                self.builder.validate_public_text(path, 'release notes', public_document=True)
                self.builder.validate_public_text(path, 'fixture.py')

    def test_cli_resolve_failures_do_not_disclose_values(self):
        original_resolve = Path.resolve
        with tempfile.TemporaryDirectory() as directory:
            notes, terms = Path(directory) / 'notes.md', Path(directory) / 'terms.json'
            notes.write_text('Manual site-only analysis.', encoding='utf-8')
            terms.write_text('["private-fixture-node"]', encoding='utf-8')
            targets = {'root': ROOT, 'private_terms': terms,
                       'default_root': Path(self.builder.__file__)}
            for case, target in targets.items():
                for error_type in (OSError, RuntimeError):
                    for with_output in (False, True):
                        with self.subTest(case=case, error=error_type.__name__, output=with_output):
                            output = Path(directory) / 'output'
                            argv = ['build_release.py', '--check-notes', str(notes),
                                    '--private-terms', str(terms)]
                            if case != 'default_root':
                                argv.extend(['--root', str(ROOT)])
                            if with_output:
                                argv.extend(['--output', str(output)])

                            def resolve(path, *args, **kwargs):
                                if path == target:
                                    raise error_type('private-fixture-value: ' + str(path))
                                return original_resolve(path, *args, **kwargs)

                            stdout, stderr = io.StringIO(), io.StringIO()
                            with mock.patch.object(sys, 'argv', argv), \
                                    mock.patch.object(Path, 'resolve', new=resolve), \
                                    contextlib.redirect_stdout(stdout), \
                                    contextlib.redirect_stderr(stderr):
                                try:
                                    self.builder.main()
                                    code = 0
                                except SystemExit as error:
                                    code = error.code
                                except (OSError, RuntimeError):
                                    code = None
                            self.assertEqual(code, 2, 'resolution errors must become sanitized CLI exits')
                            self.assertEqual(stdout.getvalue(), '')
                            self.assertTrue(stderr.getvalue())
                            for value in ('private-fixture-value', str(target), str(notes),
                                          str(terms), str(output), 'Traceback'):
                                self.assertNotIn(value, stderr.getvalue())
                            self.assertFalse(output.exists())

    def test_private_terms_validate_allowed_source_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            for name in self.builder.SOURCE_FILES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            private = 'private-fixture-' + 'node'
            with (root / 'README.md').open('a', encoding='utf-8') as stream:
                stream.write('\n' + private + '\n')
            output = Path(directory) / 'output'
            with self.assertRaises(ValueError):
                self.builder.build(root, output, private_terms=[private])
            self.assertFalse(output.exists())

    def test_release_notes_are_checked_before_any_package_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            private = 'private-fixture-' + 'node'
            with self.assertRaises(ValueError):
                self.builder.build(ROOT, output, release_notes='Keep ' + private + ' unchanged',
                                   private_terms=[private])
            self.assertFalse(output.exists())

    def test_notes_supplied_to_builder_cannot_skip_the_private_list(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            with self.assertRaises(ValueError):
                self.builder.build(ROOT, output, release_notes='Manual site-only analysis.')
            self.assertFalse(output.exists())

    def test_release_notes_reject_credentials_even_without_a_private_term_list(self):
        validator = getattr(self.builder, 'validate_public_text', None)
        self.assertTrue(callable(validator), 'release notes must use the credential guard')
        with self.assertRaises(ValueError):
            validator('token: ' + 'ghp_' + 'x' * 40, 'release notes', public_document=True)
        for prefix in ('', '   ', '> '):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                validator(prefix + '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----', 'release notes')

    def test_notes_only_cli_needs_private_terms_and_never_creates_a_package(self):
        with tempfile.TemporaryDirectory() as directory:
            notes, terms = Path(directory) / 'notes.md', Path(directory) / 'terms.json'
            notes.write_text('Manual site-only analysis. No automatic bans.', encoding='utf-8')
            terms.write_text('["private-fixture-node"]', encoding='utf-8')
            command = [sys.executable, '-B', str(ROOT / 'tools/build_release.py'),
                       '--check-notes', str(notes), '--private-terms', str(terms)]
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['notes_checked'])
            self.assertEqual(set(Path(directory).iterdir()), {notes, terms})
            result = subprocess.run(command[:-2], capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(str(notes).encode(), result.stderr)
            notes.write_text('Private ' + 'private-fixture-node', encoding='utf-8')
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'private-fixture-node', result.stderr)


if __name__ == '__main__':
    unittest.main()
