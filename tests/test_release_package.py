import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]


class ReleasePackageTest(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'tools/build_release.py'
        self.assertTrue(path.is_file(), 'release builder is missing')
        spec = importlib.util.spec_from_file_location('release_builder', path)
        self.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.builder)

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
                self.assertEqual(metadata['versions'], '0.1')
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


if __name__ == '__main__':
    unittest.main()
