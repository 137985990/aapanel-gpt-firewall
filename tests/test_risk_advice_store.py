import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

import ban_store


NOW = 1793040000
HASH = 'a' * 64


def event(path, ts=NOW - 60, site='fixture.example', ip='192.0.2.17', rule='user_agent'):
    return dict(site=site, ip=ip, ts=ts, path=path, rule_type=rule)


def scan(count=30, repeats=2, families=('env', 'repository'), start=NOW - 300, step=1):
    targets = []
    for family in families:
        for index in range(count):
            suffix = {'env': '.env.production', 'repository': '.git/config',
                      'credentials': '.aws/credentials', 'backup': 'database.sql.gz'}[family]
            targets.append('/app{}/{}'.format(index, suffix))
    return [event(path, start + index * step)
            for index, path in enumerate(targets * repeats)]


class RiskAdviceAnalyzerTest(unittest.TestCase):
    def setUp(self):
        cls = getattr(ban_store, 'RiskAdviceAnalyzer', None)
        self.assertIsNotNone(cls, 'RiskAdviceAnalyzer is not implemented')
        self.analyzer = cls()

    def analyze(self, rows, now=NOW):
        return self.analyzer.analyze(rows, now=now)

    def test_empty_and_ordinary_api_are_observation_only(self):
        self.assertEqual(self.analyze([]), [])
        rows = [event('/v1/chat/completions', NOW - index, rule='empty_ua') for index in range(2000)]
        result = self.analyze(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['recommended_seconds'], 0)
        self.assertEqual(result[0]['related_rows'], 0)
        self.assertEqual(result[0]['strong_targets'], 0)
        self.assertEqual(result[0]['family_counts'], {})
        self.assertIn('\u89c2\u5bdf', result[0]['name'])

    def test_two_family_scan_recommends_24_hours_with_contract_fields(self):
        item = self.analyze(scan())[0]
        self.assertEqual(set(item), {'site', 'ip', 'fingerprint', 'name', 'recommended_seconds',
                                    'related_rows', 'strong_targets', 'family_counts', 'raw_targets',
                                    'first_seen', 'last_seen', 'samples'})
        self.assertEqual(item['recommended_seconds'], 86400)
        self.assertEqual(item['related_rows'], 120)
        self.assertEqual(item['strong_targets'], 60)
        self.assertEqual(item['family_counts'], {'env': 30, 'repository': 30})
        self.assertRegex(item['fingerprint'], r'^[0-9a-f]{64}$')
        self.assertLessEqual(len(item['samples']), 10)

    def test_high_intensity_three_family_scan_recommends_seven_days(self):
        item = self.analyze(scan(50, families=('env', 'repository', 'credentials')))[0]
        self.assertEqual(item['recommended_seconds'], 604800)
        self.assertEqual(item['strong_targets'], 150)
        self.assertEqual(item['related_rows'], 300)

    def test_single_family_requires_fifty_distinct_and_one_hundred_rows(self):
        self.assertEqual(self.analyze(scan(49, 3, ('env',)))[0]['recommended_seconds'], 0)
        self.assertEqual(self.analyze(scan(50, 1, ('env',)))[0]['recommended_seconds'], 0)
        self.assertEqual(self.analyze(scan(50, 2, ('env',)))[0]['recommended_seconds'], 86400)

    def test_single_family_rows_cannot_be_borrowed_from_one_other_target(self):
        rows = scan(50, 1, ('env',), start=NOW - 200)
        rows += [event('/.git/config', NOW - 100 + index) for index in range(50)]
        self.assertEqual(self.analyze(rows)[0]['recommended_seconds'], 0)

    def test_two_family_count_boundaries(self):
        targets = ['/a{}/.env'.format(index) for index in range(23)] + ['/.git/config', '/.git/HEAD']
        rows = [event(targets[index % 25], NOW - 60 + index) for index in range(60)]
        self.assertEqual(self.analyze(rows)[0]['recommended_seconds'], 86400)
        self.assertEqual(self.analyze(rows[:-1])[0]['recommended_seconds'], 0)
        self.assertEqual(self.analyze([row for row in rows if row['path'] != '/a22/.env'])[0]['recommended_seconds'], 0)
        singleton = [dict(row, path='/.git/config') if row['path'] == '/.git/HEAD' else row for row in rows]
        self.assertEqual(self.analyze(singleton)[0]['recommended_seconds'], 0)

    def test_rolling_window_includes_exact_boundary_but_not_one_second_more(self):
        rows = scan(15, start=NOW - 600)
        rows = [dict(row, ts=NOW - 600 if index < 30 else NOW) for index, row in enumerate(rows)]
        self.assertEqual(self.analyze(rows)[0]['recommended_seconds'], 86400)
        rows = [dict(row, ts=row['ts'] - 1) if index < 30 else row for index, row in enumerate(rows)]
        self.assertEqual(self.analyze(rows)[0]['recommended_seconds'], 0)

    def test_rolling_not_clock_buckets(self):
        start = NOW - NOW % 600 - 30
        self.assertEqual(self.analyze(scan(start=start), now=start + 130)[0]['recommended_seconds'], 86400)

    def test_seven_day_rolling_hour_boundary(self):
        rows = scan(50, families=('env', 'repository', 'credentials'))
        rows = [dict(row, ts=NOW - 3600 if index < 150 else NOW) for index, row in enumerate(rows)]
        self.assertEqual(self.analyze(rows)[0]['recommended_seconds'], 604800)
        rows = [dict(row, ts=row['ts'] - 1) if index < 150 else row for index, row in enumerate(rows)]
        self.assertNotEqual(self.analyze(rows)[0]['recommended_seconds'], 604800)

    def test_duplicate_lines_queries_encodings_and_rule_labels_do_not_inflate(self):
        rows = scan()
        variants = [dict(row, path=row['path'].replace('.env', '%2eenv').replace('.git', '%252egit') + '?secret=redacted',
                         rule_type='other') for row in rows]
        first, second = self.analyze(rows)[0], self.analyze(rows + rows + variants)[0]
        for name in ('recommended_seconds', 'strong_targets', 'related_rows', 'fingerprint'):
            self.assertEqual(first[name], second[name], name)
        self.assertGreater(second['raw_targets'], first['raw_targets'])
        self.assertFalse(any('secret' in sample or '?' in sample for sample in second['samples']))

    def test_slash_dot_segments_and_two_pass_decode_are_canonical(self):
        rows = scan()
        variants = [dict(row, path='/x/../' + row['path'].replace('/', '//').lstrip('/')) for row in rows]
        self.assertEqual(self.analyze(rows)[0]['fingerprint'], self.analyze(variants)[0]['fingerprint'])
        triple = [dict(row, path=row['path'].replace('.env', '%25252eenv').replace('.git', '%25252egit')) for row in rows]
        self.assertEqual(self.analyze(triple)[0]['recommended_seconds'], 0)

    def test_public_path_normalizer_is_reusable_without_analysis(self):
        self.assertEqual(self.analyzer.normalize_path('/a//b/../%252eenv?key=secret'), '/a/.env')
        self.assertEqual(self.analyzer.normalize_path('/A/a/'), '/A/a/')
        with self.assertRaises(ValueError):
            self.analyzer.normalize_path('/%GG')

    def test_terminal_dot_segments_preserve_directory_semantics(self):
        suffixes = ('/.', '/%2e', '/%252e', '/child/..', '/child/%2e%2e', '/child/%252e%252e')
        for suffix in suffixes:
            with self.subTest(suffix=suffix):
                self.assertEqual(self.analyzer.normalize_path('/a/.env' + suffix), '/a/.env/')
                self.assertEqual(self.analyzer.normalize_path('/a/.git/config' + suffix), '/a/.git/config/')
                self.assertEqual(self.analyzer.normalize_path('/a/.env' + suffix + '/'), '/a/.env/')

    def test_sensitive_named_directories_cannot_create_scan_advice(self):
        for suffix in ('/.', '/%2e', '/%252e', '/child/..'):
            with self.subTest(suffix=suffix):
                rows = [dict(row, path=row['path'] + suffix) for row in scan()]
                item = self.analyze(rows)[0]
                equivalent = self.analyze([dict(row, path=row['path'] + '/') for row in rows])[0]
                self.assertEqual(item['strong_targets'], 0)
                self.assertEqual(item['recommended_seconds'], 0)
                self.assertEqual(item['fingerprint'], equivalent['fingerprint'])

    def test_same_sensitive_target_retries_do_not_meet_target_diversity(self):
        rows = [event('/.env', NOW - index) for index in range(2000)]
        item = self.analyze(rows)[0]
        self.assertEqual(item['strong_targets'], 1)
        self.assertEqual(item['related_rows'], 2000)
        self.assertEqual(item['recommended_seconds'], 0)

    def test_seven_day_row_and_target_boundaries(self):
        rows = scan(50, families=('env', 'repository', 'credentials'))
        self.assertNotEqual(self.analyze(rows[:-1])[0]['recommended_seconds'], 604800)
        reduced = [dict(row, path='/app0/.aws/credentials')
                   if row['path'] == '/app49/.aws/credentials' else row for row in rows]
        self.assertNotEqual(self.analyze(reduced)[0]['recommended_seconds'], 604800)

    def test_meaningful_posix_case_is_not_lowercased(self):
        rows = [event('/A/.env', NOW - 4), event('/a/.env', NOW - 3), event('/A/.ENV', NOW - 2)]
        item = self.analyze(rows)[0]
        self.assertEqual(item['strong_targets'], 2)
        self.assertEqual(item['family_counts'], {'env': 2})

    def test_ordinary_download_admin_and_query_values_are_not_strong(self):
        paths = ['/admin', '/downloads/backup.zip', '/downloads/report.bak', '/config.json',
                 '/search?target=/.env', '/.environment', '/.env.example', '/x/.git/guide.html']
        item = self.analyze([event(path, NOW - index) for index, path in enumerate(paths * 100)])[0]
        self.assertEqual(item['strong_targets'], 0)
        self.assertEqual(item['recommended_seconds'], 0)

    def test_known_sensitive_families_are_nonoverlapping(self):
        paths = ['/a/.env.bak', '/a/.git/config', '/a/.aws/credentials', '/a/database.sql.gz',
                 '/a/.ssh/id_ed25519', '/a/.npmrc', '/etc/shadow', '/a/wp-config.php.bak']
        item = self.analyze([event(path) for path in paths])[0]
        self.assertEqual(item['strong_targets'], len(paths))
        self.assertEqual(sum(item['family_counts'].values()), len(paths))
        self.assertEqual(set(item['family_counts']), {'env', 'repository', 'credentials', 'backup'})

    def test_sites_and_ips_are_never_combined(self):
        rows = scan(15, 1)
        other = [dict(row, site='other.example', ts=row['ts'] + 1) for row in rows]
        third = [dict(row, ip='192.0.2.18', ts=row['ts'] + 1) for row in rows]
        items = self.analyze(rows + other + third)
        self.assertEqual(len(items), 3)
        self.assertTrue(all(item['recommended_seconds'] == 0 for item in items))

    def test_ipv6_canonicalization_and_mapped_ipv4_share_identity(self):
        rows = scan()
        first = self.analyze([dict(row, ip='2001:0DB8:0:0:0:0:0:1') for row in rows])[0]
        self.assertEqual(first['ip'], '2001:db8::1')
        mapped = self.analyze(rows + [dict(row, ip='::ffff:192.0.2.17') for row in rows])[0]
        self.assertEqual(mapped['related_rows'], len(rows))

    def test_fingerprint_is_stable_until_evidence_expires_or_changes(self):
        rows = scan()
        original = copy.deepcopy(rows)
        item = self.analyze(rows)[0]
        self.assertEqual(item['fingerprint'], self.analyze(list(reversed(rows)), now=NOW + 1)[0]['fingerprint'])
        self.assertEqual(item['fingerprint'], self.analyze(rows + [event('/ordinary')])[0]['fingerprint'])
        self.assertNotEqual(item['fingerprint'], self.analyze(rows + [event('/new/.env')])[0]['fingerprint'])
        self.assertNotEqual(item['fingerprint'], self.analyze(rows, now=rows[0]['ts'] + 86401)[0]['fingerprint'])
        self.assertEqual(rows, original)

    def test_outside_24_hour_rows_do_not_qualify(self):
        self.assertEqual(self.analyze([dict(row, ts=NOW - 86401) for row in scan()]), [])
        self.assertEqual(self.analyze([event('/.env', NOW - 86400)])[0]['strong_targets'], 1)

    def test_invalid_or_ambiguous_rows_fail_explicitly(self):
        changes = [dict(ts=NOW + 1), dict(ts=True), dict(ts='123'), dict(site='../escape'),
                   dict(ip='garbage'), dict(ip='fe80::1%eth0'), dict(path='http://example/.env'),
                   dict(path='/.env\x00'), dict(path='/%xx/.env'), dict(path='/' + 'x' * 8193),
                   dict(path='/broken\\.env'), dict(rule_type=None)]
        for change in changes:
            with self.subTest(change=change):
                row = event('/.env')
                row.update(change)
                with self.assertRaises(ValueError):
                    self.analyze([row])


class ScopedBanStoreTest(unittest.TestCase):
    def setUp(self):
        cls = getattr(ban_store, 'ScopedBanStore', None)
        self.assertIsNotNone(cls, 'ScopedBanStore is not implemented')
        self.cls = cls
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / 'manual_site_bans.json'
        self.now = NOW
        self.store = cls(self.path, now_fn=lambda: self.now)

    def add(self, **overrides):
        args = dict(site='fixture.example', ip='192.0.2.17', seconds=86400, evidence_hash=HASH)
        args.update(overrides)
        return self.store.add(**args)

    def write_snapshot(self, value):
        self.path.write_text(json.dumps(value), encoding='utf-8')

    def test_missing_read_does_not_create_files_or_lock(self):
        self.assertEqual(self.store.snapshot(), dict(version=1, revision='0' * 32, entries=[]))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_add_exact_schema_finite_expiry_and_read_only_snapshot(self):
        snapshot = self.add()
        self.assertEqual(set(snapshot), {'version', 'revision', 'entries'})
        self.assertRegex(snapshot['revision'], r'^[0-9a-f]{32}$')
        row = snapshot['entries'][0]
        self.assertEqual(row, dict(site='fixture.example', ip='192.0.2.17', started_at=NOW,
                                  expires_at=NOW + 86400, duration=86400,
                                  reason='risk_advice', evidence_hash=HASH))
        body = self.path.read_bytes()
        self.now += 86401
        self.assertEqual(self.store.snapshot(), snapshot)
        self.assertEqual(self.path.read_bytes(), body)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(self.path.with_name(self.path.name + '.lock').stat().st_mode), 0o600)

    def test_duplicate_apply_is_idempotent_even_if_time_has_advanced(self):
        first = self.add()
        body = self.path.read_bytes()
        self.now += 10
        self.assertEqual(self.add(), first)
        self.assertEqual(self.path.read_bytes(), body)

    def test_preserves_existing_stronger_active_record_and_its_provenance(self):
        first = self.add(seconds=315360000)
        self.now += 100
        self.assertEqual(self.add(seconds=86400, evidence_hash='b' * 64), first)

    def test_can_extend_shorter_ban_without_modifying_other_sites(self):
        self.add()
        self.add(site='other.example')
        original_other = next(row for row in self.store.snapshot()['entries'] if row['site'] == 'other.example')
        result = self.add(seconds=604800, evidence_hash='b' * 64)
        self.assertEqual(next(row for row in result['entries'] if row['site'] == 'fixture.example')['duration'], 604800)
        self.assertEqual(next(row for row in result['entries'] if row['site'] == 'other.example'), original_other)

    def test_expired_same_ip_can_receive_new_ban(self):
        self.add(seconds=60)
        self.now += 60
        row = self.add(seconds=120)['entries'][0]
        self.assertEqual(row['started_at'], self.now)
        self.assertEqual(row['expires_at'], self.now + 120)

    @contextmanager
    def transaction_after_delay(self):
        with self.transaction_before_delay() as directory:
            self.now += 61
            yield directory

    def test_duration_starts_after_transaction_lock_wait(self):
        self.transaction_before_delay = self.store._transaction
        with patch.object(self.store, '_transaction', self.transaction_after_delay):
            row = self.add(seconds=60)['entries'][0]
        self.assertEqual(row['started_at'], self.now)
        self.assertEqual(row['expires_at'], self.now + 60)

    def test_capacity_cleanup_uses_time_after_transaction_lock_wait(self):
        self.add(seconds=60)
        self.transaction_before_delay = self.store._transaction
        with patch.object(self.store, '_transaction', self.transaction_after_delay), \
                patch.object(self.store, 'MAX_ENTRIES', 1):
            try:
                snapshot = self.add(ip='192.0.2.18', seconds=60)
            except ValueError as error:
                self.fail('Expired lock-wait record must not consume capacity: ' + str(error))
        self.assertEqual([row['ip'] for row in snapshot['entries']], ['192.0.2.18'])

    def test_expired_history_is_pruned_only_when_an_explicit_add_changes_storage(self):
        self.add(seconds=60)
        self.add(site='other.example', seconds=604800)
        self.now += 60
        before = self.store.snapshot()
        body = self.path.read_bytes()
        self.assertEqual(len(before['entries']), 2)
        self.assertEqual(self.add(site='other.example', seconds=604800), before)
        self.assertEqual(self.path.read_bytes(), body)
        active_other = next(row for row in before['entries'] if row['site'] == 'other.example')
        with patch.object(self.store, 'MAX_ENTRIES', 2):
            result = self.add(ip='192.0.2.18', seconds=120)
        self.assertEqual(len(result['entries']), 2)
        self.assertEqual(next(row for row in result['entries'] if row['site'] == 'other.example'), active_other)
        self.assertFalse(any(row['site'] == 'fixture.example' and row['ip'] == '192.0.2.17'
                             for row in result['entries']))

    def test_remove_is_site_scoped_and_idempotent(self):
        self.add()
        self.add(site='other.example')
        result = self.store.remove('fixture.example', '192.0.2.17')
        self.assertEqual([row['site'] for row in result['entries']], ['other.example'])
        self.assertEqual(self.store.remove('fixture.example', '192.0.2.17'), result)

    def test_remove_absent_store_does_not_initialize_snapshot(self):
        result = self.store.remove('fixture.example', '192.0.2.17')
        self.assertEqual(result['revision'], '0' * 32)
        self.assertFalse(self.path.exists())

    def test_expected_revision_is_checked_inside_transaction(self):
        first = self.add()
        self.add(site='other.example')
        body = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.store.remove('fixture.example', '192.0.2.17', expected_revision=first['revision'])
        with self.assertRaises(ValueError):
            self.add(ip='192.0.2.18', expected_revision=first['revision'])
        self.assertEqual(self.path.read_bytes(), body)

    def test_exact_expected_revision_allows_add_and_remove(self):
        first = self.add(expected_revision='0' * 32)
        second = self.add(ip='192.0.2.18', expected_revision=first['revision'])
        self.assertNotEqual(first['revision'], second['revision'])
        final = self.store.remove('fixture.example', '192.0.2.18', expected_revision=second['revision'])
        self.assertEqual(final['entries'], first['entries'])
        self.assertNotEqual(final['revision'], second['revision'])

    def test_snapshot_returns_detached_records(self):
        first = self.add()
        first['entries'][0]['duration'] = 123
        self.assertEqual(self.store.snapshot()['entries'][0]['duration'], 86400)

    def test_write_capacity_errors_leave_original_snapshot_unchanged(self):
        self.add()
        body = self.path.read_bytes()
        with patch.object(self.store, 'MAX_ENTRIES', 1):
            with self.assertRaises(ValueError):
                self.add(ip='192.0.2.18')
        with patch.object(self.store, 'MAX_BYTES', len(body) + 1):
            with self.assertRaises(ValueError):
                self.add(ip='192.0.2.18')
        self.assertEqual(self.path.read_bytes(), body)

    def test_input_validation_does_not_create_snapshot(self):
        changes = [dict(site='../outside'), dict(ip='bad'), dict(ip='fe80::1%eth0'),
                   dict(seconds=True), dict(seconds='60'), dict(seconds=59), dict(seconds=315360001),
                   dict(evidence_hash='A' * 64), dict(evidence_hash='a' * 63),
                   dict(expected_revision='garbage')]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.add(**change)
        self.assertFalse(self.path.exists())

    def test_add_canonicalizes_ipv6_and_mapped_ipv4(self):
        self.assertEqual(self.add(ip='2001:0DB8:0:0:0:0:0:1')['entries'][0]['ip'], '2001:db8::1')
        result = self.add(ip='::ffff:192.0.2.17')
        self.assertIn('192.0.2.17', [row['ip'] for row in result['entries']])

    def test_corrupt_duplicate_fields_and_unknown_schema_never_reset(self):
        good = self.add()
        bad_values = [b'', b'null', b'{broken', b'\xff',
                      b'{"version":1,"version":1,"revision":"' + b'1' * 32 + b'","entries":[]}']
        for change in (dict(extra=1), dict(version=True), dict(entries={}), dict(revision='X' * 32)):
            value = copy.deepcopy(good)
            value.update(change)
            bad_values.append(json.dumps(value).encode('utf-8'))
        for body in bad_values:
            self.path.write_bytes(body)
            with self.subTest(body=body[:100]):
                with self.assertRaises(ValueError):
                    self.store.snapshot()
                with self.assertRaises(ValueError):
                    self.add()
                with self.assertRaises(ValueError):
                    self.store.remove('fixture.example', '192.0.2.17')
                self.assertEqual(self.path.read_bytes(), body)

    def test_snapshot_rejects_noncanonical_or_inconsistent_rows(self):
        good = self.add()
        for change in (dict(extra=True), dict(site='../outside'), dict(ip='2001:0DB8::1'),
                       dict(ip='::ffff:c000:211'), dict(started_at=True), dict(expires_at=NOW),
                       dict(duration=59), dict(duration=315360001), dict(reason='cc'), dict(evidence_hash='z' * 64)):
            value = copy.deepcopy(good)
            value['entries'][0].update(change)
            self.write_snapshot(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.store.snapshot()
        self.write_snapshot(dict(good, entries=good['entries'] * 2))
        with self.assertRaises(ValueError):
            self.store.snapshot()

    def test_snapshot_and_mutations_refuse_symlinks(self):
        target = self.root / 'target.json'
        target.write_text('{"sentinel":true}')
        try:
            self.path.symlink_to(target)
        except OSError:
            self.skipTest('symlinks unavailable')
        original = target.read_bytes()
        for operation in (self.store.snapshot, self.add,
                          lambda: self.store.remove('fixture.example', '192.0.2.17')):
            with self.assertRaises((ValueError, OSError)):
                operation()
        self.assertEqual(target.read_bytes(), original)

    def test_parent_directory_and_lock_symlinks_are_rejected(self):
        directory = self.root / 'real'
        directory.mkdir()
        link = self.root / 'linked'
        try:
            link.symlink_to(directory, target_is_directory=True)
        except OSError:
            self.skipTest('symlinks unavailable')
        other = self.cls(link / 'manual.json', now_fn=lambda: self.now)
        with self.assertRaises((ValueError, OSError)):
            other.snapshot()
        with self.assertRaises((ValueError, OSError)):
            other.add('fixture.example', '192.0.2.17', 60, HASH)
        lock = self.path.with_name(self.path.name + '.lock')
        lock.symlink_to(directory / 'outside')
        with self.assertRaises((ValueError, OSError)):
            self.add()
        self.assertFalse((directory / 'outside').exists())

    def test_hardlinked_snapshot_and_lock_are_rejected(self):
        self.add()
        sibling = self.root / 'hardlink'
        os.link(str(self.path), str(sibling))
        with self.assertRaises((ValueError, OSError)):
            self.store.snapshot()
        with self.assertRaises((ValueError, OSError)):
            self.add()
        sibling.unlink()
        lock = self.path.with_name(self.path.name + '.lock')
        os.link(str(lock), str(sibling))
        with self.assertRaises((ValueError, OSError)):
            self.add()

    def test_nonregular_oversize_and_overcapacity_snapshots_are_rejected(self):
        self.path.mkdir()
        with self.assertRaises((ValueError, OSError)):
            self.store.snapshot()
        self.path.rmdir()
        self.path.write_bytes(b' ' * (1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            self.store.snapshot()
        self.path.unlink()
        good = self.add()
        self.write_snapshot(dict(good, entries=good['entries'] * 4097))
        with self.assertRaises(ValueError):
            self.store.snapshot()

    def test_failed_replace_preserves_previous_bytes_and_removes_tempfile(self):
        self.add()
        body = self.path.read_bytes()
        files = set(self.root.iterdir())
        with patch.object(ban_store.os, 'replace', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                self.add(ip='192.0.2.18')
        self.assertEqual(self.path.read_bytes(), body)
        self.assertEqual(set(self.root.iterdir()), files)

    def test_permanent_lock_inode_survives_replacement(self):
        self.add()
        lock = self.path.with_name(self.path.name + '.lock')
        original = lock.stat()
        self.add(ip='192.0.2.18')
        self.store.remove('fixture.example', '192.0.2.17')
        current = lock.stat()
        self.assertEqual((original.st_dev, original.st_ino), (current.st_dev, current.st_ino))

    def test_concurrent_independent_stores_do_not_lose_updates(self):
        errors = []
        barrier = threading.Barrier(8)

        def worker(index):
            try:
                instance = self.cls(self.path, now_fn=lambda: self.now)
                barrier.wait(timeout=5)
                instance.add('fixture.example', '192.0.2.{}'.format(index + 1), 60, HASH)
            except Exception as error:
                errors.append(error)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(self.store.snapshot()['entries']), 8)


if __name__ == '__main__':
    unittest.main()
