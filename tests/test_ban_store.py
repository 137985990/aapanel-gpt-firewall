import json
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parents[1]
if str(PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR))

from ban_store import BanStore


class BanStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.rule_path = Path(self.tmp.name) / "ip_black.json"
        self.meta_path = Path(self.tmp.name) / "ip_black_meta.json"
        self.now = 1_778_180_000

    def tearDown(self):
        self.tmp.cleanup()

    def write_rules(self, rules):
        self.rule_path.write_text(json.dumps(rules))

    def read_rules(self):
        return json.loads(self.rule_path.read_text())

    def store(self):
        return BanStore(self.rule_path, self.meta_path, now_fn=lambda: self.now)

    def test_prune_expired_preserves_active(self):
        self.write_rules([
            [[1, 1, 1, 1], [1, 1, 1, 1], self.now - 1],
            [[2, 2, 2, 2], [2, 2, 2, 2], self.now + 100],
        ])
        changed = self.store().prune_and_migrate()
        self.assertTrue(changed)
        self.assertEqual(self.read_rules(), [
            [[2, 2, 2, 2], [2, 2, 2, 2], self.now + 100],
        ])

    def test_migrates_no_expire_exact_ip_to_temp(self):
        self.write_rules([[[3, 3, 3, 3], [3, 3, 3, 3]]])
        self.store().prune_and_migrate(default_seconds=28800)
        self.assertEqual(self.read_rules()[0][2], self.now + 28800)

    def test_preserves_no_expire_range(self):
        self.write_rules([[[4, 4, 4, 1], [4, 4, 4, 255]]])
        self.store().prune_and_migrate()
        self.assertEqual(self.read_rules(), [[[4, 4, 4, 1], [4, 4, 4, 255]]])

    def test_add_temp_ban_deduplicates_active(self):
        self.write_rules([[[5, 5, 5, 5], [5, 5, 5, 5], self.now + 100]])
        added = self.store().add_temp_ban("5.5.5.5", 28800, reason="manual_temp")
        self.assertFalse(added)
        self.assertEqual(len(self.read_rules()), 1)

    def test_remove_exact_ip_by_value(self):
        self.write_rules([
            [[6, 6, 6, 6], [6, 6, 6, 6], self.now + 100],
            [[7, 7, 7, 7], [7, 7, 7, 7], self.now + 100],
        ])
        removed = self.store().remove_exact_ip("7.7.7.7")
        self.assertTrue(removed)
        self.assertEqual(self.read_rules(), [
            [[6, 6, 6, 6], [6, 6, 6, 6], self.now + 100],
        ])

    def test_clear_exact_ips_preserves_ranges(self):
        self.write_rules([
            [[8, 8, 8, 8], [8, 8, 8, 8], self.now + 100],
            [[9, 9, 9, 1], [9, 9, 9, 255]],
        ])
        removed = self.store().clear_exact_ips()
        self.assertEqual(removed, 1)
        self.assertEqual(self.read_rules(), [
            [[9, 9, 9, 1], [9, 9, 9, 255]],
        ])


if __name__ == "__main__":
    unittest.main()
