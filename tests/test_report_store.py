import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from report_store import BackgroundReports, fcntl


class BackgroundReportsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.reports = BackgroundReports(self.directory.name, ttl=300)
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()
        self.reports.close()
        self.directory.cleanup()

    def wait_ready(self, key="all"):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = self.reports.request(key, lambda: self.fail("duplicate build"))
            if not result.get("loading"):
                return result
            self.release.wait(0.005) if not self.release.is_set() else time.sleep(0.005)
        self.fail("background build did not complete")

    def prune_paths(self):
        self.reports.max_entries = 1
        old = Path(self.directory.name) / "old.json"
        current = Path(self.directory.name) / "current.json"
        old.write_text("{}")
        current.write_text("{}")
        os.utime(old, (1, 1))
        os.utime(current, (2, 2))
        return old, current

    def test_prune_supports_python37_unlink_signature(self):
        old, current = self.prune_paths()
        unlink = Path.unlink

        def python37_unlink(path):
            return unlink(path)

        with mock.patch.object(Path, "unlink", python37_unlink):
            self.reports._prune(current)
        self.assertFalse(old.exists())
        self.assertTrue(current.exists())

    def test_prune_ignores_a_file_removed_before_unlink(self):
        old, current = self.prune_paths()
        unlink = Path.unlink

        def concurrent_unlink(path):
            unlink(path)
            raise FileNotFoundError(str(path))

        with mock.patch.object(Path, "unlink", concurrent_unlink):
            self.reports._prune(current)
        self.assertFalse(old.exists())
        self.assertTrue(current.exists())

    def test_prune_propagates_other_unlink_io_errors(self):
        old, current = self.prune_paths()
        for error in (PermissionError("denied"), OSError("disk failure")):
            with self.subTest(error=type(error).__name__):
                def failed_unlink(path):
                    raise error

                with mock.patch.object(Path, "unlink", failed_unlink):
                    with self.assertRaises(type(error)) as raised:
                        self.reports._prune(current)
                self.assertIs(raised.exception, error)
        self.assertTrue(old.exists())
        self.assertTrue(current.exists())

    def test_prune_never_removes_current_even_outside_retention_limit(self):
        old, current = self.prune_paths()
        self.reports._prune(old)
        self.assertTrue(old.exists())
        self.assertTrue(current.exists())

    def test_slow_first_build_returns_immediately_and_polls_share_one_job(self):
        calls = []

        def build():
            calls.append(1)
            self.release.wait(2)
            return {"status": True, "summary": {"total_requests": 7}}

        started = time.monotonic()
        first = self.reports.request("all", build)
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertTrue(first["loading"])
        for _ in range(10):
            self.assertTrue(self.reports.request("all", build)["loading"])
        self.release.set()
        ready = self.wait_ready()
        self.assertEqual(ready["summary"]["total_requests"], 7)
        self.assertEqual(len(calls), 1)

    def test_snapshots_survive_reopening_and_parameters_are_isolated(self):
        self.reports.request("one-site", lambda: {"status": True, "summary": {"total_requests": 9}})
        self.wait_ready("one-site")
        reopened = BackgroundReports(self.directory.name, ttl=300)
        try:
            result = reopened.request("one-site", lambda: self.fail("fresh disk cache ignored"))
            self.assertFalse(result["loading"])
            self.assertEqual(result["summary"]["total_requests"], 9)
            self.assertTrue(reopened.request("another-site", lambda: {"summary": {}})["loading"])
        finally:
            reopened.close()

    def test_refresh_serves_old_data_and_failure_does_not_overwrite_it(self):
        self.reports.request("all", lambda: {"status": True, "summary": {"total_requests": 7}})
        self.wait_ready()

        def fail_build():
            self.release.wait(2)
            raise RuntimeError("private filesystem path must not leak")

        stale = self.reports.request("all", fail_build, force=True)
        self.assertTrue(stale["loading"])
        self.assertEqual(stale["summary"]["total_requests"], 7)
        with self.assertLogs("report_store", level="ERROR"):
            self.release.set()
            failed = self.wait_ready()
        self.assertEqual(failed["summary"]["total_requests"], 7)
        self.assertTrue(failed["error"])
        self.assertNotIn("private filesystem", failed["error"])
        snapshots = list(Path(self.directory.name).glob("*.json"))
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(json.loads(snapshots[0].read_text())["report"]["summary"]["total_requests"], 7)

    def test_response_mutations_do_not_corrupt_the_snapshot(self):
        self.reports.request("all", lambda: {"summary": {"total_requests": 7}})
        result = self.wait_ready()
        result["summary"]["total_requests"] = 999
        self.assertEqual(self.wait_ready()["summary"]["total_requests"], 7)

    @unittest.skipIf(fcntl is None, "requires Linux process-shared flock")
    def test_another_worker_sees_refresh_in_progress_even_with_fresh_cache(self):
        self.reports.request("all", lambda: {"summary": {"total_requests": 7}})
        self.wait_ready()
        other = BackgroundReports(self.directory.name)
        started = threading.Event()

        def rebuild():
            started.set()
            self.release.wait(2)
            return {"summary": {"total_requests": 8}}

        try:
            self.reports.request("all", rebuild, force=True)
            self.assertTrue(started.wait(1))
            result = other.request("all", lambda: self.fail("duplicate refresh"))
            self.assertTrue(result["loading"])
            self.assertEqual(result["summary"]["total_requests"], 7)
            self.release.set()
            self.wait_ready()
            result = other.request("all", lambda: self.fail("fresh cache ignored"))
            self.assertFalse(result["loading"])
            self.assertEqual(result["summary"]["total_requests"], 8)
        finally:
            self.release.set()
            other.close()

    def test_new_snapshot_from_another_worker_clears_an_old_error(self):
        def fail_build():
            raise RuntimeError("failed refresh")

        with self.assertLogs("report_store", level="ERROR"):
            self.reports.request("all", fail_build)
            failed = self.wait_ready()
        self.assertTrue(failed["error"])
        other = BackgroundReports(self.directory.name)
        try:
            other.request("all", lambda: {"summary": {"total_requests": 9}})
            other.close()
            recovered = self.reports.request("all", lambda: self.fail("fresh cache ignored"))
            self.assertEqual(recovered["summary"]["total_requests"], 9)
            self.assertNotIn("error", recovered)
        finally:
            other.close()

    @unittest.skipIf(fcntl is None, "requires Linux process-shared flock")
    def test_force_refresh_cannot_be_swallowed_by_an_ordinary_cache_reader(self):
        self.reports.request("all", lambda: {"summary": {"total_requests": 7}})
        self.wait_ready()
        other = BackgroundReports(self.directory.name)
        reading = threading.Event()
        release_reader = threading.Event()
        original_load = other._load
        builds = []

        def slow_load(path):
            reading.set()
            release_reader.wait(2)
            return original_load(path)

        other._load = slow_load
        reader = threading.Thread(target=lambda: other.request("all", lambda: {"status": False}))
        reader.start()
        try:
            self.assertTrue(reading.wait(1))
            self.reports.request("all", lambda: (builds.append(1) or {"summary": {"total_requests": 8}}), force=True)
            release_reader.set()
            reader.join(2)
            self.wait_ready()
            self.assertEqual(builds, [1])
        finally:
            release_reader.set()
            reader.join(2)
            other.close()


if __name__ == "__main__":
    unittest.main()
