import hashlib
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPORT_STORE_VERSION = 3

try:
    import fcntl
except ImportError:
    fcntl = None


def _worker_runtime():
    try:
        from gevent import monkey
    except ImportError:
        return threading.Lock(), ThreadPoolExecutor(max_workers=1, thread_name_prefix="waf-statistics")
    if not monkey.is_module_patched("threading"):
        return threading.Lock(), ThreadPoolExecutor(max_workers=1, thread_name_prefix="waf-statistics")
    from gevent.pool import Group
    from gevent.threadpool import ThreadPool

    class NativeWorker:
        def __init__(self):
            self.pool = ThreadPool(1)
            self.dispatchers = Group()

        def submit(self, function, *args):
            # A full gevent thread pool yields during submission. Keep that wait
            # outside the request and its short native-thread critical section.
            self.dispatchers.spawn(self.pool.spawn, function, *args)

        def shutdown(self, wait=True):
            if self.pool is None:
                return
            if wait:
                self.dispatchers.join()
                self.pool.join()
            self.pool.kill()
            self.pool = None

    return monkey.get_original("_thread", "allocate_lock")(), NativeWorker()


class BackgroundReports:
    """Serve atomic report snapshots while one worker refreshes expensive data."""

    def __init__(self, directory, ttl=300, max_entries=16):
        self.directory = Path(directory)
        self.ttl = ttl
        self.max_entries = max_entries
        self._lock, self._executor = _worker_runtime()
        self._pending = set()
        self._errors = {}

    def _path(self, key):
        digest = hashlib.sha256(str(key).encode("utf-8")).hexdigest()
        return self.directory / (digest + ".json")

    def _load(self, path):
        try:
            with path.open("r", encoding="utf-8") as stream:
                item = json.load(stream)
            if (item.get("version") == 1 and isinstance(item.get("report"), dict)
                    and isinstance(item.get("generated_at"), (int, float))
                    and isinstance(item.get("started_at", item["generated_at"]), (int, float))
                    and isinstance(item.get("refresh_revision", ""), str)):
                return item
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        return None

    def request(self, key, build, force=False):
        key = str(key)
        now = time.time()
        with self._lock:
            guard = None
            shared_loading = False
            try:
                if force:
                    self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                    self._save(self._path(key).with_suffix(".refresh"),
                               {"requested_at": now, "revision": uuid.uuid4().hex})
                snapshot = self._load(self._path(key))
                result = snapshot["report"] if snapshot else {}
                requested_at, revision = self._refresh_identity(key)
                sampled_at = snapshot.get("started_at", snapshot["generated_at"]) if snapshot else 0
                fresh = (snapshot is not None and 0 <= now - sampled_at < self.ttl
                         and (revision or sampled_at >= requested_at)
                         and snapshot.get("refresh_revision", "") == revision)
                if key not in self._pending:
                    guard = self._claim_job(key)
                    shared_loading = guard is None
                error = self._errors.get(key)
                if error and snapshot and snapshot["generated_at"] >= error[0]:
                    self._errors.pop(key, None)
                    error = None
                retry = error is None or now - error[0] >= 15 or force
                if (force or not fresh) and key not in self._pending and retry and (guard is not None or force):
                    if len(self._pending) >= self.max_entries:
                        result.update(status=True, loading=False, error="统计任务较多，请稍后重试。")
                        return result
                    self._pending.add(key)
                    self._errors.pop(key, None)
                    try:
                        self._executor.submit(self._refresh, key, build, now, guard)
                    except Exception:
                        self._pending.discard(key)
                        raise
                    guard = None
            except OSError:
                logging.getLogger(__name__).exception("WAF statistics job state unavailable")
                self._errors[key] = (now, True)
                snapshot = self._load(self._path(key))
                result = snapshot["report"] if snapshot else {}
            finally:
                self._release_job(guard)
            loading = key in self._pending or shared_loading
            error = self._errors.get(key)
        result.update(status=True, loading=loading, cached=snapshot is not None)
        if error and not loading:
            result["error"] = "统计生成失败，请点击刷新重试。"
        return result

    def _refresh_identity(self, key):
        try:
            with self._path(key).with_suffix(".refresh").open(encoding="utf-8") as stream:
                marker = json.load(stream)
                return float(marker.get("requested_at", 0)), str(marker.get("revision", ""))
        except (OSError, ValueError, TypeError, AttributeError):
            return 0, ""

    def _claim_job(self, key, blocking=False):
        if fcntl is None:
            return True
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self._path(key).with_suffix(".lock")
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            os.close(descriptor)
            return None
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _release_job(self, guard):
        if guard is not None and guard is not True:
            os.close(guard)

    def _refresh(self, key, build, requested_at, guard):
        completed = False
        built_revision = None
        try:
            if guard is None:
                guard = self._claim_job(key, blocking=True)
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Panel workers share this lock, so simultaneous requests cannot scan
            # the multi-GB logs in several processes at once.
            with (self.directory / "statistics.lock").open("a+") as lock_file:
                if fcntl is not None:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                path = self._path(key)
                while True:
                    with self._lock:
                        refresh_at, revision = self._refresh_identity(key)
                        existing = self._load(path)
                        satisfied = built_revision is not None and built_revision == revision
                        if (satisfied or (existing
                                and existing.get("started_at", existing["generated_at"]) >= max(requested_at, refresh_at)
                                and existing.get("refresh_revision", "") == revision)):
                            # Retire the job under the request lock so a last-moment
                            # force cannot observe pending and lose its follow-up.
                            self._release_job(guard)
                            guard = None
                            self._pending.discard(key)
                            completed = True
                            return
                        started_at = time.time()
                    report = build()
                    if not isinstance(report, dict) or report.get("status") is False:
                        raise ValueError("invalid statistics report")
                    snapshot = {"version": 1, "started_at": started_at, "refresh_revision": revision,
                                "generated_at": time.time(), "report": report}
                    self._save(path, snapshot)
                    self._prune(path)
                    built_revision = revision
        except Exception:
            logging.getLogger(__name__).exception("WAF statistics refresh failed")
            with self._lock:
                self._errors[key] = (time.time(), True)
                if len(self._errors) > self.max_entries:
                    self._errors.pop(next(iter(self._errors)))
        finally:
            self._release_job(guard)
            if not completed:
                with self._lock:
                    self._pending.discard(key)

    def _save(self, path, snapshot):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.directory,
                                             prefix=".snapshot-", delete=False) as stream:
                temporary = stream.name
                json.dump(snapshot, stream, ensure_ascii=False, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            temporary = None
        finally:
            if temporary is not None:
                os.unlink(temporary)

    def _prune(self, current):
        snapshots = sorted(self.directory.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        for path in snapshots[self.max_entries:]:
            if path != current:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    def close(self):
        self._executor.shutdown(wait=True)


website_reports = BackgroundReports("/www/server/panel/plugin/free_waf/data/statistics")
