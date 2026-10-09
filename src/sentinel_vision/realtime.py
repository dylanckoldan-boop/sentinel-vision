"""Real-time protection: scans files the moment they are created, modified or moved into a watched folder.

Events are debounced (a file is scanned once it has stopped changing for a moment) so a large
download is scanned once when complete rather than hundreds of times while it is being written.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections.abc import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from sentinel_vision.scanner import Scanner, ScanResult

log = logging.getLogger(__name__)

SETTLE_SECONDS = 1.5
MAX_WAIT_SECONDS = 30  # scan anyway if a file keeps changing this long
TEMP_SUFFIXES = (".crdownload", ".part", ".partial", ".download", ".tmp", ".svrestore")


class _Handler(FileSystemEventHandler):
    def __init__(self, sink: Callable[[str], None]) -> None:
        self.sink = sink

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.sink(os.fsdecode(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.sink(os.fsdecode(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.sink(os.fsdecode(event.dest_path))

    def on_closed(self, event: FileSystemEvent) -> None:  # Linux inotify IN_CLOSE_WRITE
        if not event.is_directory:
            self.sink(os.fsdecode(event.src_path))


class RealtimeProtection:
    def __init__(self, scanner: Scanner, on_result: Callable[[ScanResult], None] | None = None) -> None:
        self.scanner = scanner
        self.on_result = on_result
        self._observer: Observer | None = None
        self._pending: dict[str, tuple[float, float]] = {}  # path -> (first_seen, last_event)
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.files_scanned = 0
        self.threats_blocked = 0
        self.watching: list[str] = []
        self.errors: list[str] = []

    @property
    def running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def _sink(self, path: str) -> None:
        if path.endswith(TEMP_SUFFIXES) or self.scanner.is_excluded(path):
            return
        now = time.monotonic()
        with self._lock:
            first = self._pending.get(path, (now, now))[0]
            self._pending[path] = (first, now)

    def _debouncer(self) -> None:
        while not self._stop.wait(0.5):
            now = time.monotonic()
            ready = []
            with self._lock:
                for path, (first, last) in list(self._pending.items()):
                    if now - last >= SETTLE_SECONDS or now - first >= MAX_WAIT_SECONDS:
                        ready.append(path)
                        del self._pending[path]
            for p in ready:
                self._queue.put(p)

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                path = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                if not os.path.isfile(path):
                    continue
                results = self.scanner.scan_file(path, origin="realtime")
                self.files_scanned += 1
                top = results[0]
                if top.infected:
                    self.threats_blocked += 1
                    if self.on_result:
                        self.on_result(top)
            except Exception:
                log.exception("real-time scan failed for %s", path)

    def start(self, paths: list[str]) -> None:
        self.stop()
        self._stop.clear()
        self.errors = []
        observer = Observer()
        handler = _Handler(self._sink)
        watching = []
        for p in paths:
            p = os.path.abspath(os.path.expanduser(p))
            if not os.path.isdir(p):
                self.errors.append(f"{p}: folder does not exist")
                continue
            try:
                observer.schedule(handler, p, recursive=True)
                watching.append(p)
            except OSError as exc:  # e.g. inotify watch limit reached
                self.errors.append(f"{p}: {exc}")
        observer.start()
        self._observer = observer
        self.watching = watching
        self._threads = [threading.Thread(target=self._debouncer, name="rt-debounce", daemon=True)]
        self._threads += [threading.Thread(target=self._worker, name=f"rt-scan-{i}", daemon=True) for i in range(2)]
        for t in self._threads:
            t.start()
        self.scanner.db.log_event("realtime", f"Real-time protection on: watching {len(watching)} folder(s)")

    def stop(self) -> None:
        self._stop.set()
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass
            self._observer = None
            self.scanner.db.log_event("realtime", "Real-time protection off", "warning")
        for t in self._threads:
            t.join(timeout=2)
        self._threads = []
        self.watching = []
