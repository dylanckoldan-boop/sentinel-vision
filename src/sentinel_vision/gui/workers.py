"""Background execution helpers. All engine work happens off the UI thread; results come back via signals."""

from __future__ import annotations

import threading
import traceback
from collections.abc import Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal


class TaskSignals(QObject):
    progress = Signal(int, str)
    item = Signal(object)
    message = Signal(str)
    finished = Signal(object)
    failed = Signal(str)


class Task(QRunnable):
    """Run ``fn(task)`` in the global pool. ``fn`` may call task.progress/item/message and check task.cancel."""

    def __init__(self, fn: Callable[[Task], object]) -> None:
        super().__init__()
        self.fn = fn
        self.signals = TaskSignals()
        self.cancel = threading.Event()
        # Python owns the lifetime (see `start`): letting Qt auto-delete the runnable while queued
        # signals are still in flight to the UI thread is a classic PySide use-after-free.
        self.setAutoDelete(False)

    def progress(self, n: int, text: str) -> None:
        self.signals.progress.emit(n, text)

    def item(self, obj: object) -> None:
        self.signals.item.emit(obj)

    def message(self, text: str) -> None:
        self.signals.message.emit(text)

    def run(self) -> None:
        try:
            result = self.fn(self)
        except Exception as exc:
            traceback.print_exc()
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        self.signals.finished.emit(result)


_LIVE: set[Task] = set()


def start(task: Task) -> Task:
    """Start a task and keep it (and its signal object) alive until its result reached the UI thread."""
    _LIVE.add(task)
    release = lambda *_: _LIVE.discard(task)  # noqa: E731 - connected after user slots, so runs last
    task.signals.finished.connect(release)
    task.signals.failed.connect(release)
    QThreadPool.globalInstance().start(task)
    return task


class Bridge(QObject):
    """Thread-safe hop from engine callbacks (any thread) into the Qt event loop."""

    realtime_result = Signal(object)
    network_alert = Signal(object)
    status_changed = Signal()
