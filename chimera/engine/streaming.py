"""
chimera.engine.streaming — Clepsydra Buffered Ingestor.

Implements threshold-triggered batch release for log streaming.

The Clepsydra Escapement model: events flow in continuously, but are
only released to the detection pipeline when:
  - the buffer reaches `release_threshold` events, OR
  - `timeout_seconds` has elapsed since the last flush, whichever comes first.

This smooths CPU consumption under log volume spikes and eliminates
per-event Python overhead in the feature engineering + scoring hot path.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Callable, Iterator, Optional

logger = logging.getLogger(__name__)


class StreamingBuffer:
    """Ring buffer with threshold-triggered batch release.

    Thread-safe: push() and flush() can be called from different threads.

    Parameters
    ----------
    release_threshold:
        Number of events that triggers an automatic batch release.
    timeout_seconds:
        If no release has occurred after this interval, force a flush.
    max_capacity:
        Hard cap on buffer size (older events are dropped with a warning
        if the consumer falls behind).
    """

    def __init__(
        self,
        release_threshold: int = 200,
        timeout_seconds: float = 5.0,
        max_capacity: int = 10_000,
    ) -> None:
        self.release_threshold = release_threshold
        self.timeout_seconds = timeout_seconds
        self.max_capacity = max_capacity

        # Plain deque — no maxlen. The explicit overflow check in push() is
        # the correct guard. deque(maxlen=N) would silently drop oldest events
        # on overflow rather than incrementing _dropped, making the counter
        # and warning useless.
        self._buffer: deque[dict] = deque()
        self._lock = threading.Lock()
        self._last_flush: float = time.monotonic()
        self._dropped: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def push(self, event: dict) -> Optional[list[dict]]:
        """Push one event into the buffer.

        Returns
        -------
        list[dict] or None
            A batch of events to process if the threshold is exceeded or
            the timeout has elapsed. None if the buffer is still filling.
        """
        with self._lock:
            if len(self._buffer) >= self.max_capacity:
                self._dropped += 1
                if self._dropped % 100 == 1:
                    logger.warning(
                        "[streaming] Buffer at capacity (%d events). "
                        "Dropped %d events so far.",
                        self.max_capacity, self._dropped,
                    )
                return None

            self._buffer.append(event)
            now = time.monotonic()
            should_release = (
                len(self._buffer) >= self.release_threshold
                or (now - self._last_flush) >= self.timeout_seconds
            )

            if should_release:
                return self._drain()
        return None

    def flush(self) -> list[dict]:
        """Force drain all buffered events, regardless of threshold."""
        with self._lock:
            return self._drain()

    def push_all(self, events: list[dict]) -> Iterator[list[dict]]:
        """Push multiple events and yield batches as they become ready.

        Parameters
        ----------
        events:
            Sequence of event dicts.

        Yields
        ------
        list[dict]
            Batches of events ready for processing.
        """
        for event in events:
            batch = self.push(event)
            if batch:
                yield batch

        # Flush remainder
        remainder = self.flush()
        if remainder:
            yield remainder

    @property
    def size(self) -> int:
        """Current number of buffered events."""
        with self._lock:
            return len(self._buffer)

    @property
    def dropped_count(self) -> int:
        """Total events dropped due to capacity overflow. Thread-safe."""
        with self._lock:
            return self._dropped

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _drain(self) -> list[dict]:
        """Move all buffered events into a list and reset the buffer."""
        batch = list(self._buffer)
        self._buffer.clear()
        self._last_flush = time.monotonic()
        logger.debug("[streaming] Flushed %d events.", len(batch))
        return batch

    def __repr__(self) -> str:
        return (
            f"StreamingBuffer(size={self.size}, "
            f"threshold={self.release_threshold}, "
            f"timeout={self.timeout_seconds}s, "
            f"dropped={self._dropped})"
        )
