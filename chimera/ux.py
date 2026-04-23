"""
Lightweight human-facing CLI UX helpers for Chimera.

The JSON contract remains machine-stable on stdout. All live presentation
is sent to stderr and auto-disables when the terminal is not interactive.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from threading import Event, Thread
from typing import Iterator, Optional, TextIO
import sys
import time

import click


_FIRE_BANNER = [
    r"   (  )   (   )  )",
    r"    ) (   )  (  (",
    r"    ( )  (    ) )",
    r"    _____________",
    r"   <_____________> ___",
    r"   |             |/ _ \\",
    r"   |   CHIMERA   | | | |",
    r"   |   v0.6.0    | |_| |",
    r"___|             |\\___/",
    r"/    \___________/    \\",
    r"\\_____________________/",
]

_FIRE_SPINNER_FRAMES = [
    " .    ( ) ",
    " ..  (  ) ",
    " .'. )(.  ",
    " : .'.:   ",
    " '.: :'   ",
    "  `:*:`   ",
]


@dataclass
class LiveConsole:
    """Small ASCII live console for package-like CLI feedback."""

    enabled: bool = True
    stream: Optional[TextIO] = None
    emit_when_disabled: bool = True

    def __post_init__(self) -> None:
        self.stream = self.stream or sys.stderr
        self.enabled = bool(self.enabled and getattr(self.stream, "isatty", lambda: False)())

    def echo(self, message: str = "") -> None:
        click.echo(message, err=True)

    def banner(self, title: str, subtitle: str = "") -> None:
        if not self.enabled:
            return
        self.echo()
        for line in _FIRE_BANNER:
            self.echo(f"  {line}")
        self.echo(f"  {title}")
        if subtitle:
            self.echo(f"  {subtitle}")
        self.echo()

    def note(self, message: str) -> None:
        if not self.enabled and not self.emit_when_disabled:
            return
        prefix = "[*]" if not self.enabled else "[chimera]"
        self.echo(f"{prefix} {message}")

    @contextmanager
    def stage(self, label: str) -> Iterator[None]:
        """Render a live spinner while a stage is in flight."""
        if not self.enabled:
            if self.emit_when_disabled:
                self.echo(f"[*] {label}...")
            yield
            return

        stop_event = Event()
        failed = {"value": False}

        def _spin() -> None:
            idx = 0
            while not stop_event.is_set():
                frame = _FIRE_SPINNER_FRAMES[idx % len(_FIRE_SPINNER_FRAMES)]
                click.echo(f"\r{frame} {label}...", err=True, nl=False)
                time.sleep(0.08)
                idx += 1

        thread = Thread(target=_spin, daemon=True)
        thread.start()
        try:
            yield
        except Exception:
            failed["value"] = True
            raise
        finally:
            stop_event.set()
            thread.join(timeout=0.3)
            status = "[FAIL]" if failed["value"] else "[OK]"
            click.echo(f"\r{status} {label}".ljust(len(label) + 16), err=True)


def make_live_console(*, json_output: bool) -> LiveConsole:
    """Return a stderr-bound live console that never contaminates JSON stdout."""
    return LiveConsole(enabled=not json_output, emit_when_disabled=not json_output)
