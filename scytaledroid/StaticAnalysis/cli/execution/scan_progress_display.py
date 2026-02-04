"""Progress rendering helpers for static analysis scans."""

from __future__ import annotations

import time


def _format_elapsed(seconds: float) -> str:
    total = max(0, int(seconds))
    minutes = total // 60
    seconds = total % 60
    return f"{minutes:02d}:{seconds:02d}"


def _truncate_label(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return f"{value[: max_len - 3].rstrip()}..."


class _PipelineProgress:
    def __init__(
        self,
        total: int,
        show_splits: bool,
        show_artifacts: bool,
        show_checkpoints: bool,
    ) -> None:
        self.total = max(1, int(total))
        self.show_splits = show_splits
        self.show_artifacts = show_artifacts
        self.show_checkpoints = show_checkpoints
        self._start = time.monotonic()
        self._last_len = 0
        self._last_checkpoint = 0

    def start(self, index: int, label: str) -> None:
        if self.show_splits:
            return
        return

    def finish(self, index: int, label: str) -> None:
        if not self.show_artifacts:
            return
        if self.show_splits:
            line = f"[{index:2d}/{self.total}] {label} OK"
            print(line)
            return
        if not self.show_checkpoints:
            return
        if index == self.total or (index - self._last_checkpoint) >= 5:
            self._last_checkpoint = index
            elapsed = _format_elapsed(time.monotonic() - self._start)
            self._clear_line()
            tail = _truncate_label(label, 48)
            print(
                f"Completed {index}/{self.total} artifacts ({elapsed} elapsed) | last: {tail}"
            )

    def error(self, index: int, label: str, message: str) -> None:
        if not self.show_artifacts:
            return
        self._clear_line()
        tail = _truncate_label(label, 48)
        print(f"ERROR Artifact {index}/{self.total}: {tail} - {message}")

    def skip(self, index: int, label: str, message: str) -> None:
        if not self.show_artifacts:
            return
        self._clear_line()
        tail = _truncate_label(label, 48)
        if message == "dry-run (not persisted)":
            print(f"EXECUTED Artifact {index}/{self.total}: {tail} — NOT STORED (diagnostic)")
        else:
            print(f"SKIP Artifact {index}/{self.total}: {tail} - {message}")

    def end(self) -> None:
        if self.show_splits or not self.show_artifacts:
            return
        if self._last_len:
            self._clear_line()
            print()

    def flush_line(self) -> None:
        """Clear the in-place progress line before printing multiline output."""
        if self.show_splits:
            return
        self._clear_line()

    def _render_line(self, text: str) -> None:
        truncated = _truncate_label(text, 96)
        padded = truncated.ljust(self._last_len)
        self._last_len = max(self._last_len, len(truncated))
        print(f"\r{padded}", end="", flush=True)

    def _clear_line(self) -> None:
        if self._last_len:
            print(f"\r{' ' * self._last_len}\r", end="", flush=True)
            self._last_len = 0


__all__ = ["_PipelineProgress", "_format_elapsed", "_truncate_label"]