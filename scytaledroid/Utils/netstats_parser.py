"""Parsing helpers for dumpsys netstats output."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from pathlib import Path


@dataclass(frozen=True)
class NetstatsSample:
    uid: str
    ts_utc: datetime | None
    rx_bytes: int | None
    tx_bytes: int | None
    source: str
    parse_method: str


class NetstatsParser:
    """Parse netstats output into structured samples."""

    def __init__(self) -> None:
        self._uid_token = re.compile(r"\buid\b", re.IGNORECASE)
        self._uid_pattern_template = r"\buid[:=]\s*{uid}\b"
        self._rx_pattern = re.compile(r"\brx(?:Bytes|_bytes)?[:=]\s*(\d+)", re.IGNORECASE)
        self._tx_pattern = re.compile(r"\btx(?:Bytes|_bytes)?[:=]\s*(\d+)", re.IGNORECASE)

    def parse_detail(self, output: str, uid: str, *, ts_utc: datetime | None = None) -> NetstatsSample:
        return self._parse_output(output, uid, ts_utc=ts_utc, parse_source="detail")

    def parse_uid(self, output: str, uid: str, *, ts_utc: datetime | None = None) -> NetstatsSample:
        return self._parse_output(output, uid, ts_utc=ts_utc, parse_source="uid")

    def detect_format(self, output: str, uid: str) -> str:
        uid_pattern = re.compile(self._uid_pattern_template.format(uid=re.escape(uid)), re.IGNORECASE)
        has_uid_tokens = False
        matched_uid_line = False
        for line in output.splitlines():
            if self._uid_token.search(line):
                has_uid_tokens = True
            if uid_pattern.search(line):
                matched_uid_line = True
                break
        if matched_uid_line or has_uid_tokens:
            return "uid_lines"
        if self._rx_pattern.search(output) or self._tx_pattern.search(output):
            return "uidless"
        return "unknown"

    def write_debug_capture(
        self,
        output: str,
        *,
        uid: str,
        destination: Path,
        max_lines: int = 40,
    ) -> None:
        lines = self._extract_relevant_lines(output, uid=uid, max_lines=max_lines)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _parse_output(
        self,
        output: str,
        uid: str,
        *,
        ts_utc: datetime | None,
        parse_source: str,
    ) -> NetstatsSample:
        uid_pattern = re.compile(self._uid_pattern_template.format(uid=re.escape(uid)), re.IGNORECASE)
        bytes_in = 0
        bytes_out = 0
        matched_uid_line = False
        has_uid_tokens = False
        found_rx_tx = False
        for line in output.splitlines():
            if self._uid_token.search(line):
                has_uid_tokens = True
            if not uid_pattern.search(line):
                continue
            matched_uid_line = True
            rx_match = self._rx_pattern.search(line)
            tx_match = self._tx_pattern.search(line)
            if rx_match:
                bytes_in += int(rx_match.group(1))
                found_rx_tx = True
            if tx_match:
                bytes_out += int(tx_match.group(1))
                found_rx_tx = True
        if matched_uid_line or has_uid_tokens:
            if not found_rx_tx:
                return NetstatsSample(
                    uid=uid,
                    ts_utc=ts_utc,
                    rx_bytes=None,
                    tx_bytes=None,
                    source="netstats",
                    parse_method=f"{parse_source}_uid",
                )
            return NetstatsSample(
                uid=uid,
                ts_utc=ts_utc,
                rx_bytes=bytes_in,
                tx_bytes=bytes_out,
                source="netstats",
                parse_method=f"{parse_source}_uid",
            )
        bytes_in = 0
        bytes_out = 0
        for line in output.splitlines():
            rx_match = self._rx_pattern.search(line)
            tx_match = self._tx_pattern.search(line)
            if rx_match:
                bytes_in += int(rx_match.group(1))
                found_rx_tx = True
            if tx_match:
                bytes_out += int(tx_match.group(1))
                found_rx_tx = True
        if not found_rx_tx:
            return NetstatsSample(
                uid=uid,
                ts_utc=ts_utc,
                rx_bytes=None,
                tx_bytes=None,
                source="netstats",
                parse_method=f"{parse_source}_uidless",
            )
        return NetstatsSample(
            uid=uid,
            ts_utc=ts_utc,
            rx_bytes=bytes_in,
            tx_bytes=bytes_out,
            source="netstats",
            parse_method=f"{parse_source}_uidless",
        )

    def _extract_relevant_lines(self, output: str, *, uid: str, max_lines: int) -> list[str]:
        uid_pattern = re.compile(self._uid_pattern_template.format(uid=re.escape(uid)), re.IGNORECASE)
        lines: list[str] = []
        for line in output.splitlines():
            if uid_pattern.search(line) or self._rx_pattern.search(line) or self._tx_pattern.search(line):
                lines.append(line)
            if len(lines) >= max_lines:
                return lines[:max_lines]
        if lines:
            return lines[:max_lines]
        fallback_lines = output.splitlines()[:max_lines]
        return fallback_lines if fallback_lines else ["<no netstats output>"]


__all__ = ["NetstatsParser", "NetstatsSample"]
