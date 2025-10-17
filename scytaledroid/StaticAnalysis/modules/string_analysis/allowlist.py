"""Documentary noise handling for string analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore


@dataclass(frozen=True)
class NoisePolicy:
    """Represents documentary allow-lists for hosts and sources."""

    hosts_documentary: frozenset[str]
    sources_documentary: frozenset[str]

    def is_documentary_host(self, host: str | None) -> bool:
        if not host:
            return False
        return host.lower() in self.hosts_documentary

    def is_documentary_source(self, source: str | None) -> bool:
        if not source:
            return False
        return source.lower() in self.sources_documentary


def load_noise_policy(path: str | Path | None) -> NoisePolicy:
    """Load a ``NoisePolicy`` from *path* if the file exists."""

    if path is None:
        return NoisePolicy(frozenset(), frozenset())
    file_path = Path(path)
    if not file_path.exists():
        return NoisePolicy(frozenset(), frozenset())
    config = tomllib.loads(file_path.read_text("utf-8"))
    hosts = config.get("hosts", {}).get("doc", [])
    sources = config.get("sources", {}).get("doc", [])
    return NoisePolicy(
        hosts_documentary=frozenset(host.lower() for host in hosts),
        sources_documentary=frozenset(src.lower() for src in sources),
    )


__all__ = ["NoisePolicy", "load_noise_policy"]
