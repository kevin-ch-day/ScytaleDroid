"""Common protocol definitions for static-analysis modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Protocol, Sequence

from ..core.models import StaticAnalysisReport


@dataclass(frozen=True)
class AppModuleContext:
    """Context passed to static modules for per-app execution."""

    report: StaticAnalysisReport
    package_name: str
    apk_path: Path
    metadata: Mapping[str, object] = field(default_factory=dict)
    session_stamp: Optional[str] = None
    scope_label: Optional[str] = None

    @property
    def app_id(self) -> Optional[str]:
        value = self.metadata.get("app_id")
        if value is None:
            return None
        return str(value)

    @property
    def apk_id(self) -> Optional[str]:
        value = self.metadata.get("apk_id")
        if value is None:
            return None
        return str(value)

    @property
    def sha256(self) -> Optional[str]:
        hashes = self.report.hashes or {}
        value = hashes.get("sha256")
        if isinstance(value, str) and value.strip():
            return value
        meta_value = self.metadata.get("sha256")
        if isinstance(meta_value, str) and meta_value.strip():
            return meta_value
        return None


@dataclass(frozen=True)
class ModuleResult:
    """Container for data produced by a module run."""

    module: str
    data: Mapping[str, Any] = field(default_factory=dict)
    summary: Mapping[str, Any] = field(default_factory=dict)
    findings: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    errors: Sequence[str] = field(default_factory=tuple)


class StaticModule(Protocol):
    """Interface implemented by static-analysis modules."""

    name: str
    writes_to_db: bool

    def run(self, context: AppModuleContext) -> ModuleResult:
        """Execute the module and return its structured result."""

    def persist(self, result: ModuleResult) -> None:
        """Persist module output to the database (no-op for read-only modules)."""

    def summarize(self, result: ModuleResult) -> Mapping[str, Any]:
        """Return a lightweight summary suitable for console output."""

