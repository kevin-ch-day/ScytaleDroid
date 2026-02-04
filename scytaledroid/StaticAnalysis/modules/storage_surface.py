"""Storage/URI exposure posture module."""

from __future__ import annotations

import json
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

from scytaledroid.StaticAnalysis._androguard import merge_bounds_warnings, open_apk_safely
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .module_api import AppModuleContext, ModuleResult, StaticModule

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_FILE_PROVIDER_META_NAMES = {
    "android.support.FILE_PROVIDER_PATHS",
    "androidx.core.FILE_PROVIDER_PATHS",
}
_FILE_PROVIDER_CLASSES = {
    "androidx.core.content.FileProvider",
    "android.support.v4.content.FileProvider",
}


@dataclass(frozen=True)
class _ProviderRecord:
    name: str
    authorities: tuple[str, ...]
    exported: bool
    read_permission: str | None
    write_permission: str | None
    base_permission: str | None
    grant_uri_permissions: bool
    path_permissions: tuple[Mapping[str, str], ...]
    meta_resources: tuple[str, ...]


class StorageSurfaceModule(StaticModule):
    """Map FileProvider posture and content-provider ACLs."""

    name = "storage_surface"
    writes_to_db = True

    @staticmethod
    def _run_key(context: AppModuleContext) -> str:
        value = context.metadata.get("run_id")
        if isinstance(value, str) and value.strip():
            return value.strip()
        if context.session_stamp:
            return f"{context.session_stamp}:{context.package_name}"
        return context.package_name

    def run(self, context: AppModuleContext) -> ModuleResult:
        apk, warnings = open_apk_safely(str(context.apk_path))
        if warnings:
            merge_bounds_warnings(context.metadata, warnings)
            log.warning(
                "Resource table parsing emitted bounds warnings",
                category="static_analysis",
                extra={
                    "event": "storage_surface.resource_bounds_warning",
                    "apk_path": str(context.apk_path),
                    "package_name": context.package_name,
                    "warning_lines": warnings,
                },
            )
        if not context.session_stamp:
            return ModuleResult(module=self.name)
        manifest = apk.get_android_manifest_xml()
        providers = _collect_providers(manifest)
        resource_cache = _load_resource_cache(context.apk_path)

        fileprovider_rows = []
        provider_acl_rows = []
        run_key = self._run_key(context)

        for record in providers:
            paths = _resolve_fileprovider_paths(record, resource_cache)
            risk = _assess_risk(record, paths)
            read_perm = record.read_permission or record.base_permission or ""
            write_perm = record.write_permission or record.base_permission or ""
            for authority in record.authorities or (record.name,):
                fileprovider_rows.append(
                    {
                        "run_key": run_key,
                        "authority": authority,
                        "provider_name": record.name,
                        "exported": int(record.exported),
                        "grant_uri_permissions": int(record.grant_uri_permissions),
                        "read_perm": read_perm,
                        "write_perm": write_perm,
                        "base_perm": record.base_permission,
                        "path_globs": json.dumps(paths),
                        "risk": risk,
                    }
                )
                # Base-level ACL row
                provider_acl_rows.append(
                    {
                        "run_key": run_key,
                        "authority": authority,
                        "provider_name": record.name,
                        "path": "*",
                        "path_type": "base",
                        "read_perm": read_perm,
                        "write_perm": write_perm,
                        "base_perm": record.base_permission,
                        "exported": int(record.exported),
                    }
                )
                for entry in record.path_permissions:
                    for attr in ("path", "pathPrefix", "pathPattern"):
                        value = entry.get(attr)
                        if not value:
                            continue
                        provider_acl_rows.append(
                            {
                                "run_key": run_key,
                                "authority": authority,
                                "provider_name": record.name,
                                "path": value,
                                "path_type": attr,
                                "read_perm": entry.get("readPermission") or "",
                                "write_perm": entry.get("writePermission") or "",
                                "base_perm": record.base_permission,
                                "exported": int(record.exported),
                            }
                        )

        summary = {
            "fileproviders": sum(1 for row in fileprovider_rows if _is_fileprovider(row["provider_name"])),
            "broad": sum(1 for row in fileprovider_rows if "broad" in (row.get("risk") or "")),
            "exported_providers": sum(row.get("exported", 0) for row in fileprovider_rows),
        }

        data = {
            "context": {
                "package_name": context.package_name,
                "session_stamp": context.session_stamp,
                "scope_label": context.scope_label,
                "app_id": context.app_id,
                "apk_id": context.apk_id,
                "sha256": context.sha256,
                "run_key": run_key,
            },
            "fileproviders": fileprovider_rows,
            "provider_acl": provider_acl_rows,
        }

        return ModuleResult(module=self.name, data=data, summary=summary)

    def persist(self, result: ModuleResult) -> None:
        """Legacy persistence disabled; canonical pipeline handles provider data."""
        return

    def summarize(self, result: ModuleResult) -> Mapping[str, int]:
        payload = result.summary or {}
        return {
            "fileproviders": int(payload.get("fileproviders", 0)),
            "broad": int(payload.get("broad", 0)),
            "exported_providers": int(payload.get("exported_providers", 0)),
        }


def _collect_providers(manifest_root) -> Sequence[_ProviderRecord]:
    application = manifest_root.find("application")
    if application is None:
        return tuple()

    providers: list[_ProviderRecord] = []
    for element in application.findall("provider"):
        name = element.get(f"{_ANDROID_NS}name") or ""
        exported_attr = element.get(f"{_ANDROID_NS}exported")
        exported = (exported_attr or "").strip().lower() == "true"
        grant_uri = (element.get(f"{_ANDROID_NS}grantUriPermissions") or "").strip().lower() in {"true", "1"}
        read_perm = (element.get(f"{_ANDROID_NS}readPermission") or "").strip() or None
        write_perm = (element.get(f"{_ANDROID_NS}writePermission") or "").strip() or None
        base_perm = (element.get(f"{_ANDROID_NS}permission") or "").strip() or None
        authorities_raw = (element.get(f"{_ANDROID_NS}authorities") or "").split(",")
        authorities = tuple(sorted({token.strip() for token in authorities_raw if token.strip()}))

        path_perms: list[Mapping[str, str]] = []
        for path_node in element.findall("path-permission"):
            entry: dict[str, str] = {}
            for attr in ("path", "pathPrefix", "pathPattern"):
                value = path_node.get(f"{_ANDROID_NS}{attr}")
                if value:
                    entry[attr] = value
            if not entry:
                continue
            entry["readPermission"] = (
                path_node.get(f"{_ANDROID_NS}readPermission")
                or read_perm
                or base_perm
                or ""
            )
            entry["writePermission"] = (
                path_node.get(f"{_ANDROID_NS}writePermission")
                or write_perm
                or base_perm
                or ""
            )
            path_perms.append(entry)

        meta_resources = tuple(
            _normalise_resource_reference(meta.get(f"{_ANDROID_NS}resource"))
            for meta in element.findall("meta-data")
            if (meta.get(f"{_ANDROID_NS}name") or "") in _FILE_PROVIDER_META_NAMES
        )
        meta_resources = tuple(filter(None, meta_resources))

        providers.append(
            _ProviderRecord(
                name=name,
                authorities=authorities,
                exported=exported,
                read_permission=read_perm or base_perm,
                write_permission=write_perm or base_perm,
                base_permission=base_perm,
                grant_uri_permissions=grant_uri,
                path_permissions=tuple(path_perms),
                meta_resources=meta_resources,
            )
        )

    return tuple(providers)


def _normalise_resource_reference(value: str | None) -> str | None:
    if not value:
        return None
    token = value.strip()
    if not token.startswith("@"):
        return None
    try:
        _, tail = token.split("/", 1)
    except ValueError:
        return None
    return tail.replace(".", "_")


def _load_resource_cache(apk_path: Path) -> Mapping[str, list[str]]:
    cache: dict[str, list[str]] = {}
    with zipfile.ZipFile(apk_path, "r") as archive:
        for name in archive.namelist():
            if not name.startswith("res/xml") or not name.endswith(".xml"):
                continue
            key = Path(name).stem
            data = archive.read(name)
            cache.setdefault(key, []).append(data.decode("utf-8", "ignore"))
    return cache


def _resolve_fileprovider_paths(record: _ProviderRecord, cache: Mapping[str, list[str]]) -> list[str]:
    paths: list[str] = []
    if not record.meta_resources:
        return paths
    for resource_key in record.meta_resources:
        for payload in cache.get(resource_key, []):
            try:
                root = ElementTree.fromstring(payload)
            except ElementTree.ParseError:
                continue
            for child in root:
                path = child.get("path") or child.get(f"{_ANDROID_NS}path") or ""
                name = child.tag.split("}")[-1]
                paths.append(f"{name}:{path or '/'}")
    return paths


def _assess_risk(record: _ProviderRecord, paths: Iterable[str]) -> str:
    flags: list[str] = []
    if record.exported and not record.read_permission and not record.write_permission:
        flags.append("world")
    if record.grant_uri_permissions and record.exported:
        flags.append("grant")
    for entry in paths:
        _, _, suffix = entry.partition(":")
        if suffix in {"/", "*", "/*"} or ".." in suffix:
            flags.append("broad")
            break
    return " | ".join(flags) if flags else "normal"


def _is_fileprovider(provider_name: str | None) -> bool:
    if not provider_name:
        return False
    if provider_name in _FILE_PROVIDER_CLASSES:
        return True
    return provider_name.lower().endswith(".fileprovider")


__all__ = ["StorageSurfaceModule"]
