"""Storage/URI exposure posture module."""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping
from xml.etree import ElementTree

from scytaledroid.Database.db_func.harvest import storage_surface as storage_db
from scytaledroid.StaticAnalysis._androguard import APK

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

    def run(self, context: AppModuleContext) -> ModuleResult:
        apk = APK(str(context.apk_path))
        manifest = apk.get_android_manifest_xml()
        providers = _collect_providers(manifest)
        resource_cache = _load_resource_cache(context.apk_path)

        fileprovider_rows = []
        provider_acl_rows = []

        for record in providers:
            paths = _resolve_fileprovider_paths(record, resource_cache)
            risk = _assess_risk(record, paths)
            grant_flags = "uri" if record.grant_uri_permissions else "none"
            for authority in record.authorities or (record.name,):
                fileprovider_rows.append(
                    {
                        "authority": authority,
                        "provider_name": record.name,
                        "exported": int(record.exported),
                        "grant_flags": grant_flags,
                        "path_globs": json.dumps(paths),
                        "risk": risk,
                    }
                )
                provider_acl_rows.append(
                    {
                        "authority": authority,
                        "provider_name": record.name,
                        "read_perm": record.read_permission,
                        "write_perm": record.write_permission,
                        "base_perm": record.base_permission,
                        "exported": int(record.exported),
                        "path_perms_json": json.dumps(record.path_permissions),
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
            },
            "fileproviders": fileprovider_rows,
            "provider_acl": provider_acl_rows,
        }

        return ModuleResult(module=self.name, data=data, summary=summary)

    def persist(self, result: ModuleResult) -> None:
        if not result.data:
            return
        try:
            storage_db.ensure_tables()
            storage_db.replace_fileproviders(
                result.data.get("context", {}), result.data.get("fileproviders", ())
            )
            storage_db.replace_provider_acl(
                result.data.get("context", {}), result.data.get("provider_acl", ())
            )
        except Exception:
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

