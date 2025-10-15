from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

pytest.importorskip("bs4")

from scytaledroid.Utils.AndroidPermCatalog import api
from scytaledroid.Utils.AndroidPermCatalog.parser import parse_manifest_permissions


def _build_section(permission: str, body: str, *, data_version: str = "33") -> str:
    return f"""
    <section data-version-added=\"{data_version}\">
      <h2 id=\"{permission}\">{permission}</h2>
      {body}
    </section>
    """


def test_build_catalog_from_docs_merges_adservices_permissions() -> None:
    primary_html = """
    <html><body>
    {section}
    </body></html>
    """.format(
        section=_build_section(
            "android.permission.ACCESS_FINE_LOCATION",
            "<p>Protection level: dangerous</p><p>Summary.</p>",
            data_version="4",
        )
    )

    adservices_html = """
    <html><body>
    {section}
    </body></html>
    """.format(
        section=_build_section(
            "android.permission.ACCESS_ADSERVICES_TOPICS",
            """
            <dl>
              <dt>Protection level</dt>
              <dd>
                <span class=\"devsite-chip\">Signature</span>
                <span class=\"devsite-chip\">Privileged</span>
              </dd>
            </dl>
            <p>Controls access to Topics.</p>
            """,
        )
    )

    docs = [
        (primary_html, "https://example.com/reference/android/Manifest.permission"),
        (adservices_html, "https://example.com/reference/android/adservices/common/AdServicesPermissions"),
    ]

    catalog = api.build_catalog_from_docs(docs)

    shorts = {entry.short: entry for entry in catalog}
    assert "ACCESS_FINE_LOCATION" in shorts
    assert shorts["ACCESS_FINE_LOCATION"].protection == "dangerous"

    assert "ACCESS_ADSERVICES_TOPICS" in shorts
    adservices_entry = shorts["ACCESS_ADSERVICES_TOPICS"]
    assert adservices_entry.protection_tokens == ("signature", "privileged")
    assert adservices_entry.doc_url.endswith("#android.permission.ACCESS_ADSERVICES_TOPICS")


def test_parse_manifest_permissions_handles_protection_list_layout() -> None:
    html = """
    <html><body>
    {section}
    </body></html>
    """.format(
        section=_build_section(
            "android.permission.READ_PRECISE_PHONE_STATE",
            """
            <div>
              <p><strong>Protection levels</strong></p>
              <ul>
                <li>Signature</li>
                <li>Privileged</li>
              </ul>
            </div>
            <p>Grants precise phone state access.</p>
            """,
        )
    )

    entries = parse_manifest_permissions(
        html,
        base_url="https://example.com/reference/android/Manifest.permission",
    )

    assert len(entries) == 1
    entry = entries[0]
    assert entry.short == "READ_PRECISE_PHONE_STATE"
    assert entry.protection_tokens == ("signature", "privileged")
