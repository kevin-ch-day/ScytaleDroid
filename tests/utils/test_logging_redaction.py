from __future__ import annotations

import json
import logging

from scytaledroid.Utils.LoggingUtils.logging_core import (
    JsonFormatter,
    SafeFormatter,
    redact_log_value,
)


def _record(message: str, **extras: object) -> logging.LogRecord:
    record = logging.LogRecord("security-test", logging.INFO, __file__, 1, message, (), None)
    for key, value in extras.items():
        setattr(record, key, value)
    return record


def test_redact_log_value_handles_common_secret_key_variants() -> None:
    redacted = redact_log_value(
        {
            "db_passwd": "db-password",
            "clientSecret": "client-secret",
            "access_token": "access-token",
            "X-API-Key": "api-key",
            "profile_key": "retain-this",
        }
    )

    assert redacted == {
        "db_passwd": "***REDACTED***",
        "clientSecret": "***REDACTED***",
        "access_token": "***REDACTED***",
        "X-API-Key": "***REDACTED***",
        "profile_key": "retain-this",
    }


def test_json_formatter_redacts_message_and_structured_secrets() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjb2RleCJ9.signaturevalue"
    record = _record(
        f"authorization=Bearer top-secret-token jwt={token} client_secret=client-value",
        db_passwd="database-value",
    )

    payload = json.loads(JsonFormatter().format(record))

    assert "top-secret-token" not in payload["message"]
    assert token not in payload["message"]
    assert "client-value" not in payload["message"]
    assert payload["db_passwd"] == "***REDACTED***"


def test_safe_formatter_redacts_message_without_mutating_log_record() -> None:
    record = _record("x-api-key: top-secret-value")

    rendered = SafeFormatter("%(message)s").format(record)

    assert "top-secret-value" not in rendered
    assert "top-secret-value" in str(record.msg)
