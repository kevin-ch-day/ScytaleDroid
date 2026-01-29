"""Mitmproxy addon to log basic request flow metadata."""

from __future__ import annotations

import json
import os
import time

from mitmproxy import http


def request(flow: http.HTTPFlow) -> None:
    log_path = os.environ.get("SCYTALE_MITM_FLOW_LOG")
    if not log_path:
        return
    record = {
        "ts": time.time(),
        "host": flow.request.host,
        "port": flow.request.port,
        "scheme": flow.request.scheme,
        "method": flow.request.method,
        "path": flow.request.path,
    }
    try:
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass
