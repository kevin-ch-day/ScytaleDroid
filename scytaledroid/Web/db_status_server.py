"""Minimal HTTP endpoint to report DB backend and schema_version.

Usage:
    python -m scytaledroid.Web.db_status_server --host 0.0.0.0 --port 8080

No auth, no UI polish; intended for Phase-1 coexistence checks so web + CLI
can prove they see the same database and schema version.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core.db_engine import DatabaseEngine
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def _gather_status() -> tuple[int, dict[str, object]]:
    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
    host = str(cfg.get("host", "<unknown>"))
    port = str(cfg.get("port", "<unknown>"))
    database = str(cfg.get("database", "<unknown>"))
    user = str(cfg.get("user", "<unknown>"))
    schema_version: str | None = None

    try:
        engine = DatabaseEngine()
        engine.fetch_one("SELECT 1")
        try:
            row = engine.fetch_one(
                "SELECT version, applied_at_utc FROM schema_version ORDER BY applied_at_utc DESC LIMIT 1"
            )
            schema_version = str(row[0]) if row else None
        except Exception as exc:
            log.warning(f"db_status: schema_version unavailable ({exc})", category="database")
            return 503, {
                "ok": False,
                "backend": backend,
                "host": host,
                "port": port,
                "database": database,
                "user": user,
                "schema_version": None,
                "error": f"schema_version unavailable: {exc}",
            }
        return 200, {
            "ok": True,
            "backend": backend,
            "host": host,
            "port": port,
            "database": database,
            "user": user,
            "schema_version": schema_version,
        }
    except Exception as exc:
        log.error(f"db_status: connection failed ({exc})", category="database")
        return 503, {
            "ok": False,
            "backend": backend,
            "host": host,
            "port": port,
            "database": database,
            "user": user,
            "schema_version": None,
            "error": str(exc),
        }


class _StatusHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler naming
        if self.path not in {"/", "/db_status"}:
            self.send_response(404)
            self.end_headers()
            return
        status_code, payload = _gather_status()
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args):  # noqa: A003 - inherited name
        # Silence default stdout logging; rely on logging_utils.
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DB status HTTP endpoint")
    parser.add_argument("--host", default="127.0.0.1", help="Listen host")
    parser.add_argument("--port", type=int, default=8080, help="Listen port")
    args = parser.parse_args(argv)

    server = HTTPServer((args.host, args.port), _StatusHandler)
    log.info(f"db_status server listening on {args.host}:{args.port}", category="database")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
