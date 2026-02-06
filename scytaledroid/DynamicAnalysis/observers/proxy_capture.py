"""Proxy-based network capture observer (mitmproxy/mitmdump)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

from scytaledroid.DeviceAnalysis.adb import client as adb_client, shell as adb_shell
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.observers.base import Observer, ObserverHandle, ObserverResult


class ProxyCaptureObserver(Observer):
    observer_id = "proxy_capture"
    observer_name = "Proxy Capture"

    def start(self, run_ctx: RunContext) -> ObserverHandle:
        if not adb_client.is_available():
            raise RuntimeError("adb binary not available on PATH")
        if not run_ctx.device_serial:
            raise RuntimeError("device serial required for proxy capture")
        mitm_bin, hint = resolve_mitmdump_path()
        if mitm_bin is None:
            message = "mitmdump/mitmproxy not available on PATH"
            if hint:
                message = f"{message}. {hint}"
            raise RuntimeError(message)

        port = int(getattr(run_ctx, "proxy_port", 8890))
        capture_dir = run_ctx.run_dir / f"artifacts/{self.observer_id}"
        capture_dir.mkdir(parents=True, exist_ok=True)
        capture_path = capture_dir / "proxy_capture.mitm"
        meta_path = capture_dir / "proxy_capture_meta.json"
        flow_log_path = capture_dir / "flows.jsonl"

        adb_shell.run_shell(run_ctx.device_serial, ["reverse", f"tcp:{port}", f"tcp:{port}"])
        adb_shell.run_shell(run_ctx.device_serial, ["settings", "put", "global", "http_proxy", f"127.0.0.1:{port}"])

        addon_path = Path(__file__).with_name("mitm_flow_logger.py")
        env = os.environ.copy()
        env["SCYTALE_MITM_FLOW_LOG"] = str(flow_log_path)
        process = subprocess.Popen(
            [mitm_bin, "-p", str(port), "-w", str(capture_path), "-s", str(addon_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        time.sleep(1.0)
        if process.poll() is not None:
            stderr = _read_process_stderr(process)
            raise RuntimeError(f"mitmdump exited early. {stderr}".strip())
        if not _is_port_listening(port):
            process.terminate()
            stderr = _read_process_stderr(process)
            raise RuntimeError(f"mitmdump did not open port {port}. {stderr}".strip())
        meta_path.write_text(
            json.dumps(
                {
                    "proxy_host": "127.0.0.1",
                    "proxy_port": port,
                    "mitm_binary": mitm_bin,
                    "capture_path": str(capture_path.name),
                    "flow_log_path": str(flow_log_path.name),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return ObserverHandle(
            observer_id=self.observer_id,
            payload={
                "process": process,
                "capture_path": capture_path,
                "meta_path": meta_path,
                "flow_log_path": flow_log_path,
                "port": port,
            },
        )

    def stop(self, handle: ObserverHandle | None, run_ctx: RunContext) -> ObserverResult:
        if handle is None or handle.payload is None:
            raise RuntimeError("proxy capture handle missing")
        payload = handle.payload
        process = payload["process"]
        capture_path: Path = payload["capture_path"]
        meta_path: Path = payload["meta_path"]
        flow_log_path: Path = payload["flow_log_path"]
        port = payload["port"]

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

        artifacts: list[ArtifactRecord] = []
        if meta_path.exists():
            digest = hashlib.sha256(meta_path.read_bytes()).hexdigest()
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(meta_path.relative_to(run_ctx.run_dir)),
                    type="proxy_capture_meta",
                    sha256=digest,
                    size_bytes=meta_path.stat().st_size,
                    produced_by=self.observer_id,
                    origin="host",
                    pull_status="n/a",
                )
            )

        if flow_log_path.exists():
            digest = hashlib.sha256(flow_log_path.read_bytes()).hexdigest()
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(flow_log_path.relative_to(run_ctx.run_dir)),
                    type="proxy_flow_log",
                    sha256=digest,
                    size_bytes=flow_log_path.stat().st_size,
                    produced_by=self.observer_id,
                    origin="host",
                    pull_status="n/a",
                )
            )
            summary_path = _write_flow_summary(flow_log_path, flow_log_path.parent)
            if summary_path:
                digest = hashlib.sha256(summary_path.read_bytes()).hexdigest()
                artifacts.append(
                    ArtifactRecord(
                        relative_path=str(summary_path.relative_to(run_ctx.run_dir)),
                        type="network_flow_summary",
                        sha256=digest,
                        size_bytes=summary_path.stat().st_size,
                        produced_by=self.observer_id,
                        origin="host",
                        pull_status="n/a",
                    )
                )

        status = "success"
        error = None
        if capture_path.exists():
            digest = hashlib.sha256(capture_path.read_bytes()).hexdigest()
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(capture_path.relative_to(run_ctx.run_dir)),
                    type="proxy_capture",
                    sha256=digest,
                    size_bytes=capture_path.stat().st_size,
                    produced_by=self.observer_id,
                    origin="host",
                    pull_status="n/a",
                )
            )
        else:
            status = "failed"
            error = "Proxy capture file missing."
            error_path = run_ctx.run_dir / f"artifacts/{self.observer_id}/observer_error.txt"
            error_path.write_text(error or "")
            digest = hashlib.sha256(error_path.read_bytes()).hexdigest()
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(error_path.relative_to(run_ctx.run_dir)),
                    type="observer_error",
                    sha256=digest,
                    size_bytes=error_path.stat().st_size,
                    produced_by=self.observer_id,
                    origin="host",
                    pull_status="n/a",
                )
            )

        if run_ctx.device_serial:
            try:
                adb_shell.run_shell(run_ctx.device_serial, ["settings", "put", "global", "http_proxy", ":0"])
                adb_shell.run_shell(run_ctx.device_serial, ["settings", "delete", "global", "http_proxy"])
                adb_shell.run_shell(run_ctx.device_serial, ["reverse", "--remove", f"tcp:{port}"])
            except Exception:
                pass

        return ObserverResult(
            observer_id=self.observer_id,
            status=status,
            error=error,
            artifacts=artifacts,
        )


def resolve_mitmdump_path() -> tuple[str | None, str | None]:
    env_path = os.environ.get("MITMDUMP_PATH")
    if env_path:
        candidate = Path(env_path).expanduser()
        if candidate.exists():
            return str(candidate), None
        return None, f"MITMDUMP_PATH is set but missing: {candidate}"

    mitm_bin = shutil.which("mitmdump") or shutil.which("mitmproxy")
    if mitm_bin:
        return mitm_bin, None

    local_bin = Path.home() / ".local" / "bin" / "mitmdump"
    if local_bin.exists():
        hint = "Add to PATH: export PATH=\"$HOME/.local/bin:$PATH\""
        return str(local_bin), hint

    return None, "Install mitmproxy or set MITMDUMP_PATH"


def _read_process_stderr(process: subprocess.Popen[str]) -> str:
    if process.stderr is None:
        return ""
    try:
        return process.stderr.read() or ""
    except OSError:
        return ""


def _is_port_listening(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _write_flow_summary(flow_log_path: Path, output_dir: Path) -> Path | None:
    destinations: set[str] = set()
    request_count = 0
    first_ts = None
    last_ts = None
    try:
        lines = flow_log_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = payload.get("host")
        port = payload.get("port")
        ts = payload.get("ts")
        if host and port:
            destinations.add(f"{host}:{port}")
        request_count += 1
        if isinstance(ts, (int, float)):
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts
    summary_path = output_dir / "network_flow_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "destinations": sorted(destinations),
                "request_count": request_count,
                "first_ts": first_ts,
                "last_ts": last_ts,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return summary_path


__all__ = ["ProxyCaptureObserver", "resolve_mitmdump_path"]
