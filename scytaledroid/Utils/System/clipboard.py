"""Best-effort clipboard helper for CLI workflows.

We avoid hard dependencies; if no clipboard tool is available, callers can
fall back to printing the value.
"""

from __future__ import annotations

import shutil
import subprocess


def copy_text(text: str) -> bool:
    """Copy *text* to the system clipboard. Returns True on success."""

    payload = (text or "").encode("utf-8")
    if not payload:
        return False

    # Prefer Wayland; fall back to X11.
    for cmd in (("wl-copy",), ("xclip", "-selection", "clipboard")):
        exe = cmd[0]
        if not shutil.which(exe):
            continue
        try:
            subprocess.run(
                list(cmd),
                input=payload,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            return True
        except Exception:
            continue
    return False

