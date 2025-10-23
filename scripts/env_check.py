#!/usr/bin/env python3
import shutil, sys, json, subprocess
import importlib

def which(cmd):
    p = shutil.which(cmd)
    return {"cmd": cmd, "path": p, "ok": bool(p)}

def pyver():
    return {"python": sys.version.split()[0], "executable": sys.executable}

def pipver(pkg):
    try:
        m = importlib.import_module(pkg)
        v = getattr(m, "__version__", "unknown")
        return {"package": pkg, "version": v, "ok": True}
    except Exception as e:
        return {"package": pkg, "error": str(e), "ok": False}

def try_aapt2():
    a2 = shutil.which("aapt2")
    if not a2:
        return {"aapt2": False, "hint": "Install Android build-tools; ensure aapt2 on PATH"}
    try:
        out = subprocess.check_output([a2, "version"], timeout=4).decode(errors="ignore").strip()
        return {"aapt2": True, "version": out}
    except Exception as e:
        return {"aapt2": True, "error": str(e)}

def main():
    out = {
        "python": pyver(),
        "bins": [which("aapt2"), which("apksigner")],
        "py": [pipver("androguard")],
    }
    out["aapt2_status"] = try_aapt2()
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()
