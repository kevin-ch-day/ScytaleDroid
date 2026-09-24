"""Disposable Linux/KVM outer worker for the pinned benign instrument only.

No host network or personal filesystem is exposed. The fixed read-only /usr and
SDK shares supply public runtime tools; writable export is one fresh directory.
"""

from __future__ import annotations

import gzip
import hashlib
import re
import shutil
import subprocess
from pathlib import Path


def build_boot_image(destination: Path, *, kernel_release: str) -> dict:
    """Build a minimal initramfs from installed public binaries and kernel modules."""
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", kernel_release):
        raise ValueError("Invalid kernel release")
    destination.mkdir(parents=True, exist_ok=False)
    root = destination / "root"
    root.mkdir()
    for name in [
        "bin",
        "lib64",
        "modules",
        "dev",
        "proc",
        "sys",
        "usr",
        "sdk",
        "control",
        "export",
        "work",
        "tmp",
        "etc",
        "run",
        "home",
    ]:
        (root / name).mkdir()
    binaries = ["/usr/bin/bash", "/usr/bin/mount", "/usr/bin/kmod"]
    for name in binaries:
        src = Path(name)
        shutil.copyfile(src, root / "bin" / src.name)
        (root / "bin" / src.name).chmod(0o755)
        dependencies = subprocess.check_output(["ldd", name], text=True)
        for lib in re.findall(r"(/[\w/+.\-]+)", dependencies):
            p = Path(lib)
            if p.is_file():
                shutil.copyfile(p, root / "lib64" / p.name)
                (root / "lib64" / p.name).chmod(0o755)
    (root / "bin/insmod").symlink_to("kmod")
    modules = []
    for name in ["virtio_pci", "virtio_blk", "ext4", "9p", "9pnet_virtio", "kvm_amd"]:
        output = subprocess.check_output(
            ["modprobe", "--set-version", kernel_release, "--show-depends", name], text=True
        )
        for line in output.splitlines():
            if not line.startswith("insmod "):
                continue
            src = Path(line.split()[1])
            if src.name not in modules:
                modules.append(src.name)
                shutil.copyfile(src, root / "modules" / src.name)
    init = """#!/bin/bash
set -eu
/bin/mount -t devtmpfs devtmpfs /dev
exec >/dev/console 2>&1
/bin/mount -t proc proc /proc
/bin/mount -t sysfs sysfs /sys
"""
    init += "".join("/bin/insmod /modules/" + name + "\n" for name in modules)
    init += """/bin/mount -t 9p -o trans=virtio,version=9p2000.L,ro,nosuid,nodev usr /usr
/bin/mount --bind /usr/bin /bin
/bin/mount --bind /usr/lib64 /lib64
/bin/ln -s /usr/lib /lib
/bin/mount -t 9p -o trans=virtio,version=9p2000.L,ro,nosuid,nodev sdk /sdk
/bin/mount -t 9p -o trans=virtio,version=9p2000.L,ro,nosuid,nodev control /control
/bin/mount -t 9p -o trans=virtio,version=9p2000.L export /export
/usr/sbin/mkfs.ext4 -q -F /dev/vda
/bin/mount -o nosuid,nodev /dev/vda /work
/bin/mount -t tmpfs tmpfs /tmp
/bin/ip link set lo up
export PATH=/usr/bin:/sdk/platform-tools
export HOME=/work/home
export LANG=C.UTF-8
export ANDROID_SDK_ROOT=/sdk ANDROID_HOME=/sdk
export ANDROID_AVD_HOME=/work/avds ANDROID_USER_HOME=/work/home/.android
export ANDROID_ADB_SERVER_PORT=5038 ADB_SERVER_SOCKET=localfilesystem:/work/adb-server.sock
/bin/cp -r /control/avds /work/avds
/bin/cp /control/trial.json /work/trial.json
/bin/ln -s /control/fixture.apk /fixture.apk
/usr/bin/python3 /control/worker_entry.py
/bin/sync
/bin/poweroff -f
"""
    (root / "init").write_text(init)
    (root / "init").chmod(0o755)
    names = ["."] + [str(p.relative_to(root)) for p in sorted(root.rglob("*"))]
    archive = subprocess.run(
        ["cpio", "-o", "-H", "newc", "--quiet"],
        input=("\n".join(names) + "\n").encode(),
        cwd=root,
        capture_output=True,
        check=True,
    ).stdout
    image = destination / "initramfs.cpio.gz"
    with image.open("wb") as f:
        with gzip.GzipFile(fileobj=f, mode="wb", mtime=0) as z:
            z.write(archive)
    kernel = destination / "vmlinuz"
    shutil.copyfile(Path("/boot") / ("vmlinuz-" + kernel_release), kernel)
    return {
        "kernel_release": kernel_release,
        "kernel_sha256": hashlib.sha256(kernel.read_bytes()).hexdigest(),
        "initramfs_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        "modules": modules,
    }


def worker_command(
    *, boot: Path, sdk: Path, control: Path, export: Path, scratch: Path
) -> list[str]:
    """Fixed QEMU mounts inside a rootless network/filesystem namespace."""
    paths = [Path(p).resolve(strict=True) for p in (boot, sdk, control, export, scratch)]
    if len(set(paths)) != 5 or any(a in b.parents for a in paths for b in paths if a != b):
        raise ValueError("Worker input/export directories must be separate")
    if any(p == Path("/") or p == Path.home() for p in paths):
        raise ValueError("Broad worker mount rejected")
    boot, sdk, control, export, scratch = paths
    cmd = [
        "/usr/bin/bwrap",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/bin",
        "/bin",
        "--ro-bind",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dev-bind",
        "/dev/kvm",
        "/dev/kvm",
        "--tmpfs",
        "/tmp",
        "--setenv",
        "PATH",
        "/usr/bin",
        "--setenv",
        "HOME",
        "/tmp",
    ]
    for src, dst, readonly in [
        (boot, "/boot", True),
        (sdk, "/sdk", True),
        (control, "/control", True),
        (export, "/export", False),
        (scratch, "/scratch", False),
    ]:
        cmd += ["--ro-bind" if readonly else "--bind", str(src), dst]
    cmd += [
        "/usr/bin/qemu-system-x86_64",
        "-enable-kvm",
        "-cpu",
        "host",
        "-m",
        "4096",
        "-smp",
        "2",
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-nic",
        "none",
        "-no-reboot",
        "-drive",
        "file=/scratch/disk.raw,format=raw,if=virtio,cache=none",
        "-kernel",
        "/boot/vmlinuz",
        "-initrd",
        "/boot/initramfs.cpio.gz",
        "-append",
        "console=ttyS0 rdinit=/init panic=1 quiet",
    ]
    for tag, path, ro in [
        ("usr", "/usr", True),
        ("sdk", "/sdk", True),
        ("control", "/control", True),
        ("export", "/export", False),
    ]:
        cmd += [
            "-virtfs",
            f"local,path={path},mount_tag={tag},security_model=none"
            + (",readonly=on" if ro else ""),
        ]
    return cmd
