"""ADB-backed interaction automation for live dynamic captures.

This module is intentionally separate from the paper/scripted protocol runtime.
It gives operators a duration-bounded way to exercise an app during capture
without changing run countability, evidence policy, or DB state.
"""

from __future__ import annotations

import random
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from scytaledroid.DeviceAnalysis.adb import shell as adb_shell


@dataclass(frozen=True)
class DeviceGeometry:
    width: int = 720
    height: int = 1612

    def point(self, x_ratio: float, y_ratio: float) -> tuple[int, int]:
        x = int(round(max(0.0, min(1.0, float(x_ratio))) * self.width))
        y = int(round(max(0.0, min(1.0, float(y_ratio))) * self.height))
        return x, y


@dataclass(frozen=True)
class AutomationAction:
    label: str
    op: str
    args: tuple[object, ...] = ()
    delay_after_s: float = 0.5
    mutation_candidate: bool = False

    def adb_command(self, geometry: DeviceGeometry) -> list[str] | None:
        if self.op == "sleep":
            return None
        if self.op == "tap":
            x, y = geometry.point(float(self.args[0]), float(self.args[1]))
            return ["input", "tap", str(x), str(y)]
        if self.op == "swipe":
            x1, y1 = geometry.point(float(self.args[0]), float(self.args[1]))
            x2, y2 = geometry.point(float(self.args[2]), float(self.args[3]))
            duration_ms = int(self.args[4]) if len(self.args) > 4 else 650
            return ["input", "swipe", str(x1), str(y1), str(x2), str(y2), str(duration_ms)]
        if self.op == "text":
            return ["input", "text", adb_input_text(str(self.args[0]))]
        if self.op == "keyevent":
            return ["input", "keyevent", str(self.args[0])]
        if self.op == "monkey_launch":
            return [
                "monkey",
                "-p",
                str(self.args[0]),
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ]
        raise ValueError(f"Unsupported automation op: {self.op}")


def adb_input_text(value: str) -> str:
    """Escape a simple string for ``adb shell input text``."""
    text = str(value or "")
    text = text.replace("%", "%25")
    text = text.replace(" ", "%s")
    text = text.replace("&", "\\&")
    text = text.replace("(", "\\(").replace(")", "\\)")
    return text


def parse_wm_size(output: str) -> DeviceGeometry:
    match = re.search(r"Physical size:\s*(\d+)x(\d+)", str(output or ""))
    if not match:
        return DeviceGeometry()
    return DeviceGeometry(width=int(match.group(1)), height=int(match.group(2)))


def read_device_geometry(serial: str) -> DeviceGeometry:
    return parse_wm_size(adb_shell.run_shell(serial, ["wm", "size"], timeout=5.0))


def foreground_package_from_window_dump(output: str) -> str | None:
    """Extract the foreground package from a ``dumpsys window``/activity snippet."""
    text = str(output or "")
    for line in text.splitlines():
        if not any(
            marker in line
            for marker in ("mCurrentFocus", "mFocusedApp", "mFocusedWindow", "topResumedActivity")
        ):
            continue
        match = re.search(r"u0\s+([a-zA-Z0-9_.]+)/[a-zA-Z0-9_.$]+", line)
        if match:
            return str(match.group(1) or "").strip().lower() or None
    return None


def read_foreground_package(serial: str) -> str | None:
    try:
        activity_output = adb_shell.run_shell(
            serial,
            ["dumpsys", "activity", "activities"],
            timeout=5.0,
        )
        package = foreground_package_from_window_dump(activity_output)
        if package:
            return package
        window_output = adb_shell.run_shell(serial, ["dumpsys", "window"], timeout=5.0)
        return foreground_package_from_window_dump(window_output)
    except Exception:
        return None


def _repeat_to_duration(actions: list[AutomationAction], *, duration_s: int) -> list[AutomationAction]:
    if duration_s <= 0:
        return list(actions)
    out: list[AutomationAction] = []
    total = 0.0
    idx = 0
    while total < duration_s and idx < max(len(actions) * 12, len(actions)):
        action = actions[idx % len(actions)]
        out.append(action)
        total += max(float(action.delay_after_s), 0.0)
        if action.op == "swipe":
            total += 0.8
        elif action.op in {"tap", "text", "keyevent", "monkey_launch"}:
            total += 0.2
        idx += 1
    return out


def build_x_twitter_plan(
    *,
    duration_s: int,
    allow_mutation: bool = False,
    submit_test_post: bool = False,
) -> list[AutomationAction]:
    """Build a deterministic X/Twitter app exercise plan.

    Coordinates are ratio-based so the same plan can run on different screen
    sizes. Mutation-capable steps are included only when explicitly requested.
    """
    actions = [
        AutomationAction("launch X", "monkey_launch", ("com.twitter.android",), 2.5),
        AutomationAction("home feed scroll 1", "swipe", (0.50, 0.78, 0.50, 0.28, 650), 2.0),
        AutomationAction("home feed scroll 2", "swipe", (0.50, 0.78, 0.50, 0.28, 650), 2.0),
        AutomationAction("open visible post/detail", "tap", (0.50, 0.48), 3.0),
        AutomationAction("return from post/detail", "keyevent", ("BACK",), 1.0),
        AutomationAction("open search/explore tab", "tap", (0.30, 0.92), 2.0),
        AutomationAction("tap search box", "tap", (0.45, 0.08), 1.0),
        AutomationAction("search neutral topic", "text", ("android privacy security",), 0.5),
        AutomationAction("submit search", "keyevent", ("ENTER",), 3.0),
        AutomationAction("scroll search results", "swipe", (0.50, 0.78, 0.50, 0.30, 650), 2.0),
        AutomationAction("return from search", "keyevent", ("BACK",), 1.0),
        AutomationAction("open Grok tab", "tap", (0.50, 0.92), 4.0),
        AutomationAction("return from Grok if nested", "keyevent", ("BACK",), 1.0),
        AutomationAction("open notifications tab", "tap", (0.70, 0.92), 3.0),
        AutomationAction("scroll notifications", "swipe", (0.50, 0.78, 0.50, 0.35, 650), 1.5),
        AutomationAction("open chat/messages tab", "tap", (0.90, 0.92), 3.0),
        AutomationAction("return to home tab", "tap", (0.10, 0.92), 2.0),
        AutomationAction("home feed scroll 3", "swipe", (0.50, 0.78, 0.50, 0.28, 650), 2.0),
    ]
    if allow_mutation:
        actions.extend(
            [
                AutomationAction("open compose", "tap", (0.89, 0.84), 2.0, True),
                AutomationAction(
                    "type labeled test draft",
                    "text",
                    ("ScytaleDroid Android X interactive capture test",),
                    1.0,
                    True,
                ),
            ]
        )
        if submit_test_post:
            actions.append(
                AutomationAction("submit labeled test post", "tap", (0.90, 0.08), 3.0, True)
            )
        else:
            actions.extend(
                [
                    AutomationAction("back out of draft", "keyevent", ("BACK",), 1.0, True),
                    AutomationAction("dismiss draft prompt if shown", "keyevent", ("BACK",), 1.0, True),
                ]
            )
    actions.append(AutomationAction("settle foreground", "sleep", (), 4.0))
    return _repeat_to_duration(actions, duration_s=duration_s)


def build_safe_fuzz_plan(
    *,
    duration_s: int,
    seed: int = 1,
    allow_mutation: bool = False,
) -> list[AutomationAction]:
    """Build a bounded generic app fuzz plan.

    Default fuzzing avoids the top/bottom action strips and mostly uses swipes
    plus occasional safe navigation-tab taps. With ``allow_mutation`` it may tap
    inside the content area, but it still does not type text.
    """
    rng = random.Random(int(seed))
    actions: list[AutomationAction] = []
    total = 0.0
    while total < max(int(duration_s), 1):
        roll = rng.random()
        if roll < 0.65:
            start_y = rng.uniform(0.68, 0.82)
            end_y = rng.uniform(0.25, 0.42)
            actions.append(
                AutomationAction(
                    "fuzz content scroll",
                    "swipe",
                    (rng.uniform(0.42, 0.58), start_y, rng.uniform(0.42, 0.58), end_y, 500),
                    rng.uniform(0.8, 1.8),
                )
            )
            total += 2.0
        elif roll < 0.85:
            actions.append(
                AutomationAction(
                    "fuzz bottom navigation tap",
                    "tap",
                    (rng.choice((0.10, 0.30, 0.50, 0.70, 0.90)), 0.92),
                    rng.uniform(1.5, 3.0),
                )
            )
            total += 2.0
        elif allow_mutation:
            actions.append(
                AutomationAction(
                    "fuzz content tap",
                    "tap",
                    (rng.uniform(0.20, 0.80), rng.uniform(0.25, 0.78)),
                    rng.uniform(1.0, 2.0),
                    True,
                )
            )
            total += 1.5
        else:
            actions.append(AutomationAction("fuzz settle", "sleep", (), rng.uniform(1.0, 2.0)))
            total += 1.5
    return actions


def run_automation_actions(
    *,
    serial: str,
    actions: Iterable[AutomationAction],
    geometry: DeviceGeometry | None = None,
    dry_run: bool = False,
    run_shell: Callable[[str, list[str]], str] | None = None,
    expected_package: str | None = None,
    package_lock: bool = True,
    foreground_reader: Callable[[str], str | None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, int]:
    geometry = geometry or read_device_geometry(serial)
    executor = run_shell or (lambda device_serial, command: adb_shell.run_shell(device_serial, command))
    target_package = str(expected_package or "").strip().lower()
    read_foreground = foreground_reader or read_foreground_package
    counts = {
        "planned": 0,
        "executed": 0,
        "mutating": 0,
        "skipped_dry_run": 0,
        "foreground_checks": 0,
        "foreground_recoveries": 0,
        "blocked_foreground": 0,
    }

    def _is_target_foreground() -> bool:
        if not package_lock or not target_package:
            return True
        counts["foreground_checks"] += 1
        return str(read_foreground(serial) or "").strip().lower() == target_package

    def _recover_target_foreground() -> bool:
        if not package_lock or not target_package:
            return True
        if _is_target_foreground():
            return True
        for _idx in range(2):
            executor(serial, ["input", "keyevent", "BACK"])
            counts["foreground_recoveries"] += 1
            if _is_target_foreground():
                return True
        executor(
            serial,
            [
                "monkey",
                "-p",
                target_package,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
        )
        counts["foreground_recoveries"] += 1
        return _is_target_foreground()

    for action in actions:
        counts["planned"] += 1
        if action.mutation_candidate:
            counts["mutating"] += 1
        command = action.adb_command(geometry)
        if dry_run:
            counts["skipped_dry_run"] += 1
        elif command is not None:
            if not _recover_target_foreground():
                counts["blocked_foreground"] += 1
                continue
            executor(serial, command)
            counts["executed"] += 1
            if not _recover_target_foreground():
                counts["blocked_foreground"] += 1
        if not dry_run:
            sleep(max(float(action.delay_after_s), 0.0))
    return counts


__all__ = [
    "AutomationAction",
    "DeviceGeometry",
    "adb_input_text",
    "build_safe_fuzz_plan",
    "build_x_twitter_plan",
    "foreground_package_from_window_dump",
    "parse_wm_size",
    "read_device_geometry",
    "read_foreground_package",
    "run_automation_actions",
]
