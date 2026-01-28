"""Manual scenario runner for dynamic analysis."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import time

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

from scytaledroid.DynamicAnalysis.core.run_context import RunContext


@dataclass(frozen=True)
class ScenarioResult:
    started_at: datetime
    ended_at: datetime
    notes: str | None = None


class ManualScenarioRunner:
    def run(self, run_ctx: RunContext) -> ScenarioResult:
        if run_ctx.interactive:
            print(
                status_messages.status(
                    f"Scenario: {run_ctx.scenario_id}. Use the app now.",
                    level="info",
                )
            )
            prompt_utils.press_enter_to_continue("Press Enter to start the scenario...")
            started_at = datetime.now(timezone.utc)
            prompt_utils.press_enter_to_continue("Press Enter when the scenario is complete...")
            ended_at = datetime.now(timezone.utc)
        else:
            started_at = datetime.now(timezone.utc)
            time.sleep(max(run_ctx.duration_seconds, 0))
            ended_at = datetime.now(timezone.utc)
        return ScenarioResult(started_at=started_at, ended_at=ended_at)


__all__ = ["ManualScenarioRunner", "ScenarioResult"]
