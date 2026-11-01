# Device pilot protocol (cohort definition)

Status: protocol object and queue-counting rule only. No capture was run; the
phone is not needed to validate or plan a cohort. Implementation:
`scytaledroid/DynamicAnalysis/research/device_pilot_cohort.py`
(contract `device_pilot_cohort_v1`).

## Cohort

- One source-owned, non-root device path (absolute; never under
  `/data/data`, `/data/user`, `/data/system`, `/system`, `/root`, `/vendor`).
- Exactly 24 controlled sessions, 8 per state, spread round-robin over at
  least three distinct days.
- States: `strict_idle` (screen on, no interaction, notifications held),
  `qfg` (quick foreground: launch, idle, background), `scripted_interactive`
  (the scripted interaction for the app).
- Partition labels come from the held-out calibration allocator
  (`heldout_calibration.allocate_sessions`): `strict_idle` sessions are whole
  sessions allocated to `fit` / `calibrate` / `test`; `qfg` and
  `scripted_interactive` sessions are always `test`. The seed is part of the
  cohort so the allocation is reproducible before any capture.
- Explicit outcome per session, recorded once after execution:
  `executed_send` (the scripted send happened and was captured),
  `no_send_control` (control session; no send expected), `unreached` (the
  scripted step was not reached), `capture_loss` (observer or PCAP loss),
  `false_attribution` (traffic observed but attributable to another source).
  Until recorded, a session is `planned`. Outcomes never change counting.

## Guided queue counting

The guided queue counts toward this cohort only captures whose manifest tier
is `dataset` and whose `session_id` belongs to the cohort; a second capture
for the same session, an exploratory-tier capture or a capture for a foreign
session is reported under `ignored` and never counted
(`count_dataset_tier_captures`). `remaining` is 24 minus counted sessions.

## What this does not do

It does not start captures, select devices, modify the guided-run quota logic
or write into evidence packs. Wiring the counting rule into the guided queue's
quota display is a separate change that must preserve the existing per-app
`baseline_required` logic.
