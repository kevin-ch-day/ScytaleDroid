# Manual Test Plan - APK Pull Refactor

## Preconditions
- Have an Android device connected with `adb devices` showing a serial.
- Ensure `adb` is available on `PATH`.

## Commands

### 1) Baseline pull with inventory snapshot
```
python main.py
```
Navigate to Device Analysis → APK Pull and select a scope with packages.

**Expected:**
- Plan overview renders with counts and policy.
- Pull completes and artifacts are written under `data/device_apks/<serial>/<YYYYMMDD>/`.

### 2) Delta filter behavior
Run an inventory sync first, then re-run APK Pull and ensure the delta filter applies when a delta summary exists.

**Expected:**
- Delta scope message indicates the number of packages scheduled.
- If delta has no changes, the flow informs you and returns to scope selection.

### 3) Scoped refresh option
Choose a scoped refresh during the pull flow.

**Expected:**
- Scoped refresh runs and produces a scoped snapshot.
- Flow resumes and allows selection based on refreshed data.

### 4) Noninteractive path (if wired in automation)
Invoke the workflow from a Python shell:
```
from scytaledroid.DeviceAnalysis.apk.workflow import run_apk_pull
run_apk_pull("<serial>", auto_scope=True, noninteractive=True)
```

**Expected:**
- No prompts are shown.
- Pull executes using auto scope and completes or returns a failure OperationResult.

## Phase 2 Verification

### 5) Workflow wrapper entrypoint
Invoke the workflows wrapper from a Python shell:
```
from scytaledroid.DeviceAnalysis.workflows.apk_pull_workflow import run_apk_pull
run_apk_pull("<serial>", auto_scope=True, noninteractive=True)
```

**Expected:**
- Behavior matches the APK workflow entrypoint.
- No new prompts or output changes beyond the existing APK flow.
