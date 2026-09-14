# ScriptScrap agency capture runbook

This is the start-to-finish Windows procedure for recording a long employee
session and taking the complete result away for offline analysis.

The default command below uses ScriptScrap's **maximum available passive capture
mode**: normal Playwright and runtime sensors plus the forensic Firefox extension.
It captures response bodies up to the project's 8 MiB blob limit, script source
before execution and the real cookie jar, in addition to user actions, network
traffic, forms, controls, tables, application states, storage inventories and
visual traces. It does not enable source rewriting and therefore does not alter
the portal's JavaScript.

No browser recorder can literally observe everything. Read
[`docs/known-limitations.md`](docs/known-limitations.md) for the remaining browser
blind spots. The session health report records which ones affected each run.

## Before going to the agency

Use the project version containing commit `85dc35a` or later. If the remediation
branch has not yet been merged into `main`, clone or switch to it explicitly:

```powershell
git switch phase23-remediation-plan-a
git pull
git rev-parse --short HEAD
```

The last command must print `85dc35a` or a newer commit that contains it.

For a complete validation machine, install developer tools and run the checks:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-ScriptScrap.ps1 -IncludeDeveloperTools

$Uv = Join-Path $env:LOCALAPPDATA "ScriptScrap\bin\uv.exe"
& $Uv run --no-sync python diagnostics\check_environment.py
& $Uv run --no-sync ruff check .
& $Uv run --no-sync pytest
```

Commit `85dc35a` expects Ruff to pass and pytest to report `1389 passed, 11
skipped`. The environment check must report zero failures. Documented warnings
are allowed. Git is not required for agency capture; when Git is unavailable,
the one source-quality test that asks Git to classify workspace assets is
skipped.

## First installation on the agency PC

1. Copy the complete ScriptScrap project folder to the PC.
2. Open PowerShell inside that folder.
3. Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-ScriptScrap.ps1
```

The first installation needs internet access. It installs private, pinned copies
of `uv`, Python, dependencies and the verified Camoufox browser for the current
Windows user. Administrator rights and preinstalled development tools are not
required.

The installer must finish with:

```text
ScriptScrap installation completed successfully.
```

Do not run the complete pytest suite on the agency PC unless it was deliberately
prepared as a development/validation machine with `-IncludeDeveloperTools` and
Git. The installer environment check and browser smoke test are the operational
checks required for capture.

## Start the employee recording

From the project folder, run one command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Agency-Capture.ps1
```

The script performs the environment check, creates a unique session under the
current user's Documents folder, starts maximum passive forensic capture, and
then runs health, analysis and sanitised export after the recording ends.

At the prompts:

1. Enter the portal's complete starting URL, including `https://`.
2. Enter any additional **authorised platform domains** separated by commas, or
   press Enter for none. Enter domains only, for example:

   ```text
   login.insurer.example,api.vendor.example
   ```

The starting host and all its subdomains are already included. A separate login,
API or document host must be listed before capture if its DOM, query strings,
headers and bodies are needed. Unlisted domains are retained as metadata only.

When the browser opens, minimise the PowerShell window and give the browser to
the employee.

## Instructions for the employee

- Work only in the Camoufox window opened by ScriptScrap.
- Sign in and work normally. No workflow needs to be named or started separately.
- Use menus, hover controls, searches, forms, radio buttons, checkboxes,
  dropdowns, autocomplete, tables, sorting, filtering, pagination, uploads,
  downloads, tabs and popups normally.
- Leave the ScriptScrap PowerShell window running and do not press Enter.
- Do not close the browser or PowerShell when changing tasks.
- Tell the operator when the entire recording session is finished.

ScriptScrap writes events incrementally and adds a checkpoint every 30 seconds.

## End the recording correctly

1. Leave the Camoufox window open.
2. Return to the ScriptScrap PowerShell window.
3. Press **Enter once**.
4. Wait while ScriptScrap drains every open in-scope tab and frame, closes the
   browser, writes the manifest, runs health and analysis, and creates the
   sanitised export.
5. Do not close PowerShell until it prints `Agency capture completed`.

The final output prints:

- the complete unredacted session path;
- the session outcome;
- the number of events;
- the number of sensor errors;
- the exact command for opening the workspace.

The path is also written to:

```text
Documents\ScriptScrapCaptures\LAST_CAPTURE.txt
```

## Review the captured session

Open a new PowerShell in the project folder and run:

```powershell
$Uv = Join-Path $env:LOCALAPPDATA "ScriptScrap\bin\uv.exe"
$CaptureRoot = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "ScriptScrapCaptures"
$Session = Get-Content -LiteralPath (Join-Path $CaptureRoot "LAST_CAPTURE.txt") -Raw

& $Uv run --no-sync scriptscrap health $Session
& $Uv run --no-sync scriptscrap workspace $Session
```

The workspace opens locally. Check Overview, Health, Timeline, Activities, Forms,
Tables, UI Elements, Endpoints, Schemas and Technologies. Confirm that the
employee's actions, form fields, option choices, table interactions and navigation
appear. Press `Ctrl+C` in PowerShell to stop the workspace server.

`PARTIAL / HIGH COVERAGE` can be legitimate when it is explained by a documented
browser limitation. A failed primary sensor, a non-clean completion, zero events
or unexplained sensor errors must be investigated before relying on the session.

## Copy the complete data for offline analysis

Copy the **entire session directory**, not only `export/shared`. The full folder
contains `events.jsonl`, the manifest, visual traces, forensic blobs, the derived
SQLite store, the local report and the sanitised export.

Example for an external drive mounted as `E:`:

```powershell
$CaptureRoot = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "ScriptScrapCaptures"
$Session = (Get-Content -LiteralPath (Join-Path $CaptureRoot "LAST_CAPTURE.txt") -Raw).Trim()
$DestinationRoot = "E:\ScriptScrapCaptures"

New-Item -ItemType Directory -Force -Path $DestinationRoot | Out-Null
Copy-Item -LiteralPath $Session -Destination $DestinationRoot -Recurse
```

Verify the copied session contains these files before leaving:

```powershell
$CopiedSession = Join-Path $DestinationRoot (Split-Path $Session -Leaf)
Test-Path (Join-Path $CopiedSession "events.jsonl")
Test-Path (Join-Path $CopiedSession "session_manifest.json")
Test-Path (Join-Path $CopiedSession "session.sqlite")
Test-Path (Join-Path $CopiedSession "analysis\report.md")
Test-Path (Join-Path $CopiedSession "export\shared\dataset.json")
```

All five commands must print `True`. Keep the full session directory protected:
it is an unredacted authenticated capture. `export/shared` is the separate
sanitised copy intended for sharing.

## Alternative commands

Use normal capture instead of forensic capture only when full bodies, script
sources and the cookie jar are not needed:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Agency-Capture.ps1 -Normal
```

Choose a different output root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Agency-Capture.ps1 -CaptureRoot "D:\ScriptScrapCaptures"
```

If a capture is interrupted, preserve its directory. Do not reuse it for another
recording. Start the script again to create a new session, then analyse the
partial folder separately with:

```powershell
$Uv = Join-Path $env:LOCALAPPDATA "ScriptScrap\bin\uv.exe"
& $Uv run --no-sync scriptscrap health "C:\path\to\interrupted-session"
& $Uv run --no-sync scriptscrap analyze "C:\path\to\interrupted-session"
```
