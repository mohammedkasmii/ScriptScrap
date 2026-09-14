[CmdletBinding()]
param(
    [string]$CaptureRoot = (Join-Path `
        ([Environment]::GetFolderPath("MyDocuments")) "ScriptScrapCaptures"),
    [ValidateRange(1, 8388608)]
    [int]$MaxBodyBytes = 8388608,
    [switch]$Normal,
    [switch]$CrossSiteSessionCompatibility
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$UvExe = Join-Path $env:LOCALAPPDATA "ScriptScrap\bin\uv.exe"

function Assert-LastCommand {
    param([Parameter(Mandatory = $true)][string]$Message)
    if ($LASTEXITCODE -ne 0) {
        throw "$Message (exit code $LASTEXITCODE)"
    }
}

if (-not (Test-Path -LiteralPath $UvExe -PathType Leaf)) {
    throw @"
ScriptScrap's private uv.exe was not found at:
  $UvExe

Run this first from the project folder:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-ScriptScrap.ps1
"@
}

New-Item -ItemType Directory -Force -Path $CaptureRoot | Out-Null
$SessionName = "agency-{0}-{1}" -f `
    (Get-Date -Format "yyyyMMdd-HHmmss"),
    ([guid]::NewGuid().ToString("N").Substring(0, 6))
$SessionPath = Join-Path $CaptureRoot $SessionName
$LastCaptureFile = Join-Path $CaptureRoot "LAST_CAPTURE.txt"
[IO.File]::WriteAllText(
    $LastCaptureFile,
    $SessionPath,
    [Text.UTF8Encoding]::new($false)
)

Push-Location $ProjectRoot
try {
    Write-Host ""
    Write-Host "==> Checking the ScriptScrap environment" -ForegroundColor Cyan
    & $UvExe run --no-sync python diagnostics\check_environment.py
    Assert-LastCommand "The environment check found a blocking problem"

    Write-Host ""
    Write-Host "==> Session output" -ForegroundColor Cyan
    Write-Host $SessionPath -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The investigator will ask for:" -ForegroundColor Cyan
    Write-Host "  1. The complete https:// portal URL."
    Write-Host "  2. Any additional authorised domains, separated by commas."
    Write-Host "     Enter domain names only (for example login.example.com), not URLs."
    Write-Host ""
    Write-Host "When the browser opens, minimise this terminal and let the employee work." -ForegroundColor Green
    Write-Host "Press ENTER here only after the complete work session is finished." -ForegroundColor Green
    Write-Host ""

    $CaptureArguments = @(
        "run", "--no-sync", "python",
        "camoufox\camoufox_investigator.py",
        "--output", $SessionPath
    )
    if (-not $Normal) {
        $CaptureArguments += @(
            "--forensic",
            "--forensic-max-body-bytes", ([string]$MaxBodyBytes)
        )
    }
    if ($CrossSiteSessionCompatibility) {
        $CaptureArguments += "--cross-site-session-compatibility"
    }

    & $UvExe @CaptureArguments
    Assert-LastCommand "The capture process failed; preserve the session directory for diagnosis"

    $EventLog = Join-Path $SessionPath "events.jsonl"
    $ManifestPath = Join-Path $SessionPath "session_manifest.json"
    if (-not (Test-Path -LiteralPath $EventLog -PathType Leaf)) {
        throw "Capture ended without events.jsonl in $SessionPath"
    }
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Capture ended without session_manifest.json in $SessionPath"
    }

    Write-Host ""
    Write-Host "==> Assessing capture health" -ForegroundColor Cyan
    & $UvExe run --no-sync scriptscrap health $SessionPath
    Assert-LastCommand "Capture-health assessment failed"

    Write-Host ""
    Write-Host "==> Building the offline analysis and evidence store" -ForegroundColor Cyan
    & $UvExe run --no-sync scriptscrap analyze $SessionPath
    Assert-LastCommand "Offline analysis failed"

    Write-Host ""
    Write-Host "==> Building the sanitised shareable export" -ForegroundColor Cyan
    & $UvExe run --no-sync scriptscrap export $SessionPath
    Assert-LastCommand "Sanitised export failed"

    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    Write-Host ""
    Write-Host "==> Agency capture completed" -ForegroundColor Green
    Write-Host "Full unredacted session: $SessionPath"
    Write-Host "Session outcome:          $($Manifest.completion.outcome)"
    Write-Host "Events recorded:          $($Manifest.event_spine.events_emitted)"
    Write-Host "Sensor errors:            $($Manifest.counters.sensor_errors)"
    Write-Host ""
    Write-Host "Open the local workspace with:"
    Write-Host "& `"$UvExe`" run --no-sync scriptscrap workspace `"$SessionPath`""
    Write-Host ""
    Write-Host "The complete path is also saved in: $LastCaptureFile"

    if (-not $Manifest.completion.clean) {
        Write-Warning "The manifest did not mark this session clean. Keep the folder and inspect health before relying on it."
    }
    if ([int]$Manifest.counters.sensor_errors -gt 0) {
        Write-Warning "One or more sensor errors were recorded. Inspect the Health view before relying on this session."
    }
}
finally {
    Pop-Location
}
