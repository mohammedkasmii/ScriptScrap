[CmdletBinding()]
param(
    [switch]$IncludeDeveloperTools,
    [switch]$SkipBrowserSmokeTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ProjectRoot = $PSScriptRoot
$PythonVersion = "3.14"
$CamoufoxBuild = "152.0.4-beta.29"
$CamoufoxPin = "official/prerelease/$CamoufoxBuild"
$UvVersion = "0.12.12"
$UvInstallDir = Join-Path $env:LOCALAPPDATA "ScriptScrap\bin"
$UvExe = Join-Path $UvInstallDir "uv.exe"

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-LastCommand {
    param([Parameter(Mandatory = $true)][string]$Message)
    if ($LASTEXITCODE -ne 0) {
        throw "$Message (exit code $LASTEXITCODE)"
    }
}

function Get-InstalledCamoufoxBuild {
    $BuildOutput = & $UvExe run --no-sync python -c `
        "from camoufox.pkgman import installed_verstr; print(installed_verstr())" 2>$null
    if ($LASTEXITCODE -ne 0 -or $null -eq $BuildOutput) {
        return $null
    }
    return ([string]($BuildOutput | Select-Object -Last 1)).Trim()
}

if ($env:OS -ne "Windows_NT") {
    throw "This installer is for Windows agency workstations."
}

$RequiredFiles = @(
    "pyproject.toml",
    "uv.lock",
    ".python-version",
    "diagnostics\check_environment.py",
    "camoufox\camoufox_investigator.py"
)
foreach ($RelativePath in $RequiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot $RelativePath) -PathType Leaf)) {
        throw "Missing $RelativePath. Copy the complete ScriptScrap project folder, then run this installer from its root."
    }
}

Push-Location $ProjectRoot
try {
    # Windows PowerShell 5.1 can otherwise negotiate an obsolete TLS version.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if (-not (Test-Path -LiteralPath $UvExe -PathType Leaf)) {
        Write-Step "Installing uv $UvVersion for the current Windows user"
        New-Item -ItemType Directory -Force -Path $UvInstallDir | Out-Null

        $OldUnmanagedInstall = $env:UV_UNMANAGED_INSTALL
        $OldNoModifyPath = $env:UV_NO_MODIFY_PATH
        try {
            # Official standalone installer. UV_UNMANAGED_INSTALL keeps it in
            # LocalAppData and avoids administrator rights or PATH changes.
            $env:UV_UNMANAGED_INSTALL = $UvInstallDir
            $env:UV_NO_MODIFY_PATH = "1"
            $InstallerUrl = "https://astral.sh/uv/$UvVersion/install.ps1"
            $Installer = Invoke-RestMethod -Uri $InstallerUrl
            Invoke-Expression $Installer
        }
        finally {
            if ($null -eq $OldUnmanagedInstall) {
                Remove-Item Env:UV_UNMANAGED_INSTALL -ErrorAction SilentlyContinue
            }
            else {
                $env:UV_UNMANAGED_INSTALL = $OldUnmanagedInstall
            }
            if ($null -eq $OldNoModifyPath) {
                Remove-Item Env:UV_NO_MODIFY_PATH -ErrorAction SilentlyContinue
            }
            else {
                $env:UV_NO_MODIFY_PATH = $OldNoModifyPath
            }
        }
    }

    if (-not (Test-Path -LiteralPath $UvExe -PathType Leaf)) {
        throw "uv was not installed at $UvExe. Check that HTTPS access to astral.sh is allowed."
    }

    Write-Step "Checking uv"
    & $UvExe --version
    Assert-LastCommand "uv could not start"

    Write-Step "Installing managed Python $PythonVersion"
    & $UvExe python install $PythonVersion
    Assert-LastCommand "Python $PythonVersion installation failed"

    Write-Step "Installing ScriptScrap's locked dependencies"
    $SyncArguments = @("sync", "--locked", "--python", $PythonVersion)
    if ($IncludeDeveloperTools) {
        $SyncArguments += "--all-groups"
    }
    else {
        $SyncArguments += "--no-dev"
    }
    & $UvExe @SyncArguments
    Assert-LastCommand "Dependency installation failed"

    $InstalledCamoufoxBuild = Get-InstalledCamoufoxBuild
    if ($InstalledCamoufoxBuild -eq $CamoufoxBuild) {
        Write-Step "Using the installed Camoufox browser build $CamoufoxBuild"
    }
    else {
        Write-Step "Installing the verified Camoufox browser build $CamoufoxBuild"
        # `fetch <version>` downloads the requested build but does not reactivate it
        # if another installed build is already active. Pinning afterwards makes this
        # installer safe to re-run on a workstation whose browser has drifted.
        "y" | & $UvExe run --no-sync python -m camoufox fetch "official/$CamoufoxBuild"
        Assert-LastCommand "Camoufox browser installation failed"
        & $UvExe run --no-sync python -m camoufox set $CamoufoxPin
        Assert-LastCommand "Camoufox browser activation failed"

        $InstalledCamoufoxBuild = Get-InstalledCamoufoxBuild
        if ($InstalledCamoufoxBuild -ne $CamoufoxBuild) {
            throw "Camoufox $CamoufoxBuild could not be installed and activated. Check that api.github.com and github.com are allowed by the network, then run the installer again."
        }
    }

    Write-Step "Installing Playwright Firefox for generated workflows"
    & $UvExe run --no-sync playwright install firefox
    Assert-LastCommand "Playwright Firefox installation failed"

    Write-Step "Running ScriptScrap's environment check"
    & $UvExe run --no-sync python diagnostics\check_environment.py
    Assert-LastCommand "The ScriptScrap environment check found a blocking problem"

    if (-not $SkipBrowserSmokeTest) {
        Write-Step "Launching Camoufox for an offline smoke test"
        $SmokeTest = @'
from camoufox.addons import DefaultAddons
from camoufox.sync_api import Camoufox

with Camoufox(
    headless=True,
    humanize=False,
    geoip=False,
    exclude_addons=[DefaultAddons.UBO],
) as browser:
    page = browser.new_page()
    page.goto("data:text/html,<title>ScriptScrap ready</title>")
    assert page.title() == "ScriptScrap ready"

print("Camoufox launch smoke test passed.")
'@
        # Windows PowerShell 5.1 can remove nested quotes from a multiline
        # native-command argument. A temporary file preserves the Python source.
        $SmokeTestPath = Join-Path ([IO.Path]::GetTempPath()) `
            ("scriptscrap-browser-smoke-{0}.py" -f [guid]::NewGuid())
        try {
            [IO.File]::WriteAllText(
                $SmokeTestPath,
                $SmokeTest,
                [Text.UTF8Encoding]::new($false)
            )
            & $UvExe run --no-sync python $SmokeTestPath
            Assert-LastCommand "Camoufox was installed but could not launch"
        }
        finally {
            Remove-Item -LiteralPath $SmokeTestPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Step "Checking the ScriptScrap command"
    & $UvExe run --no-sync scriptscrap --help | Out-Null
    Assert-LastCommand "The scriptscrap command could not start"

    Write-Host ""
    Write-Host "ScriptScrap installation completed successfully." -ForegroundColor Green
    Write-Host "Start an investigation with:"
    Write-Host "  & `"$UvExe`" run --no-sync python camoufox\camoufox_investigator.py"
    Write-Host ""
    Write-Host "The PC needs internet access during installation. After installation, normal capture and analysis can run without development tools."
}
finally {
    Pop-Location
}
