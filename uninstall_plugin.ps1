param(
    [Parameter(Position = 0)]
    [string]$TargetWorkspace = "",
    [switch]$RemoveImage = $false
)

$ErrorActionPreference = "Continue"

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
$NormScriptDir = ($ScriptDir -replace "\\", "/").TrimEnd("/")

# Resolve target project directory:
# 1. Explicit -TargetWorkspace
# 2. If running from <Project>/.agents/plugins/redo/uninstall_plugin.ps1, auto-detect <Project>
# 3. Current working directory ($PWD) if not the redo source repo
if (-not $TargetWorkspace) {
    if ($NormScriptDir -match '(?i)^(.+)/\.agents/plugins/redo$') {
        $TargetWorkspace = $Matches[1]
    } elseif ($NormScriptDir -match '(?i)^(.+)/(?:redo-plugin|\.redo)$') {
        $TargetWorkspace = $Matches[1]
    } else {
        $cwd = (Get-Location).Path
        if ($cwd -ne $ScriptDir) {
            $TargetWorkspace = $cwd
        } else {
            throw "Please specify the target project folder to uninstall redo from:`n  .\uninstall_plugin.ps1 -TargetWorkspace '<ProjectPath>'"
        }
    }
}

$GhcrImage = "ghcr.io/mat-ocl/redo:latest"

Write-Host "[*] Uninstalling redo from project: $TargetWorkspace" -ForegroundColor Cyan

# 1. Stop any running redo containers for this image
$runningGhcr = & docker ps -q --filter "ancestor=$GhcrImage" 2>$null
if ($runningGhcr) {
    Write-Host "[*] Stopping running '$GhcrImage' containers..." -ForegroundColor Cyan
    & docker stop $runningGhcr *> $null
}

# 2. Remove project-local redo files and configs
if (Test-Path $TargetWorkspace) {
    foreach ($rel in @(
        ".agents\plugins\redo",
        "redo-plugin",
        ".agents\skills\reverse-engineering",
        ".agents\skills\install-redo",
        ".agents\rules\AGENTS.md",
        ".zed\settings.json",
        ".cursor\mcp.json",
        ".claude\settings.local.json",
        ".vscode\mcp.json",
        ".mcp.json"
    )) {
        $targetPath = Join-Path $TargetWorkspace $rel
        if (Test-Path $targetPath) {
            Remove-Item -Path $targetPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed: $targetPath" -ForegroundColor Green
        }
    }

    # Remove empty dot-directories if nothing else is inside them
    foreach ($emptyCandidate in @(".agents\plugins", ".agents\skills", ".agents\rules", ".agents", ".zed", ".cursor", ".claude", ".vscode")) {
        $dirPath = Join-Path $TargetWorkspace $emptyCandidate
        if (Test-Path $dirPath) {
            $remaining = Get-ChildItem -Path $dirPath -Force -ErrorAction SilentlyContinue
            if (-not $remaining -or $remaining.Count -eq 0) {
                Remove-Item -Path $dirPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# 3. Optionally remove Docker image
if ($RemoveImage) {
    Write-Host "[*] Removing Docker image '$GhcrImage'..." -ForegroundColor Cyan
    & docker rmi -f $GhcrImage 2>$null
    Write-Host "[+] Docker image removed." -ForegroundColor Green
} else {
    Write-Host "[i] Docker image '$GhcrImage' was kept cached locally (pass -RemoveImage to delete the ~4.3 GB image)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[+] redo uninstalled from $TargetWorkspace." -ForegroundColor Green
