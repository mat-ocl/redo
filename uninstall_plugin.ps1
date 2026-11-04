param(
    [switch]$RemoveImage = $false,
    [switch]$SkipZed = $false,
    [string]$TargetWorkspace = "",
    [string]$PluginDest = ""
)

$ErrorActionPreference = "Continue"

$GhcrImage = "ghcr.io/mat-ocl/redo:latest"

if (-not $PluginDest) {
    $PluginDest = Join-Path $HOME ".gemini\config\plugins\redo"
}

Write-Host "[*] Uninstalling redo (mat-ocl/redo)..." -ForegroundColor Cyan

# 1. Stop any running redo containers
$runningGhcr = & docker ps -q --filter "ancestor=$GhcrImage" 2>$null
if ($runningGhcr) {
    Write-Host "[*] Stopping running '$GhcrImage' containers..." -ForegroundColor Cyan
    & docker stop $runningGhcr *> $null
}

# 2. Remove Antigravity plugin directory (~/.gemini/config/plugins/redo)
if (Test-Path $PluginDest) {
    Remove-Item -Path $PluginDest -Recurse -Force
    Write-Host "[+] Removed Antigravity plugin directory: $PluginDest" -ForegroundColor Green

    # Notify running Antigravity Language Server to unload MCP tools immediately
    try {
        $lsProc = Get-CimInstance Win32_Process -Filter "Name LIKE 'language_server_windows%.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($lsProc -and $lsProc.CommandLine -match '--csrf_token\s+([a-f0-9-]+)') {
            $csrf = $Matches[1]
            $conns = Get-NetTCPConnection -OwningProcess $lsProc.ProcessId -State Listen -ErrorAction SilentlyContinue
            foreach ($conn in $conns) {
                $url = "https://127.0.0.1:$($conn.LocalPort)/exa.language_server_pb.LanguageServerService/JetboxWriteState"
                try {
                    Invoke-RestMethod -Uri $url -Method Post -Headers @{
                        "x-codeium-csrf-token" = $csrf
                        "Connect-Protocol-Version" = "1"
                    } -ContentType "application/json" -Body '{"key":"plugins/enabled","value":"true"}' -SkipCertificateCheck -TimeoutSec 1 *> $null
                    break
                } catch {}
            }
        }
    } catch {}
} else {
    Write-Host "[*] Antigravity plugin directory not found at $PluginDest (already removed)." -ForegroundColor DarkGray
}

# 3. Remove workspace-level .agents, .zed, and redo-plugin files if -TargetWorkspace was provided
if ($TargetWorkspace -and (Test-Path $TargetWorkspace)) {
    foreach ($rel in @(
        "redo-plugin",
        ".zed\settings.json",
        ".agents\skills\reverse-engineering",
        ".agents\skills\install-redo",
        ".agents\rules\AGENTS.md"
    )) {
        $targetPath = Join-Path $TargetWorkspace $rel
        if (Test-Path $targetPath) {
            Remove-Item -Path $targetPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed workspace file/folder: $targetPath" -ForegroundColor Green
        }
    }
}

# 4. Clean up Zed Editor global settings (%APPDATA%\Zed\settings.json)
if (-not $SkipZed -and $env:APPDATA) {
    $ZedSettingsPath = Join-Path $env:APPDATA "Zed\settings.json"
    if (Test-Path $ZedSettingsPath) {
        try {
            $RawText = Get-Content -Path $ZedSettingsPath -Raw -Encoding UTF8
            if ($RawText -match '"redo(?:-tools)?"\s*:\s*\{') {
                # Remove the "redo" block inside context_servers
                $Cleaned = [regex]::Replace(
                    $RawText,
                    '(?ms)\s*"redo(?:-tools)?"\s*:\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}\s*,?',
                    ""
                )
                # Clean up any trailing comma before closing brace of context_servers
                $Cleaned = [regex]::Replace($Cleaned, ',(\s*\})', '$1')
                Set-Content -Path $ZedSettingsPath -Value $Cleaned -NoNewline -Encoding UTF8
                Write-Host "[+] Removed 'redo' from global Zed settings: $ZedSettingsPath" -ForegroundColor Green
            }
        } catch {
            Write-Host "[!] Could not update global Zed settings at '$ZedSettingsPath' (file may be locked by Zed)." -ForegroundColor Yellow
        }
    }
}

# 5. Optionally remove Docker image
if ($RemoveImage) {
    Write-Host "[*] Removing Docker image '$GhcrImage'..." -ForegroundColor Cyan
    & docker rmi -f $GhcrImage 2>$null
    Write-Host "[+] Docker image removed." -ForegroundColor Green
} else {
    Write-Host "[i] Docker image '$GhcrImage' was kept cached locally (pass -RemoveImage to delete the ~4.3 GB image)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[+] redo uninstallation complete." -ForegroundColor Green
