param(
    [switch]$Uninstall = $false,
    [switch]$RemoveImage = $false,
    [switch]$BuildImage = $false,
    [switch]$PullImage = $false,
    [switch]$SkipImage = $false,
    [switch]$SkipZed = $false,
    [switch]$SelfContained = $false,
    [string]$TargetWorkspace = "",
    [ValidateSet("pwsh", "docker")]
    [string]$ZedMode = "pwsh",
    [string]$PluginDest = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = $PSScriptRoot
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

if ($Uninstall) {
    $UninstallScript = Join-Path $RepoRoot "uninstall_plugin.ps1"
    if (Test-Path $UninstallScript) {
        & $UninstallScript -RemoveImage:$RemoveImage -SkipZed:$SkipZed -TargetWorkspace $TargetWorkspace -PluginDest $PluginDest
        exit $LASTEXITCODE
    } else {
        throw "uninstall_plugin.ps1 not found at $UninstallScript"
    }
}

$ImageName = "ghcr.io/mat-ocl/redo:latest"

# 1. Ensure Docker image 'ghcr.io/mat-ocl/redo:latest' is available (prefers fast GHCR pull unless -BuildImage is passed)
if (-not $SkipImage) {
    if ($BuildImage) {
        Write-Host "[*] Building Docker image '$ImageName' from $RepoRoot..." -ForegroundColor Cyan
        Push-Location $RepoRoot
        try {
            & docker compose --profile static build
            if ($LASTEXITCODE -ne 0) {
                throw "Docker build failed with exit code $LASTEXITCODE"
            }
            Write-Host "[+] Docker image '$ImageName' built successfully." -ForegroundColor Green
        } finally {
            Pop-Location
        }
    } else {
        & docker image inspect $ImageName *> $null
        $imageExists = ($LASTEXITCODE -eq 0)
        if (-not $imageExists -or $PullImage) {
            Write-Host "[*] Pulling pre-built Docker image '$ImageName' from GitHub Container Registry..." -ForegroundColor Cyan
            & docker pull $ImageName
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] Pulled '$ImageName' successfully." -ForegroundColor Green
            } else {
                Write-Host "[!] GHCR pull unavailable; falling back to local Docker build..." -ForegroundColor Yellow
                Push-Location $RepoRoot
                try {
                    & docker compose --profile static build
                    if ($LASTEXITCODE -ne 0) {
                        throw "Docker build failed with exit code $LASTEXITCODE"
                    }
                } finally {
                    Pop-Location
                }
            }
        } else {
            Write-Host "[+] Docker image '$ImageName' is already present locally." -ForegroundColor Green
        }
    }
}

# 2. Install/Update Antigravity Plugin (~/.gemini/config/plugins/redo)
if (-not $PluginDest) {
    $PluginDest = Join-Path $HOME ".gemini\config\plugins\redo"
}

# Detect if running from a temporary/scratch clone (e.g. Antigravity brain\...\scratch or Temp)
$IsTempClone = ($RepoRoot -match '(?i)(\\scratch\\|\\temp\\|/tmp/)') -or $SelfContained

$PluginSource = Join-Path $RepoRoot "plugin\redo"
if (Test-Path $PluginSource) {
    Write-Host "[*] Installing Antigravity plugin to: $PluginDest" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $PluginDest -Force | Out-Null
    Copy-Item -Path (Join-Path $PluginSource "*") -Destination $PluginDest -Recurse -Force

    # Always copy run_re_mcp.ps1, run_re_mcp.sh, re_mcp_server.py, and uninstall_plugin.ps1 into the plugin directory so it can run or uninstall self-contained
    Copy-Item -Path (Join-Path $RepoRoot "run_re_mcp.ps1") -Destination (Join-Path $PluginDest "run_re_mcp.ps1") -Force
    if (Test-Path (Join-Path $RepoRoot "run_re_mcp.sh")) {
        Copy-Item -Path (Join-Path $RepoRoot "run_re_mcp.sh") -Destination (Join-Path $PluginDest "run_re_mcp.sh") -Force
    }
    Copy-Item -Path (Join-Path $RepoRoot "re_mcp_server.py") -Destination (Join-Path $PluginDest "re_mcp_server.py") -Force
    if (Test-Path (Join-Path $RepoRoot "uninstall_plugin.ps1")) {
        Copy-Item -Path (Join-Path $RepoRoot "uninstall_plugin.ps1") -Destination (Join-Path $PluginDest "uninstall_plugin.ps1") -Force
    }

    # Remove legacy single-workspace state files and ensure per-conversation workspaces directory exists
    foreach ($legacyFile in @("active_workspace.txt", "known_workspaces.txt")) {
        Remove-Item -Path (Join-Path $PluginDest $legacyFile) -Force -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path $RepoRoot $legacyFile) -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path (Join-Path $PluginDest "workspaces") -Force | Out-Null

    if ($IsTempClone) {
        $LauncherPath = (Join-Path $PluginDest "run_re_mcp.ps1") -replace "\\", "/"
        Write-Host "[*] Temporary/scratch clone detected: using self-contained launcher at $LauncherPath" -ForegroundColor Cyan
    } else {
        $LauncherPath = (Join-Path $RepoRoot "run_re_mcp.ps1") -replace "\\", "/"
    }

    # Dynamically write mcp_config.json with the resolved path to run_re_mcp.ps1
    $McpConfigObj = @{
        mcpServers = @{
            "redo" = @{
                command = "pwsh"
                args = @(
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    $LauncherPath
                )
            }
        }
    }
    $McpConfigPath = Join-Path $PluginDest "mcp_config.json"
    $McpConfigObj | ConvertTo-Json -Depth 6 | Set-Content -Path $McpConfigPath -Encoding UTF8
    Write-Host "[+] Installed Antigravity plugin and updated $McpConfigPath" -ForegroundColor Green
}

# 3. Optionally install .agents rules, skills, and project registration into a target project workspace
if ($TargetWorkspace -and (Test-Path $TargetWorkspace)) {
    $ResolvedTarget = (Resolve-Path $TargetWorkspace).Path -replace "\\", "/"
    New-Item -ItemType Directory -Path (Join-Path $TargetWorkspace "samples") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $TargetWorkspace "output") -Force | Out-Null

    $SourceAgents = Join-Path $RepoRoot ".agents"
    $DestAgents = Join-Path $TargetWorkspace ".agents"
    if (Test-Path $SourceAgents) {
        New-Item -ItemType Directory -Path $DestAgents -Force | Out-Null
        Copy-Item -Path (Join-Path $SourceAgents "*") -Destination $DestAgents -Recurse -Force
        Write-Host "[+] Copied .agents rules and skills into workspace: $DestAgents" -ForegroundColor Green
    }

    # Register target workspace in the per-project workspace registry
    $WsRegistryDir = Join-Path $PluginDest "workspaces"
    New-Item -ItemType Directory -Path $WsRegistryDir -Force | Out-Null
    $SafeWsName = ($ResolvedTarget -replace '[^a-zA-Z0-9_-]', '_')
    $WsEntryPath = Join-Path $WsRegistryDir "project_${SafeWsName}.json"
    @{
        conversationId = "project_${SafeWsName}"
        workspacePath  = $ResolvedTarget
        workspacePaths = @($ResolvedTarget)
        updatedAtUtc   = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    } | ConvertTo-Json -Depth 4 | Set-Content -Path $WsEntryPath -Encoding UTF8
    Write-Host "[+] Registered project workspace in multiplexer: $ResolvedTarget" -ForegroundColor Green
}

# 4. Install/Update Zed Editor Configuration (unless -SkipZed is passed)
$ZedInstaller = Join-Path $RepoRoot "install_zed.ps1"
if (-not $SkipZed -and (Test-Path $ZedInstaller)) {
    Write-Host "[*] Configuring Zed Editor MCP integration..." -ForegroundColor Cyan
    if ($IsTempClone) {
        & $ZedInstaller -Mode "docker"
    } else {
        & $ZedInstaller -Mode $ZedMode
    }
}

Write-Host ""
Write-Host "=== Generic MCP Client Configuration Snippet ===" -ForegroundColor Yellow
Write-Host "Add this to your claude_desktop_config.json, .cursor/mcp.json, or mcp_config.json:"
Write-Host @"
{
  "mcpServers": {
    "redo": {
      "command": "pwsh",
      "args": [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "$LauncherPath"
      ]
    }
  }
}
"@
