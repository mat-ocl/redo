param(
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

$GhcrImage = "ghcr.io/mat-ocl/redo:latest"
$LocalImage = "re-sandbox:latest"

# 1. Ensure Docker image 're-sandbox:latest' is available (prefers fast GHCR pull unless -BuildImage is passed)
if (-not $SkipImage) {
    if ($BuildImage) {
        Write-Host "[*] Building Docker image '$LocalImage' from $RepoRoot..." -ForegroundColor Cyan
        Push-Location $RepoRoot
        try {
            & docker compose --profile static build
            if ($LASTEXITCODE -ne 0) {
                throw "Docker build failed with exit code $LASTEXITCODE"
            }
            Write-Host "[+] Docker image '$LocalImage' built successfully." -ForegroundColor Green
        } finally {
            Pop-Location
        }
    } else {
        & docker image inspect $LocalImage *> $null
        $imageExists = ($LASTEXITCODE -eq 0)
        if (-not $imageExists -or $PullImage) {
            Write-Host "[*] Pulling pre-built Docker image '$GhcrImage' from GitHub Container Registry..." -ForegroundColor Cyan
            & docker pull $GhcrImage
            if ($LASTEXITCODE -eq 0) {
                & docker tag $GhcrImage $LocalImage
                Write-Host "[+] Pulled '$GhcrImage' and tagged as '$LocalImage'." -ForegroundColor Green
            } else {
                Write-Host "[!] GHCR pull unavailable or image private; falling back to local Docker build..." -ForegroundColor Yellow
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
            Write-Host "[+] Docker image '$LocalImage' is already present locally." -ForegroundColor Green
        }
    }
}

# 2. Install/Update Antigravity Plugin (~/.gemini/config/plugins/re-sandbox)
if (-not $PluginDest) {
    $PluginDest = Join-Path $HOME ".gemini\config\plugins\re-sandbox"
}

# Detect if running from a temporary/scratch clone (e.g. Antigravity brain\...\scratch or Temp)
$IsTempClone = ($RepoRoot -match '(?i)(\\scratch\\|\\temp\\|/tmp/)') -or $SelfContained

$PluginSource = Join-Path $RepoRoot "plugin\re-sandbox"
if (Test-Path $PluginSource) {
    Write-Host "[*] Installing Antigravity plugin to: $PluginDest" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $PluginDest -Force | Out-Null
    Copy-Item -Path (Join-Path $PluginSource "*") -Destination $PluginDest -Recurse -Force

    # Always copy run_re_mcp.ps1 and re_mcp_server.py into the plugin directory so it can run self-contained
    Copy-Item -Path (Join-Path $RepoRoot "run_re_mcp.ps1") -Destination (Join-Path $PluginDest "run_re_mcp.ps1") -Force
    Copy-Item -Path (Join-Path $RepoRoot "re_mcp_server.py") -Destination (Join-Path $PluginDest "re_mcp_server.py") -Force

    if ($IsTempClone) {
        $LauncherPath = (Join-Path $PluginDest "run_re_mcp.ps1") -replace "\\", "/"
        Write-Host "[*] Temporary/scratch clone detected: using self-contained launcher at $LauncherPath" -ForegroundColor Cyan
    } else {
        $LauncherPath = (Join-Path $RepoRoot "run_re_mcp.ps1") -replace "\\", "/"
    }

    # Dynamically write mcp_config.json with the resolved path to run_re_mcp.ps1
    $McpConfigObj = @{
        mcpServers = @{
            "re-sandbox-tools" = @{
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

# 3. Optionally install .agents rules & skills into a target project workspace
if ($TargetWorkspace -and (Test-Path $TargetWorkspace)) {
    $SourceAgents = Join-Path $RepoRoot ".agents"
    $DestAgents = Join-Path $TargetWorkspace ".agents"
    if (Test-Path $SourceAgents) {
        New-Item -ItemType Directory -Path $DestAgents -Force | Out-Null
        Copy-Item -Path (Join-Path $SourceAgents "*") -Destination $DestAgents -Recurse -Force
        Write-Host "[+] Copied .agents rules and skills into workspace: $DestAgents" -ForegroundColor Green
    }
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
    "re-sandbox-tools": {
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
