param(
    [switch]$BuildImage = $false,
    [switch]$SkipZed = $false,
    [ValidateSet("pwsh", "docker")]
    [string]$ZedMode = "pwsh",
    [string]$PluginDest = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = $PSScriptRoot
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

$LauncherPath = (Join-Path $RepoRoot "run_re_mcp.ps1") -replace "\\", "/"

# 1. Optionally build the Docker image
if ($BuildImage) {
    Write-Host "[*] Building Docker image 're-sandbox:latest' from $RepoRoot..." -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        & docker compose --profile static build
        if ($LASTEXITCODE -ne 0) {
            throw "Docker build failed with exit code $LASTEXITCODE"
        }
        Write-Host "[+] Docker image 're-sandbox:latest' built successfully." -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

# 2. Install/Update Antigravity Plugin (~/.gemini/config/plugins/re-sandbox)
if (-not $PluginDest) {
    $PluginDest = Join-Path $HOME ".gemini\config\plugins\re-sandbox"
}

$PluginSource = Join-Path $RepoRoot "plugin\re-sandbox"
if (Test-Path $PluginSource) {
    Write-Host "[*] Installing Antigravity plugin to: $PluginDest" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $PluginDest -Force | Out-Null
    Copy-Item -Path (Join-Path $PluginSource "*") -Destination $PluginDest -Recurse -Force

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

# 3. Install/Update Zed Editor Configuration (unless -SkipZed is passed)
$ZedInstaller = Join-Path $RepoRoot "install_zed.ps1"
if (-not $SkipZed -and (Test-Path $ZedInstaller)) {
    Write-Host "[*] Configuring Zed Editor MCP integration..." -ForegroundColor Cyan
    & $ZedInstaller -Mode $ZedMode
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
