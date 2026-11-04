param(
    [Parameter(Position = 0)]
    [string]$TargetWorkspace = "",
    [switch]$Uninstall = $false,
    [switch]$RemoveImage = $false,
    [switch]$BuildImage = $false,
    [switch]$PullImage = $false,
    [switch]$SkipImage = $false
)

$ErrorActionPreference = "Stop"

$RepoRoot = $PSScriptRoot
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

$NormalizedRepoRoot = ((Resolve-Path $RepoRoot).Path -replace "\\", "/").TrimEnd("/")

# Resolve target project directory (defaults to current working directory if different from $RepoRoot)
if (-not $TargetWorkspace) {
    $cwd = ((Get-Location).Path -replace "\\", "/").TrimEnd("/")
    if ($cwd -ne $NormalizedRepoRoot) {
        $TargetWorkspace = $cwd
    } else {
        throw "Please specify the target project folder to install redo into (do not install into the redo clone itself):`n  .\install_plugin.ps1 -TargetWorkspace '<ProjectPath>'"
    }
}

if (-not (Test-Path $TargetWorkspace)) {
    New-Item -ItemType Directory -Path $TargetWorkspace -Force | Out-Null
}
$ResolvedTarget = ((Resolve-Path $TargetWorkspace).Path -replace "\\", "/").TrimEnd("/")
if ($ResolvedTarget -eq $NormalizedRepoRoot) {
    throw "TargetWorkspace ('$ResolvedTarget') cannot be the redo installer clone itself. Pass your actual project folder path to -TargetWorkspace."
}

if ($Uninstall) {
    $UninstallScript = Join-Path $RepoRoot "uninstall_plugin.ps1"
    if (Test-Path $UninstallScript) {
        & $UninstallScript -TargetWorkspace $ResolvedTarget -RemoveImage:$RemoveImage
        exit $LASTEXITCODE
    } else {
        throw "uninstall_plugin.ps1 not found at $UninstallScript"
    }
}

$ImageName = "ghcr.io/mat-ocl/redo:latest"

# 1. Ensure Docker image 'ghcr.io/mat-ocl/redo:latest' is available locally
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

# 2. Create project samples/ and output/ directories
New-Item -ItemType Directory -Path (Join-Path $ResolvedTarget "samples") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $ResolvedTarget "output") -Force | Out-Null

# 3. Install self-contained redo plugin into <Project>/.agents/plugins/redo/
$ProjectPluginDir = Join-Path $ResolvedTarget ".agents\plugins\redo"
New-Item -ItemType Directory -Path $ProjectPluginDir -Force | Out-Null

$PluginSource = Join-Path $RepoRoot "plugin\redo"
if (Test-Path $PluginSource) {
    Copy-Item -Path (Join-Path $PluginSource "*") -Destination $ProjectPluginDir -Recurse -Force
}

foreach ($file in @("run_re_mcp.ps1", "run_re_mcp.sh", "re_mcp_server.py", "uninstall_plugin.ps1")) {
    $src = Join-Path $RepoRoot $file
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $ProjectPluginDir $file) -Force
    }
}

$LauncherPath = ((Join-Path $ProjectPluginDir "run_re_mcp.ps1") -replace "\\", "/")
$CommonArgs = @(
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $LauncherPath,
    "-ProjectDir",
    $ResolvedTarget
)

# Write <Project>/.agents/plugins/redo/mcp_config.json (Google Antigravity workspace plugin MCP)
$AntigravityMcpPath = Join-Path $ProjectPluginDir "mcp_config.json"
@{
    mcpServers = @{
        redo = @{
            command = "pwsh"
            args    = $CommonArgs
        }
    }
} | ConvertTo-Json -Depth 6 | Set-Content -Path $AntigravityMcpPath -Encoding UTF8
Write-Host "[+] Installed self-contained workspace plugin: $ProjectPluginDir" -ForegroundColor Green

# 4. Copy workspace .agents/rules and .agents/skills into <Project>/.agents/
$SourceAgents = Join-Path $RepoRoot ".agents"
$DestAgents = Join-Path $ResolvedTarget ".agents"
if (Test-Path $SourceAgents) {
    foreach ($sub in @("rules", "skills")) {
        $srcSub = Join-Path $SourceAgents $sub
        if (Test-Path $srcSub) {
            $dstSub = Join-Path $DestAgents $sub
            New-Item -ItemType Directory -Path $dstSub -Force | Out-Null
            Copy-Item -Path (Join-Path $srcSub "*") -Destination $dstSub -Recurse -Force
        }
    }
    Write-Host "[+] Installed workspace rules & skills: $DestAgents" -ForegroundColor Green
}

# 5. Write workspace-scoped editor MCP configs inside <Project>

# 5a. Zed Editor: <Project>/.zed/settings.json (context_servers.redo without deprecated 'source' or user-only 'agent')
$ZedDir = Join-Path $ResolvedTarget ".zed"
New-Item -ItemType Directory -Path $ZedDir -Force | Out-Null
$ZedSettingsPath = Join-Path $ZedDir "settings.json"
@{
    context_servers = @{
        redo = @{
            command = "pwsh"
            args    = $CommonArgs
            env     = @{}
        }
    }
} | ConvertTo-Json -Depth 6 | Set-Content -Path $ZedSettingsPath -Encoding UTF8
Write-Host "[+] Wrote Zed workspace config: $ZedSettingsPath" -ForegroundColor Green

# Optional: If Zed is installed (global settings.json exists), merge project-agnostic mcp:redo:* tool permissions
# into Zed's global settings.json (where Zed's schema requires 'agent.tool_permissions'). Never fail if unavailable.
$ZedGlobalSettingsPath = if ($env:APPDATA) {
    Join-Path $env:APPDATA "Zed\settings.json"
} else {
    Join-Path $HOME ".config/zed/settings.json"
}
if (Test-Path $ZedGlobalSettingsPath) {
    try {
        $ServerPyFile = Join-Path $ProjectPluginDir "re_mcp_server.py"
        $ToolNames = @()
        if (Test-Path $ServerPyFile) {
            $PyContent = Get-Content -Path $ServerPyFile -Raw -Encoding UTF8
            $ToolMatches = [regex]::Matches($PyContent, '(?m)^@mcp\.tool\(\)\s*\r?\ndef\s+([a-zA-Z0-9_]+)\s*\(')
            foreach ($m in $ToolMatches) {
                $ToolNames += $m.Groups[1].Value
            }
        }
        $RawGlobalJson = Get-Content -Path $ZedGlobalSettingsPath -Raw -Encoding UTF8
        # Strip full-line // comments and trailing commas so both PS 5.1 and pwsh 7+ parse Zed JSONC cleanly
        $CleanGlobalJson = [regex]::Replace($RawGlobalJson, '(?m)^\s*//.*$', '')
        $CleanGlobalJson = [regex]::Replace($CleanGlobalJson, ',(\s*[\}\]])', '$1')
        if ([string]::IsNullOrWhiteSpace($CleanGlobalJson)) {
            $CleanGlobalJson = "{}"
        }
        $GlobalObj = $CleanGlobalJson | ConvertFrom-Json
        if (-not $GlobalObj) {
            $GlobalObj = [pscustomobject]@{}
        }
        if (-not ($GlobalObj.PSObject.Properties.Name -contains "agent") -or -not $GlobalObj.agent) {
            $GlobalObj | Add-Member -NotePropertyName "agent" -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        if (-not ($GlobalObj.agent.PSObject.Properties.Name -contains "tool_permissions") -or -not $GlobalObj.agent.tool_permissions) {
            $GlobalObj.agent | Add-Member -NotePropertyName "tool_permissions" -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        if (-not ($GlobalObj.agent.tool_permissions.PSObject.Properties.Name -contains "tools") -or -not $GlobalObj.agent.tool_permissions.tools) {
            $GlobalObj.agent.tool_permissions | Add-Member -NotePropertyName "tools" -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        foreach ($tName in $ToolNames) {
            $permKey = "mcp:redo:$tName"
            $GlobalObj.agent.tool_permissions.tools | Add-Member -NotePropertyName $permKey -NotePropertyValue ([pscustomobject]@{ default = "allow" }) -Force
        }
        $GlobalObj | ConvertTo-Json -Depth 12 | Set-Content -Path $ZedGlobalSettingsPath -Encoding UTF8 -ErrorAction Stop
        Write-Host "[+] Updated Zed global tool_permissions ($($ToolNames.Count) mcp:redo:* tools allowed): $ZedGlobalSettingsPath" -ForegroundColor Green
    } catch {
        Write-Host "[i] Note: Did not update Zed global tool_permissions in $ZedGlobalSettingsPath ($($_.Exception.Message)). Project .zed/settings.json is still configured." -ForegroundColor Yellow
    }
} else {
    Write-Host "[i] Note: Zed global settings file not found ($ZedGlobalSettingsPath); skipped global agent.tool_permissions auto-allow." -ForegroundColor DarkGray
}

# 5b. Cursor: <Project>/.cursor/mcp.json
$CursorDir = Join-Path $ResolvedTarget ".cursor"
New-Item -ItemType Directory -Path $CursorDir -Force | Out-Null
$CursorMcpPath = Join-Path $CursorDir "mcp.json"
@{
    mcpServers = @{
        redo = @{
            command = "pwsh"
            args    = $CommonArgs
        }
    }
} | ConvertTo-Json -Depth 6 | Set-Content -Path $CursorMcpPath -Encoding UTF8
Write-Host "[+] Wrote Cursor workspace config: $CursorMcpPath" -ForegroundColor Green

# 5c. Claude Code: <Project>/.mcp.json + <Project>/.claude/settings.local.json (tool permissions)
$ClaudeMcpPath = Join-Path $ResolvedTarget ".mcp.json"
@{
    mcpServers = @{
        redo = @{
            command = "pwsh"
            args    = $CommonArgs
        }
    }
} | ConvertTo-Json -Depth 6 | Set-Content -Path $ClaudeMcpPath -Encoding UTF8

$ClaudeDir = Join-Path $ResolvedTarget ".claude"
New-Item -ItemType Directory -Path $ClaudeDir -Force | Out-Null
$ClaudeSettingsPath = Join-Path $ClaudeDir "settings.local.json"
@{
    permissions = @{
        allow = @(
            "mcp__redo",
            "mcp__redo__*"
        )
    }
    enableAllProjectMcpServers = $true
    enabledMcpjsonServers      = @("redo")
} | ConvertTo-Json -Depth 6 | Set-Content -Path $ClaudeSettingsPath -Encoding UTF8
Write-Host "[+] Wrote Claude Code workspace config & tool permissions: $ClaudeMcpPath, $ClaudeSettingsPath" -ForegroundColor Green

# 5d. VS Code (Copilot MCP): <Project>/.vscode/mcp.json
$VsCodeDir = Join-Path $ResolvedTarget ".vscode"
New-Item -ItemType Directory -Path $VsCodeDir -Force | Out-Null
$VsCodeMcpPath = Join-Path $VsCodeDir "mcp.json"
@{
    servers = @{
        redo = @{
            type    = "stdio"
            command = "pwsh"
            args    = $CommonArgs
        }
    }
} | ConvertTo-Json -Depth 6 | Set-Content -Path $VsCodeMcpPath -Encoding UTF8
Write-Host "[+] Wrote VS Code workspace config: $VsCodeMcpPath" -ForegroundColor Green

# 6. Restart/remove any running redo container for this project so updated re_mcp_server.py takes effect immediately
$ProjectLeaf = (Split-Path -Leaf $ResolvedTarget).ToLowerInvariant() -replace '[^a-z0-9_.-]', '-'
$ProjectLeaf = $ProjectLeaf.Trim('-', '.', '_')
if ($ProjectLeaf) {
    $ContainerName = "redo-$ProjectLeaf"
    & docker rm -f $ContainerName *> $null
}

Write-Host ""
Write-Host "[+] redo is now installed locally inside project: $ResolvedTarget" -ForegroundColor Cyan
Write-Host "    - Input binaries : $ResolvedTarget/samples/"
Write-Host "    - Output files   : $ResolvedTarget/output/"
Write-Host "    - Uninstall      : pwsh -File `"$ProjectPluginDir\uninstall_plugin.ps1`" -TargetWorkspace `"$ResolvedTarget`""
