param(
    [ValidateSet("pwsh", "docker")]
    [string]$Mode = "pwsh",
    [switch]$BuildImage = $false,
    [switch]$InstallGlobalRules = $false,
    [string]$ZedSettingsPath = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = $PSScriptRoot
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

$NormRepoRoot = ($RepoRoot -replace "\\", "/").TrimEnd("/")
$LauncherPath = "${NormRepoRoot}/run_re_mcp.ps1"

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

# 2. Construct the 're-sandbox' context_servers entry for Zed
if ($Mode -eq "docker") {
    $DockerExe = "docker"
    if (Test-Path "C:\Program Files\Docker\Docker\resources\bin\docker.exe") {
        $DockerExe = "C:/Program Files/Docker/Docker/resources/bin/docker.exe"
    }
    $DockerArgs = @(
        "run", "-i", "--rm",
        "--network", "none",
        "--cap-drop", "ALL",
        "--cap-add", "CHOWN",
        "--cap-add", "DAC_OVERRIDE",
        "--cap-add", "SETUID",
        "--cap-add", "SETGID",
        "--cap-add", "SYS_PTRACE",
        "--security-opt", "seccomp=unconfined",
        "--security-opt", "no-new-privileges:true",
        "-e", "PYTHONUNBUFFERED=1",
        "-v", "${NormRepoRoot}/re_mcp_server.py:/opt/re-mcp/re_mcp_server.py:ro",
        "-v", "${NormRepoRoot}/samples:/workspace/samples:ro",
        "-v", "${NormRepoRoot}/output:/workspace/output:rw"
    )
    if (Test-Path "C:\CODE") {
        $DockerArgs += @(
            "-v", "C:/CODE:/workspace/host_code:rw",
            "-e", "RE_HOST_CODE_ROOT=C:/CODE"
        )
    }
    $DockerArgs += @("re-sandbox:latest", "re-mcp-server")

    $ArgsJsonList = ($DockerArgs | ForEach-Object { "        `"$_`"" }) -join ",`n"
    $ServerBlockJson = @"
    "re-sandbox": {
      "source": "custom",
      "command": "$DockerExe",
      "args": [
$ArgsJsonList
      ],
      "env": {}
    }
"@
} else {
    $ServerBlockJson = @"
    "re-sandbox": {
      "source": "custom",
      "command": "pwsh",
      "args": [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "$LauncherPath"
      ],
      "env": {}
    }
"@
}

# 3. Update workspace-local .zed/settings.json
$LocalZedDir = Join-Path $RepoRoot ".zed"
New-Item -ItemType Directory -Path $LocalZedDir -Force | Out-Null
$LocalZedSettings = Join-Path $LocalZedDir "settings.json"
$LocalJsonContent = @"
{
  "context_servers": {
$ServerBlockJson
  }
}
"@
Set-Content -Path $LocalZedSettings -Value $LocalJsonContent -Encoding UTF8
Write-Host "[+] Updated workspace Zed config: $LocalZedSettings" -ForegroundColor Green

# 4. Update global Zed settings (%APPDATA%\Zed\settings.json) preserving JSONC comments
if (-not $ZedSettingsPath) {
    $ZedConfigDir = Join-Path $env:APPDATA "Zed"
    New-Item -ItemType Directory -Path $ZedConfigDir -Force | Out-Null
    $ZedSettingsPath = Join-Path $ZedConfigDir "settings.json"
}

if (-not (Test-Path $ZedSettingsPath)) {
    Set-Content -Path $ZedSettingsPath -Value $LocalJsonContent -Encoding UTF8
    Write-Host "[+] Created global Zed settings at: $ZedSettingsPath" -ForegroundColor Green
} else {
    $BackupPath = "${ZedSettingsPath}.re-sandbox.bak"
    Copy-Item -Path $ZedSettingsPath -Destination $BackupPath -Force
    Write-Host "[*] Backed up existing Zed settings to: $BackupPath" -ForegroundColor DarkGray

    $RawText = Get-Content -Path $ZedSettingsPath -Raw -Encoding UTF8

    # Helper to find matching closing brace '}' for an opening '{' at $OpenIdx
    function Find-MatchingBrace([string]$Text, [int]$OpenIdx) {
        $Depth = 0
        $InStr = $false
        $Esc = $false
        $InLineComment = $false
        for ($i = $OpenIdx; $i -lt $Text.Length; $i++) {
            $ch = $Text[$i]
            if ($InLineComment) {
                if ($ch -eq "`n") { $InLineComment = $false }
                continue
            }
            if ($InStr) {
                if ($Esc) { $Esc = $false }
                elseif ($ch -eq '\') { $Esc = $true }
                elseif ($ch -eq '"') { $InStr = $false }
                continue
            }
            if ($ch -eq '/' -and ($i + 1 -lt $Text.Length) -and $Text[$i + 1] -eq '/') {
                $InLineComment = $true
                $i++
                continue
            }
            if ($ch -eq '"') { $InStr = $true; continue }
            if ($ch -eq '{') { $Depth++ }
            elseif ($ch -eq '}') {
                $Depth--
                if ($Depth -eq 0) { return $i }
            }
        }
        return -1
    }

    $CtxMatch = [regex]::Match($RawText, '"context_servers"\s*:\s*\{')
    if ($CtxMatch.Success) {
        $CtxOpenIdx = $CtxMatch.Index + $CtxMatch.Length - 1
        $CtxCloseIdx = Find-MatchingBrace -Text $RawText -OpenIdx $CtxOpenIdx
        if ($CtxCloseIdx -gt $CtxOpenIdx) {
            $CtxBody = $RawText.Substring($CtxOpenIdx, $CtxCloseIdx - $CtxOpenIdx + 1)
            $ReMatch = [regex]::Match($CtxBody, '"re-sandbox(?:-tools)?"\s*:\s*\{')
            if ($ReMatch.Success) {
                $ReOpenInBody = $ReMatch.Index + $ReMatch.Length - 1
                $ReCloseInBody = Find-MatchingBrace -Text $CtxBody -OpenIdx $ReOpenInBody
                if ($ReCloseInBody -gt $ReOpenInBody) {
                    $AbsStart = $CtxOpenIdx + $ReMatch.Index
                    $AbsEnd = $CtxOpenIdx + $ReCloseInBody
                    $ReplacementEntry = $ServerBlockJson.TrimStart()
                    $UpdatedText = $RawText.Substring(0, $AbsStart) + $ReplacementEntry + $RawText.Substring($AbsEnd + 1)
                    Set-Content -Path $ZedSettingsPath -Value $UpdatedText -NoNewline -Encoding UTF8
                    Write-Host "[+] Updated existing 're-sandbox' entry in global Zed settings: $ZedSettingsPath" -ForegroundColor Green
                }
            } else {
                # Insert inside context_servers right after its opening '{'
                $UpdatedText = $RawText.Substring(0, $CtxOpenIdx + 1) + "`n" + $ServerBlockJson + "," + $RawText.Substring($CtxOpenIdx + 1)
                Set-Content -Path $ZedSettingsPath -Value $UpdatedText -NoNewline -Encoding UTF8
                Write-Host "[+] Added 're-sandbox' to 'context_servers' in global Zed settings: $ZedSettingsPath" -ForegroundColor Green
            }
        }
    } else {
        # Insert a new "context_servers" block before the final closing '}'
        $LastBrace = $RawText.LastIndexOf('}')
        if ($LastBrace -gt 0) {
            $CtxBlock = @"
  "context_servers": {
$ServerBlockJson
  }
}
"@
            $Prefix = $RawText.Substring(0, $LastBrace).TrimEnd()
            if (-not $Prefix.EndsWith(",") -and -not $Prefix.EndsWith("{")) {
                $Prefix += ","
            }
            $UpdatedText = $Prefix + "`n" + $CtxBlock + "`n"
            Set-Content -Path $ZedSettingsPath -Value $UpdatedText -NoNewline -Encoding UTF8
            Write-Host "[+] Added 'context_servers.re-sandbox' block to global Zed settings: $ZedSettingsPath" -ForegroundColor Green
        }
    }
}

# 5. Optionally append RE-Sandbox rules to global %APPDATA%\Zed\AGENTS.md
if ($InstallGlobalRules) {
    $ZedAgentsPath = Join-Path (Split-Path -Parent $ZedSettingsPath) "AGENTS.md"
    $RepoRulesPath = Join-Path $RepoRoot ".agents\rules\AGENTS.md"
    if (Test-Path $RepoRulesPath) {
        $RulesContent = Get-Content -Path $RepoRulesPath -Raw -Encoding UTF8
        if (Test-Path $ZedAgentsPath) {
            $ExistingAgents = Get-Content -Path $ZedAgentsPath -Raw -Encoding UTF8
            if ($ExistingAgents -notmatch "Reverse Engineering Sandbox Rules") {
                Add-Content -Path $ZedAgentsPath -Value "`n`n$RulesContent" -Encoding UTF8
                Write-Host "[+] Appended RE-Sandbox rules to global Zed AGENTS.md: $ZedAgentsPath" -ForegroundColor Green
            } else {
                Write-Host "[*] RE-Sandbox rules already present in $ZedAgentsPath" -ForegroundColor Yellow
            }
        } else {
            Set-Content -Path $ZedAgentsPath -Value $RulesContent -Encoding UTF8
            Write-Host "[+] Created global Zed AGENTS.md at: $ZedAgentsPath" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "Zed Editor integration is ready! Open Zed -> Agent Panel -> verify 're-sandbox' MCP server is active." -ForegroundColor Cyan
