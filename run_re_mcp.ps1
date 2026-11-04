param(
    [string]$ProjectDir = "",
    [string]$ImageName = "ghcr.io/mat-ocl/redo:latest"
)

$ErrorActionPreference = "Stop"

# 1. Resolve script directory & plugin state directory
$RepoRoot = $PSScriptRoot
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

$PluginStateDir = Join-Path $HOME ".gemini\config\plugins\re-sandbox"
if (-not (Test-Path $PluginStateDir)) {
    $PluginStateDir = $RepoRoot
}
$WorkspacesDir = Join-Path $PluginStateDir "workspaces"

# 2. Resolve Docker executable (handles GUI editors like Zed with minimal PATH)
$DockerCmd = "docker"
if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
    $DefaultDockerExe = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    if (Test-Path $DefaultDockerExe) {
        $DockerCmd = $DefaultDockerExe
    }
}

# 2b. Ensure Docker image exists locally; fall back to tagging legacy re-sandbox:latest or pulling from GHCR
& $DockerCmd image inspect $ImageName *> $null
if ($LASTEXITCODE -ne 0) {
    & $DockerCmd image inspect "re-sandbox:latest" *> $null
    if ($LASTEXITCODE -eq 0) {
        & $DockerCmd tag "re-sandbox:latest" $ImageName *> $null
    } else {
        [Console]::Error.WriteLine("[*] Local image '$ImageName' not found. Pulling '$ImageName'...")
        & $DockerCmd pull $ImageName *> $null
    }
}

# 3. Check if this MCP server instance is explicitly pinned to a project (-ProjectDir or RE_PROJECT_DIR)
#    or has a startup working directory ($StartupCwd) from editors like Zed, Cursor, VS Code, or Claude Code.
$PinnedProjectDir = ""
if ($ProjectDir -and (Test-Path $ProjectDir)) {
    $PinnedProjectDir = ($ProjectDir -replace "\\", "/").TrimEnd("/")
} elseif ($env:RE_PROJECT_DIR -and (Test-Path $env:RE_PROJECT_DIR)) {
    $PinnedProjectDir = ($env:RE_PROJECT_DIR -replace "\\", "/").TrimEnd("/")
}

$StartupCwd = ""
$cwd = (Get-Location).Path
$isSystemOrEditorCwd = (
    ($cwd -eq $HOME) -or
    ($cwd -eq $RepoRoot) -or
    ($cwd -eq $PluginStateDir) -or
    ($cwd -match '(?i)\\AppData\\Local\\Programs\\') -or
    ($cwd -match '(?i)\\\.gemini\\') -or
    ($cwd -match '(?i)^C:\\Windows') -or
    ($cwd -match '(?i)^C:\\Program Files')
)
if (-not $isSystemOrEditorCwd -and (Test-Path $cwd)) {
    $StartupCwd = ($cwd -replace "\\", "/").TrimEnd("/")
}

$ServerScriptPath = Join-Path $RepoRoot "re_mcp_server.py"
$NormalizedServerScript = if (Test-Path $ServerScriptPath) { $ServerScriptPath -replace "\\", "/" } else { "" }
$NormalizedRepoRoot = ($RepoRoot -replace "\\", "/").TrimEnd("/")

function Get-RegisteredWorkspaces {
    $list = @()
    foreach ($wsDir in @($WorkspacesDir, (Join-Path $RepoRoot "workspaces"))) {
        if (Test-Path $wsDir) {
            $files = Get-ChildItem -Path $wsDir -Filter "*.json" -File -ErrorAction SilentlyContinue |
                     Sort-Object -Property LastWriteTimeUtc -Descending
            foreach ($f in $files) {
                try {
                    $obj = Get-Content -Path $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                    if (-not $obj) { continue }
                    if ($obj.workspacePaths) {
                        foreach ($p in $obj.workspacePaths) {
                            $np = ([string]$p -replace "\\", "/").TrimEnd("/")
                            if ($np -and ($list -notcontains $np) -and (Test-Path $np)) {
                                $list += $np
                            }
                        }
                    } elseif ($obj.workspacePath) {
                        $np = ([string]$obj.workspacePath -replace "\\", "/").TrimEnd("/")
                        if ($np -and ($list -notcontains $np) -and (Test-Path $np)) {
                            $list += $np
                        }
                    }
                } catch {}
            }
        }
    }
    if ($StartupCwd -and ($list -notcontains $StartupCwd)) {
        $list += $StartupCwd
    }
    return $list
}

function Resolve-ProjectRootFromPath([string]$rawPath) {
    $p = $rawPath.Trim()
    if ($p -match '^file:///') {
        $p = [System.Uri]::UnescapeDataString(($p -replace '^file:///', ''))
    }
    $norm = ($p -replace "\\", "/").TrimEnd("/")

    if ($PinnedProjectDir -and ($norm -ieq $PinnedProjectDir -or $norm.StartsWith("$PinnedProjectDir/", [System.StringComparison]::OrdinalIgnoreCase))) {
        return $PinnedProjectDir
    }

    $regWorkspaces = @(Get-RegisteredWorkspaces)
    foreach ($ws in $regWorkspaces) {
        if ($norm -ieq $ws -or $norm.StartsWith("$ws/", [System.StringComparison]::OrdinalIgnoreCase)) {
            return $ws
        }
    }

    # Walk up host directory hierarchy to find the project root
    $dir = $norm
    if (-not (Test-Path $dir -PathType Container)) {
        $parent = Split-Path -Parent $dir
        if ($parent) {
            $dir = ($parent -replace "\\", "/").TrimEnd("/")
        }
    }

    $leaf = Split-Path -Leaf $dir
    if ($leaf -in @("samples", "output", "staged", "ghidra_cache")) {
        $parent = Split-Path -Parent $dir
        if ($parent) {
            $dir = ($parent -replace "\\", "/").TrimEnd("/")
        }
    }

    $curr = $dir
    for ($i = 0; $i -lt 6; $i++) {
        if (-not $curr -or $curr -match '^[a-zA-Z]:$') { break }
        foreach ($marker in @(".git", ".agents", ".zed", ".vscode", ".cursor", "CMakeLists.txt", "Cargo.toml", "package.json", "pyproject.toml")) {
            if (Test-Path (Join-Path $curr $marker)) {
                return ($curr -replace "\\", "/").TrimEnd("/")
            }
        }
        $next = Split-Path -Parent $curr
        if (-not $next -or $next -eq $curr) { break }
        $curr = ($next -replace "\\", "/").TrimEnd("/")
    }

    if (Test-Path $dir -PathType Container) {
        return $dir
    }
    return $NormalizedRepoRoot
}

$FilePathKeys = @(
    "file_path", "binary_path", "target_path", "archive_path", "apk_path",
    "assembly_path", "pyc_path", "wasm_path", "asar_path", "script_path",
    "custom_rule_path", "post_script"
)
$AllPathKeys = @("project_dir") + $FilePathKeys + @("subdir", "source_or_path")

function Test-IsHostAbsolutePath([string]$val) {
    if (-not $val) { return $false }
    return ($val -match '^[a-zA-Z]:[/\\]') -or ($val -match '^file:///') -or ($val -match '^/(Users|home|mnt)/')
}

function Resolve-CallTargetAndRewriteArgs($msgObj) {
    $argsObj = $msgObj.params.arguments
    $toolName = [string]$msgObj.params.name
    $targetProj = ""

    # 1. Check if any argument already contains an explicit host path
    if ($null -ne $argsObj) {
        foreach ($k in $AllPathKeys) {
            $val = [string]$argsObj.$k
            if ($val -and (Test-IsHostAbsolutePath $val)) {
                if ($k -eq "source_or_path" -and $argsObj.is_inline_source -eq $true) { continue }
                $targetProj = Resolve-ProjectRootFromPath $val
                break
            }
        }
    }

    # 2. If no explicit host path was provided, resolve the target project from PinnedProjectDir or RegisteredWorkspaces
    if (-not $targetProj) {
        if ($PinnedProjectDir) {
            $targetProj = $PinnedProjectDir
        } else {
            $regList = @(Get-RegisteredWorkspaces)
            # Check if a relative file path was passed and exists in one of the open workspaces
            if ($null -ne $argsObj -and $regList.Count -gt 0) {
                foreach ($k in $FilePathKeys) {
                    $relVal = ([string]$argsObj.$k -replace '^[./\\]+', '')
                    if ($relVal -and -not ($relVal -match '^/(workspace|tmp)(/|$)')) {
                        foreach ($ws in $regList) {
                            if ((Test-Path (Join-Path $ws $relVal)) -or (Test-Path (Join-Path $ws "samples\$relVal"))) {
                                $targetProj = $ws
                                break
                            }
                        }
                        if ($targetProj) { break }
                    }
                }
            }
            if (-not $targetProj -and $regList.Count -gt 0) {
                $targetProj = [string]$regList[0]
            }
        }
    }

    if (-not $targetProj) {
        $targetProj = if ($StartupCwd) { $StartupCwd } else { $NormalizedRepoRoot }
    }

    # 3. Auto-resolve relative paths in arguments against $targetProj so they map cleanly to $targetProj's container
    if ($null -ne $argsObj) {
        foreach ($k in $FilePathKeys) {
            $val = [string]$argsObj.$k
            if ($val -and -not (Test-IsHostAbsolutePath $val) -and -not ($val -match '^/(workspace|tmp)(/|$)')) {
                $cleanRel = ($val -replace '^[./\\]+', '') -replace '\\', '/'
                $cand1 = "$targetProj/$cleanRel"
                $cand2 = "$targetProj/samples/$cleanRel"
                if (Test-Path $cand1) {
                    $argsObj.$k = $cand1
                } elseif (Test-Path $cand2) {
                    $argsObj.$k = $cand2
                } else {
                    $argsObj.$k = $cand1
                }
            }
        }

        if ($toolName -eq "dsp56300_assemble" -and $argsObj.source_or_path -and ($argsObj.is_inline_source -ne $true)) {
            $sp = [string]$argsObj.source_or_path
            if (-not (Test-IsHostAbsolutePath $sp) -and -not ($sp -match '^/(workspace|tmp)(/|$)')) {
                $cleanRel = ($sp -replace '^[./\\]+', '') -replace '\\', '/'
                if (Test-Path "$targetProj/$cleanRel") {
                    $argsObj.source_or_path = "$targetProj/$cleanRel"
                }
            }
        }

        if ($toolName -in @("list_workspace_files", "search_workspace_files")) {
            $sub = [string]$argsObj.subdir
            if (-not $sub -or $sub -eq ".") {
                $defaultSub = if ($toolName -eq "search_workspace_files") { "$targetProj/output" } else { $targetProj }
                $argsObj | Add-Member -NotePropertyName "subdir" -NotePropertyValue $defaultSub -Force
            } elseif (-not (Test-IsHostAbsolutePath $sub) -and -not ($sub -match '^/(workspace|tmp)(/|$)')) {
                $cleanSub = ($sub -replace '^[./\\]+', '') -replace '\\', '/'
                $argsObj | Add-Member -NotePropertyName "subdir" -NotePropertyValue "$targetProj/$cleanSub" -Force
            }
        }

        if ($toolName -in @("stage_file_from_base64", "stage_text_file")) {
            if (-not $argsObj.project_dir) {
                $argsObj | Add-Member -NotePropertyName "project_dir" -NotePropertyValue $targetProj -Force
            }
        }
    }

    $rewrittenJson = $msgObj | ConvertTo-Json -Depth 20 -Compress
    return [PSCustomObject]@{
        TargetProj    = [string]$targetProj
        RewrittenJson = [string]$rewrittenJson
    }
}

# 4. Per-Project Container Pool
$Workers = @{}
$script:InitRequestLine = ""
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Get-OrStartProjectWorker([string]$projDir) {
    $normProj = ($projDir -replace "\\", "/").TrimEnd("/")
    $key = $normProj.ToLowerInvariant()

    if ($Workers.ContainsKey($key)) {
        $existing = $Workers[$key]
        if (-not $existing.HasExited) {
            return $existing
        }
        $Workers.Remove($key)
    }

    $samplesDir = Join-Path $normProj "samples"
    $outputDir  = Join-Path $normProj "output"
    if (-not (Test-Path $samplesDir)) {
        New-Item -ItemType Directory -Path $samplesDir -Force -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $samplesMount = ($samplesDir -replace "\\", "/") + ":/workspace/samples:ro"
    $outputMount  = ($outputDir  -replace "\\", "/") + ":/workspace/output:rw"
    $projectMount = "${normProj}:/workspace/project:rw"

    $argList = @(
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
        "-e", "RE_PROJECT_ROOT=${normProj}",
        "-v", $samplesMount,
        "-v", $outputMount,
        "-v", $projectMount
    )

    if ($NormalizedServerScript) {
        $argList += @("-v", "${NormalizedServerScript}:/opt/re-mcp/re_mcp_server.py:ro")
    }
    if ($env:OLLAMA_HOST) {
        $argList += @("-e", "OLLAMA_HOST=$($env:OLLAMA_HOST)")
    }
    if ($env:OPENAI_BASE_URL) {
        $argList += @("-e", "OPENAI_BASE_URL=$($env:OPENAI_BASE_URL)")
    }
    $argList += @($ImageName, "re-mcp-server")

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $DockerCmd
    foreach ($a in $argList) {
        $psi.ArgumentList.Add($a)
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $false
    $psi.StandardInputEncoding = $utf8NoBom
    $psi.StandardOutputEncoding = $utf8NoBom

    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.StandardInput.NewLine = "`n"

    # If the MCP initialize handshake already happened on an earlier worker, replay it on this new project worker
    if ($script:InitRequestLine) {
        $proc.StandardInput.WriteLine($script:InitRequestLine)
        $proc.StandardInput.Flush()
        $null = $proc.StandardOutput.ReadLine()
        $proc.StandardInput.WriteLine('{"jsonrpc":"2.0","method":"notifications/initialized"}')
        $proc.StandardInput.Flush()
    }

    $Workers[$key] = $proc
    return $proc
}

function Get-DefaultProjectDir {
    if ($PinnedProjectDir) { return $PinnedProjectDir }
    $reg = @(Get-RegisteredWorkspaces)
    if ($reg.Count -gt 0 -and $reg[0]) { return [string]$reg[0] }
    if ($StartupCwd) { return $StartupCwd }
    return $NormalizedRepoRoot
}

# 5. Main MCP JSON-RPC Stdio Multiplexer Loop (uses raw stdin/stdout streams so it works with CREATE_NO_WINDOW)
$stdinReader  = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), $utf8NoBom)
$stdoutWriter = [System.IO.StreamWriter]::new([Console]::OpenStandardOutput(), $utf8NoBom)
$stdoutWriter.NewLine = "`n"
$stdoutWriter.AutoFlush = $true

try {
    while ($null -ne ($line = $stdinReader.ReadLine())) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        $msg = $null
        try {
            $msg = $trimmed | ConvertFrom-Json
        } catch {
            continue
        }

        $method = [string]$msg.method
        $hasId  = ($null -ne $msg.PSObject.Properties["id"])

        if ($method -eq "initialize") {
            $defaultProj = Get-DefaultProjectDir
            $worker = Get-OrStartProjectWorker $defaultProj
            $script:InitRequestLine = $trimmed
            $worker.StandardInput.WriteLine($trimmed)
            $worker.StandardInput.Flush()
            $resp = $worker.StandardOutput.ReadLine()
            if ($null -ne $resp) {
                $stdoutWriter.WriteLine($resp)
            }
        } elseif ($method -eq "tools/call") {
            $resolved = Resolve-CallTargetAndRewriteArgs $msg
            $targetProj = [string]$resolved.TargetProj
            $rewrittenLine = [string]$resolved.RewrittenJson

            $worker = Get-OrStartProjectWorker $targetProj
            $worker.StandardInput.WriteLine($rewrittenLine)
            $worker.StandardInput.Flush()
            if ($hasId) {
                $resp = $worker.StandardOutput.ReadLine()
                if ($null -ne $resp) {
                    $stdoutWriter.WriteLine($resp)
                }
            }
        } else {
            $defaultProj = Get-DefaultProjectDir
            $worker = Get-OrStartProjectWorker $defaultProj
            $worker.StandardInput.WriteLine($trimmed)
            $worker.StandardInput.Flush()
            if ($hasId) {
                $resp = $worker.StandardOutput.ReadLine()
                if ($null -ne $resp) {
                    $stdoutWriter.WriteLine($resp)
                }
            }
        }
    }
} finally {
    foreach ($proc in $Workers.Values) {
        try {
            if (-not $proc.HasExited) {
                $proc.StandardInput.Close()
                if (-not $proc.WaitForExit(2000)) {
                    $proc.Kill()
                }
            }
        } catch {}
    }
}
