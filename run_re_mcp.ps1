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
$ActiveWorkspaceFile = Join-Path $PluginStateDir "active_workspace.txt"

# 2. Resolve Docker executable (handles GUI editors like Zed with minimal PATH)
$DockerCmd = "docker"
if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
    $DefaultDockerExe = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    if (Test-Path $DefaultDockerExe) {
        $DockerCmd = $DefaultDockerExe
    }
}

# 2b. Ensure ghcr.io/mat-ocl/redo:latest image exists locally; auto-pull from GHCR on stderr if missing
& $DockerCmd image inspect $ImageName *> $null
if ($LASTEXITCODE -ne 0) {
    [Console]::Error.WriteLine("[*] Local image '$ImageName' not found. Pulling '$ImageName'...")
    & $DockerCmd pull $ImageName 1>&2
}

# 3. Resolve active project directory:
#    Priority:
#    a) Explicit -ProjectDir or $env:RE_PROJECT_DIR
#    b) Active workspace synced by Antigravity plugin lifecycle hook (active_workspace.txt)
#    c) Current working directory ($cwd) when spawned per-project by Zed, Cursor, VS Code, Windsurf, or Claude Code
#    d) Fallback to $RepoRoot
if (-not $ProjectDir -and $env:RE_PROJECT_DIR) {
    $ProjectDir = $env:RE_PROJECT_DIR
}

$cwd = (Get-Location).Path
$isSystemOrEditorCwd = (
    ($cwd -eq $HOME) -or
    ($cwd -eq $RepoRoot) -or
    ($cwd -match '(?i)\\AppData\\Local\\Programs\\') -or
    ($cwd -match '(?i)^C:\\Windows') -or
    ($cwd -match '(?i)^C:\\Program Files')
)

if (-not $ProjectDir -and -not $isSystemOrEditorCwd -and (Test-Path $cwd)) {
    # Editor (Zed / Cursor / VS Code / Claude Code) spawned MCP server directly inside the user's project folder
    $ProjectDir = $cwd
}

if (-not $ProjectDir -and (Test-Path $ActiveWorkspaceFile)) {
    # Antigravity plugin hook recorded the active workspace path
    $savedWs = (Get-Content -Path $ActiveWorkspaceFile -Raw -ErrorAction SilentlyContinue).Trim()
    if ($savedWs -and (Test-Path $savedWs)) {
        $ProjectDir = $savedWs
    }
}

if (-not $ProjectDir) {
    $ProjectDir = $RepoRoot
}

$SamplesDir = Join-Path $ProjectDir "samples"
$OutputDir  = Join-Path $ProjectDir "output"

if (-not (Test-Path $SamplesDir)) {
    New-Item -ItemType Directory -Path $SamplesDir -Force | Out-Null
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$NormalizedProjectDir = ($ProjectDir -replace "\\", "/").TrimEnd("/")
$SamplesMount = ($SamplesDir -replace "\\", "/") + ":/workspace/samples:ro"
$OutputMount  = ($OutputDir  -replace "\\", "/") + ":/workspace/output:rw"
$ProjectMount = "${NormalizedProjectDir}:/workspace/project:rw"

$dockerArgs = @(
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
    "-e", "RE_PROJECT_ROOT=${NormalizedProjectDir}",
    "-v", $SamplesMount,
    "-v", $OutputMount,
    "-v", $ProjectMount
)

$ServerScriptPath = Join-Path $RepoRoot "re_mcp_server.py"
if (Test-Path $ServerScriptPath) {
    $NormalizedServerScript = $ServerScriptPath -replace "\\", "/"
    $dockerArgs += @("-v", "${NormalizedServerScript}:/opt/re-mcp/re_mcp_server.py:ro")
}

# 4. Forward optional local LLM environment variables if configured on host
if ($env:OLLAMA_HOST) {
    $dockerArgs += @("-e", "OLLAMA_HOST=$($env:OLLAMA_HOST)")
}
if ($env:OPENAI_BASE_URL) {
    $dockerArgs += @("-e", "OPENAI_BASE_URL=$($env:OPENAI_BASE_URL)")
}

$dockerArgs += @($ImageName, "re-mcp-server")

& $DockerCmd @dockerArgs
