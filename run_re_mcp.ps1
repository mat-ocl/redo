param(
    [string]$ProjectDir = "",
    [string]$HostCodeDir = "",
    [string]$ImageName = "re-sandbox:latest"
)

$ErrorActionPreference = "Stop"

# 1. Resolve repository root (directory containing this script)
$RepoRoot = $PSScriptRoot
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# 2. Resolve Docker executable (handles GUI editors like Zed with minimal PATH)
$DockerCmd = "docker"
if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
    $DefaultDockerExe = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    if (Test-Path $DefaultDockerExe) {
        $DockerCmd = $DefaultDockerExe
    }
}

# 3. Resolve target project directory (explicit arg -> env var -> current working directory -> repo root)
if (-not $ProjectDir -and $env:RE_PROJECT_DIR) {
    $ProjectDir = $env:RE_PROJECT_DIR
}
if (-not $ProjectDir) {
    $cwd = (Get-Location).Path
    if ((Test-Path (Join-Path $cwd "samples")) -or (Test-Path (Join-Path $cwd "output"))) {
        $ProjectDir = $cwd
    } else {
        $ProjectDir = $RepoRoot
    }
}

$SamplesDir = Join-Path $ProjectDir "samples"
$OutputDir  = Join-Path $ProjectDir "output"

if (-not (Test-Path $SamplesDir)) {
    New-Item -ItemType Directory -Path $SamplesDir -Force | Out-Null
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$SamplesMount = ($SamplesDir -replace "\\", "/") + ":/workspace/samples:ro"
$OutputMount  = ($OutputDir  -replace "\\", "/") + ":/workspace/output:rw"
$ServerScriptPath = (Join-Path $RepoRoot "re_mcp_server.py") -replace "\\", "/"
$ServerScriptMount = "${ServerScriptPath}:/opt/re-mcp/re_mcp_server.py:ro"

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
    "-v", $SamplesMount,
    "-v", $OutputMount,
    "-v", $ServerScriptMount
)

# 4. Resolve optional multi-project parent code directory (env var -> explicit arg -> C:\CODE fallback)
if (-not $HostCodeDir -and $env:RE_HOST_CODE_DIR) {
    $HostCodeDir = $env:RE_HOST_CODE_DIR
}
if (-not $HostCodeDir -and (Test-Path "C:\CODE")) {
    $HostCodeDir = "C:\CODE"
}

if ($HostCodeDir -and (Test-Path $HostCodeDir)) {
    $NormalizedHostCode = ($HostCodeDir -replace "\\", "/").TrimEnd("/")
    $dockerArgs += @(
        "-v", "${NormalizedHostCode}:/workspace/host_code:rw",
        "-e", "RE_HOST_CODE_ROOT=${NormalizedHostCode}"
    )
}

# 5. Forward optional local LLM environment variables if configured on host
if ($env:OLLAMA_HOST) {
    $dockerArgs += @("-e", "OLLAMA_HOST=$($env:OLLAMA_HOST)")
}
if ($env:OPENAI_BASE_URL) {
    $dockerArgs += @("-e", "OPENAI_BASE_URL=$($env:OPENAI_BASE_URL)")
}

$dockerArgs += @($ImageName, "re-mcp-server")

& $DockerCmd @dockerArgs
