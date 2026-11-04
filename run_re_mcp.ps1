param(
    [string]$ProjectDir = "",
    [string]$ImageName = "ghcr.io/mat-ocl/redo:latest"
)

$ErrorActionPreference = "Stop"

# 1. Resolve directory containing this script
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
$NormScriptDir = ($ScriptDir -replace "\\", "/").TrimEnd("/")

# 2. Resolve Docker executable (handles GUI editors like Zed with minimal PATH)
$DockerCmd = "docker"
if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
    $DefaultDockerExe = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    if (Test-Path $DefaultDockerExe) {
        $DockerCmd = $DefaultDockerExe
    }
}

# 3. Ensure Docker image exists locally; pull from GHCR if missing
& $DockerCmd image inspect $ImageName *> $null
if ($LASTEXITCODE -ne 0) {
    [Console]::Error.WriteLine("[*] Local image '$ImageName' not found. Pulling '$ImageName'...")
    & $DockerCmd pull $ImageName *> $null
}

# 4. Resolve the project root directory:
#    Priority 1: Explicit -ProjectDir parameter or RE_PROJECT_DIR environment variable
#    Priority 2: Project-local installation path (<Project>/.agents/plugins/redo or <Project>/redo-plugin)
#    Priority 3: Editor working directory ($PWD) if not a system/AppData directory
if (-not $ProjectDir -and $env:RE_PROJECT_DIR) {
    $ProjectDir = $env:RE_PROJECT_DIR
}

if (-not $ProjectDir) {
    if ($NormScriptDir -match '(?i)^(.+)/\.agents/plugins/redo$') {
        $ProjectDir = $Matches[1]
    } elseif ($NormScriptDir -match '(?i)^(.+)/(?:redo-plugin|\.redo)$') {
        $ProjectDir = $Matches[1]
    } else {
        $cwd = (Get-Location).Path
        $isSystemOrEditorCwd = (
            ($cwd -eq $HOME) -or
            ($cwd -match '(?i)\\AppData\\') -or
            ($cwd -match '(?i)\\\.gemini\\') -or
            ($cwd -match '(?i)^C:\\Windows') -or
            ($cwd -match '(?i)^C:\\Program Files')
        )
        if (-not $isSystemOrEditorCwd -and (Test-Path $cwd)) {
            $ProjectDir = $cwd
        } else {
            $ProjectDir = $ScriptDir
        }
    }
}

$NormalizedProject = ((Resolve-Path $ProjectDir).Path -replace "\\", "/").TrimEnd("/")
$ProjectLeaf = (Split-Path -Leaf $NormalizedProject).ToLowerInvariant() -replace '[^a-z0-9_.-]', '-'
$ProjectLeaf = $ProjectLeaf.Trim('-', '.', '_')
if (-not $ProjectLeaf) {
    $ProjectLeaf = "workspace"
}
$ContainerName = "redo-$ProjectLeaf"

# Remove any stale/previous container for this project so --name always succeeds cleanly
& $DockerCmd rm -f $ContainerName *> $null

$SamplesDir = Join-Path $NormalizedProject "samples"
$OutputDir  = Join-Path $NormalizedProject "output"

if (-not (Test-Path $SamplesDir)) {
    New-Item -ItemType Directory -Path $SamplesDir -Force | Out-Null
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$SamplesMount = ($SamplesDir -replace "\\", "/") + ":/workspace/samples:ro"
$OutputMount  = ($OutputDir  -replace "\\", "/") + ":/workspace/output:rw"
$ProjectMount = "${NormalizedProject}:/workspace/project:rw"

$DockerArgs = @(
    "run", "-i", "--rm",
    "--name", $ContainerName,
    "--hostname", $ContainerName,
    "--label", "redo.project=${NormalizedProject}",
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
    "-e", "RE_PROJECT_ROOT=${NormalizedProject}",
    "-v", $SamplesMount,
    "-v", $OutputMount,
    "-v", $ProjectMount
)

$ServerScriptPath = Join-Path $ScriptDir "re_mcp_server.py"
if (Test-Path $ServerScriptPath) {
    $NormalizedServerScript = $ServerScriptPath -replace "\\", "/"
    $DockerArgs += @("-v", "${NormalizedServerScript}:/opt/re-mcp/re_mcp_server.py:ro")
}

if ($env:OLLAMA_HOST) {
    $DockerArgs += @("-e", "OLLAMA_HOST=$($env:OLLAMA_HOST)")
}
if ($env:OPENAI_BASE_URL) {
    $DockerArgs += @("-e", "OPENAI_BASE_URL=$($env:OPENAI_BASE_URL)")
}

$DockerArgs += @($ImageName, "re-mcp-server")

& $DockerCmd @DockerArgs
exit $LASTEXITCODE
