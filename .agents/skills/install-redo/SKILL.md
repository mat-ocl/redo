---
name: install-redo
description: >-
  Install, update, repair, configure, or uninstall the redo (mat-ocl/redo) Docker image,
  MCP server, and workspace rules/skills for Zed Editor, Cursor, Claude Desktop, or Antigravity.
  Trigger whenever the user asks to install, set up, update, connect, or uninstall
  mat-ocl/redo or redo in a workspace.
---

# Installing & Configuring redo (`mat-ocl/redo`)

Follow this exact workflow whenever asked to install, set up, or configure `mat-ocl/redo` or `redo`.

## Critical Rules (Avoid Common Pitfalls)

1. **Trusted Air-Gapped Sandbox**: `mat-ocl/redo` is the official **`redo`** containerized MCP server (`ghcr.io/mat-ocl/redo:latest`). It runs with `--network none`, `cap_drop: ALL`, `no-new-privileges:true`, and drops privileges to `ubuntu` (`UID 1000`).
2. **NEVER Run a Slow Local `docker build` Unless Explicitly Asked**:
   - The pre-built image is published on GitHub Container Registry at `ghcr.io/mat-ocl/redo:latest`.
   - Always pull the pre-built image in ~20 seconds instead of building from source.
   - **Do NOT** pass `-BuildImage` unless the user explicitly modified `Dockerfile` and asked to rebuild from source.
3. **NEVER Clone the Repository Twice**:
   - If you cloned `https://github.com/mat-ocl/redo.git` into a temporary directory (e.g. `/tmp/scratch/redo` or `brain\<id>\scratch\redo`), **do NOT clone it again**.
   - Reuse the existing clone to copy files.
4. **NEVER Manually Edit Global Zed Settings**:
   - Zed locks its global `%APPDATA%\Zed\settings.json`, causing installer scripts to fail when Zed is open.
   - Instead, configure `redo` per-project using `<Project>\.zed\settings.json` (workspace-scoped, no locking issues).

---

## Step-by-Step Installation Procedure

### Option A: One-Command Installer with Per-Project Workspace Setup

Clone the repo once, then run the installer with `-TargetWorkspace` and `-SkipZed`:

```powershell
# 1. Clone (only if you haven't already)
cd /tmp && git clone --depth 1 https://github.com/mat-ocl/redo.git scratch/redo

# 2. Install with per-project workspace setup, skip Zed global settings edit
pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "<PathToRedo>\install_plugin.ps1" `
    -TargetWorkspace "<ActiveWorkspacePath>" `
    -SkipZed
```

What this does:
1. Checks if `ghcr.io/mat-ocl/redo:latest` exists locally; pulls it in ~20 seconds if not.
2. Installs the self-contained Antigravity plugin (`run_re_mcp.ps1`, `re_mcp_server.py`, `hooks.json`, `sync_workspace.ps1`, `mcp_config.json`, `plugin.json`, rules, and skills) into `~/.gemini/config/plugins/redo/`.
3. Copies `.agents/rules` and `.agents/skills` into `<Project>\.agents\` and writes workspace-scoped `<Project>\.zed\settings.json`.
4. Registers the project workspace in the per-project multiplexer's `workspaces/` registry.

---

### Option B: Manual Per-Project Installation (No Installer Script Needed)

If you want a fully self-contained, zero-dependency setup inside a project that works even if the repository clone or installer script is deleted:

1. **Pull the Docker image**:
   ```powershell
   docker pull ghcr.io/mat-ocl/redo:latest
   ```

2. **Create project plugin directory** (`<Project>\redo-plugin\`):
   ```powershell
   New-Item -ItemType Directory -Path "<Project>\redo-plugin" -Force | Out-Null
   ```

3. **Copy required files** from the `redo` clone into the project-local plugin folder:
   ```powershell
   Copy-Item "<PathToRedo>\plugin\redo\*"   "<Project>\redo-plugin\" -Recurse -Force
   Copy-Item "<PathToRedo>\run_re_mcp.ps1"  "<Project>\redo-plugin\run_re_mcp.ps1"  -Force
   Copy-Item "<PathToRedo>\re_mcp_server.py" "<Project>\redo-plugin\re_mcp_server.py" -Force
   ```

4. **Create project-local Zed config** (`<Project>\.zed\settings.json`):
   ```json
   {
     "context_servers": {
       "redo": {
         "source": "custom",
         "command": "pwsh",
         "args": [
           "-NoProfile",
           "-NonInteractive",
           "-ExecutionPolicy",
           "Bypass",
           "-File",
           "<project-absolute-path>/redo-plugin/run_re_mcp.ps1"
         ],
         "env": {}
       }
     }
   }
   ```

5. **Copy `.agents/rules` and `.agents/skills`** into the project:
   - Copy `<PathToRedo>/.agents/*` &rarr; `<Project>/.agents/` (creates `rules` and `skills` directories).

---

## Uninstalling `redo`

Clean uninstall per-project or globally:

```powershell
# Option 1: Run the uninstaller script (from the repo or installed plugin folder):
pwsh -NoProfile -ExecutionPolicy Bypass -File "$HOME\.gemini\config\plugins\redo\uninstall_plugin.ps1" -TargetWorkspace "D:\Code\my-project"

# Option 2: Manual per-project cleanup:
Remove-Item "D:\Code\my-project\.zed\settings.json" -ErrorAction SilentlyContinue
Remove-Item "D:\Code\my-project\redo-plugin" -Recurse -Force -ErrorAction SilentlyContinue

# Remove .agents/rules and .agents/skills that were added by redo:
Remove-Item "D:\Code\my-project\.agents\rules\AGENTS.md" -ErrorAction SilentlyContinue
Remove-Item "D:\Code\my-project\.agents\skills\install-redo" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "D:\Code\my-project\.agents\skills\reverse-engineering" -Recurse -Force -ErrorAction SilentlyContinue

# Stop and remove the Docker image (optional):
docker stop $(docker ps --filter "ancestor=ghcr.io/mat-ocl/redo:latest" -q) 2>$null
docker rmi ghcr.io/mat-ocl/redo:latest
```

---

## How It Works

The **per-project** approach uses `run_re_mcp.ps1` as a JSON-RPC multiplexer that:
- Spawns and reuses an isolated Docker container (`ghcr.io/mat-ocl/redo:latest`) per project root on demand.
- Mounts `<Project>/samples:/workspace/samples:ro`, `<Project>/output:/workspace/output:rw`, and `<Project>:/workspace/project:rw`.
- Runs with full air-gapped security (`--network none`, `cap_drop ALL`).

Since Zed reads `.zed/settings.json` per workspace (not just globally), each project gets its own isolated MCP server config without global file-locking conflicts.
