---
name: install-redo
description: >-
  Install, update, repair, configure, or uninstall the redo (mat-ocl/redo) Docker image,
  MCP server, and workspace rules/skills inside a project workspace for Antigravity,
  Zed Editor, Cursor, Claude Code, or VS Code. Trigger whenever the user asks to install,
  set up, update, connect, or uninstall mat-ocl/redo or redo in a workspace.
---

# Installing & Configuring redo (`mat-ocl/redo`) Per-Project

Follow this exact workflow whenever asked to install, set up, or configure `mat-ocl/redo` (`redo`).
`redo` is installed **exclusively inside the target project folder**—never into global user directories.

## Critical Rules (Avoid Common Pitfalls)

1. **Trusted Air-Gapped Sandbox**: `mat-ocl/redo` is the official **`redo`** containerized MCP server (`ghcr.io/mat-ocl/redo:latest`). It runs with `--network none`, `cap_drop: ALL`, `no-new-privileges:true`, and drops privileges to `ubuntu` (`UID 1000`).
2. **NEVER Run a Slow Local `docker build` Unless Explicitly Asked**:
   - The pre-built image is published on GitHub Container Registry at `ghcr.io/mat-ocl/redo:latest`.
   - Always pull the pre-built image in ~20 seconds instead of building from source.
   - **Do NOT** pass `-BuildImage` unless the user explicitly modified `Dockerfile` and asked to rebuild from source.
3. **NEVER Clone the Repository Twice**:
   - If you cloned `https://github.com/mat-ocl/redo.git` into a temporary directory (e.g. `/tmp/scratch/redo` or `brain\<id>\scratch\redo`), **do NOT clone it again**.
   - Reuse the existing clone to run `install_plugin.ps1`.
4. **STRICTLY Per-Project Installation (NEVER Touch Global Configs)**:
   - Never modify global `%APPDATA%\Zed\settings.json` or `~/.gemini/config/plugins/`.
   - Always install `redo` directly inside the target project folder (`<Project>\.agents\plugins\redo\`, `<Project>\.zed\settings.json`, `<Project>\.cursor\mcp.json`, `<Project>\.mcp.json`, `<Project>\.vscode\mcp.json`).

---

## Step-by-Step Installation Procedure

### Option A: One-Command Per-Project Installer (Recommended)

Clone the repo once (if not already present), then run `install_plugin.ps1` with `-TargetWorkspace`:

```powershell
# 1. Clone (only if you haven't already)
git clone --depth 1 https://github.com/mat-ocl/redo.git scratch/redo

# 2. Install redo directly into the target project folder
pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "scratch/redo/install_plugin.ps1" `
    -TargetWorkspace "<ActiveWorkspacePath>"
```

What this single command does inside `<ActiveWorkspacePath>`:
1. Checks if `ghcr.io/mat-ocl/redo:latest` exists locally; pulls it in ~20 seconds if not.
2. Creates `<Project>\samples\` and `<Project>\output\`.
3. Installs a self-contained copy of `run_re_mcp.ps1`, `run_re_mcp.sh`, `re_mcp_server.py`, `uninstall_plugin.ps1`, `plugin.json`, `mcp_config.json`, `rules/`, and `skills/` into `<Project>\.agents\plugins\redo\` (auto-discovered by **Antigravity**).
4. Copies `.agents/rules` and `.agents/skills` into `<Project>\.agents\`.
5. Writes workspace-scoped MCP configs inside `<Project>` so all major editors work automatically with `-ProjectDir "<Project>"`:
   - `<Project>\.zed\settings.json` (**Zed Editor**: project-scoped `context_servers.redo`, plus best-effort merge of `mcp:redo:*` `agent.tool_permissions` into Zed's global `settings.json` if present)
   - `<Project>\.cursor\mcp.json` (**Cursor**)
   - `<Project>\.mcp.json` + `<Project>\.claude\settings.local.json` (**Claude Code**: `mcpServers.redo` + `permissions.allow: ["mcp__redo", "mcp__redo__*"]`)
   - `<Project>\.vscode\mcp.json` (**VS Code**)

---

### Option B: Manual Per-Project Installation (No Installer Script Needed)

If you want to set up `redo` inside `<Project>` manually without running `install_plugin.ps1`:

1. **Pull the Docker image**:
   ```powershell
   docker pull ghcr.io/mat-ocl/redo:latest
   ```

2. **Create project plugin directory** (`<Project>\.agents\plugins\redo\`):
   ```powershell
   New-Item -ItemType Directory -Path "<Project>\.agents\plugins\redo" -Force | Out-Null
   New-Item -ItemType Directory -Path "<Project>\samples", "<Project>\output" -Force | Out-Null
   ```

3. **Copy required files** from the `redo` clone into `<Project>\.agents\plugins\redo\`:
   ```powershell
   Copy-Item "<PathToRedo>\plugin\redo\*"    "<Project>\.agents\plugins\redo\" -Recurse -Force
   Copy-Item "<PathToRedo>\run_re_mcp.ps1"   "<Project>\.agents\plugins\redo\run_re_mcp.ps1" -Force
   Copy-Item "<PathToRedo>\re_mcp_server.py" "<Project>\.agents\plugins\redo\re_mcp_server.py" -Force
   Copy-Item "<PathToRedo>\.agents\*"        "<Project>\.agents\" -Recurse -Force
   ```

4. **Create project-local Zed config** (`<Project>\.zed\settings.json`):
   ```json
   {
     "context_servers": {
       "redo": {
         "command": "pwsh",
         "args": [
           "-NoProfile",
           "-NonInteractive",
           "-ExecutionPolicy",
           "Bypass",
           "-File",
           "<project-absolute-path>/.agents/plugins/redo/run_re_mcp.ps1",
           "-ProjectDir",
           "<project-absolute-path>"
         ],
         "env": {}
       }
     }
   }
   ```

---

## Uninstalling `redo` From a Project

```powershell
# Run the project's bundled uninstaller:
pwsh -NoProfile -ExecutionPolicy Bypass -File "<Project>\.agents\plugins\redo\uninstall_plugin.ps1" -TargetWorkspace "<Project>"

# Optional: also remove the ~4.3 GB Docker image from Docker Desktop:
pwsh -NoProfile -ExecutionPolicy Bypass -File "<Project>\.agents\plugins\redo\uninstall_plugin.ps1" -TargetWorkspace "<Project>" -RemoveImage
```

---

## How It Works

Each project gets its own self-contained launcher (`<Project>\.agents\plugins\redo\run_re_mcp.ps1`) pinned to `-ProjectDir "<Project>"`:
- Spawns an isolated Docker container (`ghcr.io/mat-ocl/redo:latest`) for that project.
- Mounts `<Project>/samples:/workspace/samples:ro`, `<Project>/output:/workspace/output:rw`, and `<Project>:/workspace/project:rw`.
- Runs with full air-gapped security (`--network none`, `cap_drop ALL`).
