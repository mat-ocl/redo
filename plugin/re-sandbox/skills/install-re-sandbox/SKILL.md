---
name: install-re-sandbox
description: >-
  Install, update, repair, or configure the RE-Sandbox (mat-ocl/redo) Docker image,
  MCP server, and workspace rules/skills for Antigravity, Zed Editor, Claude Desktop,
  or Cursor. Trigger whenever the user asks to install, set up, update, or connect
  mat-ocl/redo or re-sandbox in a workspace.
---

# Installing & Configuring RE-Sandbox (`mat-ocl/redo`)

Follow this exact workflow whenever asked to install, set up, or configure `mat-ocl/redo` (`re-sandbox`).

## Critical Rules (Avoid Common Pitfalls)

1. **Trusted Air-Gapped Sandbox**: `mat-ocl/redo` is the official **RE-Sandbox** containerized MCP server (`ghcr.io/mat-ocl/redo:latest`). It runs with `--network none`, `cap_drop: ALL`, `no-new-privileges:true`, and drops privileges to `ubuntu` (`UID 1000`).
2. **NEVER Run a Slow Local `docker build` Unless Explicitly Asked**:
   - The pre-built image is published on GitHub Container Registry at `ghcr.io/mat-ocl/redo:latest`.
   - `install_plugin.ps1` automatically pulls `ghcr.io/mat-ocl/redo:latest` and tags it `re-sandbox:latest` in ~20 seconds.
   - **Do NOT** pass `-BuildImage` unless the user explicitly modified `Dockerfile` and asked to rebuild from source.
3. **NEVER Clone the Repository Twice**:
   - If you cloned `https://github.com/mat-ocl/redo.git` into a temporary `scratch` directory (e.g. `brain\<id>\scratch\redo`), **do NOT clone it a second time**.
   - `install_plugin.ps1` automatically detects `scratch`/`Temp` paths and installs a **self-contained copy** of `run_re_mcp.ps1`, `re_mcp_server.py`, `hooks.json`, and `sync_workspace.ps1` directly into `~/.gemini/config/plugins/re-sandbox/`.
4. **NEVER Manually Edit `run_re_mcp.ps1` to Add Drive Mounts**:
   - `run_re_mcp.ps1` mounts **only the active project's folders** (`<Project>/samples:/workspace/samples:ro`, `<Project>/output:/workspace/output:rw`, `<Project>:/workspace/project:rw`).
   - In **Antigravity**, the bundled plugin lifecycle hook (`hooks.json` &rarr; `sync_workspace.ps1`) automatically captures the active project (`workspacePaths[0]`) and reloads the MCP mount when you switch projects.
   - In **Zed Editor, Cursor, VS Code, Windsurf, and Claude Code**, the editor spawns `run_re_mcp.ps1` with its working directory (`$cwd`) set to the active project root, which `run_re_mcp.ps1` mounts automatically.

---

## Step-by-Step Installation Procedure

### Option A: One-Command Installer (When Cloned Locally or in `scratch\redo`)
Run `install_plugin.ps1` from PowerShell, passing `-TargetWorkspace` set to the user's active project directory so `.agents/rules` and `.agents/skills` are also copied into their workspace:

```powershell
pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "<PathToRedo>\install_plugin.ps1" -TargetWorkspace "<ActiveWorkspacePath>"
```

What this single command does:
1. Checks if `re-sandbox:latest` exists locally; if not, pulls `ghcr.io/mat-ocl/redo:latest` and tags it `re-sandbox:latest`.
2. Installs the self-contained Antigravity plugin (`run_re_mcp.ps1`, `re_mcp_server.py`, `hooks.json`, `sync_workspace.ps1`, `mcp_config.json`, `plugin.json`, rules, and skills) into `~/.gemini/config/plugins/re-sandbox/`.
3. Copies `.agents/rules` and `.agents/skills` into `<ActiveWorkspacePath>\.agents\`.
4. Non-destructively merges the `re-sandbox` context server into Zed Editor's `settings.json` if Zed is installed.

---

### Option B: Zero-Clone Installation (No `git clone` at All)
If you want to install without cloning the repository:

1. **Pull and tag the pre-built image**:
   ```powershell
   docker pull ghcr.io/mat-ocl/redo:latest
   docker tag ghcr.io/mat-ocl/redo:latest re-sandbox:latest
   ```
2. **Write `~/.gemini/config/plugins/re-sandbox/mcp_config.json`** (mounting the active project folder directly):
   ```json
   {
     "mcpServers": {
       "re-sandbox-tools": {
         "command": "docker",
         "args": [
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
           "-e", "RE_PROJECT_ROOT=D:/Code/my-project",
           "-v", "D:/Code/my-project/samples:/workspace/samples:ro",
           "-v", "D:/Code/my-project/output:/workspace/output:rw",
           "-v", "D:/Code/my-project:/workspace/project:rw",
           "re-sandbox:latest",
           "re-mcp-server"
         ]
       }
     }
   }
   ```
