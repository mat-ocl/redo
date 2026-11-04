#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# redo Per-Project MCP Container Multiplexer (Linux / macOS)
# ==============================================================================
# Spawns and manages an isolated Docker container per project root on demand.
# Resolves both explicit host paths and relative project paths across open
# workspaces (workspaces/<conversationId>.json) and the startup directory.
# ==============================================================================

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="${RE_IMAGE_NAME:-ghcr.io/mat-ocl/redo:latest}"
EXPLICIT_PROJECT_DIR="${1:-${RE_PROJECT_DIR:-}}"

if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo "[*] Local image '${IMAGE_NAME}' not found. Pulling '${IMAGE_NAME}'..." >&2
    docker pull "${IMAGE_NAME}" >&2 || true
fi

if command -v python3 >/dev/null 2>&1; then
    exec python3 -u - "${REPO_ROOT}" "${IMAGE_NAME}" "${EXPLICIT_PROJECT_DIR}" <<'PYEOF'
import json
import os
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
image_name = sys.argv[2]
explicit_proj = sys.argv[3].strip() if len(sys.argv) > 3 else ""
startup_cwd = Path.cwd().resolve()
plugin_state_dir = Path.home() / ".gemini" / "config" / "plugins" / "redo"

PATH_PARAM_KEYS = (
    "file_path", "binary_path", "archive_path", "apk_path", "asar_path",
    "wasm_path", "pyc_path", "js_path", "output_file_path", "input_file_path",
    "rules_path", "output_dir", "project_dir"
)
PROJECT_MARKERS = (
    ".git", ".agents", ".zed", ".vscode", ".cursor", ".mcp.json",
    "CMakeLists.txt", "Cargo.toml", "package.json", "pyproject.toml", "sln"
)

def get_open_workspaces():
    candidates = []
    seen = set()
    if explicit_proj and Path(explicit_proj).is_dir():
        p = str(Path(explicit_proj).resolve())
        seen.add(p)
        candidates.append(p)

    ws_dirs = [repo_root / "workspaces", plugin_state_dir / "workspaces"]
    json_files = []
    for d in ws_dirs:
        if d.is_dir():
            json_files.extend(d.glob("*.json"))
    json_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

    for jf in json_files:
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
            paths = []
            if data.get("workspacePath"):
                paths.append(data["workspacePath"])
            if isinstance(data.get("workspacePaths"), list):
                paths.extend(data["workspacePaths"])
            for raw in paths:
                if raw and Path(raw).is_dir():
                    norm = str(Path(raw).resolve())
                    if norm not in seen:
                        seen.add(norm)
                        candidates.append(norm)
        except Exception:
            pass

    if startup_cwd not in (Path.home(), repo_root, Path("/")) and startup_cwd.is_dir():
        s = str(startup_cwd)
        if s not in seen:
            seen.add(s)
            candidates.append(s)

    if not candidates:
        candidates.append(str(repo_root))
    return candidates

def find_project_root_from_path(raw_path: str):
    if not raw_path or raw_path.startswith(("/workspace", "/tmp")):
        return None
    p = Path(raw_path)
    if not p.is_absolute():
        return None
    open_ws = get_open_workspaces()
    norm_str = str(p.resolve()) if p.exists() else str(p)
    for ws in open_ws:
        if norm_str == ws or norm_str.startswith(ws + "/"):
            return ws
    parts = list(p.parts)
    for marker in ("samples", "output"):
        if marker in parts:
            idx = parts.index(marker)
            if idx > 1:
                cand = Path(*parts[:idx])
                if cand.is_dir():
                    return str(cand.resolve())
    curr = p if p.is_dir() else p.parent
    walk = curr
    for _ in range(6):
        if walk in (Path("/"), Path.home()):
            break
        if walk.is_dir():
            for m in PROJECT_MARKERS:
                if (walk / m).exists():
                    return str(walk.resolve())
        walk = walk.parent
    if curr.is_dir():
        return str(curr.resolve())
    return None

def resolve_tool_call(msg_obj):
    params = msg_obj.get("params") or {}
    tool_name = params.get("name", "")
    args = params.get("arguments")
    open_ws = get_open_workspaces()
    target_proj = None

    if isinstance(args, dict):
        if args.get("project_dir"):
            target_proj = find_project_root_from_path(str(args["project_dir"]))
        if not target_proj:
            for k in PATH_PARAM_KEYS:
                val = args.get(k)
                if isinstance(val, str) and val:
                    found = find_project_root_from_path(val)
                    if found:
                        target_proj = found
                        break
        if not target_proj and isinstance(args.get("subdir"), str) and args["subdir"]:
            target_proj = find_project_root_from_path(args["subdir"])

        if not target_proj:
            rel_candidates = []
            for k in PATH_PARAM_KEYS:
                val = args.get(k)
                if isinstance(val, str) and val and not val.startswith("/"):
                    rel_candidates.append(val.lstrip("./"))
            sub = args.get("subdir")
            if isinstance(sub, str) and sub and not sub.startswith("/") and sub not in ("samples", "output", "."):
                rel_candidates.append(sub.lstrip("./"))
            for rel in rel_candidates:
                for ws in open_ws:
                    if (Path(ws) / rel).exists() or (Path(ws) / "samples" / rel).exists():
                        target_proj = ws
                        break
                if target_proj:
                    break

    if not target_proj:
        target_proj = open_ws[0]

    if isinstance(args, dict):
        for k in PATH_PARAM_KEYS:
            val = args.get(k)
            if isinstance(val, str) and val and not val.startswith("/"):
                clean_rel = val.lstrip("./")
                c1 = Path(target_proj) / clean_rel
                c2 = Path(target_proj) / "samples" / clean_rel
                if c1.exists():
                    args[k] = str(c1)
                elif c2.exists():
                    args[k] = str(c2)
                else:
                    args[k] = str(c1)
        if tool_name in ("list_workspace_files", "search_workspace_files"):
            sub = str(args.get("subdir") or "")
            if not sub or sub == ".":
                args["subdir"] = f"{target_proj}/output" if tool_name == "search_workspace_files" else target_proj
            elif not sub.startswith("/"):
                args["subdir"] = f"{target_proj}/{sub.lstrip('./')}"
        if tool_name in ("stage_file_from_base64", "stage_text_file") and not args.get("project_dir"):
            args["project_dir"] = target_proj

    return target_proj, json.dumps(msg_obj, separators=(",", ":"))

workers = {}
init_request_line = None

def get_worker(proj_dir: str):
    norm_proj = str(Path(proj_dir).resolve())
    proc = workers.get(norm_proj)
    if proc and proc.poll() is None:
        return proc

    samples_dir = Path(norm_proj) / "samples"
    output_dir = Path(norm_proj) / "output"
    samples_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "docker", "run", "-i", "--rm",
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
        "-e", f"RE_PROJECT_ROOT={norm_proj}",
        "-v", f"{samples_dir}:/workspace/samples:ro",
        "-v", f"{output_dir}:/workspace/output:rw",
        "-v", f"{norm_proj}:/workspace/project:rw",
    ]
    local_server = repo_root / "re_mcp_server.py"
    if local_server.is_file():
        cmd.extend(["-v", f"{local_server}:/opt/re-mcp/re_mcp_server.py:ro"])
    cmd.extend([image_name, "re-mcp-server"])

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if init_request_line:
        proc.stdin.write(init_request_line + "\n")
        proc.stdin.flush()
        _ = proc.stdout.readline()
        proc.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        proc.stdin.flush()

    workers[norm_proj] = proc
    return proc

try:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        method = msg.get("method", "")
        has_id = "id" in msg

        if method == "initialize":
            init_request_line = line
            default_proj = get_open_workspaces()[0]
            w = get_worker(default_proj)
            init_request_line = line
            w.stdin.write(line + "\n")
            w.stdin.flush()
            resp = w.stdout.readline()
            if resp:
                sys.stdout.write(resp)
                sys.stdout.flush()
            continue

        if not has_id:
            if method == "notifications/initialized":
                for w in list(workers.values()):
                    if w.poll() is None:
                        w.stdin.write(line + "\n")
                        w.stdin.flush()
            continue

        if method == "tools/call":
            target_proj, rewritten = resolve_tool_call(msg)
            w = get_worker(target_proj)
            w.stdin.write(rewritten + "\n")
            w.stdin.flush()
            resp = w.stdout.readline()
            if resp:
                sys.stdout.write(resp)
                sys.stdout.flush()
        else:
            default_proj = get_open_workspaces()[0]
            w = get_worker(default_proj)
            w.stdin.write(line + "\n")
            w.stdin.flush()
            resp = w.stdout.readline()
            if resp:
                sys.stdout.write(resp)
                sys.stdout.flush()
finally:
    for w in workers.values():
        try:
            if w.poll() is None:
                w.stdin.close()
                w.terminate()
        except Exception:
            pass
PYEOF
fi
