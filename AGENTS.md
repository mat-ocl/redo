# AI Agent Instructions (`RE-Sandbox`)

This repository provides a hardened, containerized **Reverse Engineering & Binary/DSP Analysis Sandbox** (`re-sandbox:latest`) paired with a **FastMCP Server** (`re_mcp_server.py`) exposing 48 specialized tools over `stdio`.

---

## 0. Autonomous AI Agent Installation (Zero-Clone Mode — No `git clone` Required)

If a user gives you a link to this GitHub repository and asks you to install or set up `re-sandbox` **without cloning the repository to disk**, follow these exact steps. Because `re_mcp_server.py` is baked directly into `/opt/re-mcp/re_mcp_server.py` (with an unbuffered wrapper at `/usr/local/bin/re-mcp-server`) inside the Docker image, **no local repository clone or helper scripts on disk are required**.

### Step 1: Build the Docker Image Directly from GitHub
Run `docker build` using the remote GitHub repository URL as the build context:

```bash
docker build --target final -t re-sandbox:latest https://github.com/mat-ocl/redo.git
```

### Step 2: Register the MCP Server in Zero-Clone Mode
Choose the user's active IDE / MCP client and write the corresponding configuration using `docker run` directly. Mount the user's root projects directory (e.g. `C:/CODE` on Windows or `$HOME/code` on Linux/macOS) to `/workspace/host_code:rw` and set `RE_HOST_CODE_ROOT` to match:

#### Option A: Zed Editor (`%APPDATA%\Zed\settings.json` on Windows, `~/.config/zed/settings.json` on Linux/macOS)
Merge the following `"re-sandbox"` entry into the `"context_servers"` object in Zed's `settings.json`:

```json
{
  "context_servers": {
    "re-sandbox": {
      "source": "custom",
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
        "-e", "RE_HOST_CODE_ROOT=C:/CODE",
        "-v", "C:/CODE:/workspace/host_code:rw",
        "re-sandbox:latest",
        "re-mcp-server"
      ],
      "env": {}
    }
  }
}
```
*(Note: On Windows, if Zed's environment `PATH` does not include Docker, set `"command"` to `"C:/Program Files/Docker/Docker/resources/bin/docker.exe"`).*

#### Option B: Google Antigravity (`~/.gemini/config/plugins/re-sandbox/mcp_config.json`) / Claude Desktop / Cursor / Windsurf
Write the following JSON to the MCP configuration file (and for Antigravity, also copy `plugin/re-sandbox/plugin.json`, `rules/AGENTS.md`, and `skills/reverse-engineering/SKILL.md` into `~/.gemini/config/plugins/re-sandbox/`):

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
        "-e", "RE_HOST_CODE_ROOT=C:/CODE",
        "-v", "C:/CODE:/workspace/host_code:rw",
        "re-sandbox:latest",
        "re-mcp-server"
      ]
    }
  }
}
```

---

## 1. Repository Architecture

- **`Dockerfile`**: 4-stage Ubuntu 24.04 build:
  1. `downloader`: Fetches Ghidra Headless (`11.2`), JADX (`1.5.0`), Apktool (`2.10.0`), Mandiant `capa` (`8.0.1`) + rules, Mandiant `GoReSym` (`3.0.1`), Detect-It-Easy CLI (`diec` `3.21`), and Community YARA rules.
  2. `cpp-builder`: Compiles Radare2 (`/opt/radare2`), Decompyle++ (`pycdc` / `pycdas` in `/opt/pycdc`), and the **Motorola DSP56300** toolchain (`dsp56300-disasm` & `dsp56300-asm` from `xemu-project/dsp56300` in `/opt/dsp56300/bin`).
  3. `python-builder`: Creates `/opt/re-venv` with `mcp[cli]`, `flare-floss`, `frida-tools`, `pyinstxtractor-ng`, `lief`, `pefile`, `pyelftools`, `r2pipe`, `yara-python`, and `capstone`.
  4. `final`: Hardened runtime image with Java 21, .NET 8 SDK (`ilspycmd`), Node.js 22 (`asar`, `synchrony`, `deobfuscator`, `js-beautify`, `rea`), WABT/Binaryen (`wasm-decompile`, `wasm2wat`), `binwalk`, `upx`, `7z`, `innoextract`, `unsquashfs`, `gdb-multiarch`, `lldb`, `strace`, `ltrace`, and `qemu-user`.
- **`compose.yml`**: Defines two security-hardened profiles:
  - `static` (`re-static`): Air-gapped (`network_mode: none`), `read_only: true` root filesystem, `cap_drop: ALL`.
  - `dynamic` (`re-dynamic`): Isolated internal bridge network, `SYS_PTRACE` enabled for `gdb`, `strace`, `ltrace`, and `qemu-user`.
- **`re_mcp_server.py`**: FastMCP server mounted read-only at `/opt/re-mcp/re_mcp_server.py` (so edits to `re_mcp_server.py` on the host take effect immediately without rebuilding the Docker image).
- **`run_re_mcp.ps1` / `run_re_mcp.sh`**: Portable host launchers that start an ephemeral container and connect MCP `stdio`.

---

## 2. Mandatory Agent Workflow & Tool Selection Rules

When asked to inspect, triage, disassemble, or decompile binaries, installers, firmware, or DSP ROMs:

### A. Path Resolution & Output Routing
- Pass the full host path (e.g. `C:/CODE/<project>/samples/<file>`) or relative workspace path (`samples/<file>`) directly to the `re-sandbox-tools` MCP tools.
- `_translate_host_path()` automatically maps host paths into `/workspace/host_code/...` or `/workspace/samples/...`, and `_get_output_dir()` routes all decompilations, extracted archives, and Ghidra project caches into `<project>/output/`.
- **Never** commit target binaries, proprietary samples, or generated outputs into git. Keep inputs in `samples/` and outputs in `output/`.

### B. Initial Triage (Always Run First)
1. Call `file_triage` to determine file magic, hashes, overall Shannon entropy, UPX status, Detect-It-Easy (`diec`) summary, and ecosystem heuristics.
2. For native PE/ELF/Mach-O binaries, call `pe_elf_headers` and `diec_detect` to inspect section-level Shannon entropy, exports, imports, TLS callbacks, and compiler/packer signatures.

### C. Object-Oriented C++ & Native Binaries (`.exe`, `.dll`, `.so`, `.dylib`)
1. Call `cpp_rtti_and_vtables` to recover MSVC/Itanium C++ class inheritance hierarchies and VTable virtual addresses.
2. For individual functions or VTable methods:
   - Use `r2_disassemble_function` (fast targeted `af @ <addr>; pdf @ <addr>`) for immediate assembly inspection (<2 seconds even on 20MB+ binaries).
   - Use `ghidra_decompile_function` with `fast_mode=True` on large (>5MB) binaries to skip full-program auto-analysis and decompile the target function into C pseudocode in ~5-8 seconds.

### D. Motorola DSP56300 Firmware & DSP Analysis
1. Use `dsp56300_disassemble` (powered by `dsp56300-disasm`) to disassemble 24-bit Motorola DSP56300 program memory:
   - Use `word_format="u24be"` (default) for native 3-byte big-endian DSP ROM dumps.
   - Use `word_format="u24le"` for 3-byte little-endian dumps, `"u32le"` for 4-byte little-endian words, `"u32be"` for 4-byte big-endian words, or `"u24be_swap16"` for 16-bit byte-swapped EPROM dumps.
   - If the DSP56300 code is embedded inside a larger host binary or monolithic firmware image, pass `byte_offset` and `byte_length` to slice and disassemble the exact region without manual file carving.
   - Pass `save_output=True` to write the full `.asm` listing to `output/` for regex searching with `search_workspace_files`.
2. Use `dsp56300_assemble` (powered by `dsp56300-asm`) to assemble DSP56300 assembly code into binary or `.lod` format when testing or verifying DSP algorithms.
3. For control-flow / decompiler analysis in Ghidra, `ghidra_headless_analyze` also supports `processor="DSP56300:BE:24:default"`.
