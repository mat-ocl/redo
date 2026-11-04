# redo Workspace Plugin (`redo`)

Per-project containerized Reverse Engineering, Binary/Hex Conversion & DSP Analysis MCP plugin (`<Project>/.agents/plugins/redo/`).

## Features
- **Strictly Per-Project Isolation**: Installed directly inside `<Project>/.agents/plugins/redo/`, mounting only that project's folders (`<Project>/samples`, `<Project>/output`, `<Project>`) into an air-gapped container and routing all outputs and Ghidra caches to `<Project>/output/`.
- **50 Specialized Tools**: Covers native PE/ELF/Mach-O (Radare2, Ghidra 12.2 Headless, Detect-It-Easy, capa, FLOSS, YARA, C++ RTTI/VTables), Binary/Hex inspection & conversion (`binary_hex_dump`, `binary_hex_convert` / `binhexconv`), Motorola DSP56300 (`dsp56300-disasm` / `dsp56300-asm`), .NET (`ilspycmd`), Android (`jadx`, `apktool`), Python (`pyinstxtractor-ng`, `pycdc`), Go (`GoReSym`), WebAssembly (`wabt`), Electron (`asar`, `synchrony`), and dynamic tracing (`gdb`, `lldb`, `strace`, `ltrace`, `qemu-user`).
- **Multi-Editor Workspace Support**: Works out of the box with Google Antigravity (`.agents/plugins/redo/`), Zed Editor (`.zed/settings.json`), Cursor (`.cursor/mcp.json`), Claude Code (`.mcp.json`), and VS Code (`.vscode/mcp.json`).
