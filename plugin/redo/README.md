# redo Plugin (`redo`)

Containerized Reverse Engineering, Binary/Hex Conversion & DSP Analysis MCP plugin for Antigravity.

## Features
- **Per-Project Container Isolation**: Uses `hooks.json` (`sync_workspace.ps1`) and `run_re_mcp.ps1` to spawn an isolated container per project, mounting only that project's folders (`<Project>/samples`, `<Project>/output`, `<Project>`) and routing all outputs and Ghidra caches to `<Project>/output/`.
- **50 Specialized Tools**: Covers native PE/ELF/Mach-O (Radare2, Ghidra 12.2 Headless, Detect-It-Easy, capa, FLOSS, YARA, C++ RTTI/VTables), Binary/Hex inspection & conversion (`binary_hex_dump`, `binary_hex_convert` / `binhexconv`), Motorola DSP56300 (`dsp56300-disasm` / `dsp56300-asm`), .NET (`ilspycmd`), Android (`jadx`, `apktool`), Python (`pyinstxtractor-ng`, `pycdc`), Go (`GoReSym`), WebAssembly (`wabt`), Electron (`asar`, `synchrony`), and dynamic tracing (`gdb`, `lldb`, `strace`, `ltrace`, `qemu-user`).
- **Toggleable**: Enable or disable anytime from the Antigravity Plugins page (`customization://redo`) so non-RE projects stay lightweight.
