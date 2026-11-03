# RE Sandbox Plugin (`re-sandbox`)

Containerized Reverse Engineering & DSP Analysis MCP plugin for Antigravity.

## Features
- **Multi-Project Support**: Automatically maps `C:\CODE\<project>\samples` (or `RE_HOST_CODE_DIR`) and writes outputs, DSP disassemblies, and Ghidra caches to `C:\CODE\<project>\output`.
- **48 Specialized Tools**: Covers native PE/ELF/Mach-O (Radare2, Ghidra 11.2 Headless, Detect-It-Easy, capa, FLOSS, YARA, C++ RTTI/VTables), Motorola DSP56300 (`dsp56300-disasm` / `dsp56300-asm`), .NET (`ilspycmd`), Android (`jadx`, `apktool`), Python (`pyinstxtractor-ng`, `pycdc`), Go (`GoReSym`), WebAssembly (`wabt`), Electron (`asar`, `synchrony`), and dynamic tracing (`gdb`, `lldb`, `strace`, `ltrace`, `qemu-user`).
- **Toggleable**: Enable or disable anytime from the Antigravity Plugins page (`customization://re-sandbox`) so non-RE projects stay lightweight.
