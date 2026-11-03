# RE Sandbox Plugin (`re-sandbox`)

Containerized Reverse Engineering, Binary/Hex Conversion & DSP Analysis MCP plugin for Antigravity.

## Features
- **Automatic Per-Project Folder Mapping**: Uses `hooks.json` (`sync_workspace.ps1`) to automatically mount only the active project's folders (`<Project>/samples`, `<Project>/output`, `<Project>`) into the container and route all outputs and Ghidra caches to `<Project>/output/`.
- **50 Specialized Tools**: Covers native PE/ELF/Mach-O (Radare2, Ghidra 12.2 Headless, Detect-It-Easy, capa, FLOSS, YARA, C++ RTTI/VTables), Binary/Hex inspection & conversion (`binary_hex_dump`, `binary_hex_convert` / `binhexconv`), Motorola DSP56300 (`dsp56300-disasm` / `dsp56300-asm`), .NET (`ilspycmd`), Android (`jadx`, `apktool`), Python (`pyinstxtractor-ng`, `pycdc`), Go (`GoReSym`), WebAssembly (`wabt`), Electron (`asar`, `synchrony`), and dynamic tracing (`gdb`, `lldb`, `strace`, `ltrace`, `qemu-user`).
- **Toggleable**: Enable or disable anytime from the Antigravity Plugins page (`customization://re-sandbox`) so non-RE projects stay lightweight.
