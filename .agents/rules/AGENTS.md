# Reverse Engineering Sandbox Rules

When the `re-sandbox` plugin is enabled and the user asks to inspect, triage, disassemble, or decompile binaries, installers, archives, or Motorola DSP56300 ROMs (`.exe`, `.dll`, `.so`, `.dylib`, `.bin`, `.rom`, `.lod`, `.apk`, `.pyc`, `.wasm`, `.asar`):

- Pass the full Windows path of the target file in the current workspace (e.g. `C:/CODE/<project>/samples/<file>`) directly to the `re-sandbox-tools` MCP tools. The MCP server automatically translates host paths into container paths and routes generated artifacts/decompilations into `<project>/output/`.
- For native PE/ELF/Mach-O or object-oriented C++ binaries, run `file_triage`, `pe_elf_headers`, and `cpp_rtti_and_vtables` before decompiling individual functions or vtable methods with `ghidra_decompile_function` (`fast_mode=True` for large binaries) or `r2_disassemble_function`.
- For Motorola DSP56300 ROM dumps, firmware, or embedded 24-bit DSP code blocks, use `dsp56300_disassemble` (specifying `word_format="u24be"`, `"u24le"`, `"u32le"`, `"u32be"`, or `"u24be_swap16"`, and optional `byte_offset`/`byte_length` when slicing from a larger binary).
