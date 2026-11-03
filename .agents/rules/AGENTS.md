# Reverse Engineering Sandbox Rules

When the `re-sandbox` plugin is enabled and the user asks to inspect, triage, disassemble, or decompile binaries, installers, archives, or Motorola DSP56300 ROMs (`.exe`, `.dll`, `.so`, `.dylib`, `.bin`, `.rom`, `.lod`, `.apk`, `.pyc`, `.wasm`, `.asar`):

- Pass the relative path inside the active project (e.g. `samples/<file>`) or full path inside the active workspace directly to the `re-sandbox-tools` MCP tools. The MCP server automatically maps the active project's folders into the container and routes generated artifacts/decompilations into `<project>/output/`.
- For native PE/ELF/Mach-O or object-oriented C++ binaries, run `file_triage`, `pe_elf_headers`, and `cpp_rtti_and_vtables` before decompiling individual functions or vtable methods with `ghidra_decompile_function` (`fast_mode=True` for large binaries) or `r2_disassemble_function`.
- For Motorola DSP56300 ROM dumps, firmware, or embedded 24-bit DSP code blocks, use `dsp56300_disassemble` (specifying `word_format="u24be"`, `"u24le"`, `"u32le"`, `"u32be"`, or `"u24be_swap16"`, and optional `byte_offset`/`byte_length` when slicing from a larger binary).
- To inspect raw binary data, SysEx (`.syx`) dumps, headers, or ROM lookup tables as hexadecimal text—or convert binary files to/from hex text—use `binary_hex_dump` (supports `search_hex_pattern` with `??` wildcards, `canonical`, and `u24be`) and `binary_hex_convert` (`bin2hext`) instead of `read_workspace_file`.
