---
name: reverse-engineering
description: >-
  Reverse-engineer native PE/ELF/Mach-O binaries, Motorola DSP56300 firmware/ROMs,
  C++ RTTI/VTables, .NET assemblies, Android APKs, PyInstaller/Python bytecode,
  Go binaries, WebAssembly, and Electron ASAR archives using the containerized re-sandbox-tools MCP server.
---

# Reverse Engineering Workflow (`re-sandbox-tools`)

Use the `re-sandbox-tools` MCP server whenever analyzing compiled binaries, DSP firmware, or packed archives.

## 1. Multi-Project Path Handling
- Pass the full path of any file in the current workspace (e.g. `C:/CODE/MyProject/samples/target.exe`) directly to the MCP tools.
- All extracted files, decompilations, DSP assembly listings, and cached Ghidra projects are automatically written to `<project>/output/`.

## 2. Recommended Analysis Sequence
1. **Triage & Packer Detection**:
   - Call `file_triage` and `diec_detect` to identify file format, compiler, linker, protector/packer (UPX, VMProtect, Themida), and section entropy.
   - Call `pe_elf_headers` for section Shannon entropy, exports, TLS callbacks, and PE resource directories.
   - Call `yara_scan` (`ruleset="all_die"`, `"peid"`, `"packer"`, or `"crypto"`) to scan for packer or cryptographic signatures.
2. **C++ & Native Binary Analysis**:
   - Call `cpp_rtti_and_vtables` to reconstruct MSVC/Itanium class inheritance hierarchies and VTable virtual addresses.
   - Call `r2_disassemble_function` or `ghidra_decompile_function` (use `fast_mode=True` on >5MB binaries for rapid single-function decompilation) on target exports or VTable method addresses.
3. **Motorola DSP56300 Firmware & DSP Analysis**:
   - Call `dsp56300_disassemble` to decode 24-bit Motorola DSP56300 program words into readable assembly (`dsp56300-disasm`).
   - Choose `word_format`:
     - `"u24be"` (default): 3 bytes/word, big-endian (native DSP56300 ROM order).
     - `"u24le"`: 3 bytes/word, little-endian.
     - `"u32le"`: 4 bytes/word, little-endian padded.
     - `"u32be"`: 4 bytes/word, big-endian padded.
     - `"u24be_swap16"`: 16-bit byte-swapped EPROM image.
   - Use `byte_offset` and `byte_length` when DSP56300 code is embedded inside a larger host binary or firmware file, and `save_output=True` to persist the full `.asm` file in `<project>/output/` for `search_workspace_files`.
   - Call `dsp56300_assemble` (`dsp56300-asm`) to assemble `.asm` files or inline DSP56300 instructions into binary or `.lod` format.
4. **Managed / Bytecode / Archive Targets**:
   - **.NET / C#**: `dotnet_list_types`, `dotnet_decompile`
   - **Android / JVM**: `jadx_extract_manifest`, `jadx_list_classes`, `jadx_decompile_class`, `apktool_decode`
   - **Python**: `pyinstaller_extract_and_decompile`, `pyc_decompile`
   - **Go**: `go_extract_symbols`
   - **WebAssembly**: `wasm_decompile`
   - **Electron / JS**: `asar_list`, `asar_extract`, `js_deobfuscate`, `js_beautify_file`
5. **Binary Hex Inspection & Conversion (`BinHexConv`)**:
   - Call `binary_hex_dump` to inspect raw binary windows (`[byte_offset, byte_length]`) as `canonical` hex+ASCII, `u24be` 24-bit DSP words, `spaced`, `raw`, or `c_array`, or to locate byte sequences with `search_hex_pattern` (e.g. `"F0 43 ?? 00"`).
   - Call `binary_hex_convert` (`binhexconv` / `bin2hext`) to convert binary/SysEx/ROM files to hexadecimal text in `<project>/output/` (`direction="bin_to_hex"`) and convert hex text back into binary (`direction="hex_to_bin"`).
