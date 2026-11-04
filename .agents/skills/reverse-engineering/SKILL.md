---
name: reverse-engineering
description: >-
  Reverse-engineer native PE/ELF/Mach-O binaries, Motorola DSP56300 firmware/ROMs,
  C++ RTTI/VTables, .NET assemblies, Android APKs, PyInstaller/Python bytecode,
  Go binaries, WebAssembly, and Electron ASAR archives using the containerized redo MCP server.
---

# Reverse Engineering Workflow (`redo`)

Use the `redo` MCP server whenever analyzing compiled binaries, DSP firmware, or packed archives.

## 1. Per-Project Path Handling
- Pass the relative path inside the active project (e.g. `samples/target.exe`) or full path inside the active workspace directly to the MCP tools.
- All extracted files, decompilations, DSP assembly listings, algorithm skeletons, and cached Ghidra projects are automatically written to `<project>/output/`.

## 2. Recommended Analysis Sequence
1. **Triage, Section Offsets & VA->File-Offset Resolution**:
   - Call `file_triage` and `diec_detect` to identify file format, compiler, linker, protector/packer (UPX, VMProtect, Themida), and section entropy.
   - Call `pe_elf_headers` for section VAs, RVAs, raw file offsets (`PointerToRawData` / `sh_offset`), Shannon entropy, exports, TLS callbacks, and PE resource directories. Pass `lookup_va="0x870b50, 0x8714e0"` to resolve one or more VAs/RVAs directly to their raw file offsets.
   - Call `yara_scan` (`ruleset="all_die"`, `"peid"`, `"packer"`, or `"crypto"`) to scan for packer or cryptographic signatures.
2. **C++ & Native Binary Analysis + Raw Firmware (`ppc`, `arm`, `mips`, `m68k`) + Algorithm Skeletons**:
   - Call `cpp_rtti_and_vtables` to reconstruct MSVC/Itanium class inheritance hierarchies and VTable virtual addresses.
   - Call `r2_disassemble_function`, `r2_decompile_function`, or `ghidra_decompile_function` (use `fast_mode=True` on >5MB binaries for rapid single-function decompilation) on target exports or VTable method addresses.
   - For headerless raw `.bin`/`.rom` firmware blobs (e.g. 32-bit Big-Endian PowerPC `ppc_be`, ARM, MIPS, m68k, Tricore):
     - Pass `arch="ppc", bits=32, big_endian=True` (and optional `base_addr="0x..."`) to `r2_list_functions`, `r2_disassemble_function` (pass `num_instructions=64` for linear disassembly), `r2_decompile_function`, `r2_xrefs`, `r2_callgraph`, or `generate_algorithm_skeleton`.
     - Pass `processor="PowerPC:BE:32:default"` (and optional `base_address="0x..."`) to `ghidra_decompile_function`, `ghidra_list_functions`, or `ghidra_decompile_all` for full Ghidra C decompilation of raw firmware.
   - Call `generate_algorithm_skeleton` (`target_language="python"` or `"csharp"`, optional `table_vas="0x870b50:256, 0x8714e0:72"`) to extract a function's Control Flow Graph (`agfj`), pseudocode (`pdc`), immediate constants, and referenced `.rdata`/`.data` lookup tables into a runnable `.py` or `.cs` implementation skeleton in `<project>/output/`.
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
5. **Binary Hex Inspection, Conversion & CyberChef-Style Crypto Transforms**:
   - Call `binary_hex_dump` to inspect raw binary windows by `[byte_offset, byte_length]` or `[virtual_address, byte_length]` (e.g. `virtual_address="0x870b50"`) as `canonical` hex+ASCII, `u24be` 24-bit DSP words, `u32le`/`u32be`, `spaced`, `raw`, or `c_array`, or to locate byte sequences with `search_hex_pattern` (e.g. `"F0 43 ?? 00"`).
   - Call `binary_hex_convert` (`binhexconv` / `bin2hext`) to convert binary/SysEx/ROM files or VA slices to hexadecimal text in `<project>/output/` (`direction="bin_to_hex"`) and convert hex text back into binary (`direction="hex_to_bin"`).
   - Call `crypto_and_data_transform` to decrypt, encrypt, decompress, or word-swap binary data directly from `input_hex` or `file_path` + `virtual_address`/`byte_offset`:
     - Supports `"blowfish"`, `"blowfish_custom_boxes"` (loads custom 18-entry P-box and 4x256 S-boxes directly from `pbox_va`/`pbox_offset` and `sbox_va`/`sbox_offset` with configurable `box_endian="le"|"be"` and `block_endian="le"|"be"`), `"rc4"`, `"aes"`, `"des"`, `"3des"`, `"chacha20"`, `"xor"`, `"zlib"`, `"raw_deflate"`, `"lzma"`, `"swap32"`, `"swap16"`, and `"hashes"`.
