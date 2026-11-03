#!/opt/re-venv/bin/python3
"""
Universal FastMCP Server for Containerized Reverse Engineering & Binary/DSP Analysis.
Exposes Native (Radare2, Ghidra Headless with persistent project cache, Detect-It-Easy CLI,
capa, FLOSS, LIEF/pefile/pyelftools, C++ RTTI/VTables, Motorola DSP56300 disassembler/assembler,
YARA scanner, GDB/LLDB headless batch), Android/JVM (JADX, Apktool), .NET/C# (ilspycmd),
Python (pyinstxtractor-ng, pycdc), Go (GoReSym), WebAssembly (wabt, binaryen),
Electron/JS (asar, synchrony, deobfuscator, rea), Archive/Firmware (7z, binwalk,
innoextract, unsquashfs, upx), and Dynamic Tracing (strace, ltrace, qemu-user) as MCP tools.
"""

import base64
from collections import Counter
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from mcp.server.mcpserver import MCPServer

# Ensure /opt/radare2/lib is always on LD_LIBRARY_PATH for r2 and rabin2
_r2_lib = "/opt/radare2/lib"
if os.path.isdir(_r2_lib) and _r2_lib not in os.environ.get("LD_LIBRARY_PATH", ""):
    os.environ["LD_LIBRARY_PATH"] = (
        f"{_r2_lib}:{os.environ['LD_LIBRARY_PATH']}"
        if os.environ.get("LD_LIBRARY_PATH")
        else _r2_lib
    )

# Ensure /opt/dsp56300/bin is on PATH if present
_dsp_bin = "/opt/dsp56300/bin"
if os.path.isdir(_dsp_bin) and _dsp_bin not in os.environ.get("PATH", ""):
    os.environ["PATH"] = f"{_dsp_bin}:{os.environ.get('PATH', '')}"

# Initialize the MCP server
mcp = MCPServer("RE-Sandbox-Tools")

WORKSPACE_DIR = Path("/workspace").resolve()
SAMPLES_DIR = (WORKSPACE_DIR / "samples").resolve()
OUTPUT_DIR = (WORKSPACE_DIR / "output").resolve()
HOST_CODE_DIR = (WORKSPACE_DIR / "host_code").resolve()
GHIDRA_CACHE_DIR = (OUTPUT_DIR / "ghidra_cache").resolve()
TMP_DIR = Path("/tmp").resolve()

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
GHIDRA_CACHE_DIR.mkdir(parents=True, exist_ok=True)

_SAFE_R2_TARGET_RE = re.compile(r"^[a-zA-Z0-9_.:+-]+$")
_SAFE_HEX_OR_INT_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)$")

# =====================================================================
# Embedded Ghidra Headless Java Scripts (Ghidra 11.x native OSGi)
# =====================================================================

_GHIDRA_DECOMPILE_TARGET_JAVA = r"""
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileTarget extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: Missing target function name or address argument.");
            return;
        }
        String target = args[0].trim();
        Function found = null;

        // Try matching by address first (e.g. 0x18013f460 or 18013f460 or sub_18013f460)
        String cleanHex = target;
        if (cleanHex.startsWith("sub_") || cleanHex.startsWith("fcn.")) {
            cleanHex = cleanHex.substring(4);
        }
        if (cleanHex.startsWith("0x") || cleanHex.startsWith("0X")) {
            cleanHex = cleanHex.substring(2);
        }
        if (cleanHex.matches("^[0-9a-fA-F]{4,16}$")) {
            try {
                Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(cleanHex);
                if (addr != null) {
                    found = getFunctionContaining(addr);
                    if (found == null) {
                        disassemble(addr);
                        found = createFunction(addr, null);
                        if (found == null) {
                            found = getFunctionContaining(addr);
                        }
                    }
                }
            } catch (Exception ignored) {}
        }

        // Try matching by exact function name
        if (found == null) {
            FunctionIterator it = currentProgram.getListing().getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                String name = f.getName();
                String fullName = f.getName(true);
                if (name.equalsIgnoreCase(target)
                        || fullName.equalsIgnoreCase(target)
                        || ("sym." + name).equalsIgnoreCase(target)
                        || ("sub_" + f.getEntryPoint().toString()).equalsIgnoreCase(target)) {
                    found = f;
                    break;
                }
            }
        }

        // Fallback: substring match on function or namespace name
        if (found == null) {
            String lowerTarget = target.toLowerCase();
            FunctionIterator it = currentProgram.getListing().getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                if (f.getName(true).toLowerCase().contains(lowerTarget)) {
                    found = f;
                    break;
                }
            }
        }

        if (found == null) {
            println("ERROR: Function '" + target + "' not found in program.");
            return;
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        DecompileResults res = decomp.decompileFunction(found, 60, monitor);
        println("=== GHIDRA_DECOMP_START ===");
        println("// Function: " + found.getName(true) + " @ 0x" + found.getEntryPoint());
        if (res != null && res.decompileCompleted()) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("// Decompilation failed: " + (res != null ? res.getErrorMessage() : "unknown"));
        }
        println("=== GHIDRA_DECOMP_END ===");
        decomp.dispose();
    }
}
"""

_GHIDRA_LIST_FUNCTIONS_JAVA = r"""
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ListFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String filter = args.length > 0 ? args[0].toLowerCase() : "";
        int maxEntries = args.length > 1 ? Integer.parseInt(args[1]) : 250;

        println("=== GHIDRA_FUNCS_START ===");
        FunctionIterator it = currentProgram.getListing().getFunctions(true);
        int shown = 0;
        int total = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isThunk() || f.isExternal()) {
                continue;
            }
            String fullName = f.getName(true);
            String sig = f.getPrototypeString(false, false);
            if (!filter.isEmpty()
                    && !fullName.toLowerCase().contains(filter)
                    && !sig.toLowerCase().contains(filter)
                    && !f.getEntryPoint().toString().toLowerCase().contains(filter)) {
                continue;
            }
            total++;
            if (shown < maxEntries) {
                println(String.format("0x%s  size=%-6d  %s  [%s]",
                    f.getEntryPoint().toString(),
                    f.getBody().getNumAddresses(),
                    fullName,
                    sig));
                shown++;
            }
        }
        if (total > shown) {
            println(String.format("... [%d more matching functions omitted]", total - shown));
        }
        println("Total matching functions: " + total);
        println("=== GHIDRA_FUNCS_END ===");
    }
}
"""

_GHIDRA_DECOMPILE_ALL_JAVA = r"""
import java.io.File;
import java.io.PrintWriter;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: Missing output file path.");
            return;
        }
        File outFile = new File(args[0]);
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        int count = 0;
        try (PrintWriter out = new PrintWriter(outFile, "UTF-8")) {
            out.println("// Ghidra Headless Full Decompilation: " + currentProgram.getName());
            FunctionIterator it = currentProgram.getListing().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f.isThunk() || f.isExternal()) {
                    continue;
                }
                DecompileResults res = decomp.decompileFunction(f, 30, monitor);
                out.println("\n// =====================================================");
                out.println("// Function: " + f.getName(true) + " @ 0x" + f.getEntryPoint() + " (size: " + f.getBody().getNumAddresses() + ")");
                out.println("// =====================================================");
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    out.println(res.getDecompiledFunction().getC());
                    count++;
                } else {
                    out.println("// [Decompilation unavailable]");
                }
            }
        }
        decomp.dispose();
        println("=== GHIDRA_SUMMARY: Decompiled " + count + " functions to " + outFile.getAbsolutePath() + " ===");
    }
}
"""


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _translate_host_path(raw_path: str) -> Path:
    """
    Translate host paths (e.g. 'C:\\CODE\\MyProject\\samples\\target.exe', 'c:/CODE/...',
    or custom RE_HOST_CODE_ROOT paths) and relative project paths into container paths
    under /workspace/host_code or /workspace.
    """
    norm = raw_path.strip().replace("\\", "/")

    # 1. Check custom RE_HOST_CODE_ROOT environment variable if set
    custom_root = os.environ.get("RE_HOST_CODE_ROOT", "").strip().replace("\\", "/").rstrip("/")
    if custom_root and norm.lower().startswith(custom_root.lower()):
        rel_part = norm[len(custom_root):].strip("/")
        if HOST_CODE_DIR.exists():
            cand = (HOST_CODE_DIR / rel_part).resolve() if rel_part else HOST_CODE_DIR
            if cand.exists() or not SAMPLES_DIR.exists() or not any(SAMPLES_DIR.iterdir()):
                return cand

    # 2. Match standard Windows C:\CODE or /c/code paths
    m = re.match(r"^(?:[a-zA-Z]:|/c)/code(?:/(.*))?$", norm, re.IGNORECASE)
    if m:
        rel_part = (m.group(1) or "").strip("/")
        if HOST_CODE_DIR.exists():
            cand = (HOST_CODE_DIR / rel_part).resolve() if rel_part else HOST_CODE_DIR
            if cand.exists() or not SAMPLES_DIR.exists() or not any(SAMPLES_DIR.iterdir()):
                return cand
        # Fallback when running without /workspace/host_code mounted
        if "/samples/" in f"/{rel_part}":
            after_samples = rel_part.split("samples/", 1)[1]
            return (SAMPLES_DIR / after_samples).resolve()
        if "/output/" in f"/{rel_part}":
            after_output = rel_part.split("output/", 1)[1]
            return (OUTPUT_DIR / after_output).resolve()

    if not norm.startswith("/"):
        cand = (WORKSPACE_DIR / norm).resolve()
        if cand.exists():
            return cand
        sample_cand = (SAMPLES_DIR / norm).resolve()
        if sample_cand.exists():
            return sample_cand
        return cand

    return Path(norm).resolve()


def _get_output_dir(target: Optional[Path] = None) -> Path:
    """
    Determine the appropriate 'output/' directory for the given target file.
    If the target resides inside a project under /workspace/host_code/<project>,
    routes output into that project's own '<project>/output' directory.
    Otherwise defaults to /workspace/output.
    """
    if target is not None and _is_within(target, HOST_CODE_DIR):
        anc = target if target.is_dir() else target.parent
        proj_root = None
        curr = anc
        while curr != HOST_CODE_DIR and _is_within(curr, HOST_CODE_DIR):
            if curr.name.lower() in {"samples", "output"} and curr.parent != HOST_CODE_DIR:
                proj_root = curr.parent
                break
            if (
                (curr / "samples").is_dir()
                or (curr / "output").is_dir()
                or (curr / ".git").exists()
                or (curr / ".agents").exists()
            ):
                proj_root = curr
                break
            curr = curr.parent

        if proj_root is None:
            rel_parts = anc.relative_to(HOST_CODE_DIR).parts
            proj_root = (HOST_CODE_DIR / rel_parts[0]) if rel_parts else HOST_CODE_DIR

        proj_out = (proj_root / "output").resolve()
        if _is_within(proj_out, HOST_CODE_DIR):
            try:
                proj_out.mkdir(parents=True, exist_ok=True)
                return proj_out
            except OSError:
                pass

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR


def _validate_path(file_path: str) -> Path:
    """
    Validate that the target path exists and stays within allowed workspace/tmp boundaries.
    Automatically translates host paths (e.g. C:\\CODE\\...).
    """
    target = _translate_host_path(file_path)
    if not (_is_within(target, WORKSPACE_DIR) or _is_within(target, TMP_DIR)):
        raise ValueError(
            f"Access denied: '{file_path}' resolves outside allowed directories ({WORKSPACE_DIR}, {TMP_DIR})."
        )
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {file_path} (resolved to {target})")
    return target


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _safe_filename(name: str) -> str:
    """Sanitize a filename to prevent directory traversal."""
    clean = Path(name).name
    if not clean or clean in {".", ".."}:
        raise ValueError(f"Invalid filename: {name}")
    return clean


def _get_staging_dir(project_dir: Optional[str] = None) -> Path:
    """
    Return a writable staging directory for the target project (or default workspace).
    """
    if project_dir:
        proj_path = _translate_host_path(project_dir)
        out_dir = _get_output_dir(proj_path) / "staged"
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir
    if SAMPLES_DIR.exists() and os.access(SAMPLES_DIR, os.W_OK):
        return SAMPLES_DIR
    fallback = OUTPUT_DIR / "staged"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def _require_tool(binary_name: str) -> str:
    """Verify that a CLI tool exists on PATH and return its resolved path."""
    resolved = shutil.which(binary_name)
    if not resolved:
        raise RuntimeError(
            f"Tool '{binary_name}' is not installed in the current container image. "
            "Rebuild the Docker image (`docker compose --profile static build`) to enable this tool."
        )
    return resolved


# =====================================================================
# Workspace & Staging Tools
# =====================================================================

@mcp.tool()
def list_workspace_files(subdir: str = "") -> str:
    """
    List files available in the active project or /workspace.
    `subdir` can be a relative subdirectory (e.g. 'samples' or 'output') OR a host project
    path (e.g. 'C:/CODE/MyProject' or 'C:/CODE/MyProject/samples').
    """
    base = _translate_host_path(subdir) if subdir else WORKSPACE_DIR
    if not _is_within(base, WORKSPACE_DIR):
        raise ValueError("Directory must remain within /workspace.")
    if not base.exists():
        return f"Directory does not exist: {base}"

    entries = []
    for p in sorted(base.rglob("*")):
        if len(entries) >= 500:
            entries.append("... [truncated at 500 entries]")
            break
        rel = p.relative_to(WORKSPACE_DIR)
        kind = "DIR " if p.is_dir() else f"FILE ({p.stat().st_size} B)"
        entries.append(f"{kind}: /workspace/{rel}")
    return "\n".join(entries) if entries else f"No files found in {base}"


@mcp.tool()
def read_workspace_file(file_path: str, start_line: int = 1, max_lines: int = 250) -> str:
    """
    Read lines from a text file (e.g. decompiled C/Java/C#/Python source, DSP56300 assembly,
    manifest, JS) in /workspace, a host C:\\CODE\\... project path, or /tmp with line numbers.
    """
    target = _validate_path(file_path)
    if target.is_dir():
        raise ValueError(f"Target path is a directory, not a file: {target}")
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    total = len(lines)
    start_idx = max(0, start_line - 1)
    end_idx = min(total, start_idx + max_lines)
    numbered = [f"{i + 1}: {lines[i]}" for i in range(start_idx, end_idx)]
    header = f"// File: {target} (showing lines {start_idx + 1}-{end_idx} of {total})\n"
    return header + "\n".join(numbered)


@mcp.tool()
def search_workspace_files(
    regex_pattern: str,
    subdir: str = "output",
    file_glob: str = "*",
    max_matches: int = 100
) -> str:
    """
    Search across decompiled or extracted text files in `subdir` (can be 'output' or a
    host project output path like 'C:/CODE/MyProject/output') using a regex.
    """
    base = _translate_host_path(subdir) if subdir else WORKSPACE_DIR
    if not _is_within(base, WORKSPACE_DIR):
        raise ValueError("Subdirectory must remain within /workspace.")
    if not base.exists():
        return f"Directory does not exist: {base}"

    pattern = re.compile(regex_pattern, re.IGNORECASE)
    matches = []
    for fpath in sorted(base.rglob(file_glob)):
        if not fpath.is_file() or fpath.stat().st_size > 25 * 1024 * 1024:
            continue
        try:
            text = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                matches.append(f"{fpath}:{lineno}: {line.strip()[:200]}")
                if len(matches) >= max_matches:
                    matches.append(f"... [truncated at {max_matches} matches]")
                    return "\n".join(matches)
    return "\n".join(matches) if matches else f"No matches found for '{regex_pattern}' in {base}"


@mcp.tool()
def stage_file_from_base64(
    filename: str,
    b64_content: str,
    project_dir: Optional[str] = None
) -> str:
    """
    Directly ingest and write a binary or archive into the workspace over the MCP connection
    using Base64. Optionally pass `project_dir` (e.g. 'C:/CODE/MyProject') to stage into that project.
    """
    staging_dir = _get_staging_dir(project_dir)
    dest_path = staging_dir / _safe_filename(filename)
    file_bytes = base64.b64decode(b64_content)
    dest_path.write_bytes(file_bytes)
    return f"Successfully staged {dest_path.name} ({len(file_bytes)} bytes) at {dest_path}"


@mcp.tool()
def stage_text_file(
    filename: str,
    text_content: str,
    project_dir: Optional[str] = None
) -> str:
    """
    Directly write a script (JS, Python, C, shell, DSP56300 assembly, YARA rule, Ghidra post-script)
    into the workspace for analysis. Optionally pass `project_dir` (e.g. 'C:/CODE/MyProject').
    """
    staging_dir = _get_staging_dir(project_dir)
    dest_path = staging_dir / _safe_filename(filename)
    dest_path.write_text(text_content, encoding="utf-8")
    return f"Successfully wrote text file to {dest_path}"


# =====================================================================
# Triage, DIE (Detect-It-Easy), Headers, YARA, Capabilities & Unpacking
# =====================================================================

def _demangle_msvc_type_name(raw_name: str) -> str:
    """Convert an MSVC RTTI TypeDescriptor name (e.g. .?AVMyClass@Namespace@@) into readable C++."""
    if raw_name.startswith("_Z"):
        cxxfilt = shutil.which("llvm-cxxfilt") or shutil.which("c++filt")
        if cxxfilt:
            res = subprocess.run([cxxfilt, raw_name], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        return raw_name

    s = raw_name
    if s.startswith(".?AV") or s.startswith(".?AU"):
        s = s[4:]
    else:
        return raw_name

    if s.endswith("@@"):
        s = s[:-2]

    parts = [p for p in s.split("@") if p and not p.startswith("?")]
    if not parts:
        return raw_name
    return "::".join(reversed(parts))


def _extract_pe_rtti_and_vtables(data: bytes, max_classes: int = 250, filter_pattern: str = "") -> dict:
    """
    Parse 64-bit and 32-bit MSVC RTTI TypeDescriptors, CompleteObjectLocators,
    ClassHierarchyDescriptors, and VTable virtual addresses from a PE binary.
    """
    import pefile

    pe = pefile.PE(data=data, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B

    td_rva_to_name = {}
    ptr_size = 8 if is_64 else 4
    name_offset_in_td = ptr_size * 2  # pVFTable + spare

    for m in re.finditer(rb"\.\?A[VU][A-Za-z0-9_@?$<>]+@@\x00", data):
        str_file_off = m.start()
        td_file_off = str_file_off - name_offset_in_td
        if td_file_off < 0:
            continue
        try:
            td_rva = pe.get_rva_from_offset(td_file_off)
        except Exception:
            continue
        raw_str = m.group(0)[:-1].decode("ascii", errors="replace")
        td_rva_to_name[td_rva] = _demangle_msvc_type_name(raw_str)

    col_rva_to_info = {}
    if is_64:
        for sec in pe.sections:
            sec_data = sec.get_data()
            sec_rva = sec.VirtualAddress
            for off in range(0, len(sec_data) - 24, 4):
                sig, v_off, cd_off, td_rva, chd_rva, self_rva = struct.unpack_from("<IIIIII", sec_data, off)
                cur_rva = sec_rva + off
                if sig == 1 and self_rva == cur_rva and td_rva in td_rva_to_name:
                    bases = []
                    try:
                        chd_off = pe.get_offset_from_rva(chd_rva)
                        if chd_off is not None and chd_off + 16 <= len(data):
                            _, chd_attr, num_bases, bca_rva = struct.unpack_from("<IIII", data, chd_off)
                            if 0 < num_bases <= 64:
                                bca_off = pe.get_offset_from_rva(bca_rva)
                                if bca_off is not None and bca_off + num_bases * 4 <= len(data):
                                    for b_idx in range(num_bases):
                                        bcd_rva = struct.unpack_from("<I", data, bca_off + b_idx * 4)[0]
                                        bcd_off = pe.get_offset_from_rva(bcd_rva)
                                        if bcd_off is not None and bcd_off + 4 <= len(data):
                                            b_td_rva = struct.unpack_from("<I", data, bcd_off)[0]
                                            b_name = td_rva_to_name.get(b_td_rva)
                                            if b_name and b_name not in bases:
                                                bases.append(b_name)
                    except Exception:
                        pass
                    col_rva_to_info[cur_rva] = {
                        "class_name": td_rva_to_name[td_rva],
                        "vtable_offset": v_off,
                        "bases": bases,
                        "col_vaddr": hex(image_base + cur_rva),
                        "vtables": [],
                    }

        col_va_to_rva = {image_base + rva: rva for rva in col_rva_to_info}
        for sec in pe.sections:
            sec_data = sec.get_data()
            sec_rva = sec.VirtualAddress
            for off in range(0, len(sec_data) - 16, 8):
                val = struct.unpack_from("<Q", sec_data, off)[0]
                if val in col_va_to_rva:
                    vtable_rva = sec_rva + off + 8
                    vtable_va = image_base + vtable_rva
                    first_fn = struct.unpack_from("<Q", sec_data, off + 8)[0]
                    col_rva_to_info[col_va_to_rva[val]]["vtables"].append({
                        "vtable_vaddr": hex(vtable_va),
                        "first_method_vaddr": hex(first_fn),
                    })

    rx = re.compile(filter_pattern, re.IGNORECASE) if filter_pattern else None
    hierarchy_entries = []
    for info in col_rva_to_info.values():
        cname = info["class_name"]
        base_str = " : " + ", ".join(info["bases"][1:]) if len(info["bases"]) > 1 else ""
        full_line = f"{cname}{base_str}"
        if rx and not rx.search(full_line):
            continue
        hierarchy_entries.append({
            "class": cname,
            "bases": info["bases"][1:],
            "vtables": info["vtables"],
        })

    all_classes = sorted(set(td_rva_to_name.values()))
    if rx:
        all_classes = [c for c in all_classes if rx.search(c)]

    return {
        "image_base": hex(image_base),
        "is_64bit": is_64,
        "total_rtti_types": len(td_rva_to_name),
        "total_matched_types": len(all_classes),
        "type_names": all_classes[:max_classes],
        "resolved_classes_with_vtables": hierarchy_entries[:max_classes],
    }


@mcp.tool()
def file_triage(file_path: str) -> str:
    """
    Perform universal initial triage on a sample: file magic (`file`), size, MD5/SHA256,
    overall Shannon entropy, UPX packing check, Detect-It-Easy (`diec`) compiler/packer scan,
    and language/runtime heuristics (C++ RTTI, Motorola DSP56300 ROM/binary, .NET, Go, Rust,
    PyInstaller, Android APK/DEX, WebAssembly, Electron).
    """
    target = _validate_path(file_path)

    data = target.read_bytes()
    sha256_hash = hashlib.sha256(data).hexdigest()
    md5_hash = hashlib.md5(data).hexdigest()
    entropy = _shannon_entropy(data)

    file_res = subprocess.run(["file", "-b", str(target)], capture_output=True, text=True, timeout=15)
    upx_res = subprocess.run(["upx", "-t", str(target)], capture_output=True, text=True, timeout=15)
    upx_status = "Packed with UPX (use upx_unpack)" if upx_res.returncode == 0 else "Not UPX-packed"

    die_summary = "Not available"
    if shutil.which("diec"):
        die_res = subprocess.run(["diec", "-d", str(target)], capture_output=True, text=True, timeout=20)
        if die_res.stdout.strip():
            die_summary = "; ".join(ln.strip() for ln in die_res.stdout.splitlines() if ln.strip())

    ecosystems = []
    if b".?AV" in data or b".?AU" in data:
        ecosystems.append("MSVC C++ binary with RTTI (use cpp_rtti_and_vtables, ghidra_decompile_function)")
    if target.suffix.lower() in {".lod", ".dsp", ".56k"} or b"_DATA P" in data[:1024] or (
        target.suffix.lower() in {".bin", ".rom"} and len(data) > 0 and (len(data) % 3 == 0 or len(data) % 4 == 0)
    ):
        ecosystems.append("Potential DSP / Firmware ROM image (for Motorola DSP56300 use dsp56300_disassemble)")
    if b".vmp0" in data or b".vmp1" in data or b"VMProtect" in data:
        ecosystems.append("VMProtect packed/virtualized binary detected")
    if b"MEI\x0c\x0b\x0a\x0b\x0e" in data or b"PyInstaller" in data or b"pyi-runtime-tmpdir" in data:
        ecosystems.append("Python PyInstaller executable (use pyinstaller_extract_and_decompile)")
    if b"mscoree.dll" in data or b"BSJB" in data:
        ecosystems.append(".NET / C# managed assembly (use dotnet_list_types / dotnet_decompile)")
    if b"Go buildinf:" in data or b"runtime.main" in data or b"gopclntab" in data:
        ecosystems.append("Go binary (use go_extract_symbols / r2 / ghidra)")
    if b"rust_begin_unwind" in data or b".cargo/registry" in data:
        ecosystems.append("Rust binary (use ghidra_decompile_all / r2)")
    if b"AndroidManifest.xml" in data or b"classes.dex" in data:
        ecosystems.append("Android APK/DEX (use jadx_list_classes / apktool_decode)")
    if data[:4] == b"\x00asm":
        ecosystems.append("WebAssembly module (use wasm_decompile)")
    if target.suffix.lower() == ".asar" or b'"files":{' in data[:4096]:
        ecosystems.append("Electron ASAR archive (use asar_list / asar_extract)")
    if b"Inno Setup" in data:
        ecosystems.append("Inno Setup installer (use archive_extract)")
    if b"Nullsoft.NSIS" in data or b"Nullsoft Inst" in data:
        ecosystems.append("NSIS installer archive (use archive_list / archive_extract)")

    eco_str = "\n  - ".join(ecosystems) if ecosystems else "Standard native binary / data (use pe_elf_headers, diec_detect, r2_binary_info, ghidra_decompile_function)"

    return (
        f"Path: {target}\n"
        f"Size: {len(data)} bytes ({len(data) / (1024 * 1024):.2f} MB)\n"
        f"Overall Entropy: {entropy:.3f} / 8.000 bits/byte\n"
        f"MD5: {md5_hash}\n"
        f"SHA256: {sha256_hash}\n"
        f"File Magic: {file_res.stdout.strip()}\n"
        f"Detect-It-Easy (diec): {die_summary}\n"
        f"UPX Status: {upx_status}\n"
        f"Detected Ecosystems:\n  - {eco_str}"
    )


@mcp.tool()
def diec_detect(file_path: str, show_entropy: bool = True) -> str:
    """
    Run Detect-It-Easy CLI (`diec`) on a binary to identify packers, protectors (VMProtect,
    Themida, UPX, PACE), compilers (MSVC, GCC, Clang, Rust, Go), linkers, and section entropy.
    Direct modern replacement for PEiD / CFF Explorer packer detection.
    """
    target = _validate_path(file_path)
    diec_bin = _require_tool("diec")
    out_parts = []

    res_det = subprocess.run([diec_bin, "-d", "-j", str(target)], capture_output=True, text=True, timeout=30)
    if res_det.stdout.strip():
        out_parts.append("=== Detect-It-Easy Compiler / Packer / Library Detections ===\n" + res_det.stdout.strip())

    if show_entropy:
        res_ent = subprocess.run([diec_bin, "-e", "-j", str(target)], capture_output=True, text=True, timeout=30)
        if res_ent.stdout.strip():
            out_parts.append("=== Detect-It-Easy Section & Overlay Entropy ===\n" + res_ent.stdout.strip())

    return "\n\n".join(out_parts) if out_parts else (res_det.stderr or "No detections returned by diec.")


@mcp.tool()
def pe_elf_headers(binary_path: str) -> str:
    """
    Deeply inspect PE/ELF/Mach-O headers, sections with true Shannon entropy (0.00-8.00) to spot
    packed/encrypted sections, PE Rich headers, TLS callbacks, PE resource tables, overlay data,
    exports, and Authenticode signature status using LIEF, pefile, pyelftools, and rabin2.
    """
    target = _validate_path(binary_path)
    data = target.read_bytes()
    out_parts = []

    if data[:2] == b"MZ":
        try:
            import pefile

            pe = pefile.PE(data=data, fast_load=False)
            img_base = pe.OPTIONAL_HEADER.ImageBase
            sec_lines = [
                f"=== PE Sections & Shannon Entropy (ImageBase: 0x{img_base:x}) ===",
                f"  {'Name':<10} {'VAddr':<14} {'VSize':<10} {'RawSize':<10} {'Entropy':<9} {'Flags'}",
            ]
            for sec in pe.sections:
                sec_name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
                sec_data = sec.get_data()
                ent = _shannon_entropy(sec_data)
                flag_note = " [HIGH ENTROPY: Packed/Compressed]" if ent >= 6.8 and len(sec_data) > 512 else ""
                rwx = "".join([
                    "R" if sec.Characteristics & 0x40000000 else "-",
                    "W" if sec.Characteristics & 0x80000000 else "-",
                    "X" if sec.Characteristics & 0x20000000 else "-",
                ])
                sec_lines.append(
                    f"  {sec_name:<10} 0x{img_base + sec.VirtualAddress:012x} "
                    f"{sec.Misc_VirtualSize:<10} {sec.SizeOfRawData:<10} {ent:5.2f}/8.0  {rwx}{flag_note}"
                )

            overlay_off = pe.get_overlay_data_start_offset()
            if overlay_off is not None and overlay_off < len(data):
                ov_data = data[overlay_off:]
                ov_ent = _shannon_entropy(ov_data)
                sec_lines.append(
                    f"  {'[OVERLAY]':<10} offset=0x{overlay_off:08x} size={len(ov_data)} bytes  entropy={ov_ent:.2f}/8.0"
                )
            out_parts.append("\n".join(sec_lines))

            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                exp_lines = ["=== PE Exported Functions ==="]
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:100]:
                    ename = exp.name.decode("utf-8", errors="replace") if exp.name else f"ordinal_{exp.ordinal}"
                    exp_lines.append(f"  0x{img_base + exp.address:012x} (RVA 0x{exp.address:08x})  {ename}")
                out_parts.append("\n".join(exp_lines))

            if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
                tls_addr = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
                out_parts.append(f"=== PE TLS Directory ===\n  AddressOfCallBacks: 0x{tls_addr:x}")

            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                res_lines = ["=== PE Resource Directory ==="]
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    rtype = (
                        entry.name.decode("utf-8", errors="replace")
                        if entry.name
                        else pefile.RESOURCE_TYPE.get(entry.struct.Id, f"ID_{entry.struct.Id}")
                    )
                    count = 0
                    total_bytes = 0
                    if hasattr(entry, "directory"):
                        for sub in entry.directory.entries:
                            if hasattr(sub, "directory"):
                                for lang in sub.directory.entries:
                                    if hasattr(lang, "data"):
                                        count += 1
                                        total_bytes += lang.data.struct.Size
                    res_lines.append(f"  {str(rtype):<24} items={count:<4} total_size={total_bytes} bytes")
                out_parts.append("\n".join(res_lines))
        except Exception as exc:
            out_parts.append(f"[pefile note: {exc}]")

    elif data[:4] == b"\x7fELF":
        try:
            import io
            from elftools.elf.elffile import ELFFile

            with io.BytesIO(data) as bio:
                elf = ELFFile(bio)
                sec_lines = [
                    f"=== ELF Sections & Shannon Entropy ({elf.get_machine_arch()}, {elf.elfclass}-bit) ===",
                    f"  {'Name':<18} {'VAddr':<14} {'Size':<10} {'Entropy':<9}",
                ]
                for sec in elf.iter_sections():
                    sdata = sec.data()
                    ent = _shannon_entropy(sdata)
                    flag_note = " [HIGH ENTROPY]" if ent >= 6.8 and len(sdata) > 512 else ""
                    sec_lines.append(
                        f"  {sec.name[:18]:<18} 0x{sec['sh_addr']:012x} {sec['sh_size']:<10} {ent:5.2f}/8.0{flag_note}"
                    )
                out_parts.append("\n".join(sec_lines))
        except Exception as exc:
            out_parts.append(f"[pyelftools note: {exc}]")

    r2_sec = subprocess.run(
        ["rabin2", "-I", "-l", "-e", str(target)],
        capture_output=True,
        text=True,
        timeout=30
    )
    if r2_sec.stdout:
        out_parts.append("=== Binary Info, Entrypoints & Linked Libraries (rabin2) ===\n" + r2_sec.stdout.strip())

    if data[:2] == b"MZ" and shutil.which("osslsigncode"):
        sig_res = subprocess.run(
            ["osslsigncode", "verify", "-in", str(target)],
            capture_output=True,
            text=True,
            timeout=15
        )
        sig_text = (sig_res.stdout or sig_res.stderr).strip()
        if sig_text:
            out_parts.append("=== Digital Signature (osslsigncode) ===\n" + sig_text[:2000])

    return "\n\n".join(out_parts) if out_parts else "Could not parse binary headers."


@mcp.tool()
def yara_scan(
    target_path: str,
    ruleset: str = "all_die",
    custom_rule_path: Optional[str] = None,
    timeout_seconds: int = 120
) -> str:
    """
    Scan a binary or directory using YARA rules.
    `ruleset` can be one of the built-in rule packs:
      - 'all_die': DIE packer, PEiD, crypto, and heuristic rules (/usr/lib/die/yara_rules)
      - 'peid': 2.6MB PEiD packer/compiler signatures (/usr/lib/die/yara_rules/peid.yar)
      - 'packer': Packer & protector signatures (/usr/lib/die/yara_rules/packer.yar)
      - 'crypto': Cryptographic constant signatures (/usr/lib/die/yara_rules/crypto_signature.yar)
      - 'malware': Malware & capability rules (/usr/lib/die/yara_rules/malware_analisys.yar)
      - 'community_packers': Yara-Rules repository packers (/opt/yara-rules/packers_index.yar)
      - 'community_crypto': Yara-Rules repository crypto (/opt/yara-rules/crypto_index.yar)
    Or pass `custom_rule_path` pointing to a custom .yar file in /workspace.
    """
    target = _validate_path(target_path)
    yara_bin = _require_tool("yara")

    die_yara_dir = Path("/usr/lib/die/yara_rules")
    comm_yara_dir = Path("/opt/yara-rules")

    rule_files = []
    if custom_rule_path:
        rule_files.append(_validate_path(custom_rule_path))
    elif ruleset == "peid":
        rule_files.append(die_yara_dir / "peid.yar")
    elif ruleset == "packer":
        rule_files.extend([die_yara_dir / "packer.yar", die_yara_dir / "packer_compiler_signatures.yar"])
    elif ruleset == "crypto":
        rule_files.append(die_yara_dir / "crypto_signature.yar")
    elif ruleset == "malware":
        rule_files.append(die_yara_dir / "malware_analisys.yar")
    elif ruleset == "community_packers":
        rule_files.append(comm_yara_dir / "packers_index.yar")
    elif ruleset == "community_crypto":
        rule_files.append(comm_yara_dir / "crypto_index.yar")
    else:
        for fname in (
            "packer.yar",
            "packer_compiler_signatures.yar",
            "crypto_signature.yar",
            "DiE_BasicHeuristics_by_DosX.yar",
            "DiE_EnhancedHeuristics_by_DosX.yar",
            "DiE_InterestingThings_by_DosX.yar",
        ):
            p = die_yara_dir / fname
            if p.exists():
                rule_files.append(p)

    existing_rules = [str(r) for r in rule_files if r.exists()]
    if not existing_rules:
        return f"No YARA rule files found for ruleset='{ruleset}'. Ensure the Docker image is built."

    matches_out = []
    for rfile in existing_rules:
        res = subprocess.run(
            [yara_bin, "-w", "-s", rfile, str(target)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds
        )
        if res.stdout.strip():
            matches_out.append(f"=== Matches from {Path(rfile).name} ===\n{res.stdout.strip()[:8000]}")

    return "\n\n".join(matches_out) if matches_out else f"No YARA matches triggered across {len(existing_rules)} rule file(s)."


@mcp.tool()
def cpp_rtti_and_vtables(
    binary_path: str,
    filter_pattern: str = "",
    max_entries: int = 150
) -> str:
    """
    Recover C++ RTTI class names, full MSVC/Itanium class inheritance hierarchies, and VTable
    virtual addresses (plus first virtual method pointers) from a C++ PE/ELF/Mach-O binary.
    Essential for analyzing object-oriented C++ applications and shared libraries.
    """
    target = _validate_path(binary_path)
    data = target.read_bytes()

    if data[:2] == b"MZ":
        info = _extract_pe_rtti_and_vtables(data, max_classes=max_entries, filter_pattern=filter_pattern)
        lines = [
            f"=== MSVC C++ RTTI & VTable Recovery ({target.name}) ===",
            f"ImageBase: {info['image_base']} | 64-bit: {info['is_64bit']} | "
            f"Total RTTI Types: {info['total_rtti_types']} | Matching: {info['total_matched_types']}",
            "\n--- Resolved Class Hierarchies & VTables ---",
        ]
        for entry in info["resolved_classes_with_vtables"]:
            bases = (" : public " + ", public ".join(entry["bases"])) if entry["bases"] else ""
            vts = ", ".join(
                f"vtable={v['vtable_vaddr']} (fn0={v['first_method_vaddr']})"
                for v in entry["vtables"][:4]
            )
            lines.append(f"  class {entry['class']}{bases}\n    -> {vts or 'no direct vtable xref'}")

        if not info["resolved_classes_with_vtables"]:
            lines.append("  (No CompleteObjectLocators matched; listing raw TypeDescriptor names below)")
            for tname in info["type_names"]:
                lines.append(f"  - {tname}")
        return "\n".join(lines)

    res = subprocess.run(
        ["r2", "-e", "bin.relocs.apply=true", "-q", "-c", "e scr.color=0; ic", str(target)],
        capture_output=True,
        text=True,
        timeout=60
    )
    lines = res.stdout.splitlines()
    if filter_pattern:
        rx = re.compile(filter_pattern, re.IGNORECASE)
        lines = [ln for ln in lines if rx.search(ln)]
    return "\n".join(lines[:max_entries]) or "No C++ RTTI classes found."


# =====================================================================
# Motorola DSP56300 Disassembler & Assembler Tools (dsp56300-disasm / dsp56300-asm)
# =====================================================================

@mcp.tool()
def dsp56300_disassemble(
    file_path: str,
    word_format: str = "u24be",
    start_addr: str = "0x0",
    num_instructions: int = 0,
    byte_offset: int = 0,
    byte_length: int = 0,
    save_output: bool = False,
    output_filename: Optional[str] = None
) -> str:
    """
    Disassemble Motorola (Freescale/NXP) DSP56300 24-bit program memory binary or ROM dump
    into readable DSP56300 assembly using `dsp56300-disasm` (xemu-project/dsp56300).

    Parameters:
      - `file_path`: Path to the DSP binary/ROM file (or host container binary if using `byte_offset`).
      - `word_format`: Word packing & endianness format:
          * `'u24be'` (default): Native 24-bit big-endian (3 bytes/word: [MSB, MID, LSB]).
          * `'u24le'`: 24-bit little-endian (3 bytes/word: [LSB, MID, MSB]).
          * `'u32le'`: 32-bit little-endian padded words (4 bytes/word).
          * `'u32be'`: 32-bit big-endian padded words (4 bytes/word, auto-converted to u24be).
          * `'u24be_swap16'`: 16-bit byte-swapped EPROM dump (swaps 16-bit byte pairs, then u24be).
      - `start_addr`: Starting 24-bit DSP word address in `P:` program memory (e.g. `'0x0'` or `'0x100'`).
      - `num_instructions`: Maximum number of instructions to decode (`0` = decode entire input).
      - `byte_offset`: Optional byte offset within `file_path` to slice embedded DSP56300 code from a larger binary/ROM.
      - `byte_length`: Optional number of bytes to slice starting at `byte_offset` (`0` = until EOF).
      - `save_output`: If True (or if output > 20,000 chars), writes full disassembly to `<project>/output/<output_filename>`.
      - `output_filename`: Optional custom filename for the saved `.asm` output file.
    """
    target = _validate_path(file_path)
    disasm_bin = _require_tool("dsp56300-disasm")

    valid_formats = {"u24be", "u24le", "u32le", "u32be", "u24be_swap16"}
    fmt_clean = word_format.strip().lower()
    if fmt_clean not in valid_formats:
        raise ValueError(f"Unsupported word_format '{word_format}'. Choose from: {sorted(valid_formats)}")

    start_clean = start_addr.strip()
    if not _SAFE_HEX_OR_INT_RE.match(start_clean):
        raise ValueError(f"Invalid start_addr '{start_addr}'. Must be a hex address (e.g. '0x100') or integer.")

    raw_bytes = target.read_bytes()
    if byte_offset < 0 or byte_offset >= len(raw_bytes):
        if len(raw_bytes) == 0:
            return f"Target file {target} is empty (0 bytes)."
        raise ValueError(f"byte_offset ({byte_offset}) is out of range for file of size {len(raw_bytes)} bytes.")

    if byte_offset > 0 or byte_length > 0:
        end_off = (byte_offset + byte_length) if byte_length > 0 else len(raw_bytes)
        raw_bytes = raw_bytes[byte_offset:end_off]

    cli_format = fmt_clean
    needs_temp_input = (byte_offset > 0 or byte_length > 0)

    # Pre-process custom word packing transformations if requested
    if fmt_clean == "u32be":
        # Convert 4-byte big-endian words [0x00, MSB, MID, LSB] -> 3-byte u24be [MSB, MID, LSB]
        usable = (len(raw_bytes) // 4) * 4
        converted = bytearray()
        for i in range(0, usable, 4):
            converted.extend(raw_bytes[i + 1 : i + 4])
        raw_bytes = bytes(converted)
        cli_format = "u24be"
        needs_temp_input = True
    elif fmt_clean == "u24be_swap16":
        # Swap adjacent bytes in 16-bit EPROM pairs [B1, B0, B3, B2, ...] -> [B0, B1, B2, B3, ...]
        usable = (len(raw_bytes) // 2) * 2
        swapped = bytearray(usable)
        swapped[0::2] = raw_bytes[1:usable:2]
        swapped[1::2] = raw_bytes[0:usable:2]
        raw_bytes = bytes(swapped)
        cli_format = "u24be"
        needs_temp_input = True

    with tempfile.TemporaryDirectory(prefix="dsp56300_") as tmp_dir:
        input_path = target
        if needs_temp_input:
            input_path = Path(tmp_dir) / f"{target.stem}_slice.bin"
            input_path.write_bytes(raw_bytes)

        cmd = [disasm_bin, "--color", "never", "-f", cli_format]
        if start_clean not in {"0", "0x0", "0X0"}:
            cmd.extend(["-s", start_clean])
        if num_instructions > 0:
            cmd.extend(["-n", str(num_instructions)])
        cmd.append(str(input_path))

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if res.returncode != 0 and not res.stdout:
            return f"dsp56300-disasm error: {(res.stderr or res.stdout).strip()}"

        disasm_text = res.stdout.strip()
        line_count = len(disasm_text.splitlines())

        header_meta = (
            f"; Motorola DSP56300 Disassembly ({target.name})\n"
            f"; Word Format: {word_format} | Start Address: P:{start_clean} | "
            f"Input Slice: offset=0x{byte_offset:x}, size={len(raw_bytes)} bytes | "
            f"Decoded Lines: {line_count}\n"
        )
        full_output = f"{header_meta}\n{disasm_text}"

        if save_output or len(full_output) > 20000:
            out_name = (
                _safe_filename(output_filename)
                if output_filename
                else f"{target.stem}_dsp56300.asm"
            )
            out_path = _get_output_dir(target) / out_name
            out_path.write_text(full_output, encoding="utf-8")
            if len(full_output) > 20000:
                return (
                    f"Full DSP56300 disassembly ({line_count} lines, {len(full_output)} chars) "
                    f"saved to: {out_path}\n"
                    f"Use search_workspace_files or read_workspace_file to inspect the full listing.\n\n"
                    f"Preview:\n{full_output[:15000]}\n... [truncated {len(full_output) - 15000} chars]"
                )
            return f"Saved DSP56300 disassembly to {out_path}\n\n{full_output}"

        return full_output


@mcp.tool()
def dsp56300_assemble(
    source_or_path: str,
    word_format: str = "u24be",
    output_filename: Optional[str] = None,
    is_inline_source: bool = False
) -> str:
    """
    Assemble Motorola DSP56300 assembly source code into binary machine code or LOD format
    using `dsp56300-asm` (xemu-project/dsp56300).

    Parameters:
      - `source_or_path`: Path to an `.asm`/`.s` file in `/workspace`, OR inline assembly text if `is_inline_source=True`.
      - `word_format`: Output format (`'u24be'`, `'u24le'`, `'u32le'`, or `'lod'`).
      - `output_filename`: Optional filename in `<project>/output/` for the assembled binary.
      - `is_inline_source`: Set True if `source_or_path` contains raw DSP56300 assembly instructions directly.
    """
    asm_bin = _require_tool("dsp56300-asm")
    valid_formats = {"u24be", "u24le", "u32le", "lod"}
    fmt_clean = word_format.strip().lower()
    if fmt_clean not in valid_formats:
        raise ValueError(f"Unsupported word_format '{word_format}'. Choose from: {sorted(valid_formats)}")

    with tempfile.TemporaryDirectory(prefix="dsp56300_asm_") as tmp_dir:
        if is_inline_source:
            src_path = Path(tmp_dir) / "inline.asm"
            src_path.write_text(source_or_path, encoding="utf-8")
            out_dir = OUTPUT_DIR
            default_stem = "dsp56300_inline"
        else:
            src_path = _validate_path(source_or_path)
            out_dir = _get_output_dir(src_path)
            default_stem = src_path.stem

        ext = ".lod" if fmt_clean == "lod" else ".bin"
        out_name = _safe_filename(output_filename) if output_filename else f"{default_stem}_{fmt_clean}{ext}"
        out_path = out_dir / out_name

        cmd = [asm_bin, str(src_path), "-o", str(out_path), "-f", fmt_clean]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if res.returncode != 0 or not out_path.exists():
            return f"dsp56300-asm failed: {(res.stderr or res.stdout).strip()}"

        out_bytes = out_path.read_bytes()
        if fmt_clean == "lod":
            preview = out_path.read_text(encoding="utf-8", errors="replace")[:4000]
            return f"Assembled LOD file saved to {out_path} ({len(out_bytes)} bytes):\n\n{preview}"

        word_size = 4 if fmt_clean == "u32le" else 3
        word_count = len(out_bytes) // word_size
        hex_words = [
            out_bytes[i : i + word_size].hex()
            for i in range(0, min(len(out_bytes), word_size * 64), word_size)
        ]
        return (
            f"Successfully assembled DSP56300 binary to {out_path}\n"
            f"Format: {fmt_clean} | Size: {len(out_bytes)} bytes ({word_count} words)\n"
            f"Hex Preview (first {len(hex_words)} words):\n  " + " ".join(hex_words)
        )


@mcp.tool()
def capa_detect_capabilities(binary_path: str, timeout_seconds: int = 180) -> str:
    """
    Run Mandiant capa to automatically identify host/program capabilities in a PE/ELF/.NET
    binary (mapped to MITRE ATT&CK and MBC) and list which function addresses implement them.
    """
    target = _validate_path(binary_path)
    capa_bin = _require_tool("capa")
    cmd = [capa_bin]
    rules_dir = Path("/opt/capa/rules")
    if rules_dir.exists():
        cmd.extend(["-r", str(rules_dir)])
    cmd.extend(["-vv", str(target)])

    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    output = (res.stdout or res.stderr).strip()
    if len(output) > 20000:
        return output[:20000] + f"\n... [truncated {len(output) - 20000} chars]"
    return output or "No capabilities detected by capa."


@mcp.tool()
def archive_list(archive_path: str) -> str:
    """
    List contents of an archive or installer (.zip, .7z, .rar, .tar, .cab, .msi, .iso,
    NSIS .exe, InnoSetup .exe, or .squashfs).
    """
    target = _validate_path(archive_path)
    data_head = target.read_bytes()[:4096]

    if target.suffix.lower() in {".squashfs", ".sqsh"} or data_head[:4] == b"hsqs":
        res = subprocess.run(["unsquashfs", "-ll", str(target)], capture_output=True, text=True, timeout=30)
        return (res.stdout or res.stderr).strip()[:15000]

    if shutil.which("innoextract"):
        inno = subprocess.run(["innoextract", "-l", str(target)], capture_output=True, text=True, timeout=30)
        if inno.returncode == 0:
            return inno.stdout.strip()[:15000]

    res = subprocess.run(["7z", "l", "-y", str(target)], capture_output=True, text=True, timeout=30)
    return (res.stdout or res.stderr).strip()[:15000]


@mcp.tool()
def archive_extract(
    archive_path: str,
    output_name: Optional[str] = None,
    password: Optional[str] = None
) -> str:
    """
    Extract an archive, firmware filesystem, or Windows installer (.zip, .7z, .rar, .cab,
    .msi, .iso, NSIS .exe, InnoSetup .exe, .squashfs) into the project's output/<output_name>.
    """
    target = _validate_path(archive_path)
    folder_name = _safe_filename(output_name) if output_name else f"{target.stem}_extracted"
    out_dir = _get_output_dir(target) / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)

    data_head = target.read_bytes()[:4096]
    if target.suffix.lower() in {".squashfs", ".sqsh"} or data_head[:4] == b"hsqs":
        res = subprocess.run(
            ["unsquashfs", "-f", "-d", str(out_dir), str(target)],
            capture_output=True,
            text=True,
            timeout=120
        )
        return f"Extracted SquashFS to {out_dir}\n{(res.stdout or res.stderr).strip()}"

    if shutil.which("innoextract"):
        inno_check = subprocess.run(["innoextract", "-l", str(target)], capture_output=True, text=True, timeout=20)
        if inno_check.returncode == 0:
            res = subprocess.run(
                ["innoextract", "-e", "-d", str(out_dir), str(target)],
                capture_output=True,
                text=True,
                timeout=120
            )
            return f"Extracted InnoSetup installer to {out_dir}\n{(res.stdout or res.stderr).strip()}"

    cmd = ["7z", "x", "-y", f"-o{out_dir}"]
    if password:
        cmd.append(f"-p{password}")
    cmd.append(str(target))
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if res.returncode != 0:
        return f"Archive extraction failed: {res.stderr or res.stdout}"
    return f"Successfully extracted {target.name} to {out_dir}\n{res.stdout.strip()}"


@mcp.tool()
def binwalk_scan(file_path: str, extract: bool = False) -> str:
    """
    Scan a binary or firmware image for embedded files and signatures using Binwalk.
    If extract=True, extracts carved artifacts into the project's output/binwalk_<name>.
    """
    target = _validate_path(file_path)
    cmd = ["binwalk"]
    out_dir = _get_output_dir(target) / f"binwalk_{target.name}"
    if extract:
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend(["-e", "-C", str(out_dir)])
    cmd.append(str(target))

    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if res.returncode != 0 and not res.stdout:
        return f"Error executing binwalk: {res.stderr}"
    output = res.stdout.strip()
    if extract:
        output += f"\n\n[Extracted files saved under {out_dir}]"
    return output


@mcp.tool()
def upx_unpack(file_path: str, output_filename: Optional[str] = None) -> str:
    """
    Unpack a UPX-compressed binary into the project's output/ directory.
    """
    target = _validate_path(file_path)
    out_name = _safe_filename(output_filename) if output_filename else f"{target.stem}_unpacked{target.suffix}"
    out_path = _get_output_dir(target) / out_name
    if out_path.exists():
        out_path.unlink()

    res = subprocess.run(
        ["upx", "-d", "-o", str(out_path), str(target)],
        capture_output=True,
        text=True,
        timeout=60
    )
    if res.returncode != 0:
        return f"UPX unpack failed: {res.stderr or res.stdout}"
    return f"Successfully unpacked to {out_path}\n{res.stdout.strip()}"


# =====================================================================
# FLOSS (Mandiant Obfuscated String Solver)
# =====================================================================

@mcp.tool()
def floss_extract_strings(
    binary_path: str,
    no_static_strings: bool = False,
    min_length: int = 4,
    timeout_seconds: int = 120
) -> str:
    """
    Extract obfuscated strings (stack, tight, decoded) and optionally static strings
    from a PE/ELF/Mach-O binary using Mandiant FLOSS.
    """
    target = _validate_path(binary_path)
    cmd = ["floss", "-n", str(min_length)]
    if no_static_strings:
        cmd.append("--no-static-strings")
    cmd.append(str(target))

    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    if res.returncode != 0 and not res.stdout:
        return f"Error executing floss: {res.stderr}"
    out = res.stdout.strip()
    if len(out) > 20000:
        return out[:20000] + f"\n... [truncated {len(out) - 20000} chars]"
    return out


# =====================================================================
# Radare2 Tools (Static Analysis, Xrefs, Strings, Callgraphs, Decomp)
# =====================================================================

@mcp.tool()
def r2_binary_info(binary_path: str) -> str:
    """
    Extract file architecture, endianness, binary type, and security mitigations
    (canary, nx, pic, relro) using Radare2 (rabin2 -I).
    """
    target = _validate_path(binary_path)
    result = subprocess.run(
        ["rabin2", "-I", "-j", str(target)],
        capture_output=True,
        text=True,
        timeout=30
    )
    if result.returncode != 0:
        return f"Error executing rabin2: {result.stderr}"
    return result.stdout.strip()


@mcp.tool()
def r2_imports_exports_sections(binary_path: str) -> str:
    """
    List sections, imported APIs/functions, and exported symbols of a binary using Radare2.
    """
    target = _validate_path(binary_path)
    res = subprocess.run(
        ["rabin2", "-S", "-i", "-E", str(target)],
        capture_output=True,
        text=True,
        timeout=30
    )
    out = (res.stdout or res.stderr).strip()
    if len(out) > 20000:
        return out[:20000] + f"\n... [truncated {len(out) - 20000} chars]"
    return out


@mcp.tool()
def r2_strings(
    binary_path: str,
    filter_pattern: str = "",
    all_sections: bool = False,
    max_entries: int = 150
) -> str:
    """
    Extract strings with their virtual addresses and sections using Radare2 (rabin2 -z / -zz).
    Optionally filter strings by a case-insensitive regex pattern.
    """
    target = _validate_path(binary_path)
    flag = "-zz" if all_sections else "-z"
    res = subprocess.run(
        ["rabin2", flag, str(target)],
        capture_output=True,
        text=True,
        timeout=45
    )
    lines = res.stdout.splitlines()
    if filter_pattern:
        rx = re.compile(filter_pattern, re.IGNORECASE)
        lines = [ln for ln in lines if rx.search(ln)]

    total = len(lines)
    out = "\n".join(lines[:max_entries])
    if total > max_entries:
        out += f"\n... [{total - max_entries} matching strings omitted]"
    return out or "No matching strings found."


@mcp.tool()
def r2_list_functions(
    binary_path: str,
    filter_pattern: str = "",
    analysis_level: str = "aa",
    max_entries: int = 150
) -> str:
    """
    Analyze binary functions and list detected function names, addresses, and sizes using Radare2.
    `analysis_level` defaults to 'aa' (fast symbol/call analysis, ideal for large C++ binaries);
    use 'aaa' for deeper full-program analysis on smaller or stripped binaries.
    """
    target = _validate_path(binary_path)
    anal_cmd = "aaa" if analysis_level == "aaa" else "aa"
    cmd = [
        "r2", "-e", "bin.relocs.apply=true", "-q",
        "-c", f"e scr.color=0; {anal_cmd}; afl",
        str(target)
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    if result.returncode != 0 and not result.stdout:
        return f"Error executing r2: {result.stderr}"

    lines = result.stdout.splitlines()
    if filter_pattern:
        rx = re.compile(filter_pattern, re.IGNORECASE)
        lines = [ln for ln in lines if rx.search(ln)]

    total_funcs = len(lines)
    truncated = "\n".join(lines[:max_entries])

    if total_funcs > max_entries:
        truncated += f"\n... [{total_funcs - max_entries} functions omitted]"
    return truncated or "No matching functions found."


@mcp.tool()
def r2_xrefs(
    binary_path: str,
    target_addr_or_name: str,
    analysis_level: str = "aa"
) -> str:
    """
    Find cross-references TO (axt) and FROM (axf) a given function name, symbol, or hex address
    using Radare2 (`analysis_level` can be 'aa' for fast xrefs or 'aaa' for deep xrefs).
    """
    target = _validate_path(binary_path)
    if not _SAFE_R2_TARGET_RE.match(target_addr_or_name):
        raise ValueError(f"Invalid identifier or address '{target_addr_or_name}'.")

    anal_cmd = "aaa" if analysis_level == "aaa" else "aa; aar"
    r2_cmds = (
        f"e scr.color=0; {anal_cmd}; "
        f"?e === XREFS TO {target_addr_or_name} ===; axt @ {target_addr_or_name}; "
        f"?e === XREFS FROM {target_addr_or_name} ===; axf @ {target_addr_or_name}"
    )
    res = subprocess.run(
        ["r2", "-e", "bin.relocs.apply=true", "-q", "-c", r2_cmds, str(target)],
        capture_output=True,
        text=True,
        timeout=120
    )
    return (res.stdout or res.stderr).strip() or f"No cross-references found for {target_addr_or_name}."


@mcp.tool()
def r2_callgraph(binary_path: str, function_name_or_addr: str) -> str:
    """
    Extract the caller/callee callgraph for a specific function using Radare2 (agcj / afcf).
    """
    target = _validate_path(binary_path)
    if not _SAFE_R2_TARGET_RE.match(function_name_or_addr):
        raise ValueError(f"Invalid function identifier or address '{function_name_or_addr}'.")

    r2_cmds = f"e scr.color=0; aa; af @ {function_name_or_addr}; agcj @ {function_name_or_addr}"
    res = subprocess.run(
        ["r2", "-e", "bin.relocs.apply=true", "-q", "-c", r2_cmds, str(target)],
        capture_output=True,
        text=True,
        timeout=90
    )
    return (res.stdout or res.stderr).strip() or "No callgraph generated."


@mcp.tool()
def r2_disassemble_function(
    binary_path: str,
    function_name_or_addr: str,
    full_analysis: bool = False,
    arch: str = "",
    bits: int = 0,
    base_addr: str = ""
) -> str:
    """
    Disassemble a specific function (`af @ <target>; pdf @ <target>`) into assembly using Radare2.
    Uses fast targeted function analysis by default so large 10MB+ C++ binaries disassemble in <2s;
    set `full_analysis=True` to run `aaa` first.
    """
    target = _validate_path(binary_path)
    if not _SAFE_R2_TARGET_RE.match(function_name_or_addr):
        raise ValueError(
            f"Invalid function identifier or address '{function_name_or_addr}'. "
            "Only alphanumeric characters and '_.:+-' are allowed."
        )

    anal_prefix = "aaa" if full_analysis else f"af @ {function_name_or_addr}"
    r2_setup = "e scr.color=0; "
    if arch:
        r2_setup += f"e asm.arch={arch}; "
    if bits:
        r2_setup += f"e asm.bits={bits}; "
    if base_addr:
        r2_setup += f"e bin.baddr={base_addr}; "
    r2_commands = f"{r2_setup}{anal_prefix}; pdf @ {function_name_or_addr}"
    cmd = ["r2", "-e", "bin.relocs.apply=true", "-q", "-c", r2_commands, str(target)]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    if result.returncode != 0 and not result.stdout:
        return f"Error executing r2: {result.stderr}"
    return result.stdout.strip() or "No disassembly generated. Verify the function identifier."


@mcp.tool()
def r2_decompile_function(
    binary_path: str,
    function_name_or_addr: str,
    full_analysis: bool = False
) -> str:
    """
    Generate C-like pseudocode for a function using Radare2's built-in decompiler (pdc).
    Uses fast targeted function analysis (`af @ <target>`) by default; for higher-fidelity C
    decompilation, use `ghidra_decompile_function`.
    """
    target = _validate_path(binary_path)
    if not _SAFE_R2_TARGET_RE.match(function_name_or_addr):
        raise ValueError(f"Invalid function identifier or address '{function_name_or_addr}'.")

    anal_prefix = "aaa" if full_analysis else f"af @ {function_name_or_addr}"
    r2_commands = f"e scr.color=0; {anal_prefix}; pdc @ {function_name_or_addr}"
    result = subprocess.run(
        ["r2", "-e", "bin.relocs.apply=true", "-q", "-c", r2_commands, str(target)],
        capture_output=True,
        text=True,
        timeout=90
    )
    return result.stdout.strip() or f"Error generating pseudocode: {result.stderr}"


# =====================================================================
# Ghidra Headless Tools (Persistent Project Cache & C Decompilation)
# =====================================================================

def _get_ghidra_cache_info(target: Path, processor: Optional[str] = None) -> tuple[Path, str, bool]:
    """Return (project_dir, project_name, is_cached) for a binary under the project's output/ghidra_cache."""
    stat = target.stat()
    proc_str = f":{processor}" if processor else ""
    fingerprint = hashlib.sha256(f"{target.name}:{stat.st_size}:{int(stat.st_mtime)}{proc_str}".encode()).hexdigest()[:10]
    safe_stem = re.sub(r"[^a-zA-Z0-9_.-]", "_", target.stem)[:40]
    cache_dir = _get_output_dir(target) / "ghidra_cache"
    proj_dir = cache_dir / f"{safe_stem}_{fingerprint}"
    proj_name = f"proj_{safe_stem}"
    gpr_file = proj_dir / f"{proj_name}.gpr"
    rep_dir = proj_dir / f"{proj_name}.rep"
    proj_dir.mkdir(parents=True, exist_ok=True)
    for lock_file in proj_dir.glob("*.lock*"):
        lock_file.unlink(missing_ok=True)
    is_cached = gpr_file.exists() and rep_dir.is_dir()
    return proj_dir, proj_name, is_cached


@mcp.tool()
def ghidra_decompile_function(
    binary_path: str,
    function_name_or_addr: str,
    fast_mode: bool = False,
    timeout_seconds: int = 240
) -> str:
    """
    Decompile a single native function (by export/symbol name like 'main'/'DllMain' or
    hex virtual address like '0x18013f460') into clean C pseudocode using Ghidra's DecompInterface.
    Automatically caches the Ghidra project in <project>/output/ghidra_cache so subsequent calls
    take ~3-5 seconds.
    Set `fast_mode=True` on large (>5MB) C++ binaries to skip full-program auto-analysis and
    immediately decompile the target function in ~8 seconds (also used automatically as a fallback
    if full auto-analysis exceeds `timeout_seconds`).
    """
    target = _validate_path(binary_path)
    if not _SAFE_R2_TARGET_RE.match(function_name_or_addr):
        raise ValueError(f"Invalid function identifier or address '{function_name_or_addr}'.")

    proj_dir, proj_name, is_cached = _get_ghidra_cache_info(target)
    script_dir = Path(tempfile.mkdtemp(prefix="ghidra_scripts_"))
    script_file = script_dir / "DecompileTarget.java"
    script_file.write_text(_GHIDRA_DECOMPILE_TARGET_JAVA, encoding="utf-8")

    def _build_cmd(cached: bool, no_analysis: bool) -> list[str]:
        base = ["/opt/ghidra/support/analyzeHeadless", str(proj_dir), proj_name]
        if cached:
            base.extend(["-process", target.name, "-noanalysis"])
        else:
            base.extend(["-import", str(target), "-overwrite"])
            if no_analysis:
                base.append("-noanalysis")
        base.extend(["-scriptPath", str(script_dir), "-postScript", "DecompileTarget.java", function_name_or_addr])
        return base

    try:
        try:
            cmd = _build_cmd(cached=is_cached, no_analysis=fast_mode)
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            for lock_file in proj_dir.glob("*.lock*"):
                lock_file.unlink(missing_ok=True)
            cmd = _build_cmd(cached=False, no_analysis=True)
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        combined = (res.stdout or "") + "\n" + (res.stderr or "")
        if "=== GHIDRA_DECOMP_START ===" in combined:
            body = combined.split("=== GHIDRA_DECOMP_START ===", 1)[1]
            body = body.split("=== GHIDRA_DECOMP_END ===", 1)[0].strip()
            return body
        for line in combined.splitlines():
            if "ERROR:" in line:
                return line.strip()
        return combined[-4000:]
    finally:
        shutil.rmtree(script_dir, ignore_errors=True)


@mcp.tool()
def ghidra_list_functions(
    binary_path: str,
    filter_pattern: str = "",
    max_entries: int = 200,
    timeout_seconds: int = 240
) -> str:
    """
    List functions and their C prototypes in a binary using Ghidra Headless (reusing the cached
    Ghidra project in <project>/output/ghidra_cache if available).
    """
    target = _validate_path(binary_path)
    proj_dir, proj_name, is_cached = _get_ghidra_cache_info(target)
    script_dir = Path(tempfile.mkdtemp(prefix="ghidra_list_"))
    script_file = script_dir / "ListFunctions.java"
    script_file.write_text(_GHIDRA_LIST_FUNCTIONS_JAVA, encoding="utf-8")

    cmd = ["/opt/ghidra/support/analyzeHeadless", str(proj_dir), proj_name]
    if is_cached:
        cmd.extend(["-process", target.name, "-noanalysis"])
    else:
        cmd.extend(["-import", str(target), "-overwrite"])
    cmd.extend(["-scriptPath", str(script_dir), "-postScript", "ListFunctions.java", filter_pattern, str(max_entries)])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        combined = (res.stdout or "") + "\n" + (res.stderr or "")
        if "=== GHIDRA_FUNCS_START ===" in combined:
            body = combined.split("=== GHIDRA_FUNCS_START ===", 1)[1]
            body = body.split("=== GHIDRA_FUNCS_END ===", 1)[0].strip()
            return body
        return combined[-4000:]
    finally:
        shutil.rmtree(script_dir, ignore_errors=True)


@mcp.tool()
def ghidra_decompile_all(
    binary_path: str,
    output_filename: Optional[str] = None,
    timeout_seconds: int = 360
) -> str:
    """
    Decompile ALL non-thunk functions in a binary into a single C source file under
    the project's output/<output_filename> using Ghidra Headless (reusing the cached project if available),
    so you can search/read it with `search_workspace_files` and `read_workspace_file`.
    """
    target = _validate_path(binary_path)
    out_name = _safe_filename(output_filename) if output_filename else f"{target.stem}_ghidra_decompiled.c"
    out_path = _get_output_dir(target) / out_name

    proj_dir, proj_name, is_cached = _get_ghidra_cache_info(target)
    script_dir = Path(tempfile.mkdtemp(prefix="ghidra_all_"))
    script_file = script_dir / "DecompileAll.java"
    script_file.write_text(_GHIDRA_DECOMPILE_ALL_JAVA, encoding="utf-8")

    cmd = ["/opt/ghidra/support/analyzeHeadless", str(proj_dir), proj_name]
    if is_cached:
        cmd.extend(["-process", target.name, "-noanalysis"])
    else:
        cmd.extend(["-import", str(target), "-overwrite"])
    cmd.extend(["-scriptPath", str(script_dir), "-postScript", "DecompileAll.java", str(out_path)])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        combined = (res.stdout or "") + "\n" + (res.stderr or "")
        if out_path.exists():
            preview = "\n".join(out_path.read_text(encoding="utf-8", errors="replace").splitlines()[:80])
            return (
                f"Full decompilation written to: {out_path} ({out_path.stat().st_size} bytes)\n"
                f"Use search_workspace_files or read_workspace_file to inspect it.\n\n"
                f"Preview (first 80 lines):\n{preview}"
            )
        return f"Decompilation did not produce {out_path}. Log tail:\n{combined[-3000:]}"
    finally:
        shutil.rmtree(script_dir, ignore_errors=True)


@mcp.tool()
def ghidra_headless_analyze(
    binary_path: str,
    post_script: Optional[str] = None,
    persist_project: bool = True,
    processor: Optional[str] = None,
    base_address: Optional[str] = None,
    loader: Optional[str] = None,
    timeout_seconds: int = 300
) -> str:
    """
    Run Ghidra headless analysis on a native binary with an optional custom Ghidra post-script.
    Caches the project in <project>/output/ghidra_cache by default when `persist_project=True`.
    """
    target = _validate_path(binary_path)
    if persist_project:
        proj_dir, project_name, is_cached = _get_ghidra_cache_info(target, processor=processor)
        project_dir = str(proj_dir)
    else:
        project_dir = tempfile.mkdtemp(prefix="ghidra_proj_")
        project_name = f"proj_{target.stem}"
        is_cached = False

    cmd = ["/opt/ghidra/support/analyzeHeadless", project_dir, project_name]
    if is_cached:
        cmd.extend(["-process", target.name, "-noanalysis"])
    else:
        cmd.extend(["-import", str(target), "-overwrite"])
        if loader:
            cmd.extend(["-loader", loader])
        elif processor:
            cmd.extend(["-loader", "BinaryLoader"])
        if processor:
            cmd.extend(["-processor", processor])
        if base_address:
            cmd.extend(["-baseAddr", base_address])

    if post_script:
        script_path = _validate_path(post_script)
        cmd.extend([
            "-scriptPath", str(script_path.parent),
            "-postScript", script_path.name
        ])

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds
        )
        return res.stdout[-4000:] if res.stdout else res.stderr[-2000:]
    finally:
        if not persist_project:
            shutil.rmtree(project_dir, ignore_errors=True)


# =====================================================================
# Android & Java Tools (JADX & Apktool)
# =====================================================================

@mcp.tool()
def jadx_extract_manifest(apk_path: str) -> str:
    """
    Extract and decode the AndroidManifest.xml from an APK using JADX.
    """
    target = _validate_path(apk_path)
    with tempfile.TemporaryDirectory() as tmp_dir:
        cmd = ["jadx", "-d", tmp_dir, "--no-src", str(target)]
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        manifest_path = Path(tmp_dir) / "resources" / "AndroidManifest.xml"
        if manifest_path.exists():
            return manifest_path.read_text(encoding="utf-8", errors="replace")
        return "AndroidManifest.xml not found in decompiled output."


@mcp.tool()
def jadx_list_classes(
    archive_path: str,
    package_filter: str = "",
    max_entries: int = 300
) -> str:
    """
    Decompile an APK/DEX/JAR/AAR into the project's output/<name>_jadx (cached) and list all
    discovered Java/Kotlin class fully-qualified names (FQNs).
    """
    target = _validate_path(archive_path)
    out_dir = _get_output_dir(target) / f"{target.stem}_jadx"
    sources_dir = out_dir / "sources"
    if not sources_dir.exists():
        out_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["jadx", "-d", str(out_dir), "--show-bad-code", str(target)],
            capture_output=True,
            text=True,
            timeout=240
        )

    if not sources_dir.exists():
        return f"No Java sources generated in {out_dir}."

    classes = []
    for java_file in sorted(sources_dir.rglob("*.java")):
        rel = java_file.relative_to(sources_dir).with_suffix("")
        fqn = ".".join(rel.parts)
        if not package_filter or package_filter.lower() in fqn.lower():
            classes.append(fqn)

    total = len(classes)
    shown = "\n".join(classes[:max_entries])
    if total > max_entries:
        shown += f"\n... [{total - max_entries} classes omitted]"
    return f"Decompiled directory: {out_dir}\nTotal matching classes: {total}\n\n{shown}"


@mcp.tool()
def jadx_decompile_class(apk_path: str, class_fqn: str) -> str:
    """
    Decompile a single target class (fully qualified name, e.g. com.example.MainActivity)
    from an APK/DEX/JAR archive into Java source code.
    """
    target = _validate_path(apk_path)
    cached_file = _get_output_dir(target) / f"{target.stem}_jadx" / "sources" / (class_fqn.replace(".", "/") + ".java")
    if cached_file.exists():
        return cached_file.read_text(encoding="utf-8", errors="replace")

    with tempfile.TemporaryDirectory() as tmp_dir:
        cmd = [
            "jadx",
            "-d", tmp_dir,
            "--single-class", class_fqn,
            "--show-bad-code",
            str(target)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        relative_java_path = Path("sources") / (class_fqn.replace(".", "/") + ".java")
        decompiled_file = Path(tmp_dir) / relative_java_path

        if decompiled_file.exists():
            return decompiled_file.read_text(encoding="utf-8", errors="replace")

        matches = list(Path(tmp_dir).glob(f"**/{class_fqn.split('.')[-1]}.java"))
        if matches:
            return matches[0].read_text(encoding="utf-8", errors="replace")

        return f"Class '{class_fqn}' could not be located in output. stderr: {res.stderr}"


@mcp.tool()
def jadx_decompile_all_and_search(
    archive_path: str,
    regex_pattern: str = "",
    output_name: Optional[str] = None
) -> str:
    """
    Decompile an entire APK/DEX/JAR into the project's output/<output_name> using JADX
    and optionally search all decompiled Java/XML files for a regex pattern.
    """
    target = _validate_path(archive_path)
    folder_name = _safe_filename(output_name) if output_name else f"{target.stem}_jadx"
    out_dir = _get_output_dir(target) / folder_name
    if not (out_dir / "sources").exists():
        out_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["jadx", "-d", str(out_dir), "--show-bad-code", str(target)],
            capture_output=True,
            text=True,
            timeout=240
        )

    if not regex_pattern:
        return f"Decompiled {target.name} to {out_dir}. Use search_workspace_files or read_workspace_file to inspect."
    return search_workspace_files(regex_pattern=regex_pattern, subdir=str(out_dir))


@mcp.tool()
def apktool_decode(apk_path: str, output_name: Optional[str] = None) -> str:
    """
    Decode an APK (resources, AndroidManifest.xml, smali) into the project's output/<output_name>
    using Apktool.
    """
    target = _validate_path(apk_path)
    folder_name = _safe_filename(output_name) if output_name else f"{target.stem}_apktool"
    out_dir = _get_output_dir(target) / folder_name

    cmd = ["apktool", "d", "-f", "-o", str(out_dir), str(target)]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if res.returncode != 0:
        return f"Apktool decode failed: {res.stderr or res.stdout}"
    return f"Successfully decoded APK to {out_dir}\n{res.stdout.strip()}"


# =====================================================================
# .NET / C# Tools (ILSpy CLI - ilspycmd)
# =====================================================================

@mcp.tool()
def dotnet_list_types(assembly_path: str) -> str:
    """
    List all classes, structs, interfaces, and enums in a .NET / C# assembly (.exe or .dll)
    using ilspycmd.
    """
    target = _validate_path(assembly_path)
    ilspy = _require_tool("ilspycmd")
    res = subprocess.run(
        [ilspy, "-l", "c,i,s,d,e", str(target)],
        capture_output=True,
        text=True,
        timeout=60
    )
    if res.returncode != 0 and not res.stdout:
        return f"ilspycmd failed: {res.stderr}"
    return res.stdout.strip()


@mcp.tool()
def dotnet_decompile(
    assembly_path: str,
    type_name: Optional[str] = None,
    output_name: Optional[str] = None
) -> str:
    """
    Decompile a .NET / C# assembly (.exe or .dll) to C# source code using ilspycmd.
    If type_name is provided, returns the C# code for that specific class/type; otherwise
    decompiles the entire project into the project's output/<output_name>.
    """
    target = _validate_path(assembly_path)
    ilspy = _require_tool("ilspycmd")

    if type_name:
        res = subprocess.run(
            [ilspy, "-t", type_name, str(target)],
            capture_output=True,
            text=True,
            timeout=90
        )
        out = (res.stdout or res.stderr).strip()
        return out[:20000] if len(out) > 20000 else out

    folder_name = _safe_filename(output_name) if output_name else f"{target.stem}_dotnet_src"
    out_dir = _get_output_dir(target) / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        [ilspy, "-p", "-o", str(out_dir), str(target)],
        capture_output=True,
        text=True,
        timeout=180
    )
    if res.returncode != 0:
        return f"ilspycmd decompilation failed: {res.stderr or res.stdout}"
    cs_files = [str(p.relative_to(out_dir)) for p in sorted(out_dir.rglob("*.cs"))]
    return (
        f"Decompiled .NET assembly to {out_dir} ({len(cs_files)} .cs files):\n"
        + "\n".join(cs_files[:100])
    )


# =====================================================================
# Python Packed Executables & Bytecode (pyinstxtractor-ng & pycdc)
# =====================================================================

@mcp.tool()
def pyinstaller_extract_and_decompile(binary_path: str, pyc_filter: str = "") -> str:
    """
    Extract a PyInstaller-packed executable (.exe or ELF) into the project's output/<name>_extracted
    using pyinstxtractor-ng, and automatically decompile matching entrypoint .pyc files with pycdc.
    """
    target = _validate_path(binary_path)
    extractor = _require_tool("pyinstxtractor-ng")
    proj_out = _get_output_dir(target)
    out_dir = proj_out / f"{target.name}_extracted"

    res = subprocess.run(
        [extractor, str(target)],
        cwd=str(proj_out),
        capture_output=True,
        text=True,
        timeout=120
    )
    log_text = (res.stdout or "") + "\n" + (res.stderr or "")

    if not out_dir.exists():
        return f"PyInstaller extraction did not create {out_dir}.\nLog:\n{log_text}"

    top_pycs = sorted(out_dir.glob("*.pyc"))
    if pyc_filter:
        rx = re.compile(pyc_filter, re.IGNORECASE)
        top_pycs = [p for p in top_pycs if rx.search(p.name)]

    decompiled_sections = []
    if shutil.which("pycdc"):
        for pyc in top_pycs[:10]:
            if pyc.name in {"struct.pyc", "pyimod01_archive.pyc", "pyimod02_importers.pyc", "pyimod03_ctypes.pyc"}:
                continue
            dec = subprocess.run(["pycdc", str(pyc)], capture_output=True, text=True, timeout=30)
            if dec.stdout.strip():
                py_out = out_dir / f"{pyc.stem}.decompiled.py"
                py_out.write_text(dec.stdout, encoding="utf-8")
                decompiled_sections.append(
                    f"=== Decompiled {pyc.name} (saved to {py_out}) ===\n{dec.stdout[:5000]}"
                )

    return (
        f"Extraction log:\n{log_text.strip()}\n\n"
        f"Top-level .pyc files in {out_dir}: {[p.name for p in top_pycs]}\n\n"
        + ("\n\n".join(decompiled_sections) if decompiled_sections else "")
    )


@mcp.tool()
def pyc_decompile(pyc_path: str) -> str:
    """
    Decompile or disassemble a Python .pyc bytecode file into readable Python source using pycdc/pycdas.
    """
    target = _validate_path(pyc_path)
    pycdc_bin = _require_tool("pycdc")
    res = subprocess.run([pycdc_bin, str(target)], capture_output=True, text=True, timeout=45)
    out = res.stdout.strip()
    if not out and shutil.which("pycdas"):
        dis = subprocess.run(["pycdas", str(target)], capture_output=True, text=True, timeout=45)
        out = f"// pycdc decompilation incomplete; bytecode disassembly (pycdas):\n{dis.stdout}"
    return out[:20000] if len(out) > 20000 else (out or res.stderr)


# =====================================================================
# Go Binary Symbol & Type Recovery (GoReSym)
# =====================================================================

@mcp.tool()
def go_extract_symbols(binary_path: str, user_funcs_only: bool = True) -> str:
    """
    Extract Go compiler version, build info, package paths, user functions, and struct/type
    definitions from a Go binary (even if stripped) using Mandiant GoReSym.
    """
    target = _validate_path(binary_path)
    goresym = _require_tool("GoReSym")
    res = subprocess.run(
        [goresym, "-t", "-d", "-p", str(target)],
        capture_output=True,
        text=True,
        timeout=90
    )
    if res.returncode != 0 and not res.stdout:
        return f"GoReSym failed: {res.stderr}"

    try:
        data = json.loads(res.stdout)
        summary = {
            "Version": data.get("Version"),
            "BuildInfo": data.get("BuildInfo"),
            "UserFunctions": [
                {
                    "FullName": f.get("FullName"),
                    "Start": hex(f.get("Start", 0)),
                    "End": hex(f.get("End", 0)),
                }
                for f in (data.get("UserFunctions") or [])[:250]
            ],
            "TotalUserFunctions": len(data.get("UserFunctions") or []),
            "TotalStdFunctions": len(data.get("StdFunctions") or []),
        }
        if not user_funcs_only:
            summary["Types"] = [t.get("Str") for t in (data.get("Types") or [])[:150]]
        return json.dumps(summary, indent=2)
    except Exception:
        return res.stdout[:15000]


# =====================================================================
# WebAssembly Tools (WABT: wasm-decompile, wasm2wat, wasm-objdump)
# =====================================================================

@mcp.tool()
def wasm_decompile(wasm_path: str, mode: str = "decompile") -> str:
    """
    Analyze or decompile a WebAssembly (.wasm) binary using WABT.
    mode can be 'decompile' (C-like wasm-decompile), 'wat' (wasm2wat), or 'headers' (wasm-objdump -x).
    """
    target = _validate_path(wasm_path)
    if mode == "decompile":
        tool = _require_tool("wasm-decompile")
        cmd = [tool, str(target)]
    elif mode == "wat":
        tool = _require_tool("wasm2wat")
        cmd = [tool, str(target)]
    elif mode == "headers":
        tool = _require_tool("wasm-objdump")
        cmd = [tool, "-x", str(target)]
    else:
        raise ValueError("mode must be 'decompile', 'wat', or 'headers'.")

    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    out = (res.stdout or res.stderr).strip()
    if len(out) > 20000:
        out_file = _get_output_dir(target) / f"{target.stem}.{mode}.txt"
        out_file.write_text(out, encoding="utf-8")
        return f"Full output saved to {out_file} ({len(out)} chars).\n\nPreview:\n{out[:15000]}"
    return out


# =====================================================================
# Electron / ASAR & JavaScript Deobfuscation Tools
# =====================================================================

@mcp.tool()
def asar_list(asar_path: str) -> str:
    """
    List the contents of an Electron .asar archive without extracting it.
    """
    target = _validate_path(asar_path)
    res = subprocess.run(
        ["asar", "list", str(target)],
        capture_output=True,
        text=True,
        timeout=30
    )
    if res.returncode != 0:
        return f"Error listing ASAR archive: {res.stderr}"
    lines = res.stdout.splitlines()
    if len(lines) > 500:
        return "\n".join(lines[:500]) + f"\n... [{len(lines) - 500} files omitted]"
    return res.stdout.strip()


@mcp.tool()
def asar_extract(asar_path: str, output_name: Optional[str] = None) -> str:
    """
    Extract an Electron .asar archive into the project's output/<output_name>.
    """
    target = _validate_path(asar_path)
    folder_name = _safe_filename(output_name) if output_name else f"{target.stem}_asar"
    out_dir = _get_output_dir(target) / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)

    res = subprocess.run(
        ["asar", "extract", str(target), str(out_dir)],
        capture_output=True,
        text=True,
        timeout=120
    )
    if res.returncode != 0:
        return f"Error extracting ASAR archive: {res.stderr}"
    return f"Successfully extracted {target.name} to {out_dir}"


@mcp.tool()
def js_beautify_file(script_path: str, output_name: Optional[str] = None) -> str:
    """
    Beautify/format minified JavaScript using js-beautify and write to the project's output/.
    """
    target = _validate_path(script_path)
    out_name = _safe_filename(output_name) if output_name else f"{target.stem}.beautified.js"
    out_path = _get_output_dir(target) / out_name

    res = subprocess.run(
        ["js-beautify", "-f", str(target), "-o", str(out_path)],
        capture_output=True,
        text=True,
        timeout=60
    )
    if res.returncode != 0:
        return f"js-beautify failed: {res.stderr}"
    preview = out_path.read_text(encoding="utf-8", errors="replace")[:4000]
    return f"Saved beautified JS to {out_path}\n\nPreview:\n{preview}"


@mcp.tool()
def js_deobfuscate(
    script_path: str,
    tool: str = "synchrony",
    output_name: Optional[str] = None
) -> str:
    """
    Deobfuscate obfuscated JavaScript using 'synchrony' or 'deobfuscator'
    and save the cleaned output to the project's output/.
    """
    target = _validate_path(script_path)
    out_name = _safe_filename(output_name) if output_name else f"{target.stem}.deobf.js"
    out_path = _get_output_dir(target) / out_name

    if tool == "synchrony":
        cmd = ["synchrony", "deobfuscate", "-o", str(out_path), str(target)]
    elif tool == "deobfuscator":
        cmd = ["deobfuscator", str(target), "-o", str(out_path)]
    else:
        raise ValueError("Unsupported tool. Choose 'synchrony' or 'deobfuscator'.")

    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if res.returncode != 0 and not out_path.exists():
        return f"Deobfuscation with {tool} failed: {res.stderr or res.stdout}"

    if out_path.exists():
        preview = out_path.read_text(encoding="utf-8", errors="replace")[:4000]
        return f"Deobfuscated output written to {out_path}\n\nPreview:\n{preview}"
    return res.stdout.strip()


@mcp.tool()
def rea_analyze(target_path: str) -> str:
    """
    Run @morluto/rea static reverse-engineering analysis on a file or directory.
    """
    target = _validate_path(target_path)
    res = subprocess.run(
        ["rea", str(target)],
        capture_output=True,
        text=True,
        timeout=120
    )
    if res.returncode != 0 and not res.stdout:
        return f"Error running rea: {res.stderr}"
    return (res.stdout or res.stderr).strip()


# =====================================================================
# Dynamic Syscall / Library Call Tracing (strace / ltrace / qemu-user)
# =====================================================================

@mcp.tool()
def dynamic_trace_syscalls(
    binary_path: str,
    args: str = "",
    tracer: str = "strace",
    qemu_arch: Optional[str] = None,
    timeout_seconds: int = 10
) -> str:
    """
    Run an ELF binary under strace or ltrace (or qemu-<arch> -strace for cross-architecture
    binaries like arm, aarch64, mips) inside a temporary copy in /tmp to observe syscalls,
    file accesses, and network connection attempts.
    """
    target = _validate_path(binary_path)
    with tempfile.TemporaryDirectory(dir="/tmp") as run_dir:
        exec_copy = Path(run_dir) / target.name
        shutil.copy2(target, exec_copy)
        exec_copy.chmod(0o755)

        extra_args = shlex.split(args) if args else []
        if qemu_arch:
            qemu_bin = _require_tool(f"qemu-{qemu_arch}")
            cmd = [qemu_bin, "-strace", str(exec_copy), *extra_args]
        elif tracer == "ltrace":
            ltrace_bin = _require_tool("ltrace")
            cmd = [ltrace_bin, "-f", "-s", "200", str(exec_copy), *extra_args]
        else:
            strace_bin = _require_tool("strace")
            cmd = [strace_bin, "-f", "-s", "200", str(exec_copy), *extra_args]

        try:
            res = subprocess.run(
                cmd,
                cwd=run_dir,
                capture_output=True,
                text=True,
                timeout=timeout_seconds
            )
            out = (res.stderr or "") + "\n" + (res.stdout or "")
        except subprocess.TimeoutExpired as exc:
            out = (
                f"[Process timed out after {timeout_seconds}s]\n"
                + ((exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")))
            )

        return out.strip()[-15000:]


@mcp.tool()
def gdb_analyze(
    binary_path: str,
    gdb_commands: str = "info files\ninfo functions",
    debugger: str = "gdb",
    timeout_seconds: int = 30
) -> str:
    """
    Run headless batch commands in `gdb-multiarch` (or `lldb`) against a binary.
    Pass newline- or semicolon-separated debugger commands in `gdb_commands`
    (e.g. 'info files; disassemble main; x/16gx 0x180633250').
    """
    target = _validate_path(binary_path)
    raw_cmds = [c.strip() for part in gdb_commands.splitlines() for c in part.split(";") if c.strip()]

    if debugger == "lldb" and shutil.which("lldb"):
        cmd = ["lldb", "--batch", str(target)]
        for c in raw_cmds:
            cmd.extend(["-o", c])
    else:
        gdb_bin = shutil.which("gdb-multiarch") or _require_tool("gdb")
        cmd = [gdb_bin, "-q", "-nh", "-batch", "-ex", "set pagination off"]
        for c in raw_cmds:
            cmd.extend(["-ex", c])
        cmd.append(str(target))

    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    out = ((res.stdout or "") + "\n" + (res.stderr or "")).strip()
    return out[:20000] if len(out) > 20000 else (out or "No output returned by debugger.")


if __name__ == "__main__":
    mcp.run(transport="stdio")
