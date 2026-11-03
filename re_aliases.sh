# ==========================================
# Reverse Engineering Aliases & Helper Functions
# ==========================================

# Tool shortcuts
alias r2='r2 -e bin.relocs.apply=true -q'
alias apkd='apktool d'
alias apkb='apktool b'
alias decompile-apk='jadx -d'
alias capa-scan='capa -r /opt/capa/rules'
alias die-scan='diec -d -e'
alias yara-peid='yara -w -s /usr/lib/die/yara_rules/peid.yar'
alias yara-packers='yara -w -s /usr/lib/die/yara_rules/packer.yar'
alias yara-crypto='yara -w -s /usr/lib/die/yara_rules/crypto_signature.yar'
alias dsp563-dis='dsp56300-disasm -f u24be'
alias dsp563-dis-le='dsp56300-disasm -f u24le'
alias dsp563-dis-u32='dsp56300-disasm -f u32le'

# Ghidra Headless Helper
# Usage: ghidra-analyze <project_dir> <project_name> <binary_path>
ghidra-analyze() {
    if [ "$#" -lt 3 ]; then
        echo "Usage: ghidra-analyze <project_dir> <project_name> <binary_path>"
        return 1
    fi
    mkdir -p "$1"
    ghidra-headless "$1" "$2" -import "$3" -overwrite
}

# Motorola DSP56300 Quick Disassemble
# Usage: dsp563-dump <rom_or_bin> [u24be|u24le|u32le] [start_addr]
dsp563-dump() {
    if [ "$#" -lt 1 ]; then
        echo "Usage: dsp563-dump <rom_or_bin> [u24be|u24le|u32le] [start_addr]"
        return 1
    fi
    local fmt="${2:-u24be}"
    local start="${3:-0x0}"
    local out_file="${1%.*}_dsp56300.asm"
    echo "[*] Disassembling $1 (format=$fmt, start=$start) -> $out_file..."
    dsp56300-disasm --color never -f "$fmt" -s "$start" "$1" > "$out_file"
    echo "[+] Saved $(wc -l < "$out_file") lines to $out_file"
}

# JADX Quick Unpack
# Usage: jadx-dump <target.apk>
jadx-dump() {
    if [ "$#" -lt 1 ]; then
        echo "Usage: jadx-dump <target.apk>"
        return 1
    fi
    local out_dir="${1%.*}_jadx_out"
    echo "[*] Decompiling $1 to $out_dir..."
    jadx -d "$out_dir" --show-bad-code "$1"
}

# FLOSS Quick Strings
# Usage: floss-clean <binary_path>
floss-clean() {
    if [ "$#" -lt 1 ]; then
        echo "Usage: floss-clean <binary_path>"
        return 1
    fi
    floss --no-static-strings "$1"
}

# .NET ILSpy Quick Decompile
# Usage: dotnet-dump <assembly.exe|dll>
dotnet-dump() {
    if [ "$#" -lt 1 ]; then
        echo "Usage: dotnet-dump <assembly.exe|dll>"
        return 1
    fi
    local out_dir="${1%.*}_dotnet_src"
    mkdir -p "$out_dir"
    ilspycmd -p -o "$out_dir" "$1"
}

# GoReSym Symbol Recovery
# Usage: goresym-dump <go_binary>
goresym-dump() {
    if [ "$#" -lt 1 ]; then
        echo "Usage: goresym-dump <go_binary>"
        return 1
    fi
    GoReSym -t -d -p "$1"
}

# BinHexConv Quick Binary <-> Hex-text Helpers
# Usage: bin2hex <input.bin> [output.hex]
bin2hex() {
    if [ "$#" -lt 1 ]; then
        echo "Usage: bin2hex <input.bin> [output.hex]"
        return 1
    fi
    local out_file="${2:-${1}.hex}"
    bin2hext -b "$1" "$out_file"
    echo "[+] Saved hex text to $out_file"
}

# Usage: hex2bin <input.hex> [output.bin]
hex2bin() {
    if [ "$#" -lt 1 ]; then
        echo "Usage: hex2bin <input.hex> [output.bin]"
        return 1
    fi
    local out_file="${2:-${1%.hex}.bin}"
    bin2hext -h "$1" "$out_file"
    echo "[+] Saved binary to $out_file"
}
