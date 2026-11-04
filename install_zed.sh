#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER_PATH="${REPO_ROOT}/run_re_mcp.sh"
chmod +x "${LAUNCHER_PATH}"

# 1. Update workspace-local .zed/settings.json
mkdir -p "${REPO_ROOT}/.zed"
cat > "${REPO_ROOT}/.zed/settings.json" <<EOF
{
  "context_servers": {
    "redo": {
      "source": "custom",
      "command": "/bin/bash",
      "args": [
        "${LAUNCHER_PATH}"
      ],
      "env": {}
    }
  }
}
EOF
echo "[+] Updated workspace Zed config: ${REPO_ROOT}/.zed/settings.json"

# 2. Print snippet or create ~/.config/zed/settings.json if missing
ZED_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/zed"
mkdir -p "${ZED_CONFIG_DIR}"
ZED_SETTINGS="${ZED_CONFIG_DIR}/settings.json"

if [[ ! -f "${ZED_SETTINGS}" ]]; then
    cp "${REPO_ROOT}/.zed/settings.json" "${ZED_SETTINGS}"
    echo "[+] Created global Zed settings at: ${ZED_SETTINGS}"
else
    echo "[*] Existing Zed settings found at ${ZED_SETTINGS}."
    echo "    Ensure the following block is present under \"context_servers\":"
    cat "${REPO_ROOT}/.zed/settings.json"
fi
