#!/usr/bin/env bash
set -euo pipefail

# 1. Resolve repository root (directory containing this script)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="${RE_IMAGE_NAME:-ghcr.io/mat-ocl/redo:latest}"

PLUGIN_STATE_DIR="${HOME}/.gemini/config/plugins/re-sandbox"
ACTIVE_WORKSPACE_FILE="${PLUGIN_STATE_DIR}/active_workspace.txt"

# 2. Ensure ghcr.io/mat-ocl/redo:latest exists locally; auto-pull from GHCR on stderr if missing
if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo "[*] Local image '${IMAGE_NAME}' not found. Pulling '${IMAGE_NAME}'..." >&2
    docker pull "${IMAGE_NAME}" >&2 || true
fi

# 3. Resolve active project directory:
#    arg 1 -> RE_PROJECT_DIR -> PWD (when spawned per-project by Zed/Cursor/VS Code/Claude) -> active_workspace.txt -> REPO_ROOT
PROJECT_DIR="${1:-${RE_PROJECT_DIR:-}}"
if [[ -z "${PROJECT_DIR}" ]]; then
    if [[ "${PWD}" != "${HOME}" && "${PWD}" != "${REPO_ROOT}" && "${PWD}" != "/" ]]; then
        PROJECT_DIR="${PWD}"
    elif [[ -f "${ACTIVE_WORKSPACE_FILE}" ]]; then
        SAVED_WS="$(tr -d '\r\n' < "${ACTIVE_WORKSPACE_FILE}")"
        if [[ -n "${SAVED_WS}" && -d "${SAVED_WS}" ]]; then
            PROJECT_DIR="${SAVED_WS}"
        fi
    fi
fi
if [[ -z "${PROJECT_DIR}" ]]; then
    PROJECT_DIR="${REPO_ROOT}"
fi

SAMPLES_DIR="${PROJECT_DIR}/samples"
OUTPUT_DIR="${PROJECT_DIR}/output"
mkdir -p "${SAMPLES_DIR}" "${OUTPUT_DIR}"

DOCKER_ARGS=(
    run -i --rm
    --network none
    --cap-drop ALL
    --cap-add CHOWN
    --cap-add DAC_OVERRIDE
    --cap-add SETUID
    --cap-add SETGID
    --cap-add SYS_PTRACE
    --security-opt seccomp=unconfined
    --security-opt no-new-privileges:true
    -e "PYTHONUNBUFFERED=1"
    -e "RE_PROJECT_ROOT=${PROJECT_DIR}"
    -v "${SAMPLES_DIR}:/workspace/samples:ro"
    -v "${OUTPUT_DIR}:/workspace/output:rw"
    -v "${PROJECT_DIR}:/workspace/project:rw"
)

if [[ -f "${REPO_ROOT}/re_mcp_server.py" ]]; then
    DOCKER_ARGS+=(-v "${REPO_ROOT}/re_mcp_server.py:/opt/re-mcp/re_mcp_server.py:ro")
fi

exec docker "${DOCKER_ARGS[@]}" "${IMAGE_NAME}" re-mcp-server
