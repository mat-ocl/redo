#!/usr/bin/env bash
set -euo pipefail

# 1. Resolve directory containing this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="${RE_IMAGE_NAME:-ghcr.io/mat-ocl/redo:latest}"

# 2. Ensure ghcr.io/mat-ocl/redo:latest exists locally; auto-pull from GHCR on stderr if missing
if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo "[*] Local image '${IMAGE_NAME}' not found. Pulling '${IMAGE_NAME}'..." >&2
    docker pull "${IMAGE_NAME}" >&2 || true
fi

# 3. Resolve project directory:
#    Priority 1: Explicit arg 1 or RE_PROJECT_DIR
#    Priority 2: Project-local installation path (<Project>/.agents/plugins/redo or <Project>/redo-plugin)
#    Priority 3: PWD (if not $HOME or /)
PROJECT_DIR="${1:-${RE_PROJECT_DIR:-}}"
if [[ -z "${PROJECT_DIR}" ]]; then
    if [[ "${SCRIPT_DIR}" == */.agents/plugins/redo ]]; then
        PROJECT_DIR="${SCRIPT_DIR%/.agents/plugins/redo}"
    elif [[ "${SCRIPT_DIR}" == */redo-plugin ]]; then
        PROJECT_DIR="${SCRIPT_DIR%/redo-plugin}"
    elif [[ "${SCRIPT_DIR}" == */.redo ]]; then
        PROJECT_DIR="${SCRIPT_DIR%/.redo}"
    elif [[ "${PWD}" != "${HOME}" && "${PWD}" != "/" ]]; then
        PROJECT_DIR="${PWD}"
    else
        PROJECT_DIR="${SCRIPT_DIR}"
    fi
fi

PROJECT_DIR="$(cd "${PROJECT_DIR}" && pwd)"
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

if [[ -f "${SCRIPT_DIR}/re_mcp_server.py" ]]; then
    DOCKER_ARGS+=(-v "${SCRIPT_DIR}/re_mcp_server.py:/opt/re-mcp/re_mcp_server.py:ro")
fi

exec docker "${DOCKER_ARGS[@]}" "${IMAGE_NAME}" re-mcp-server
