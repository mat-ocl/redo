#!/usr/bin/env bash
set -euo pipefail

# 1. Resolve repository root (directory containing this script)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="${RE_IMAGE_NAME:-re-sandbox:latest}"

# 2. Resolve target project directory (arg 1 -> RE_PROJECT_DIR -> CWD if samples/output exist -> REPO_ROOT)
PROJECT_DIR="${1:-${RE_PROJECT_DIR:-}}"
if [[ -z "${PROJECT_DIR}" ]]; then
    if [[ -d "${PWD}/samples" || -d "${PWD}/output" ]]; then
        PROJECT_DIR="${PWD}"
    else
        PROJECT_DIR="${REPO_ROOT}"
    fi
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
    -v "${SAMPLES_DIR}:/workspace/samples:ro"
    -v "${OUTPUT_DIR}:/workspace/output:rw"
    -v "${REPO_ROOT}/re_mcp_server.py:/opt/re-mcp/re_mcp_server.py:ro"
)

# 3. Optional multi-project host directory mount
HOST_CODE_DIR="${RE_HOST_CODE_DIR:-}"
if [[ -n "${HOST_CODE_DIR}" && -d "${HOST_CODE_DIR}" ]]; then
    DOCKER_ARGS+=(
        -v "${HOST_CODE_DIR}:/workspace/host_code:rw"
        -e "RE_HOST_CODE_ROOT=${HOST_CODE_DIR}"
    )
fi

exec docker "${DOCKER_ARGS[@]}" "${IMAGE_NAME}" re-mcp-server
