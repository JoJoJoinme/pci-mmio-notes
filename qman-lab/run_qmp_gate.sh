#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
qemu=${QMAN_QEMU_BINARY:-/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64}
if [[ $# -gt 1 ]]; then
    echo "usage: $0 [new-output-directory]" >&2
    exit 2
fi
if [[ $# -eq 1 ]]; then
    output=$1
else
    artifact_root=${QMAN_ARTIFACT_ROOT:-"$HOME/qman-artifacts"}
    output="$artifact_root/qmp-gate-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
if [[ -e "$output" ]]; then
    echo "output must not already exist: $output" >&2
    exit 2
fi
if [[ ! -x "$qemu" ]]; then
    echo "QEMU binary is not executable: $qemu" >&2
    exit 2
fi

python3 "$repo_root/qman-lab/test_qman_qmp_gate.py"
python3 "$repo_root/qman-lab/test_qman_qmp_gate.py" \
    --integration \
    --qemu "$qemu" \
    --policy "$repo_root/qman-lab/qmp-gate-policy-v1.json" \
    --output "$output"

echo "QMP gate artifacts: $output"
