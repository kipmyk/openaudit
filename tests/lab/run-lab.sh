#!/usr/bin/env bash
# Runs every OpenAudit lab scenario in its own disposable container and scores
# the results. Containers are started with --rm and are destroyed after each run.
#
# Usage: tests/lab/run-lab.sh <linux-openaudit-cli-binary> <results-dir>
# Requires: docker (DOCKER_HOST may point at Colima), python3.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUT="$2"
IMAGE="openaudit-lab:ubuntu24.04"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

docker build -q -t "$IMAGE" "$LAB_DIR" >/dev/null

SCENARIOS=$(python3 -c "import json,sys; print(' '.join(json.load(open(sys.argv[1]))['scenarios']))" "$LAB_DIR/expected.json")
for id in $SCENARIOS; do
    echo "running $id" >&2
    docker run --rm --cap-add NET_ADMIN \
        -v "$BIN":/opt/openaudit/openaudit-cli:ro \
        -v "$LAB_DIR":/lab:ro \
        -v "$OUT":/out \
        "$IMAGE" bash /lab/run.sh "$id"
done

python3 "$LAB_DIR/evaluate.py" "$LAB_DIR/expected.json" "$OUT"

