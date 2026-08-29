#!/usr/bin/env bash
# The layout suite in a container, for machines without a headless browser.
#
# scripts/run_tests.sh skips layout when it finds no chrome/chromium, so a green
# local run says nothing about it. This builds an image that carries chromium and
# node 22 and runs the suite against the working tree, mounted read-write because
# pytest writes its own temporary databases under /tmp inside the container.
#
# The image is ~700 MB and is rebuilt only when requirements/ changes; every later
# run reuses the layer cache. Nothing here touches the runtime image.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=vidar-layout

if ! docker info >/dev/null 2>&1; then
    echo "docker is not running — start it, or install a browser and set VIDAR_CHROME" >&2
    exit 1
fi

echo "==> building $IMAGE"
docker build -q -f "$ROOT/tests/layout/Dockerfile" -t "$IMAGE" "$ROOT" >/dev/null

echo "==> running the layout suite"
# --init so a chromium that outlives the test run is reaped rather than left as
# a zombie holding the container open.
exec docker run --rm --init \
    -v "$ROOT:/app" \
    -w /app \
    "$IMAGE" "$@"
