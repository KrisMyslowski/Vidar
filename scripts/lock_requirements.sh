#!/usr/bin/env bash
# Write requirements/runtime.lock: every package the image installs, pinned, with
# the hash of each of its distributions.
#
# runtime.txt says what the service wants, in ranges a person reads. The lock
# says what was tested and what ships, exactly: two builds of one commit install
# the same bytes, and checking out an old commit to roll back restores its
# dependencies as well as its code. The Dockerfile installs with
# --require-hashes, so a package that changed under the same version is refused.
#
# Resolved for Linux and Python 3.12, whatever machine runs this — uv resolves for
# a target platform rather than for the host. The hashes cover every wheel of a
# pinned version, so the one file serves the amd64 and the arm64 image alike.
#
#   bash scripts/lock_requirements.sh            keep existing pins, add what is new
#   bash scripts/lock_requirements.sh --upgrade  move every pin to the newest allowed
#
# Existing pins are kept unless --upgrade is given: uv reads the current lock as
# its preference. That is what lets CI regenerate the file and require no diff —
# it changes only when runtime.txt does.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

UV="${UV:-}"
if [ -z "$UV" ]; then
    for candidate in .venv/bin/uv uv; do
        if command -v "$candidate" >/dev/null 2>&1; then UV="$candidate"; break; fi
    done
fi
[ -n "$UV" ] || { echo "uv not found — pip install -r requirements/dev.txt" >&2; exit 1; }

"$UV" pip compile requirements/runtime.txt \
    --python-version 3.12 \
    --python-platform x86_64-unknown-linux-gnu \
    --generate-hashes \
    --custom-compile-command "bash scripts/lock_requirements.sh" \
    --output-file requirements/runtime.lock \
    --quiet \
    "$@"
