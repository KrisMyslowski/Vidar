#!/usr/bin/env bash
set -euo pipefail

# Run from the repo root (this script lives in scripts/).
cd "$(dirname "$0")/.."

# Two ways to insist that a suite actually ran.
#
# VIDAR_STRICT=1 turns every "skipped, carry on" below into a failure. That is
# the right setting for CI, which has node and a browser, and the wrong one for
# a workstation that has neither: strict mode there aborts over a skip that was
# always going to happen, which is why the deploy script never set it and why
# four documents ended up describing the gap instead of closing it.
#
# VIDAR_REQUIRE is the closing: a comma-separated list of suite keys that must
# have run, leaving every other skip a note. The deploy sets it to the suites
# no machine has an excuse for, so the gate has teeth without depending on
# Chrome being installed. Keys: python, black, isort, ruff, pytest, layout,
# vitest.
STRICT="${VIDAR_STRICT:-0}"
REQUIRE="${VIDAR_REQUIRE:-}"
SKIPPED=()
SKIPPED_KEYS=()
RAN=()

# note_skip <key> <message>. The key is what VIDAR_REQUIRE names; the message is
# what a human reads.
note_skip() {
    SKIPPED_KEYS+=("$1")
    SKIPPED+=("$2")
    echo "SKIP: $2"
}

# ── Interpreter ──────────────────────────────────────────────────────────────
# requires-python in pyproject.toml is the contract, and the deploy image
# (python:3.12-slim) honours it. A bare `python3` on a workstation can be years
# older — the tests then pass against an interpreter the service never runs on.
# Prefer an exact match if one is installed; otherwise say so on every run.
REQUIRED="$(sed -n 's/^requires-python *= *">=\([0-9.]*\)".*/\1/p' pyproject.toml)"

# An interpreter is only usable here if it can also run the gates. A bare
# pythonX.Y from a package manager satisfies the version check and has no black,
# no isort, no pytest — and the run then dies on the first gate with a
# ModuleNotFoundError that says nothing about why. Installing one is enough to
# break a deploy that worked the day before, so the check is for the tooling.
has_tooling() {
    "$1" -c 'import black, isort, pytest' >/dev/null 2>&1
}

# Every candidate in preference order, PYTHON first when it is set. A value
# from the environment is a preference, not an instruction: an activated
# virtualenv that has since been deleted still exports its path, and treating
# that as final turned "the venv is gone" into a failed deploy. Anything that
# cannot run the gates is passed over, whoever named it.
CANDIDATES=()
[ -n "${PYTHON:-}" ] && CANDIDATES+=("$PYTHON")
CANDIDATES+=(".venv/bin/python" "python${REQUIRED}" "python3" "/usr/bin/python3")

PYTHON=""
TRIED=()
for candidate in "${CANDIDATES[@]}"; do
    command -v "$candidate" >/dev/null 2>&1 || [ -x "$candidate" ] || continue
    TRIED+=("$candidate")
    if has_tooling "$candidate"; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "FAIL: no interpreter here can run the gates (need black, isort, pytest)." >&2
    echo "  Tried: ${TRIED[*]:-none}" >&2
    echo "  Install them:  python3 -m pip install -r requirements/dev.txt" >&2
    echo "  Or build the project venv, which this script prefers when present:" >&2
    echo "    python${REQUIRED} -m venv .venv && .venv/bin/pip install -r requirements/dev.txt" >&2
    exit 1
fi

PY_VERSION="$("$PYTHON" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
if ! "$PYTHON" -c "
import sys
req = tuple(int(x) for x in '${REQUIRED}'.split('.'))
sys.exit(0 if sys.version_info[:len(req)] >= req else 1)
"; then
    note_skip python "python ${PY_VERSION} is below the required ${REQUIRED} — the suite is not \
running on the interpreter this service ships with (see deploy/Dockerfile). \
Install python${REQUIRED}, set PYTHON=..., or run the suite in the deploy image: \
docker run --rm -v \"\$PWD:/app\" -w /app python:${REQUIRED}-slim \
sh -c 'pip install -q -r requirements/runtime.txt -r requirements/dev.txt && python -m pytest -q'"
else
    RAN+=("python ${PY_VERSION}")
fi

# ── Format and lint gates ────────────────────────────────────────────────────

"$PYTHON" -m black --check .
"$PYTHON" -m isort --check-only .
RAN+=("black" "isort")

# ── Lint ─────────────────────────────────────────────────────────────────────
# Formatting is not linting: neither black nor isort can see a dead parameter or
# a symbol nobody references, and both have shipped here. ruff is a development
# dependency, so a missing one is named in the summary rather than fatal — the
# pre-commit hook installs its own pinned copy and gates the commit regardless.

if "$PYTHON" -m ruff --version >/dev/null 2>&1; then
    "$PYTHON" -m ruff check .
    RAN+=("ruff")
elif command -v ruff >/dev/null 2>&1; then
    ruff check .
    RAN+=("ruff")
else
    note_skip ruff "ruff (not installed — pip install ruff)"
fi

# ── Python suite ─────────────────────────────────────────────────────────────
# Includes tests/test_layout_browser.py, which starts the app and measures the
# rendered tables in a real headless browser (~14s of the run). Markup tests
# cannot see a column laid out at zero width or a table filling half its
# container; both shipped that way.

"$PYTHON" -m pytest -q "$@"
RAN+=("pytest")

# The layout suite skips itself from inside pytest, which a green run does not
# show. Check its preconditions here so the summary can name it — same discovery
# order as tests/layout/measure.mjs.

# measure.mjs drives Chrome over the DevTools protocol with no dependencies,
# which it can only do on a Node that has a global WebSocket: that arrived in
# 21. On an older one every layout test errors with "WebSocket is not defined",
# twenty times, saying nothing about the version. CI found that the hard way.
_NODE_WS_MAJOR=21
have_new_enough_node() {
    command -v node >/dev/null 2>&1 || return 1
    [ "$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)" \
        -ge "$_NODE_WS_MAJOR" ]
}

have_browser() {
    [ -n "${VIDAR_CHROME:-}" ] && [ -x "${VIDAR_CHROME}" ] && return 0
    for b in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
             "/Applications/Chromium.app/Contents/MacOS/Chromium" \
             "$(command -v google-chrome || true)" \
             "$(command -v chromium || true)"; do
        [ -n "$b" ] && [ -x "$b" ] && return 0
    done
    return 1
}

if ! command -v node >/dev/null 2>&1; then
    note_skip layout "layout measurement (no node)"
elif ! have_new_enough_node; then
    note_skip layout "layout measurement (node $(node -p 'process.versions.node') is older than \
${_NODE_WS_MAJOR}, which is where the global WebSocket measure.mjs needs arrived)"
elif ! have_browser; then
    note_skip layout "layout measurement (no chrome/chromium — set VIDAR_CHROME)"
else
    RAN+=("layout measurement")
fi

# ── Browser-side modules ─────────────────────────────────────────────────────
# The column picker, slide-over, tab panels and map selection are tested with
# vitest. Node is a development dependency only — the service runs without it.

echo
if ! command -v npx >/dev/null 2>&1; then
    note_skip vitest "js suite (no node)"
elif [ ! -d node_modules ]; then
    note_skip vitest "js suite (no node_modules — run 'npm install')"
else
    npx vitest run
    RAN+=("vitest")
fi

# ── Summary ──────────────────────────────────────────────────────────────────
# A green run that silently left two suites out looks exactly like a complete
# one. Name both halves, every time.

echo
echo "ran:     ${RAN[*]}"
if [ ${#SKIPPED[@]} -eq 0 ]; then
    echo "skipped: nothing"
    exit 0
fi

printf 'skipped: %s\n' "${SKIPPED[0]}"
for s in "${SKIPPED[@]:1}"; do printf '         %s\n' "$s"; done

if [ "$STRICT" = "1" ]; then
    echo
    echo "FAIL: VIDAR_STRICT=1 and ${#SKIPPED[@]} check(s) did not run."
    exit 1
fi

# Named suites are not allowed to skip, whatever else does.
if [ -n "$REQUIRE" ]; then
    missing=()
    for want in ${REQUIRE//,/ }; do
        for got in "${SKIPPED_KEYS[@]}"; do
            [ "$got" = "$want" ] && missing+=("$want") && break
        done
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo
        echo "FAIL: VIDAR_REQUIRE names ${missing[*]}, and ${#missing[@]} of them did not run."
        exit 1
    fi
fi
