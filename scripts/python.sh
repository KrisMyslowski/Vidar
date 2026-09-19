#!/usr/bin/env bash
# Run the interpreter this project's gates run on, or print which one it is.
#
#   bash scripts/python.sh -m pytest -q     run it
#   bash scripts/python.sh --which          print its path
#
# One place for the choice, used by scripts/run_tests.sh and by the pytest commit
# hook. The hook used to call a bare `python3`, which resolves to whatever is first
# on PATH at commit time: on a machine whose python3 is older than the project
# needs, every commit died on collection errors that had nothing to do with the
# change, while run_tests.sh — which already chose carefully — passed.
set -euo pipefail

cd "$(dirname "$0")/.."

# requires-python in pyproject.toml is the contract, and the deploy image honours
# it. A bare `python3` on a workstation can be years older — the tests then pass
# against an interpreter the service never runs on.
REQUIRED="$(sed -n 's/^requires-python *= *">=\([0-9.]*\)".*/\1/p' pyproject.toml)"

# An interpreter is only usable if it can also run the gates. A bare pythonX.Y
# from a package manager satisfies the version and has no black, no isort, no
# pytest — and the run then dies on the first gate with a ModuleNotFoundError
# that says nothing about why. So the check is for the tooling.
has_tooling() {
    "$1" -c 'import black, isort, pytest' >/dev/null 2>&1
}

# Every candidate in preference order, PYTHON first when it is set. A value from
# the environment is a preference, not an instruction: an activated virtualenv
# that has since been deleted still exports its path, and treating that as final
# turned "the venv is gone" into a failed deploy. Anything that cannot run the
# gates is passed over, whoever named it.
CANDIDATES=()
[ -n "${PYTHON:-}" ] && CANDIDATES+=("$PYTHON")
CANDIDATES+=(".venv/bin/python" "python${REQUIRED}" "python3" "/usr/bin/python3")

CHOSEN=""
TRIED=()
for candidate in "${CANDIDATES[@]}"; do
    command -v "$candidate" >/dev/null 2>&1 || [ -x "$candidate" ] || continue
    TRIED+=("$candidate")
    if has_tooling "$candidate"; then
        CHOSEN="$candidate"
        break
    fi
done

if [ -z "$CHOSEN" ]; then
    echo "FAIL: no interpreter here can run the gates (need black, isort, pytest)." >&2
    echo "  Tried: ${TRIED[*]:-none}" >&2
    echo "  Install them:  python3 -m pip install -r requirements/dev.txt" >&2
    echo "  Or build the project venv, which is preferred when present:" >&2
    echo "    python${REQUIRED} -m venv .venv && .venv/bin/pip install -r requirements/dev.txt" >&2
    exit 1
fi

if [ "${1:-}" = "--which" ]; then
    echo "$CHOSEN"
    exit 0
fi
exec "$CHOSEN" "$@"
