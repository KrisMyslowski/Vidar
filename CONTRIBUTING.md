# Contributing

## Setting up

```bash
pip install -r requirements/dev.txt   # pulls runtime.txt in via -r
npm install                           # browser-side tests only
pre-commit install
```

`requirements/runtime.txt` alone is not enough — the first gate fails on a
missing black. The dev file pins the same versions as `.pre-commit-config.yaml`,
so a local run and the commit hook cannot disagree about what is formatted.

**The image does not install `runtime.txt`.** It installs `requirements/runtime.lock`:
every package pinned, with hashes. After changing a range in `runtime.txt`, run
`bash scripts/lock_requirements.sh` and commit both files — CI fails when they
disagree. `--upgrade` moves every pin to the newest version the ranges allow.

## Before a commit

```bash
bash scripts/run_tests.sh
```

black, isort, ruff, pytest, then vitest; the commit hook runs the same gates.
**Read the `ran:` / `skipped:` summary it ends with** — a green run can mean a
suite did not execute. Every other test command, the strict and required-suite
modes, and running the layout suite without a local browser are in
[testing.md](docs/testing.md).

## Retaking the screenshots

The README's pictures come from synthetic traffic (`src/demo.py`) and are retaken
with one command, in the same browser container the layout suite runs in:

```bash
bash scripts/run_layout_docker.sh python scripts/take_screenshots.py
```

Retake them when the UI changes; they are otherwise the first thing to drift.

## Conventions you would not guess

- **All SQL lives in `src/queries/`.** Route handlers call query functions; they
  never build SQL.
- **No inline `on*` handlers.** The dashboard runs under a CSP with a per-request
  nonce, which cannot cover attribute handlers. Use a data attribute and a
  delegated listener in `actions.js`.
- **A classifier logic change must bump `_RULES_VERSION`**
  (`src/classifier/patterns.py`), which triggers a one-time reclassification of
  every address at startup. `CLASSIFIER_VERSION` is computed from it and the
  pattern pack's digest — it is not the constant you edit.
- **Section header comments** in `src/` are padded to 79 characters.
- **Never hardcode a group or signal colour.** `src/taxonomy.py` and the
  `--grp-*` / `--sig-*` tokens are the single source.
- **Documents are load-bearing.** Tests hold `docs/data-reference.md` to the code:
  the settings table must list every field of `Settings`, the signal table every
  entry of `VALID_SIGNALS`, and every `§` reference must be a link that resolves.

## Where things are

[architecture.md](docs/architecture.md) for how the service is built and why,
[data-reference.md](docs/data-reference.md) for every field, rule and setting,
[testing.md](docs/testing.md) for what each suite protects,
[deployment_tldr.md](docs/deployment_tldr.md) for running it on a server.
