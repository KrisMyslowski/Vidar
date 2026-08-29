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

## Before a commit

```bash
bash scripts/run_tests.sh
```

black, isort, ruff, pytest, then vitest. The commit hook runs the same gates, so
a commit that passes locally passes there.

**Read the last two lines.** The run ends with a `ran:` / `skipped:` summary,
because a workstation may lack node, a headless browser or a 3.12 interpreter and
those suites skip rather than fail — a green run can mean a suite did not
execute. `VIDAR_STRICT=1 bash scripts/run_tests.sh` turns any skip into a
failure, and `VIDAR_REQUIRE=pytest,vitest` insists on named suites while letting
the rest skip — which is what the deploy uses. Details in
[testing.md](docs/testing.md).

The layout suite is the one that skips for a reason you cannot fix by installing
a Python package: it needs a headless browser. `bash scripts/run_layout_docker.sh`
runs it in a container carrying chromium, so no browser has to be installed.

## Conventions you would not guess

- **All SQL lives in `src/queries/`.** Route handlers call query functions; they
  never build SQL.
- **No inline `on*` handlers.** The dashboard runs under a CSP with a per-request
  nonce, which cannot cover attribute handlers. Use a data attribute and a
  delegated listener in `actions.js`.
- **A classifier logic change must bump `CLASSIFIER_VERSION`**
  (`src/classifier/patterns.py`), which triggers a one-time reclassification of
  every address at startup.
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
