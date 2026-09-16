# Testing

For anyone changing the code. The suite states no size here — every count this document once
carried had drifted within a week. `python -m pytest --collect-only -q` gives the current one,
and `tests/test_docs_counts.py` fails when a test file below goes unnamed.

## 1. Running

```bash
bash scripts/run_tests.sh                    # the full gate: black, isort, ruff, pytest, vitest
VIDAR_STRICT=1 bash scripts/run_tests.sh     # same, but a skipped suite fails the run

python -m pytest -q                          # Python only — with the 3.12 environment active
python -m pytest tests/test_db.py            # one file
python -m pytest tests/test_db.py::test_insert_and_get_visits   # one test
npx vitest run                               # browser-side modules only
```

## 2. A green run can still mean a suite did not run

`run_tests.sh` ends with a `ran:` / `skipped:` summary naming each suite, because three of
them depend on things a workstation may not have. They skip rather than fail, which keeps a
laptop usable and makes the summary the only honest signal. **Read it, or set `VIDAR_STRICT=1`
to turn any skip into a hard failure.**

| Suite | Skips when | Fix |
|---|---|---|
| Layout measurement | no Chrome or Chromium found | install one, or point `VIDAR_CHROME` at it |
| Browser-side modules | `npx` or `node_modules/` missing | `npm install` once |
| Layout measurement | Node older than 21 | the global WebSocket measure.mjs uses arrived there |
| Interpreter check | `python3` is not 3.12 | point `PYTHON=` at a 3.12 |

`VIDAR_REQUIRE` is the narrower form: a comma-separated list of suite keys — `python`,
`black`, `isort`, `ruff`, `pytest`, `layout`, `vitest` — that must have run, leaving every
other skip a note. It exists because `VIDAR_STRICT` is all or nothing, and the layout suite
skips on any machine without a headless browser: a deploy gate set to strict would abort on
that alone.

So `deploy/deploy_remote.sh` sets `VIDAR_REQUIRE=python,black,isort,ruff,pytest,vitest` and
CI sets `VIDAR_STRICT=1`, which is the honest setting for a runner that has node and Chrome
and therefore no reason to skip anything.

## 3. Configuration

`pyproject.toml` sets `testpaths = ["tests"]`, `pythonpath = ["."]` and
`asyncio_mode = "auto"`. `conftest.py` overrides `LOG_PATH` and `DB_PATH` before any source
module is imported. The `tmp_db` fixture gives each test a fresh database **and clears the
dashboard's aggregate cache** — without that, a surviving entry would answer the next test
from the previous test's data.

## 4. What the suites protect

Grouped by the property they defend rather than by module, because that is what breaks.

**The data contract.** `test_db.py`, `test_db_contract.py`, `test_db_extended.py`,
`test_request_identity.py`, `test_shodan_normalization.py`, `test_shodan_migration.py`,
`test_canonical_event.py` — the schema, the migrations, the partial unique index that
deduplicates crash replays, the child tables that replaced the comma-separated Shodan columns,
and the `Visit` boundary a log format is mapped onto.

**Ingestion.** `test_log_processor*.py` (3 files), `test_log_rotation.py`,
`test_cancellation_finishes_writes.py` — parsing, filtering, rotation and truncation
handling, and that a shutdown mid-batch does not tear a write.

**Enrichment.** `test_enricher.py`, `test_enricher_backs_off.py`,
`test_enrichment_is_not_destructive.py`, `test_failures_are_visible.py` — provider
parsing, backoff, and the two invariants that cost real data when they broke: a silent Shodan
lookup must not erase stored values, and a provider failure must be visible rather than
silently recorded as "clean".

**Classification.** `test_classifier.py`, `test_pattern_pack.py` — the priority chain branch
by branch, every verdict a label the taxonomy knows with a reason attached, and the pattern
pack: an overlay only adds, a broken pack stops the service, a needle edit changes the
fingerprint, and a crawler cannot be declared without the networks it runs from.

**Behaviour and events.** `test_sessions.py`, `test_incidents.py`, `test_baseline.py`,
`test_neighbourhood.py` — sessions cut at the gap and counted in pages, incidents clustered by
signature without one campaign's panel reaching into the next, the median hour a spike is
measured against, and the /24 and ASN an address is judged beside.

**What the site gave away.** `test_exposure.py`, `test_families.py`, `test_report.py`,
`test_decisions.py` — findings that count every address, including ones not yet enriched;
explanations that appear only where they belong; a monthly report that states the rules it
applied and computes nothing of its own; and a decisions feed whose selection travels with it.

**Routes and filters.** `test_dashboard_routes.py`, `test_dashboard_filters.py`,
`test_pagination.py`, `test_url_and_findings.py`, `test_filters_that_cost_data.py`,
`test_api_routes.py`, `test_settings_status.py`, `test_cache_invalidation.py`,
`test_sql_lives_in_queries.py` — every page renders, filters compose, the filters that
*reduce* a result set are the ones most heavily pinned, a write shows on the next render, and
no route builds SQL.

**Search.** `test_search.py`, `test_help_matches_behaviour.py` — the field grammar, and
that the syntax panel describes what the parser actually does.

**Markup and layout.** `test_tip_contract.py`, `test_tooltips.py`,
`test_table_structure.py`, `test_assets.py`, `test_render_does_not_query.py`,
`test_layout_browser.py` ([§5](#5-layout-is-measured-not-inferred)) — tooltips are authored in
exactly one place, header and body rows carry identical column keys, and
templates do not issue queries during rendering.

**Security.** `test_csp.py`, `test_cross_origin_writes.py`, `test_trusted_host.py` — the CSP
header is well formed, its nonce matches the markup and changes per response, no template
carries an inline `on*` handler, a cross-site POST is refused, and a host name outside
`ALLOWED_HOSTS` — a rebound DNS name — gets nothing.

**Storage.** `test_archive.py`, `test_archive_streams.py`, `test_retention.py`,
`test_retention_boundaries.py`, `test_backup.py` — the archive round trip, pins, path safety,
month boundaries across a year, and the write-order guarantee that a zip exists before rows
are deleted.

**Validation and config.** `test_validators.py`, `test_config.py`, `test_ua_parser.py`,
`test_demo_mode.py`, `test_version.py`, `test_preflight.py` — demo data never lands on real
data, the version is one number in two files, and the last covers the checks in
`src/preflight.py`, asserting on the remedy each one names rather than only on the verdict: a check that reports "log format wrong"
without saying which field is missing sends the operator back to the documentation.

**The documents.** `test_docs.py`, `test_docs_reference.py`, `test_docs_counts.py` — every
anchor and section reference resolves, data-reference.md's settings and signal tables match the code,
and the counts and route lists in these documents match the app.

## 5. Layout is measured, not inferred

`test_layout_browser.py` starts the app on a free port and drives a real headless browser over
CDP (`tests/layout/measure.mjs`, using Node's built-in WebSocket — no dependency). It checks
every page at 1280, 1600 and 1920 px, as delivered and with each column toggled: tables fill
their container, nothing overflows out of reach, no visible column collapses to zero, body
cells line up with their headings, and columns of the same type render equally wide.

**Both column defects that ever shipped were invisible to every markup test and are caught by
this one** — jsdom computes no layout. It adds about 14 seconds.

It is also the one suite that needs something the repository cannot provide. Without a browser
it skips, and a skip is not a failure, so a machine with no Chrome never measures layout at all
and never says so louder than one line of summary. Two ways out:

```bash
VIDAR_CHROME=/path/to/chrome bash scripts/run_tests.sh   # a browser you already have
bash scripts/run_layout_docker.sh                        # or none: chromium in a container
```

The second builds `tests/layout/Dockerfile` — chromium plus node 22, since `measure.mjs` needs
the global `WebSocket` that arrived in node 21 — and runs the suite against the working tree,
mounted. The image is dependencies only and is rebuilt when `requirements/` changes; the
runtime image is untouched by any of it. Arguments are passed through, so
`bash scripts/run_layout_docker.sh python -m pytest tests/ -q` runs everything in there.

## 6. Browser-side tests

`tests/js/` covers the DOM modules with vitest and jsdom. Node is a development dependency
only; the service runs without it.

The scripts under `src/static/js/` are plain `<script>` files, not modules, so
`tests/js/helpers.js` evaluates a file's source against the current jsdom document and then
fires the event it waits for. **Load a script once per file** (`beforeAll`) — these modules
bind delegated listeners to `document`, so loading twice binds twice and every click is
handled twice.

Node 26 ships an experimental `localStorage` global that shadows jsdom's and stays undefined
without `--localstorage-file`; `tests/js/setup.js` installs a minimal in-memory `Storage` so
the column-picker tests exercise the real persistence path.

## 7. Walking the CSP by hand

`security_headers()` in `src/main.py` sends a `Content-Security-Policy` allowing only what the
dashboard was found to load. A policy fails in the *browser* and nowhere else: a blocked script
leaves the page rendering, returning 200, with every test green. `tests/test_csp.py` proves the
header is well formed and that its nonce matches the markup — it cannot prove the allow-list is
complete.

Static rendering is covered: the map, its tiles, Leaflet from unpkg and the theme bootstrap all
come up under a real headless browser with the policy active. What is left needs a hand, once,
after the first deploy — open the console and walk these four:

| Where | What must work | Which directive it exercises |
|---|---|---|
| any page | `↻ Refresh` reloads | `actions.js`, was an inline `onclick` |
| `/settings/storage` | Delete asks for confirmation first | `actions.js`, was an inline `onsubmit` |
| any page with a date filter | the date pickers refuse a future day | `actions.js`, was an inline `<script>` |
| `/visitors?view=timeline` | activity chart refetches when zoomed below three days | `connect-src 'self'` |

**Walked 2026-08-28, no violations.** Refresh performed a real reload; Delete left the month in
the database, which is the proof that the handler ran rather than the form posting straight
through; both date inputs carried `max=<today>`, an attribute the server does not send; and
zooming past the three-day boundary fetched `/api/activity?bucket=hour` for 200. Worth redoing
after any change to `actions.js`, `timeline.js` or `_CSP_TEMPLATE`.

If something is blocked, the console names the directive. Widen that one directive in
`_CSP_TEMPLATE` — never `script-src 'unsafe-inline'`: browsers ignore `'unsafe-inline'` when a
nonce is present, so the header would become decoration.
