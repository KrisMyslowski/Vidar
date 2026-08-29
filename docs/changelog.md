# Changelog

What changed, and when. Newer releases go on top and group their changes under **Added**,
**Changed**, **Fixed** and **Removed**.

The first entry is the exception: there is no "before" to compare a first release against, so it
lists the scope instead. The number lives in `src/__init__.py`, is echoed in `pyproject.toml`,
and the dashboard prints it beside its name in the sidebar, linked to the tag it names.

Versions follow [semantic versioning](https://semver.org).

---

## 1.0.0 — 2026-08-29

First public release.

Vidar reads an Nginx access log and turns raw HTTP requests into a structured account of who —
and what — is reaching a website. Nothing is added to the observed site: no script, no cookie,
no client-side tracking.

### Added

- **Archives can expire.** The rolling window bounded the database and nothing bounded the zips
  beside it, so two months of retention could sit on three years of data. Settings → Storage now
  carries a second, separate control for how long an archive outlives its own month. It defaults
  to keeping everything, so no existing deployment loses anything by updating. Age is counted
  from the month the archive names rather than the file's timestamp, pinned months are skipped,
  every automatic deletion is logged with month and size, and a window shorter than the rolling
  one is raised — below that the same pass would write a zip and delete it again. Expiry
  runs in Rolling only: Lifetime promises that nothing is deleted, and the control sits
  with the mode that produces archives.

### Changed

- The cost of a classifier-version bump is measured rather than guessed: 5.8 seconds to
  reclassify a million visits across 24 000 addresses, linear in both directions, 5.5 MB peak.
  [architecture.md](architecture.md) carries the table and the method. The risk table used to
  call it "one slow pass"; it is not one.

### Deprecated

- `RETENTION_DAYS` is removed in 2.0. It has purged nothing since retention became a calendar
  window set in the UI, and it stays declared only because an unknown key in `.env` stops the
  container — dropping the field would break the start for every operator whose file still
  names it. Setting it changes nothing in the meantime.

### Documentation

- **A privacy document.** Vidar stores an IP address for every request, enriches it from four
  external services and keeps the result for months — all of it personal data under the GDPR.
  [privacy.md](privacy.md) says what is stored, what leaves the server, what the operator is
  responsible for, and what the software cannot do for them: no anonymisation mode, no
  per-address erasure, archives that never expire. Stated rather than left to be discovered.

### Ingestion

- Tails an Nginx JSON access log, surviving rotation and truncation, and stores the read
  position so a restart resumes where it stopped rather than re-counting.
- Filters static assets and internal IPs before a request becomes a visit. Which paths count as
  your own is configuration, not a guess: `STATIC_ASSET_PREFIXES` says where your assets live,
  because a `.json` below it is your translation file and one anywhere else is somebody hunting
  for secrets.
- Records protocol errors as pseudo-paths, so a TLS handshake against the plain HTTP port is
  visible instead of silently dropped.

### Enrichment

- Four providers, all on free tiers, all optional in the sense that a failure degrades
  enrichment without stopping ingestion: **ip-api.com** (geo, ASN, proxy/hosting/mobile, batched
  100 at a time), **Shodan InternetDB** (open ports, hostnames, tags, CVEs, no API key),
  **reverse DNS** (forward-confirmed PTR) and the **Tor exit list** (cached 24 h).
- **DNSBL** lookups against `zen.spamhaus.org` and `bl.spamcop.net`, reading the returned A
  record as the answer rather than treating "it resolved" as "it is listed". Spamhaus needs a
  free DQS key; without one the signal carries no data and says so.
- Only the IP address is ever sent to a provider.

### Classification

- **Identity and reputation are separate dimensions.** 18 identity classes in 5 groups answer
  *who* the visitor is; Tor, proxy, hosting, DNSBL, Shodan-tag and mobile are six orthogonal
  signals layered on top. A person behind a VPN stays a human with a proxy signal.
- A deterministic priority chain over evidence from the visit history, behaviour-first: a
  malicious or bot-like action outranks a browser-look, and reputation alone never downgrades a
  real person.
- **Every verdict shows its work.** The visitor detail page replays the chain in the order it
  was applied — the deciding rule first, then the context that did not decide it.
- **A declared crawler is verified before it is believed or doubted.** Reverse DNS naming the
  operator confirms it; so does the network it runs on, which is the half a tenant cannot set.
  Only a claim that neither supports, from a hosting address, is an impersonator.
- Labels requalify as behaviour accumulates, and a rule change reclassifies every IP once.

### Surfaces

- **Visitors** — one page for every way of slicing the same data: group by IP, network,
  country, client or path, and switch between table, map and timeline. Aggregate rows carry a
  proportional class mix and signal bar rather than a single badge, so a row shows its
  composition instead of its majority.
- **Search is field-aware** — `country:DE`, `ua:wget`, `tag:scanner`, `port:22`, `status:4xx`,
  or a bare term matched by shape: two letters are a country, `AS…` a network, a leading `/` a
  path.
- **Map** — markers coloured by identity group, clustered or rendered as a density grid. The
  selection panel recomputes from whatever is inside the viewport, so panning is the selection.
- **Analysis** — the Identity × Signals matrix, with every cell linking to the IPs behind it.
- **Exposure** — what Shodan knows about the hosts that visited: open ports, tags and CVEs as
  facets over the same host set.
- **Overview** — totals, activity over time, and a findings list for what is worth a look.
- **Documentation** — the book in the sidebar footer opens these documents inside the
  dashboard. `docs/.order` sets the order; a document missing from it is appended rather than
  hidden. Rendered with raw HTML escaped, so a document cannot put markup into the page.

### Storage

- A single SQLite file in WAL mode; all access through one connection factory.
- **Retention is a calendar window** — the current month plus the last N (0–24, set in the UI),
  or Lifetime to keep everything. A month that falls out is written to
  `/data/archive/YYYY-MM.zip` **before** its rows are deleted, never after.
- Archives can be downloaded, re-imported for a pinned number of days, put back early, or
  deleted. Re-import is idempotent: rows keep their original id and an archived snapshot can
  never roll back fresher data.
- Daily `VACUUM INTO` snapshots, keeping the newest 7, declined rather than run when free space
  drops below 2.5× the database.
- Whole-database export as CSV or JSON, rate-limited per IP.

### Security

- The dashboard binds `127.0.0.1` and is reachable only through an SSH tunnel.
- Container runs with a read-only root filesystem, as a non-root user, with
  `no-new-privileges` and a loopback-only published port.
- A per-request CSP nonce, and no inline event handlers anywhere in the markup.
- Leaflet is pinned by subresource integrity; it and the map tiles are the only external
  browser-side requests, both named explicitly in the CSP.

### Operations

- Everything runs in one asyncio event loop inside one container: log tailer, enrichment
  worker, and the daily retention, archive and backup passes. **No cron, no queue broker, no
  second service** — periodic work lives in the application lifespan, where it runs as the same
  user and logs to `docker logs`.
- Settings pages for retention, archives, snapshots and the JSON API, plus a status page:
  read position, enrichment backlog, provider health, and the configuration the service
  actually loaded — with the DNSBL key reduced to whether it is there.
- `GET /api/stats` reports the running version alongside the figures.
- An interactive deploy script that validates the server's `.env` through the settings model,
  shows a key-name-only diff, and runs the test suite before it ships anything.
- **A preflight that names the cause when the dashboard is empty.** `python -m src.preflight`
  checks ten things inside the container — the log file and its format, both clocks, the three
  directories it writes to, the site settings — and reports the fix rather than the symptom.
  Nearly everything that goes wrong at install time is silent, and this is what breaks that.
- A configurable host port and basemap key (`VIDAR_PORT`, `CARTO_API_KEY`), so a second instance
  can run beside a tunnel to the first and the map is not stamped `API KEY REQUIRED`.

### Stack

Python 3.12, FastAPI, Jinja2, SQLite, markdown-it-py, Docker. No frontend build step and
no chart library —
bar rows, day columns, mix bars and heat grids are CSS, and inline SVG covers what CSS cannot.
