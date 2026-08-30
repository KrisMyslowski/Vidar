# Changelog

What changed, and when. Newer releases go on top and group their changes under **Added**,
**Changed**, **Fixed** and **Removed**, each carrying its version — `### Added in 1.1.0`. The
version is not decoration: these documents are rendered inside the dashboard, headings become
anchors, and two releases both called "Added" would send every link to whichever came first.

The first entry is the exception: there is no "before" to compare a first release against, so it
lists the scope instead. The number lives in `src/__init__.py`, is echoed in `pyproject.toml`,
and the dashboard prints it beside its name in the sidebar, linked to the tag it names.

Versions follow [semantic versioning](https://semver.org).

---

## 1.1.0 — 2026-08-30

Vidar stops answering only *who came* and starts answering *what happened* and *what did this
server give away* — from the same log, with nothing new collected and nothing new asked of
anybody.

### Added in 1.1.0

- **A page for what the site gave away.** `/exposure` reads the same log the other way round:
  paths that answered 2xx and that fewer than two benign addresses ever fetched. On the
  reference deployment it finds one — `/.DS_Store`, 6 148 bytes, 31 addresses over three months
  — a file that had been served since March and that nobody had noticed. Redirects, query
  strings, convention paths and percent-encoded spellings of the same file are all excluded,
  each because an earlier draft reported them and each with a test.

  Each finding carries its own explanation: what the file is, why somebody asked for it, a
  `curl` addressed to this site to check it, and how to stop serving it. The explanation hangs
  on the *family* rather than the path — nine of them, from operating-system metadata to
  diagnostic pages — because the reference deployment carries 26 609 distinct probed paths of
  which the top 500 cover 30 %, and one vulnerability is probed under twenty-five prefixes. A
  finding outside the nine is listed under *Not described here* with a `curl` and no prose,
  rather than under an invented family — the command needs no knowledge of the file, a
  description does. Detection never consults the registry: a file dropped in the document root
  under a name nothing has seen is listed the first time a scanner fetches it.

- **From nine thousand addresses to ten events.** A new page answers what happened rather than
  who came. A scanner is a program and a program starts the same way every run, so when three or
  more addresses ask for the same first five missing paths, in the same order, within an hour,
  that is one incident — with the paths it asked for, the addresses it came from, and how many of
  them are on hosting ranges or blocklists.

  The score beside each is a sort key and the page says so: its arithmetic is printed out of
  numbers already on the page, because a number whose derivation cannot be opened would put a
  score where the evidence used to be. Volume is capped so one address hammering all night cannot
  outrank a coordinated run. Empty is a valid result and the usual one on a small site, and the
  page says that in words rather than showing an empty table.

- **Behaviour, as a third axis.** Identity says what an address is and the signals say where it
  sits; neither could say what it did. Visits are now cut into **sessions** — a run of requests
  with no gap longer than 30 minutes — and each carries a behaviour: browsing, scraping, recon,
  enumeration or brute force. A human can scrape and a crawler can enumerate, and the classifier
  no longer has to weigh those against each other and crown a winner. The detail page shows the
  sentence the dashboard could not say before: arrived from a search engine, read three pages,
  then tried eleven paths that do not exist, in 180 seconds.

  Nothing is stored. Sessionising one address was measured against the evidence query that
  already runs on it — 0.10 ms against 0.42 ms at 66 visits, and 24 ms against 70 ms at 20 000 —
  because the visit index hands the rows over already ordered. That removes the migration, the
  backfill, and any session that could go stale when a month is re-imported from an archive. The
  30-minute threshold and every behaviour threshold are named constants with their reasoning
  written beside them, since each is a model decision rather than a fact.

- **Reputation from Vidar's own data.** The visitor detail page now shows what has already been
  judged next to an address: the same class mix, over the peers in its /24 (its /64 for IPv6)
  and at its ASN. It answers the cold start — a verdict needs history and a first request has
  none, but its neighbours have been seen. Nothing is fetched for it; `ip_intel` already held
  every judgement, and a `net()` SQL function derives the range. Where one group holds a
  majority it is named in words; a plurality is not, because "the largest of five groups" is
  not a character. On a new deployment the panel is empty and says so.

- **A baseline, so Vidar can say when to look.** The Overview's findings gained one that names a
  moment rather than an address: `140 addresses probing in the last hour — 6.7× the typical 21`.
  Deliberately not a chart — a chart is another thing to read, and every number nobody acts on
  makes the rest harder to. Each incident also carries one line placing it against an ordinary
  hour in the same window, including when the answer is "barely above".

  It is a **median**, and the existing Tor finding was moved onto the same footing. It compared
  today against a seven-day *mean*, which is the wrong failure mode for a spike detector: one
  busy day raises the bar, the next spike sits under it, and the finding goes quiet exactly when
  something is happening repeatedly. Hours and days with no traffic are counted back in as zeros,
  or a site busy for two hours a day has two busy hours as its normal.

  Silent where it would be guessing: no baseline under a fortnight of log, none on a site whose
  median hour is empty, and an absolute floor as well as a factor, because a multiple of almost
  nothing is not an event. The hour compared is the last complete one — the current one is still
  filling and would always compare low.

- **An interface for deciding, without deciding.** `GET /api/decisions` hands the addresses
  matching a stated selection to whatever acts — CrowdSec, nftables, a shell script. Vidar stays
  the brain and something else is the hand, which makes it compatible with those tools rather
  than a competitor to them.

  The selection travels with the answer, and every address carries its reason after a `#` — the
  convention the usual consumers already strip, so the file is machine-readable and still
  reviewable by a person. A feed whose membership rule is invisible is a blocklist, and a
  blocklist nobody can open is what the rest of this dashboard argues against. Nothing is ranked
  by a score; the order is what the address did here.

  Asked nothing in particular it answers for `threats/*` over the last week and says that this
  is a recommendation. An empty selection stays empty rather than widening to everything, and a
  capped answer says it was capped rather than quietly handing over a prefix.

- **The patterns are a file now.** 157 needles across fourteen lists lived in code, so every
  newly announced AI crawler meant a code edit, a version bump and a release for one string — and
  an operator with a company-internal scanner had to fork. They are in
  `src/classifier/patterns.toml`, with every comment that explained them, and `PATTERNS_PATH`
  names a second file merged on top. The merge is additive: a pack can add a needle and cannot
  remove one, because removing one describes a rule change and a rule change belongs in a rule.

  The thresholds did not move. Each carries a measurement against a real log and is meaningless
  apart from the rule that reads it; a data file would invite tuning one away from its
  measurement.

  `CLASSIFIER_VERSION` is now `<rules>+<pack digest>` — the digest is a fingerprint of the
  effective pack, so editing a needle reclassifies every stored address on the next start.
  Without it an operator file would apply to addresses seen after the restart and to nothing
  else, and the database would hold two vintages of judgement with no way to tell them apart.
  Comments and formatting do not affect the fingerprint; needles do.

  A broken pack stops the service naming the file, the table and the value, and
  `python -m src.preflight` reports the same without starting it. Detection that quietly falls
  back to no patterns produces a dashboard where everything is unknown and nothing is wrong.

- **The boundary between a log format and Vidar's own vocabulary has a name.** `Visit` is the
  canonical event, `LogEntry` is nginx's spelling of it, and `process_entry()` maps one onto
  the other — the mapping already existed, it was just anonymous. A second log format is now a
  second adapter and nothing else. Verdicts are unchanged: 9 110 addresses classified before and
  after, zero differences.

- The cost of a classifier-version bump is measured rather than guessed: 5.8 seconds to
  reclassify a million visits across 24 000 addresses, linear in both directions, 5.5 MB peak.
  [architecture.md](architecture.md) carries the table and the method. The risk table used to
  call it "one slow pass"; it is not one.

- **The new pages look like the rest of the dashboard.** Incidents, Exposure, the sessions and
  the neighbourhood arrived as stacks of description lists and paragraphs, which read as free
  text beside every other surface. They are what the rest of the app is: a row of tiles, then a
  table whose columns carry their meaning in their own headers, with a column picker where there
  are more columns than fit. The prose that was above the tables is in the tooltips it belonged
  in, and the bespoke green "nothing found" box gave way to the empty state every other table
  uses.

  One defect came out of that: below 1100px a table becomes cards and the field name comes from
  `data-label`, which three of the new tables never carried — a card was a date, three numbers
  and two rows of badges with nothing saying which was which. The structure suite checks
  `data-col` agreement and the layout suite measures widths a card layout does not have, so
  neither could see it. There is a test for it now.

- **`/exposure` is now `/shodan`.** The page shows what Shodan knows about the hosts that
  visited — their open ports, tags and CVEs. That is the visitor's exposure, and the name was
  needed for the other direction: what the site itself gave away. `/tools/shodan` redirects
  there as it always did.

### Fixed in 1.1.0

- **`/exposure` returned nothing under any date range.** The query put the benign class list in
  its SELECT and the time window in its WHERE, then bound them the other way round: the window
  received a class name, `v.timestamp >= 'bots/ai-crawlers'` matched no row, and the page was
  empty under every range — which is every visit to it, since the default tab is 90 days. Ten
  tests passed throughout, all of them calling the query unbounded, the one shape the page never
  uses.

- **The Overview's findings became fifty times more expensive.** The hourly baseline's
  `COUNT(DISTINCT ip)` measured 290 ms on 520 000 visits against 6 ms for every other finding
  together, and that list sits behind the nav badge on every page. It is computed once per hour
  now, keyed on the hour rather than given a duration, and passed in.

- **A log without a timezone silenced every finding.** The naive timestamp made the baseline
  raise, and the caller turns any exception into an empty findings list — so one unusable
  timestamp removed all of them and not just the one it belonged to. A single malformed
  timestamp took `/incidents` down the same way.

- **Settings answered 500 on a mount it could not write to.** The archive directory is created
  on first use, and that create sat on a *read* path: listing the archives hit a read-only
  mount, and Settings — where the gear leads — returned an error page instead of saying what was
  wrong. The listing now answers "none" and the page names the directory, the reason and the
  fix, in the same words `python -m src.preflight` uses.

- **Cards showed values with no field names.** Below 1100px a table becomes cards and the label
  comes from `data-label`, which none of the new tables carried. Neither existing suite could
  see it; there is a test for it now, and `/exposure` and `/incidents` joined the two page lists
  that measure table structure and column widths.

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
