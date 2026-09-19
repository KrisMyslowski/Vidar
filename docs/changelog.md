# Changelog

What changed, and when. Newer releases go on top and group their changes under **Added**,
**Changed**, **Fixed** and **Removed**, each carrying its version — `### Added in 1.1.0`. The
version is not decoration: these documents are rendered inside the dashboard, headings become
anchors, and two releases both called "Added" would send every link to whichever came first.

The first entry is the exception: there is no "before" to compare a first release against, so it
lists the scope instead. The number lives in `src/__init__.py`, is echoed in `pyproject.toml`,
and the dashboard prints it beside its name in the sidebar, linked to the tag it names.

Patch releases are folded into the minor they belong to. There were eleven between 1.1.0 and
1.2.0, each a day's work on the same few surfaces, and read one after another they described the
same page four times. Nothing is dropped that changed what an operator sees or how a number is
arrived at; what goes is the version headings between them.

Versions follow [semantic versioning](https://semver.org).

---

## 1.5.0 — 2026-09-18

The dashboard for a keyboard and a screen reader, and the architecture drawn from the code.
Nothing reclassifies on the first start; a host name outside `ALLOWED_HOSTS` is still refused, as
in 1.4.0.

### Added in 1.5.0

- **Every row that opens a panel opens from the keyboard.** The IPs behind an aggregation row,
  an incident, an Exposure finding and a session were reachable by mouse only. The rows are in
  the tab order now and open on Enter or Space; the panel takes focus and gives it back to the
  row when it closes, and it has a name for assistive technology.

- **Sorted columns say so.** A sortable table's current column carries `aria-sort`, and the
  client-sorted table on the Overview sorts from the keyboard too.

- **A focus ring on every control, visible control edges, readable badges.** Tabs, pills,
  buttons and disclosures showed the browser's own ring or none. Control edges hold 3:1 against
  both surfaces in both themes, and badge labels are ink on a tint — coloured text on its own
  tint was 2.91:1 at worst.

- **Architecture diagrams, generated from the code.** Seven SVGs — deployment, components, data
  model, classes, and the ingest, enrich and request sequences — replace the ASCII sketch in
  architecture.md and are served on the documentation pages. Drawing them from the code found
  five places where the prose was wrong; those are corrected.

### Changed in 1.5.0

- **Sizes, radii, stacking, motion and paddings sit on one token scale**, with a test that fails
  on a literal outside it. Motion is zeroed under `prefers-reduced-motion`. One button base
  replaces four, so buttons take the page's typeface instead of the browser's, and hover is a
  quieter tint.

- **Page width is measured instead of hidden.** `html, body { overflow-x: hidden }` cut off
  whatever spilled past the right edge without a trace; a layout test now measures every page
  from 900px up and the rule is gone. It found one overflow, on the documentation pages at
  900px, which is fixed. Phones are not a target: the dashboard is reached through an SSH tunnel.

- **The container image is built and smoke-tested in CI** on every push, not only when a
  release is tagged.

- **The demo shows every surface, and the screenshots are retaken from it.** `DEMO_MODE` seeds a
  scanning tool run twice and a file the server handed out to probers only, so Incidents and
  Exposure are no longer empty tables — and the datacentre group, which the seed never reached,
  is filled. `scripts/take_screenshots.py` retakes all nine README pictures with one command.

### Fixed in 1.5.0

- **An export could fail mid-download.** It kept one SQLite connection open across the rows it
  streamed, and each row may be produced on a different worker thread, which SQLite refuses. It
  now reads a page at a time on a connection of its own.

- **A search about requests ignored the date range.** `path:/.env` over the last week listed
  addresses that asked for it months ago. The search now matches requests inside the window.

- **Background work ran on the event loop.** After a rules change the reclassification froze
  ingestion and every page for its whole length; it and the daily tasks run on worker threads.

- **One busy address could stop the dashboard.** Its sessions were cut with a query that re-ran
  the whole cut once per session: 21.8 s for an address with 110 000 requests, minutes on a
  one-CPU server, and a few reloads of its page held every worker thread while `/health` still
  answered. The cut is computed once now — 0.8 s for the same address, with identical output.

- **A command suggested on Exposure could run what the path said.** The `curl` beside a finding
  was built from the path as a stranger sent it, unquoted; on a site that answers any path with
  200, `/x;$(…)` pasted into a terminal would run on the operator's machine. The URL is now
  one quoted shell word.

- **Smaller:** a restore pin expires by the instant it names, not by how it is written; an
  archive or snapshot is served only from its own directory, never a subdirectory; the detail
  page's Tor, proxy, Shodan and redirect lines are tested.

---

## 1.4.0 — 2026-09-17

A review release: nothing new to look at, and a good deal less that was wrong. Two changes reach
an operator directly, and both are under **Changed** — every stored address is reclassified once
on the first start, and the dashboard now refuses a host name it does not know.

### Added in 1.4.0

- **`ALLOWED_HOSTS`.** The dashboard answers only to the host names listed, loopback by default,
  and refuses any other `Host` with a 400 before a route runs. It is the defence against DNS
  rebinding: a page that points its own domain at 127.0.0.1 is same-origin to the dashboard in
  the operator's browser, which the tunnel does not prevent and the cross-origin write guard does
  not cover — it could read `/api/export` and a whole database snapshot. Behind an authenticating
  proxy, add the name you browse to.

- **Abandoned temporaries are swept.** An export zip whose download was dropped, or a snapshot
  pass killed mid-copy, left a month of visits or a whole uncompressed database on the data
  volume, hidden from every listing and outside retention. Files matching the temporary names
  and older than an hour are removed at startup and hourly, each one named in the log.

### Changed in 1.4.0

- **Classifier rules v7: a page is counted once however its query string is spelled.** The
  human gate's page floors were measured in pages, and `/?utm_source=a`, `/?utm_source=b` and
  `/?ref=c` were three of them. **Every stored address is reclassified on the first start.**

- **Convention-file needles are anchored on the slash.** `%ads.txt` also matched
  `/downloads.txt`, so probes for files like that were set aside as polite requests. A needle
  edit moves the pack digest, which reclassifies too — the same single pass as above.

- **A pattern pack that declares a crawler without `crawler_origins` refuses to load.** Added to
  `[ai_uas]` alone, the real crawler on cloud hosting was filed as an impersonator of itself.
  `name = []` says, deliberately, to verify by reverse DNS alone.

- **The container keeps no capabilities**, has a PID ceiling, and no longer ships `curl`; the
  healthcheck asks Python. No memory limit, deliberately — see
  [deployment_detail.md §8](deployment_detail.md#8-security-notes).

- **The image is built from a hashed lock and a base pinned by digest.** It installed
  `runtime.txt`'s ranges from a moving `python:3.12-slim` tag, so two builds of one commit were
  two images and rolling back restored code but not dependencies. `requirements/runtime.lock`
  pins every package with hashes and is installed with `--require-hashes`; after changing a
  range, run `scripts/lock_requirements.sh` — CI fails when the two disagree. The workflows' actions
  are pinned by commit, and Dependabot proposes new digests and actions weekly.

- **The deploy script uploads `.env` straight into the deploy root** under umask 077 instead of
  via world-readable `/tmp`, quotes every name in its remote cleanup, and keeps the newest five
  `.env` backups rather than all of them.

### Fixed in 1.4.0

- **Shodan's hostnames verified crawlers.** They were copied into `reverse_dns`, where only a
  forward-confirmed name belongs, and survived every failed confirmation — so a PTR record set to
  a googlebot.com name took an address out of `threats/*` and out of `/api/decisions`. Stored
  names Shodan could have supplied are re-checked once on the first start, and every address
  whose reverse DNS changes is re-judged.

- **ip-api answers are believed only for addresses the batch asked about.** Over plain HTTP each
  item names its own row, so anything on the path could write intel for any address. A single
  malformed item also failed the whole batch, which was then retried whole, indefinitely.

- **Exposure left out every address the enricher had not reached yet**, so a fresh burst of
  probers stayed invisible, and a finding's row disagreed with its own panel.

- **An incident's panel could list the next run of the same tool** when one member probed for
  longer than the incident gap — six addresses under a row that counts three.

- **The report said incidents cluster "inside an hour"**; they cluster within a day. It also
  counted an address twice when it took part in two incidents.

- **Archives and snapshots are durable across a power cut.** The rename was fsynced as a file
  and not as a directory entry, so the rows could be deleted and the archive lost with them. A
  restore no longer loads the whole month into memory, and the storage actions that delete data
  finish even when the request that started them is dropped.

- **Numbers that were stale after a write.** The Overview served pre-restore figures for up to a
  minute and the date picker's floor was wrong for up to an hour; the Storage page reported 0 B
  of archives, always.

- **Links that widened what they led to.** The drawer's "Open as a filtered list" dropped the
  search and New; the Overview's drill-downs carried no date window.

- **Paging.** Ties in a sort had no tiebreaker, so a page turn could repeat or skip an address,
  and a page past the end rendered an empty table under the real total.

- **Sessions counted protocol errors as pages**, and took their entry path from SQLite's
  bare-column rule where the query had three aggregates for it to follow.

- **The non-UTC warning could never fire on a real site.** Static assets were excluded from its
  count and not from its denominator.

- **Smaller:** client-supplied strings are capped where a log line becomes a visit; the visitor
  detail page no longer scans all of `ip_intel` for an IPv4 neighbourhood; a Shodan rate limit
  is announced once rather than every 4.5 s for five minutes.

---

## 1.3.0 — 2026-09-01

The last ticket on the plan, and the one that changes what Vidar is for: a dashboard has to be
visited, a report arrives.

### Added in 1.3.0

- **A monthly report.** `/report` states one month — read start to finish in about three
  minutes, and downloadable as Markdown so it reaches somebody who will never open the
  dashboard. It answers four questions and stops: who came, what happened, what this server
  handed out, and where each figure came from.

  The lead sentence is the reason it exists. On the reference deployment it reads *91,838
  requests from 3,669 addresses in 83 countries. 3 of them were people — 0.1 % of the addresses
  that reached this server.* An operator who believes they have visitors mostly has traffic, and
  a percentage in a table does not say that the way a sentence does.

  Three decisions that make it a report rather than an export. Every section prints the rule it
  applied, so **none** is informative — "no incidents" beside the definition of one is a
  measurement; on its own it could equally be a broken feature. A month with nothing in it says
  the log is worth checking rather than that the site was quiet, because zero requests is almost
  always a moved log path or an archived month. And where several incidents share a signature
  the report says so in words: the table cannot, because every row reads the same.

  **New** is asked of the whole database rather than of the month. A path served since March is
  not news in its fourth month; one that answered for the first time on the 12th is the line
  somebody wants. Windowing that test would have marked every finding new in every month it
  appeared in.

  Nothing here is computed a second way — it is the figures `/visitors`, `/incidents` and
  `/exposure` already show for the same window. A report that disagreed with the dashboard it
  came from would discredit the dashboard, not the report, so the page and the Markdown are two
  renderings of one `build_report()` rather than two documents that happen to agree today.

  No mail. That is an SMTP host, a credential and a delivery failure mode for a file that can
  already be forwarded; a cron entry and `curl -o report.md '<tunnel>/report?format=md'` is the
  whole of the missing half.

### Fixed in 1.3.0

- **The version in the sidebar linked to a release that usually does not exist.** It pointed at
  `/releases/tag/v<version>`, and a running build is normally ahead of the last tag — it was for
  every 1.1.x and for 1.2.0 — so the link 404'd from every page. It goes to the tag list, which
  is never missing and answers the question the number raises anyway.

- **`.mix-legend-dot` had a width and a height and no `display`.** An inline span ignores both.
  It went unnoticed while its only user was a flex container, which blockifies its children;
  the report puts one in a table cell, where it rendered as nothing at all.

---

## 1.2.0 — 2026-09-01

1.1.0 built the surfaces. This one makes them usable: every table on them sorts, the long ones
page, an event or a finding opens beside the list it came from, and the timeline stopped being a
picture and became something with a scale on it.

It is also where a set of counting errors came out. Several were found by asking why two numbers
on one page disagreed — which is the argument this dashboard makes for showing its work, applied
to itself.

### Added in 1.2.0

- **A comparison between all addresses and new ones.** The Addresses control has three states:
  All, New — first seen inside the selected window — and both, drawn nested so the gap between
  them is the thing you read rather than something you hold in your head between two clicks. On
  a month of real traffic 40 % of one day's requests came from addresses seen before and 8 % of
  another's; those are the same line otherwise. It filters nothing and says so, and it appears
  only on the timeline: a table row is in or out and a map marker is one address.

- **An Addresses chart beside the Activity one.** Activity counts requests, Addresses counts
  distinct addresses, and the pair separates a thousand requests from one machine from a
  thousand machines. Same five class bands, same window, same interactions.

- **Everything sorts.** Exposure on all seven columns, Served on its own seven, Incidents on
  eight of ten, and both tables inside the incident panel. Server-side, over the values rather
  than the rendered text — the client-side sorter reads what is on screen, where every ISO
  timestamp parses to the number 2026 and `980.0 B` outranks `6.0 KB`. No page changes what it
  shows first, and every default order is a column you can click to get back to.

  Signature and From on the Incidents page do not sort, and a session's requests do not either:
  the order *is* the information there. The incident panel's path list is the exception that
  proves it — it carries the arrival position in a column, so re-ordering the rows takes that
  order along instead of destroying it.

- **A finding and an incident open beside the list.** Same panel, same contract. A finding
  answers from "must I act" down to "who was it": still served — asked over the whole database,
  because a file is on disk or it is not — then what the server answered, size, when, how often
  from how many, who by identity class, where from, every spelling, and what else those
  addresses asked for here. That last line usually settles it: the nine addresses that fetched
  `/.DS_Store` on the reference month also asked for 2 358 other paths.

- **Served says what a finding is one of.** The findings table said "1 path" and never said one
  of how many. Below it now sits every path this server answers 2xx for, marked Site or Finding
  with the benign count each clears or fails — the same result set split on the same threshold,
  so the two blocks cannot disagree about a number they share.

### Changed in 1.2.0

- **The activity chart is a total and five small multiples**, not five bands stacked into one
  shape nobody could read a single class out of. The traffic-rhythm heatmap shades
  logarithmically, because one busy hour flattened every other cell to the same tone.

- **The map opens at a fixed zoom again.** Fitting the view to the markers looked tighter and
  was not: whenever their spread did not quite fit, it dropped a level, and half-size world in a
  full-size panel meant grey ground above, below and either side of it — and the world tiled
  sideways to fill the gap, drawing North America twice. Zoom 2 covers the panel.

- **An incident's addresses fall within a day of each other, not an hour.** The hour was reasoned,
  not measured: a distributed scan was expected to spread its addresses over minutes. On the
  running deployment eighteen addresses ran the same five-path probe over six days, one or two
  at a time and never three within an hour, so `/incidents` showed nothing on a week with three
  obvious campaigns in it.

### Fixed in 1.2.0

Counting, mostly. Each of these produced a plausible number that was wrong.

- **The incidents limit cut before the ordering.** `get_incidents` has no `ORDER BY` — the score
  is computed in Python afterwards — so a SQL `LIMIT` kept an arbitrary handful and the sort
  ordered only those. Asking for three on a real month returned incidents scoring 44, 39 and 37
  while the actual top three scored 135, 104 and 101: a page whose purpose is to surface the
  worst was able to drop exactly the worst.

- **The fold added distinct address counts together.** Two spellings of one path, each fetched
  by 30 addresses, were reported as 60 — anything that tried both was in both figures, under a
  column that says "distinct". The same sum decided Site from Finding, so two spellings with one
  benign visitor each reached the threshold of two and marked a path as part of the site on the
  strength of one visitor counted twice.

- **The timeline applied none of the drill-downs it displayed.** Network, country, path, client,
  address, port and minimum visits each rendered as an active pill while the header and both
  charts answered for everything. The filter chips ignored the signal filter and the search the
  same way, and the All/New selection survived no link the page built.

- **The Exposure context query took 35 seconds and answered the wrong thing.** `v.status` inside
  its subquery bound to the outer `v`, an accidental correlation that reported 26 paths where
  the truth is 2 358. Fetching the addresses first and binding them makes it 3 ms.

- **The convention filter in the Exposure SQL hid true figures**, reporting `robots.txt` as one
  request instead of 453 — it only ever caught the spellings the percent-encoding fold catches
  anyway.

- **The x-axis was not a time axis**, and a band's peak did not say what it counted — a bare
  number beside an identically named one that counted something else. The map's viewport count
  had no denominator, so a zoomed-in map never said what fraction it was showing.

- **The incident panel hung past its own edge and lost most of its content.** Six fixed-width
  columns in a 736px panel, with the whole drawer scrolling sideways instead of the table; and
  the path list stopped at forty of 266, with the rest unreachable.

- Smaller: the custom-range form dropped the sort; `empty_row` dropped `ranged`, so both new
  pages claimed to be empty under every range but the default; and the drawer's failure message
  still said "Could not load these IPs" on the three panels that are not lists of addresses.

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

  Each finding carries its own explanation, hung on the *family* rather than the path — nine of
  them — because the reference deployment carries 26 609 distinct probed paths and one
  vulnerability is probed under twenty-five prefixes. A finding outside the nine is listed with
  a `curl` and no prose rather than under an invented family. Detection never consults the
  registry: a file dropped in the document root under a name nothing has seen is listed the
  first time a scanner fetches it.

- **From nine thousand addresses to ten events.** `/incidents` answers what happened rather than
  who came. Three or more addresses asking for the same first five missing paths, in the same
  order, within an hour, is one incident. The score beside each is a sort key and the page prints
  its arithmetic out of numbers already on the page. Volume is capped so one address hammering
  all night cannot outrank a coordinated run, and an empty list is a valid result the page states
  in words.

- **Behaviour, as a third axis.** Visits are cut into sessions — a run with no gap longer than
  30 minutes — and each carries a behaviour: browsing, scraping, recon, enumeration or brute
  force. Identity says what an address is, the signals say where it sits, and neither could say
  what it did. Nothing is stored: sessionising one address measured 0.10 ms against the 0.42 ms
  of the evidence query already running on it, which removes a migration, a backfill, and any
  session that could go stale when a month is re-imported.

- **Reputation from Vidar's own data.** An address's detail page shows the class mix over its
  /24 (its /64 for IPv6) and its ASN, which answers the cold start: a verdict needs history and
  a first request has none, but its neighbours have been seen. Nothing is fetched for it.

- **A baseline, so Vidar can say when to look.** A finding that names a moment rather than an
  address: `140 addresses probing in the last hour — 6.7× the typical 21`. A median, not a mean
  — one busy day raises a mean, the next spike sits under it, and a spike detector goes quiet
  exactly when something is happening repeatedly. Silent where it would be guessing: no baseline
  under a fortnight of log, none where the median hour is empty, and an absolute floor as well as
  a factor.

- **An interface for deciding, without deciding.** `GET /api/decisions` hands the addresses
  matching a stated selection to whatever acts — CrowdSec, nftables, a shell script. The
  selection travels with the answer and every address carries its reason after a `#`, so the file
  is machine-readable and still reviewable by a person. Vidar stays the brain and something else
  is the hand.

- **The patterns are a file.** 157 needles across fourteen lists lived in code, so every newly
  announced AI crawler meant a release for one string. `src/classifier/patterns.toml`, with
  `PATTERNS_PATH` naming a second file merged additively on top — a pack can add a needle and
  cannot remove one, because removing one describes a rule change. `CLASSIFIER_VERSION` carries
  the pack's fingerprint, so editing a needle reclassifies every stored address on the next
  start rather than leaving two vintages of judgement in one database.

- **The boundary between a log format and Vidar's own vocabulary has a name.** `Visit` is the
  canonical event, `LogEntry` is nginx's spelling of it, and `process_entry()` maps one onto the
  other. A second log format is now a second adapter and nothing else. Verdicts unchanged: 9 110
  addresses classified before and after, zero differences.

- **`/exposure` is now `/shodan`.** That page shows what Shodan knows about the hosts that
  visited — the *visitor's* exposure — and the name was needed for the other direction.
  `/tools/shodan` redirects there as it always did.

### Changed in 1.1.0

- **The new pages look like the rest of the dashboard.** Incidents, Exposure, the sessions and
  the neighbourhood arrived as stacks of description lists and paragraphs. They are now what the
  rest of the app is: a row of tiles, then a table whose columns carry their meaning in their own
  headers. The prose above the tables moved into the tooltips it belonged in.

- **A claim and the evidence behind it are one click apart**, and the layout suite runs against a
  real database rather than a fixture that could not produce the shapes it was measuring.

### Fixed in 1.1.0

- **`/exposure` returned nothing under any date range.** The query put the benign class list in
  its SELECT and the time window in its WHERE, then bound them the other way round:
  `v.timestamp >= 'bots/ai-crawlers'` matched no row. Ten tests passed throughout, all of them
  calling the query unbounded — the one shape the page never uses.

- **Incidents never fired**, and behaviour was measured on what the server answered rather than
  on what the client asked for, so a session's requests read as 404s where the behaviour reads
  unserved paths. The session row did not add up either.

- **The Overview's findings became fifty times more expensive.** The hourly baseline's
  `COUNT(DISTINCT ip)` measured 290 ms on 520 000 visits against 6 ms for every other finding
  together, behind the nav badge on every page. Computed once per hour now.

- **A log without a timezone silenced every finding.** The naive timestamp made the baseline
  raise and the caller turns any exception into an empty list, so one unusable timestamp removed
  all of them. A single malformed timestamp took `/incidents` down the same way.

- **Settings answered 500 on a mount it could not write to.** Creating the archive directory sat
  on a *read* path, so listing archives on a read-only mount returned an error page from the one
  place that could have explained it. It now names the directory, the reason and the fix, in the
  same words `python -m src.preflight` uses.

- **Cards showed values with no field names.** Below 1100px a table becomes cards and the label
  comes from `data-label`, which none of the new tables carried. Neither existing suite could see
  it — the structure suite checks `data-col`, the layout suite measures widths a card layout does
  not have. There is a test for it now.

- **A design review over every page**, and the defects it found across the dashboard.

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
