# Using the Dashboard

For whoever is reading the data. Setting the service up is [deployment_tldr.md](deployment_tldr.md);
every configuration variable is in [data-reference.md §7](data-reference.md#7-config-settings-srcconfigpy).

## 1. Getting in

The dashboard binds `127.0.0.1:8080` and is not reachable from the internet:

```bash
ssh -L 8080:localhost:8080 <user>@<host>
```

Then open `http://localhost:8080`.

---

## 2. The date range governs everything

Every page resolves one window and scopes every number under it — tiles, top-N lists, the
identity matrix, the exposure facets, the charts. The range tabs sit in the page header:
`24h`, `7d`, `30d`, `90d`, `all`, plus a custom range.

**`90d` is the default and the starting state.** `all` is a deliberate choice rather than an
accident, which is why it has its own tab. The chosen window follows you across Overview,
`/visitors` and `/analysis` via a session cookie, but a URL always wins — a shared or
bookmarked link shows the window it names.

Two things are deliberately all-time and say so in place: the **Needs attention** list, where
each finding names its own timeframe ("in 6 h", "7-day average") and a filtered-away alert is
not an alert, and the **visitor detail page**, which is one IP's full history reached from a
filtered list.

---

## 3. Overview (`/`)

Leads with **Needs attention**: a rate-limit offender in the last six hours, threat IPs first
seen today, the top CVE by host count, Tor traffic at twice its 7-day baseline, the
most-requested probe path. Each finding links to the view that shows it in full, and the
sidebar badge counts them.

Below that: KPI tiles with sparklines (visits, unique IPs, error rate, bounce rate, HTTPS
rate, average response time, bandwidth), the class mix, and the top panels — countries, IPs,
pages, referrers. The visits tile compares the window against the same span immediately
before it.

The activity chart and the traffic-rhythm heatmap live on `/visitors?view=timeline`, where
they answer the page's filters instead of always answering for everything.

---

## 4. Visitors (`/visitors`)

One page, two axes.

**`?group=`** picks what a row *is*: `ip` (default), `asn`, `country`, `client`, `path`.
**`?view=`** picks the presentation: `table` (default), `map`, `timeline`.

Every grouping brings its own sort whitelist and its own search fields. `group=path` also
takes a status band (`2xx`–`5xx`); `group=ip` keeps the exact-match drill-downs (network,
path, browser, country, port, minimum visits).

### The filter rail

Two rows. On the first, the group chips — All, plus the five identity groups — where a group
with subclasses opens into a menu listing them. **Every entry carries its IP count for the
active window**, so a filter that would return nothing is visible as such before you click it.
Signals sit behind their own disclosure: Tor, Proxy/VPN, Hosting/Cloud, DNSBL, Shodan Tags,
Clean.

On the second row, the search box and a `Syntax` disclosure that unfolds a reference table
directly beneath it.

**Every active filter renders as a removable pill** — drill-downs, each class and signal value
in its taxonomy colour, the search term, and the map's viewport selection. `clear all` keeps
the grouping, the view and the time window, because the range tabs are their own control.

### Search is field-aware

A term either names its field or is recognised by shape:

```
country:DE        ua:wget         tag:scanner      port:22       status:4xx
de                AS15169         /wp-admin        192.0.2.      404
```

Two letters read as a country, `AS…` as a network, a leading `/` as a path, a dotted or
colonned run as an IP prefix, three digits as a status. Naming a field overrides the shape,
and `"quotes"` opt out of it entirely. Terms are AND-ed, at most eight. An unknown field name
is reported at the box rather than silently searched.

This matters more than it sounds. The previous blind substring across eleven columns matched
`de` against 3,617 of 11,564 IPs — 1,627 of them through `path` alone, because `/index.html`
contains those letters — against the 961 actually in Germany. Now `de` returns those 961, and
`path:de` still returns the 1,627.

### Class mix and signals

Aggregation rows show a proportional **class mix** and **signals** bar rather than a badge:
distinct-IP counts per identity group and per signal, in the legend's colours. A single
visitor has one identity, so its bar is one full-width band with the exact class in the
tooltip. Clicking a row opens a slide-over with the individual IPs behind it.

### Map view

Markers coloured by identity group — teal humans, blue bots, yellow automated, red threats,
grey unknown. **Cluster** groups nearby markers; **Heat** replaces them with a density grid
shaded on a single ramp, because density is one number and identity is what the cluster view
already carries.

The selection sidebar recomputes from the markers inside the current viewport on every pan,
so **panning is the selection**. Shift-drag a box to zoom; the resulting window appears as a
removable viewport pill in the filter rail.

### Timeline view

One line per identity group, with a hover crosshair and drag-to-zoom. **The zoom is visual
only** — the date filter stays with the range tabs. Zooming below three days fetches hourly
buckets, because daily points say nothing at that span.

---

## 5. Visitor detail (`/visitors/{ip}`)

One IP in full: the verdict chip and **"Why this verdict"** — the ordered evidence behind the
classification, deciding rule first, then the orthogonal context (headers, DNSBL, hosting,
Tor, Shodan) — followed by geo, network, exposure and a paginated request log with its own
mini map.

---

## 6. Analysis (`/analysis`)

The **Identity × Signals** matrix: who the visitors are against what their networks carry.
Every cell is a link to those IPs, and the cells count IPs seen in the window, so a cell never
offers more than the list behind it. Alongside it: status-code, HTTP-version and unusual-method
distributions, and rate limiting.

Distribution cards carry a `Table` switch that swaps the bars for the same numbers as a table.

---

## 7. Exposure (`/exposure`)

The Shodan side: facets for ports, tags and CVEs above the host table, sharing one filter
state. Narrowing by `port`, `vuln` or `tag` moves both, so a facet always describes the host
set below it.

---

The version beside the name at the top of the sidebar is the build that is answering. It is
also in `GET /api/stats`, so a script can check it without loading a page.

## 8. Documentation

The book in the middle of the sidebar footer opens these documents inside the
dashboard, so the deployment steps and the field reference are at hand through
the tunnel rather than only on GitHub. `docs/.order` sets the order of the list;
a document missing from that file is appended rather than hidden.

## 9. Settings

Behind the gear in the sidebar footer, three pages:

- **Status** (`/settings/status`) — what the service is doing and what it loaded
- **Storage & Retention** (`/settings/storage`) — retention mode, archives, snapshots
- **API** (`/settings/api`) — the four JSON endpoints and what each answers

`/settings` itself has no landing page and redirects to Status. There is no separate Exports
page; per-month downloads are part of Storage, and whole-database export is
[`/api/export`](api.md).

### Status

How far the tailer has read, how deep the enrichment queue is, whether Shodan is cooling down
after a 429, whether the DNSBL has a key — the things that otherwise mean `docker logs`. Below
that, the configuration the service actually loaded, read-only, with the DQS key reduced to
*set* or *not set*.

If one of the three site-specific settings is empty, a warning at the top says so and names what
it costs. The same line goes to the log at startup, but a log line scrolls away and the weaker
classification does not.

### Storage and retention

Retention is a **calendar window**, and it archives before it deletes.

- **Rolling** (default) — the current month plus the last N stay in the database. N defaults
  to 2 and is set on the page (0–24). A month that falls out is written to
  `/data/archive/YYYY-MM.zip` and only then removed. The window is 59–92 days depending on
  the date, which is why `RETENTION_DAYS` is inert.
- **Lifetime** — nothing is archived, nothing is deleted, and the database grows without
  bound. The page warns while this is active. Archives written under Rolling stay on disk: the
  keep window below runs only in Rolling, because a mode that promises no deletion should not
  quietly perform one.

**Archiving is not deletion**, which is the second decision on the page. The window above says
what stays in the *database*; the zip written on the way out has its own lifetime. It defaults
to keeping every archive, so two months of retention with three years of traffic means three
years on disk until you say otherwise. Setting a number expires an archive that many months
after the month it holds — counted from the month it names, not the file's timestamp, so a data
directory that was copied once does not reset every zip's age.

Two controls rather than one, deliberately: a single "retention" number would have to mean both,
and it would make restoring impossible — an archived month can be brought back, a deleted one
cannot. A window shorter than the rolling window is raised to just above it, because below that
the same nightly pass would write a zip and delete it again. Switching to a value that already
covers existing archives asks first and names how many.

The archive table lists every zip on disk:

| Action | Effect |
|---|---|
| **Download** | The zip: `meta.json`, `visits.jsonl`, `ip_intel.jsonl`. A month still in the database is zipped on demand and stays where it is |
| **Re-import** | Loads the month back into the active database and pins it there for `ARCHIVE_RESTORE_DAYS` (default 7). Clicking twice is harmless |
| **Put back** | Ends a re-import early. The zip is never deleted by this |
| **Delete** | On a database month, drops it with no archive written; on an archive, removes the zip. Both confirm first, neither can be undone |

Everything the UI hands out is a zip, written to a temp file and deleted after the response,
so nothing leaves uncompressed and no month is held in memory.

**Snapshots** are the other half: a daily gzipped `VACUUM INTO` copy of the live database,
keeping the newest `BACKUP_KEEP` (default 7). A pass declines rather than filling the volume
when free space drops below 2.5× the database. They sit on the same disk as the database, so
they cover corruption and mistaken deletion but **not** loss of the volume — the table exists
so a copy can be pulled off the host.

The daily pass runs inside the app; the page shows when it last ran.

---

## 10. Troubleshooting

| Symptom | Cause | Check |
|---|---|---|
| Dashboard unreachable | Tunnel not up | `ssh -L 8080:localhost:8080 <user>@<host>` |
| No visits appearing | nginx not writing JSON | `tail -1 /srv/nginx/logs/access.log` — must be valid JSON |
| IPs not enriched | ip-api rate limit | Wait ~60 s; look for "Rate limited" in the container logs |
| DNSBL always empty | Free zone refuses public resolvers | Expected without `DNSBL_DQS_KEY`; the log says so once per provider |
| Tor list missing | Network | Logs show "Failed to download Tor exit list"; retries every 24 h |
| Old data not purged | Lifetime mode, or the pass has not run | Settings › Storage; `docker logs vidar \| grep -i retention` |
| Disk growing | No pass, or lifetime mode | `docker exec vidar python -m src.retention` |
