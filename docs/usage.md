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
`all`, `24h`, `7d`, `30d`, `90d`, plus a custom range.

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

Below that: nine KPI tiles — visits, unique IPs, threat IPs, error rate, countries, bounce
rate, HTTPS rate, average response time, bandwidth; three of them (visits, error rate,
bandwidth) carry a sparkline. Then the class mix, and the top panels — countries, IPs, pages,
referrers, browsers, OS. The visits tile compares the window against the same span
immediately before it.

The activity chart and the traffic-rhythm heatmap live on `/visitors?view=timeline`, where
they answer the page's filters instead of always answering for everything — every filter,
including the row-level drill-downs. A pill in the rail is a narrowing the page performs;
there is no such thing here as a filter that is displayed and ignored.

There are two charts, built the same way and answering for the same selection.
**Activity** counts requests; **Addresses** counts the distinct addresses that
made them. One number answers neither question: six thousand requests from three
addresses is a scanner, three thousand addresses making two each is a crawl, and
the two shapes diverging is the finding. Under the New selection the Addresses
chart reads directly — how many addresses arrived here for the first time, per
bucket. Its counts do not add up across buckets: an address here on two days is
counted in both, and the range's own distinct total is what the filter chips
show.

Each chart is a **total** across the top and **one small band per identity group** below it,
each scaled to its own maximum with that maximum printed beside its name. One shared axis
cannot carry five series three orders of magnitude apart — measured on a month of real
traffic, threats peaked at 7 043 and humans at 16, so humans drew a third of a pixel. The
magnitude moves from the axis to a number, which is where it survives. Hovering anywhere
moves one cursor through all six.

Buckets with no traffic are drawn as zeros. They used to be left out of the query entirely
and the chart placed its points by index, so an eleven-day silence and a one-day silence got
the same width and a continuous line was drawn across weeks nobody visited in. **On a young
deployment a 90-day window is therefore mostly flat** — that is the window being reported
honestly, not an error.

The heatmap's shade is logarithmic between its own quietest and busiest cell, and the legend
names both ends. Dividing linearly put five sixths of the cells into the bottom tenth of the
ramp, which is one bright square in a uniform field rather than a rhythm. A weekday the
window is too short to contain is drawn hollow: no hour at all, which is not the same as a
quiet one.

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
Signals sit behind their own disclosure: Tor, Proxy / VPN, Hosting / Cloud, DNSBL listed,
Shodan tags, Clean, Mobile.

On the second row, the search box and a `Help ▾` disclosure that unfolds a reference
directly beneath it, in three tabs: Syntax, Classes and Signals.

### Addresses: All or New

Above the rail, beside the view and grouping strips: **All** is every address in the window,
**New** only those whose first request falls inside it — nothing of them exists before the
range starts. It narrows all three views, so the table, the map's markers and the timeline's
buckets keep describing one selection.

**All + New** is the third state and a different kind of thing: a comparison rather than a
narrowing. The two timeline charts draw both series — New nested inside All, since an address
first seen in the window is an address in the window — and the gap between them is the
returning traffic. On the reference month that gap swings hard: 40 % of one day's requests
came from addresses seen before, 8 % of another's, and a single line cannot tell those days
apart. The hover carries both figures for every group.

It exists only on the timeline, because that is where there is something to draw two series
on: a table row is in or out and a map marker is one address. It filters nothing even there —
the count in the header and the heatmap below answer for All — and the control says so rather
than leaving it to be discovered.

Two things All / New is honest about. Over the `all` range there is nothing to be new relative
to, every address would qualify, and both New and the comparison are disabled rather than
answering the same as All under a different name. And it can only speak for what the database
still holds: retention moves whole months out to a zip, and an address whose earlier visits
left with one reads as new.

**Every active filter renders as a removable pill** — drill-downs, each class and signal value
in its taxonomy colour, the search term, and the map's viewport selection. `Clear filters` keeps
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

### Sessions and behaviour

The third axis. Identity says what an address **is** and the signals say where it **sits**;
neither could say what it **did**. A **session** is a run of requests with no gap longer than
**30 minutes**, and each one carries a behaviour: **Browsing**, **Scraping**, **Recon**,
**Enumeration** or **Brute force**.

Behaviour is orthogonal to identity on purpose. A human can scrape and a search crawler can
enumerate; with only two axes the classifier had to weigh such cases against each other and
crown a winner, and now it does not have to. It belongs to the session rather than to the
address, because one address can read two pages in the morning and walk a scanner list at
night — an address-level label would have to pick one and be wrong about the rest.

Each session row is one run: **Requests** is every line in the log, **Paths** how many
different ones those were for, and **Read** + **Unserved** split that number into what the
server handed over and what it did not. Ten requests for one page is ten requests and one
path.

**Click a row for the requests it is made of.** The row is a claim — *enumeration* — and the
panel is the evidence for it: every request of that session, in arrival order. Order is not
sortable there on purpose; in a session it *is* the information, and it is what makes a
scanner's signature legible.

A session needs no stored id for this. It is a contiguous run bounded by silence, so its own
start and end select exactly its requests and nothing else.

The full request log stays below, under its own heading. It answers a different question —
which response was the largest, the slowest, over which cipher — and sorts on every column,
which is meaningless inside one session and useful across an address's whole history.

**Behaviour is read from what the client asked for, not from what the server answered.** The
figure the rules use is `unserved_paths` — distinct paths the client did not get. A redirect, a
404, a 503 and a 403 all mean the same thing to the client, and keying on 404s alone went quiet
in exactly the two places where the probing was heaviest: one address made 117 036 requests that
only ever met the port-80 redirect and so produced no 404 at all, and another probed hard enough
that the server answered 503 to more than half of it, which pushed its 404 share under the
threshold and made probing *harder* look like probing less.

Where the session got something served, a redirect is part of getting there and not a failure —
otherwise a person whose `/about` answers 301 to `/about/` reads as reconnaissance.

**One thing is not a behaviour** and is left blank: one request, or one page fetched with
nothing following from it. On a quiet site most sessions are exactly this, and labelling them
would make the majority label an artefact of the threshold rather than of the traffic.

**The thirty minutes are a model decision with no correct answer**, so they are written down
rather than tuned quietly. It is the web-analytics convention, which matters less for being
right than for being a number readers already have an intuition about. Ten minutes splits
somebody who stopped to read. Without an upper bound at all, the busiest addresses collapse
into one session covering the whole retention window — the one shape that carries no
information. A client polling at a steady ten-minute interval never opens a wide enough gap and
legitimately shows as a single session lasting days; that is why the duration column changes
unit rather than growing digits.

**The log resolves to the second.** A duration of `0 s` means "inside one second", not
"instant", and nothing below a second can be measured — burst detection ends at "per second".

Sessions are computed when the page is read, never stored, so no migration and no backfill
exists to go stale. The newest 25 are shown and the true count is stated beside them.

### Neighbourhood

A verdict needs history, and a first request has none. Its **neighbours** have one: the panel
shows what Vidar has already judged in the same **/24** (a **/64** for IPv6) and at the same
**ASN**, as the same class-mix bar the aggregation tables use. Where one identity group holds a
majority of the peers it is named in words — *"7 of 9 are Bots"*. Two things stop that sentence
from being said: a plurality rather than a majority, and fewer than **five** peers. With the
largest group at 40 % across four others nothing characterises the range; and *"1 of 1 are
Bots"* is one data point wearing the grammar of a finding. In both cases the bar and the count
stand on their own.

Nothing is fetched for this. It is `ip_intel` read by range and by operator, so it costs no
request and no provider. The address itself is never counted among its own peers, and a scope
with no peers is left out rather than drawn as an empty bar.

**It is empty on a new deployment, and stays empty for a while.** The panel says so in words
rather than showing nothing: the feature needs a log it does not have on day one, and it
sharpens as that log grows. Even on the reference deployment — 9 206 addresses over three
months — a single /24 is often thin. The peer count is always shown next to the bar for that
reason.

The ASN row links to `/visitors?asn=…`, which lists the peers themselves. The /24 has no
equivalent filter yet, so it is text.

---

## 6. Analysis (`/analysis`)

The **Identity × Signals** matrix: who the visitors are against what their networks carry.
Every cell is a link to those IPs, and the cells count IPs seen in the window, so a cell never
offers more than the list behind it. Alongside it: status-code, HTTP-version and unusual-method
distributions, and rate limiting.

Distribution cards carry a `Table` switch that swaps the bars for the same numbers as a table.

---

## 7. Incidents (`/incidents`)

Every other surface answers *who came*. This one answers *what happened* — the question somebody
actually has when they open a dashboard at three in the morning. Nine thousand rows cannot answer
it; ten events can.

A scanner is a program, and a program starts the same way every time it runs. When **3 or more
addresses** request **the same first 5 missing paths, in the same order, within a day** of each
other, that is one event rather than three visitors. Those five paths are the incident's
**signature**.

**A day, and that number came from the traffic.** An hour was the first guess, and against a
week of the reference deployment it produced no incidents at all — on a site where eighteen
addresses ran the same five-path probe, one or two at a time, over six days. Widening the window
past a day finds nothing more; narrowing it splits one campaign into fragments that each fall
under the reporting threshold and disappear.

One row per run: when it started, how long it lasted, how many addresses and networks took
part, how much it probed, how that compares with an ordinary hour, the signature, and the
addresses themselves — each linking to its own history. `DNSBL` is off by default and available
from **Columns**.

Every column sorts except two. **Score** is the default, and it is on screen: it is what the
list is ordered by, and a default ordering on a hidden column is an ordering the reader can
neither name nor restore. Sorting by anything else replaces it; clicking Score returns to it.

**Signature and From do not sort.** A signature is an *ordered* path list and that order is its
identity — sorting by its first element would destroy exactly what the column exists to show,
the same reason the requests inside a session are not sortable. From is a truncated eight of N,
so its first address is an accident of the query rather than a fact about the run.

**Click a row for what the incident is made of.** Two tables, because an incident is two things
at once: **Asked for** — every path it requested, in the order they first arrived, with how many
of its addresses tried each — and **From**, the addresses themselves, when each joined and how
long each stayed. Without the paths the panel is a list of addresses that says nothing about
what happened; without the addresses the paths are a wordlist nobody ran.

The first five paths carry a `*`: they are the signature. They lead because the list is in
arrival order, which is the order the program walks them.

**Both panel tables sort, and the paths page.** Forty at a time — the largest campaign on the
reference deployment asks for 266 distinct paths, and a list that stopped at forty with a note
saying so put the rest out of reach. The two tables carry separate parameters, so ordering the
addresses does not throw you back to page one of the paths, and the panel re-fetches itself
rather than navigating the page behind it.

This is not the exception to the rule above it. The paths table has a `#` column holding the
position each path arrived at, so sorting by Requests moves the rows and the arrival order goes
with them; the page's Signature cell has no such column, and there the order is the only place
the information lives. Addresses sort on five of their six columns — Signals is several
independent flags, and there is no one order over "Tor, hosting and listed" that is not
invented.

Only the requests the incident is built from are counted — paths that do not exist, convention
files excluded — so the panel's totals equal the row's. Two numbers describing one event is how
a page stops being believed.

The shape of the campaign is in the **From** table and the row can only give its size: eighteen
addresses over six days is a different thing from eighteen inside a minute. Each address links to its own history, where that
session expands into the requests it is made of: an event, down to a single logged line.

An incident needs no stored id either. Its signature and its stretch of time name it, and the
signature travels as a short digest because five paths do not fit in a URL — one of them on the
reference deployment is a 120-character PHP payload. The window is padded backwards by one
session gap before the sessions are rebuilt: boundaries are found by looking for silence before
a request, and cutting the visits at the incident's first moment would make an address that was
already busy look as though it had just started.

**The score is a sort key and nothing else.** It is not a measurement and no decision should
hang on its value; it exists so the page can put the interesting rows first. It has no evidence
of its own — every figure in it is a column of the same row — and the cell spells the sum out
over those figures:

> `11 addresses → 33 + 10 networks → 20 + 2 on blocklists → 8 + 132 probes → 2 = 63`

Volume is capped on purpose. One address hammering one path all night is a large number and not
an event; uncapped, it would sort the page by traffic instead of by coordination.

**Empty is a valid result and the usual one on a small site.** Correlation without volume is
noise — a surface that lowers its own bar to avoid looking idle
stops being worth opening. Every threshold is set on the under-reporting side for the same
reason: a page that cries wolf is read once.

The prefix rather than the whole path set is also deliberate. A full set breaks apart the moment
one address stops early, and it would break *silently* — two incidents where there is one, each
below the reporting threshold, so the event disappears rather than looking wrong.

This is the one page whose query is expensive: it sessionises every address in the window. It is
cached, and nothing else may ask for that shape per request.

---

## 8. Exposure (`/exposure`)

The other direction. Every other page describes visitors; this one describes what they got.

A path is listed when it answered **2xx** and fewer than two benign addresses — humans, search
crawlers, AI crawlers — ever fetched it. Those only follow what is linked, listed in
`robots.txt` or announced in a sitemap, so a successful path none of them touched is not part of
the site as it is meant to be reachable.

What is deliberately *not* listed matters as much:

| | |
|---|---|
| Redirects | Success is 2xx. On the reference log 158 531 prober requests are the HTTP→HTTPS redirect |
| Query strings | A static server ignores them, so `/?phpinfo=-1` returns the homepage. Counted once, below the table, never listed as findings |
| Convention paths | `robots.txt`, `/.well-known/`, favicons — the same list the 404 ratio uses |
| Encoded spellings | `/.DS_Store` and `/%2eDS_Store` are one file, folded into one row |

**One benign address does not clear a path; two do.** A single verdict can change — an address
here was a headless browser under one classifier version and a referred human under the next —
and a veto of one would have taken a real finding away. Where a benign address is counted, the
table shows it.

An empty table is the expected result and says so in words. Every column sorts, defaulting to
the addresses that got it.

### Served — what the findings are a subset of

The findings table says "1 path". It does not say one *of how many*. Below it, **Served** lists
every path this server answers 2xx for, marked `Site` or `Finding`, with the benign count each
one clears or fails: 90, 48, 26 … and 0. That is the same result set split on the same
threshold, so the two blocks cannot disagree about a number they share — and it is the only
place the threshold appears as a figure rather than as a parenthesis.

Convention paths and the fragments the site's own JavaScript loads are in it. They are never
findings, but they are things this server hands out, and a list of what it hands out that
omitted `robots.txt` and four content pages would answer a stranger question than either.

**Every column here sorts**, on its own parameters — ordering this block does not reorder the
findings above it, and it opens in the order it always did: `Site` before `Finding`, then the
most benign, then the most requested. Clicking **Kind** returns to exactly that.

**Addresses is distinct across spellings.** One path is often several spellings — `/.DS_Store`,
`/%2eDS_Store`, `//%2eDS_Store` are one file reached three ways, and `//`, `/./`, `/%2f` all get
the homepage back — and they fold into one row here. An address that wrote the path two ways is
one address in this column. That is why a row here can show more *requests* than the same path
shows under Visitors → Paths with a `200` filter, and never more addresses: Served counts the
whole 2xx family across every spelling, where the Paths table lists each spelling separately and
`200` is only one of the statuses a path answers with.

### What each finding is

A path and a byte count are a fright, not information. **Clicking a finding opens it**, the way
clicking an incident does. The panel answers, in that order: whether it is *still* being served
— a 404 after the last successful fetch means the file is gone, and that one question is asked
over the whole database rather than the selected range — what the server answered and on which
port, the size and whether it varied, when, how often and from how many addresses, who they
were by identity class, where they came from, every spelling, which clients asked, and what
else those same addresses requested here.

That last line is usually the one that settles it: nine addresses fetching one file also asked
for 2 358 other paths. A finding is normally one entry in a list being walked, not a thing
somebody came for.

Under that, the same four answers as before — **what the file is**, **why somebody asked for
it**, **a command to check it yourself**, and **how to stop serving it**. They used to sit
beneath the table, one panel per family. Per-path advice belongs beside the path it is about,
and rendering it in both places would print every explanation twice. The check is addressed to
`SITE_BASE_URL`, so it is a command to paste rather than a template to adapt; with that setting
blank it prints an obvious placeholder instead of a plausible hostname.

The explanation belongs to the *family*, not to the path. There are 26 609 distinct probed
paths on the reference deployment and the 500 most-requested cover 30 % of them, so a catalogue
of individual paths cannot work — PHPUnit's `eval-stdin.php` alone is probed under more than
twenty-five prefixes. Nine families are recognised: operating-system metadata, version control
directories, environment files, backups and editor leftovers, configuration files, keys and
credentials, developer tooling leftovers, log files and diagnostic pages. Three findings under
`.git/` are one thing to fix, so they get one explanation naming all three.

A finding outside those nine gets the `curl` in its panel and nothing else. That is deliberate: the command is derived from the path and needs to know nothing about
the file, while a description broad enough to cover everything would apply to any file and help
with none of them — and once it appears under every unrecognised finding, it gets skipped along
with the real ones. `src/families.py` holds the registry.

Most findings will land there, and that is the normal case rather than a gap. **The detection
does not consult the registry**: a file you drop in the document root tomorrow, under a name
nothing has seen, is listed the first time a scanner fetches it and nothing else does.

## 9. Shodan (`/shodan`)

The Shodan side: facets for ports, tags and CVEs above the host table, sharing one filter
state. Narrowing by `port`, `vuln` or `tag` moves both, so a facet always describes the host
set below it.

## 10. Report (`/report`)

Every other surface answers a question you came with. This one answers the one nobody thinks
to ask: **what was last month.** One month per report, read start to finish in about three
minutes, and downloadable as Markdown so it can be forwarded to somebody who will never open
the dashboard.

It opens on the most recent month that holds traffic, and the tabs offer only the months the
database still has — retention moves older ones out to a zip, and a report for an archived
month would render as a month in which nothing happened.

Four sections, in the order somebody asks them:

| | |
|---|---|
| **Who came** | The identity mix by address, with each group's share and how it moved against the month before. The lead sentence above it is the point of the page: on the reference deployment 0.1 % of the addresses that reached the server were people |
| **What happened** | Incidents, with the rule that defines one printed underneath — so "none" is informative rather than ambiguous. Where several incidents share a signature the report says so, because the table cannot: every row reads the same |
| **What this server handed out** | Findings, and which of them were served for the **first time** this month. That is asked of the whole database rather than of the window, or every finding is new in every month it appears in |
| **How to check any of this** | Which page each figure came from |

Nothing on this page is computed a second way. Every number is the one `/visitors`, `/incidents`
and `/exposure` already show for the same window, so the report and the dashboard cannot
disagree — and the Markdown copy is rendered from the same data as the page, for the same
reason.

**No mail.** The plan said "file or mail"; mail is an SMTP host, a credential and a delivery
failure mode for a file you can already forward. If you want it monthly, a cron entry and
`curl -o report.md '<tunnel>/report?format=md'` is the whole of it.

---

The version beside the name at the top of the sidebar is the build that is answering. It links
to the repository's tag list rather than to its own release, because a running build is often
ahead of the last tag. It is also in `GET /api/stats`, so a script can check it without loading
a page.

## 11. Documentation

The book in the middle of the sidebar footer opens these documents inside the
dashboard, so the deployment steps and the field reference are at hand through
the tunnel rather than only on GitHub. `docs/.order` sets the order of the list;
a document missing from that file is appended rather than hidden.

## 12. Settings

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
so nothing leaves uncompressed and no month is held in memory. A download dropped half-way
leaves its temp file behind; the retention task removes it once it is an hour old.

**Snapshots** are the other half: a daily gzipped `VACUUM INTO` copy of the live database,
keeping the newest `BACKUP_KEEP` (default 7). A pass declines rather than filling the volume
when free space drops below 2.5× the database. They sit on the same disk as the database, so
they cover corruption and mistaken deletion but **not** loss of the volume — the table exists
so a copy can be pulled off the host.

The daily pass runs inside the app; the page shows when it last ran.

---

## 13. Decisions (`/api/decisions`)

The third question — *how do I deal with it* — in a form another tool can read. CrowdSec,
nftables or a shell script can help themselves from here. The endpoint is documented on
**Settings → API**.

**Vidar does not decide what is blocked.** It says what somebody needs in order to decide, and
something else is the hand. Which makes it compatible with the tools that do act rather than a
competitor to them.

Two things follow from that, and both are visible in the output:

- **The selection travels with the answer.** Asked nothing in particular it answers for
  `threats/*` over the last week, and the response says so. A feed whose membership rule is
  invisible is a blocklist, and a blocklist nobody can open is what this dashboard argues
  against.
- **Every address carries its reason** — the class, the counts, and the network signals behind
  it — after a `#`, the convention Spamhaus DROP and the CrowdSec blocklists use, so the usual
  consumers already strip it and a person reading the same file still sees why.

```
# Vidar 1.4.0 — addresses matching a selection, not a verdict.
# Vidar does not decide what is blocked. Review before you act on it.
# Selection: threats/* (the recommended default)
203.0.113.60  # threats/exploit-probers · 12 probes · 24 requests · on a blocklist · Tor exit
```

Take `format=json` for the same with the full evidence per address. Nothing is ranked by a score:
the order is what the address did here — probes, then requests — because a number would collapse
the evidence into a rank that has to be trusted.

The answer is capped, and says when the cap was hit rather than quietly handing over a prefix.

---

## 14. Troubleshooting

| Symptom | Cause | Check |
|---|---|---|
| Dashboard unreachable | Tunnel not up | `ssh -L 8080:localhost:8080 <user>@<host>` |
| No visits appearing | nginx not writing JSON | `tail -1 /srv/nginx/logs/access.log` — must be valid JSON |
| IPs not enriched | ip-api rate limit | Wait ~60 s; look for "Rate limited" in the container logs |
| DNSBL always empty | Free zone refuses public resolvers | Expected without `DNSBL_DQS_KEY`; the log says so once per provider |
| Tor list missing | Network | Logs show "Failed to download Tor exit list"; retries every 24 h |
| Old data not purged | Lifetime mode, or the pass has not run | Settings › Storage; `docker logs vidar \| grep -i retention` |
| Disk growing | No pass, or lifetime mode | `docker exec vidar python -m src.retention` |
