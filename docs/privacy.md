# Privacy

Vidar processes personal data. That is not a side effect of how it is built — it is what it
does: an IP address is personal data under the GDPR, and Vidar stores one for every request,
enriches it from third-party services, and keeps the result for months.

This document is for the person running it. It says what is stored, what leaves the server,
what the operator is responsible for, and what Vidar cannot do for them yet. It is a
description of the software, not legal advice; whether a particular deployment is lawful
depends on the site, the jurisdiction and the purpose, and that judgement is not one a README
can make.

The absence of cookies is not the point. Vidar adds nothing to the observed site, which means
visitors are never asked and never see a banner — so the burden of being transparent about the
processing falls entirely on the operator's own privacy notice. Server-side, a request log
enriched with geolocation and reputation data is a more detailed record of a visitor than most
cookie-based analytics, not a lighter one.

---

## 1. What is stored

Two tables hold personal data. [data-reference.md](data-reference.md#2-database-schema) lists
every column; this is what matters for a privacy assessment.

| Where | What | Note |
| --- | --- | --- |
| `visits` | Full IP address, timestamp, method, path, status, bytes, referer, user agent, `Accept-Language`, `X-Forwarded-For`, TLS and `Sec-Fetch` details | One row per request. The IP is stored in full — Vidar has no truncation or hashing mode |
| `ip_intel` | Country, city, latitude/longitude, ISP, organisation, ASN, reverse DNS, proxy/hosting/mobile/Tor flags, DNSBL listing, derived visitor class | One row per address, refreshed every `ENRICHMENT_CACHE_TTL_DAYS` |
| `ip_intel_ports` / `_vulns` / `_cpes` / `_tags` | Open ports, CVEs, software and tags Shodan reports for that host | Deleted with the parent row |
| `rate_limits` | The client IP of `/api/export` callers | This is the operator's own tunnel, not a visitor |

City-level geolocation and a reverse DNS name attached to a full IP are, together, a fairly
sharp identifier. Treat the database as a record about identifiable people, because that is
what it is.

## 2. What leaves the server

Every address that arrives is sent to external services for enrichment.
[deployment_detail.md](deployment_detail.md#33-what-leaves-your-server-and-on-whose-terms) covers
the operational side — rate limits, licence terms, and what breaks without each one. In privacy
terms:

| Recipient | What it receives | Transport |
| --- | --- | --- |
| ip-api.com | The visitor's IP, in batches | **Plain HTTP.** The free endpoint offers no TLS, so these lookups are readable in transit |
| Shodan InternetDB | The visitor's IP | HTTPS |
| Spamhaus / DNSBL zones | The visitor's IP, reversed, as a DNS query | Plain DNS via the container's resolver |
| The configured DNS resolver | The visitor's IP, as a PTR query | Plain DNS |
| Tor Project | Nothing — the exit list is downloaded | HTTPS |

Two more receive the **operator's** address rather than a visitor's, because the operator's
browser fetches them directly: CARTO basemap tiles and Leaflet from unpkg. Visitors are not
involved.

Nothing is sent to the author of this software, and Vidar has no telemetry, update check or
call-home of any kind.

## 3. Who is responsible for what

The operator of the watched site is the controller. Vidar is a program running on their own
server; it is not a service, and there is no processor to sign an agreement with. The
enrichment providers in [§2](#2-what-leaves-the-server) are recipients, and the ones based outside the EU/EEA make each
lookup a transfer to a third country — assess that on their terms, not on this document's word.

A deployment inside the EU/EEA usually needs, at minimum:

- **A legal basis.** Security monitoring and abuse detection is the obvious candidate under
  legitimate interests (Art. 6(1)(f)), which requires a balancing test that is written down
  somewhere, not merely assumed. Vidar's purpose is narrower than "analytics", which helps the
  argument; the enrichment and the retention period work against it. Decide deliberately.
- **A privacy notice on the watched site** (Art. 13) that says server logs are retained and
  analysed, for how long, that IP addresses are transmitted to the providers in [§2](#2-what-leaves-the-server), and where
  those providers sit. Visitors have no other way to find out — Vidar is invisible to them.
- **A record of processing** (Art. 30) if the operator keeps one.
- **A retention period that was chosen**, not inherited from the default. See [§4](#4-retention-archives-and-backups).

## 4. Retention, archives and backups

Retention is configured in the dashboard under Settings → Storage, in one of two modes:

- **Rolling** — the current calendar month plus the last *N*. A month falling out of the window
  is written to a zip under `ARCHIVE_DIR`, and only then are its rows deleted.
- **Lifetime** — nothing is archived and nothing is deleted.

Two consequences worth stating plainly, because both defeat a naive reading of "retention":

1. **Archiving is not deletion.** The zip holds the same visits and intel rows, on the same
   disk, until something removes it. Settings → Storage has a second control for that, and it
   defaults to keeping every archive — so unless an operator sets a number, a rolling window of
   two months with three years of archives beside it is three years of retention. The default is
   deliberate: an update must not delete data nobody asked it to delete. It is also the setting
   most likely to be wrong for a deployment that has a retention policy on paper.
2. **Backups outlive both.** `BACKUP_KEEP` daily snapshots of the whole database sit under
   `BACKUP_DIR`, and a row deleted today remains in yesterday's snapshot until it rotates out.

Enrichment data has its own clock: an `ip_intel` row is refreshed after
`ENRICHMENT_CACHE_TTL_DAYS`, not deleted, and survives as long as the address has visits.

## 5. Answering a data subject

**Access (Art. 15).** The dashboard answers this directly: search the address on `/visitors`,
open its detail page for the full request history and the enrichment record, or call
`/api/export` — see [api.md](api.md). Note that an operator can only act on a request they can
verify, and an IP address alone rarely establishes who is asking.

**Erasure (Art. 17).** There is no per-address delete in Vidar today. Deletion is
month-granular, through Settings → Storage. Doing it for one address means going to the
database directly, with the container stopped:

```sh
sudo docker compose stop vidar
sudo sqlite3 /srv/vidar/data/vidar.db \
  "PRAGMA foreign_keys=ON;
   DELETE FROM visits    WHERE ip = '203.0.113.4';
   DELETE FROM ip_intel  WHERE ip = '203.0.113.4';"
sudo docker compose start vidar
```

The `ip_intel_*` child rows go with the parent through `ON DELETE CASCADE`, which is why
`foreign_keys=ON` matters — SQLite does not enforce it by default. This does **not** touch the
monthly archives or the daily backups; both have to be handled separately, and an archive can
only be dropped whole.

Treat this as the honest state of things rather than a recommended workflow. It is listed under
[§7](#7-known-gaps) as a gap.

## 6. What Vidar deliberately does not do

- No cookie, no script, no pixel and no client-side storage on the observed site. Nothing is
  added to it at all.
- No cross-site or cross-visit identifier beyond the IP that nginx had already logged.
- No fingerprinting: every field comes from the access log, and Vidar asks the browser for
  nothing.
- No account, no profile, no sharing with the author, no third party other than the enrichment
  providers named in [§2](#2-what-leaves-the-server).
- The dashboard binds to loopback and is reachable only through an SSH tunnel, so the data is
  not exposed by the tool that reads it.

## 7. Known gaps

Stated here rather than left to be discovered:

- **No anonymisation mode.** IPs are stored in full. There is no option to truncate the last
  octet, hash addresses with a rotating salt, or drop the address once it has been enriched —
  each of which would cost some classifier accuracy and might be the right trade for a site
  that does not need per-address history.
- **No per-address erasure.** See [§5](#5-answering-a-data-subject).
- **ip-api's free tier is plain HTTP.** Visitor addresses travel unencrypted to a third party.
  A paid endpoint or a different provider would fix it; the free tier will not.

## 8. If you are only reading one paragraph

Vidar keeps a full request history per IP address, sends every address to four external
services — one of them over unencrypted HTTP — and stores geolocation, network and reputation
data alongside. Retention deletes rows from the database but keeps them in archives and backups.
Visitors are never told any of this by Vidar, because Vidar never touches their browser: saying
so is the operator's job, and this document exists so that the operator can.
