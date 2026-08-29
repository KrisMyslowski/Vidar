# Data Reference

The authoritative reference for every data source, schema, classifier rule and setting. Where
this document and another disagree, this one is right — the others link here rather than
restate it. For how the pieces fit together see [architecture.md](architecture.md).

Keep it in sync when changing what nginx emits, the schema in `src/db.py`, the rules in
`src/classifier/`, or the settings in `src/config.py`.

---

## 1. Nginx log fields (`json_log`)

### 1.1 Original fields (13)

| JSON Key | nginx Variable | DB Column | Type | Notes |
|----------|---------------|-----------|------|-------|
| `time` | `$time_iso8601` | `timestamp` | TEXT | ISO8601, used for all time-based queries |
| `remote_addr` | `$remote_addr` | `ip` | TEXT | Client IP (may be CDN/proxy edge, not real user) |
| `request` | `$request` | *(fallback)* | — | Raw request line; used by `_derive_request_fields()` when method/uri are empty |
| `status` | `$status` | `status` | INTEGER | HTTP response code |
| `body_bytes_sent` | `$body_bytes_sent` | `bytes_sent` | INTEGER | Response body size (excludes headers) |
| `http_referer` | `$http_referer` | `referer` | TEXT | Verbatim Referer header, or `""` / `"-"` |
| `http_user_agent` | `$http_user_agent` | `user_agent` | TEXT | Raw UA string; parsed by `ua_parser.py` |
| `request_time` | `$request_time` | `request_time` | REAL | Seconds from first byte received to last byte sent |
| `ssl_protocol` | `$ssl_protocol` | `ssl_protocol` | TEXT | `TLSv1.2`, `TLSv1.3`, or `""` for plain HTTP |
| `request_method` | `$request_method` | `method` | TEXT | HTTP verb; empty for malformed traffic |
| `request_uri` | `$request_uri` | `path` | TEXT | Path + query string; empty for malformed traffic |
| `server_port` | `$server_port` | `server_port` | INTEGER | 80 or 443 |
| `http_accept_language` | `$http_accept_language` | `accept_language` | TEXT | e.g. `"de-DE,de;q=0.9,en;q=0.8"` |

### 1.2 V3 fields (6) — added 2026-06-09

| JSON Key | nginx Variable | DB Column | Type | Why It's Useful |
|----------|---------------|-----------|------|-----------------|
| `request_length` | `$request_length` | `request_length` | INTEGER | Large bodies (>1 KB on GET) signal attack payloads or upload probes |
| `http_x_forwarded_for` | `$http_x_forwarded_for` | `http_x_forwarded_for` | TEXT | Original client IP chain when behind CDN/proxy (e.g. `1.2.3.4, 10.0.0.1`) |
| `ssl_cipher` | `$ssl_cipher` | `ssl_cipher` | TEXT | Cipher suite analysis; obsolete ciphers (RC4, 3DES) flag old/malicious clients |
| `connection` | `$connection` | `connection` | INTEGER | Connection serial number for the life of the nginx process. With `connection_requests` it identifies a request uniquely, which is what lets a re-read of the log be recognised as one ([§2.1](#21-visits-29-columns)) |
| `connection_requests` | `$connection_requests` | `connection_requests` | INTEGER | `>1` = HTTP/2 multiplexing or HTTP/1.1 keepalive reuse; baseline for request bursts |
| `limit_req_status` | `$limit_req_status` | `limit_req_status` | TEXT | `PASSED`, `DELAYED`, or `REJECTED` — whether nginx rate-limited this request |

### 1.3 V4 fields (6) — added 2026-06-09 (bot/human detection)

Sec-Fetch headers are sent by every modern browser (Chrome 76+, Safari 13+, Firefox 90+) on
every request. They are **never** sent by curl, wget, Python-requests, or most scrapers.
Combined with `http_version`, they form the strongest bot/human signal available without TLS modules.

| JSON Key | nginx Variable | DB Column | Type | Why It's Useful |
|----------|---------------|-----------|------|-----------------|
| `http_version` | `$server_protocol` | `http_version` | TEXT | `HTTP/2.0` = modern browser; `HTTP/1.1` = old client or bot |
| `sec_fetch_dest` | `$http_sec_fetch_dest` | `sec_fetch_dest` | TEXT | `document` = top-level navigation; `script`/`image` = sub-resource; `""` = bot/curl |
| `sec_fetch_mode` | `$http_sec_fetch_mode` | `sec_fetch_mode` | TEXT | `navigate` = user-initiated; `cors`/`same-origin` = script fetch; `""` = bot/curl |
| `sec_fetch_site` | `$http_sec_fetch_site` | `sec_fetch_site` | TEXT | `none` = direct/bookmark; `same-origin` = internal link; `cross-site` = external link |
| `accept_encoding` | `$http_accept_encoding` | `accept_encoding` | TEXT | `br` (Brotli) = modern browser; `gzip` only = old bot; `""` = primitive client |
| `ssl_session_reused` | `$ssl_session_reused` | `ssl_session_reused` | TEXT | `r` = TLS session reused (returning client); `.` = new session |

### 1.4 Available but unused (nginx 1.29.6)

These are available in nginx and could be added later:

| Variable | Notes |
|----------|-------|
| `$bytes_sent` | Total bytes including headers (vs `$body_bytes_sent`) |
| `$http_x_real_ip` | Alternative real-IP header (when only one proxy hop) |
| `$upstream_response_time` | Backend latency (only if proxying to upstream) |
| `$ssl_session_id` | Session resumption tracking |
| `$sent_http_content_type` | Response content type |
| `$gzip_ratio` | Compression ratio (if gzip module active) |

---

## 2. Database schema

### 2.1 `visits` (29 columns)

| Column | Type | Source | Description |
|--------|------|--------|-------------|
| `id` | INTEGER PK | — | Auto-increment |
| `ip` | TEXT NOT NULL | `remote_addr` | Client IP |
| `timestamp` | TEXT NOT NULL | `time` | ISO8601 from nginx |
| `method` | TEXT | `request_method` + fallback | HTTP verb |
| `path` | TEXT | `request_uri` + fallback | Path + query string |
| `server_port` | INTEGER | `server_port` + ssl fallback | 80 or 443 |
| `status` | INTEGER | `status` | HTTP response code |
| `bytes_sent` | INTEGER | `body_bytes_sent` | Response body bytes |
| `user_agent` | TEXT | `http_user_agent` | Raw UA string |
| `referer` | TEXT | `http_referer` | Referer header |
| `request_time` | REAL | `request_time` | Response time in seconds |
| `ssl_protocol` | TEXT | `ssl_protocol` | TLSv1.x or `""` |
| `browser` | TEXT | `ua_parser(user_agent)` | e.g. Chrome, Firefox, curl |
| `os` | TEXT | `ua_parser(user_agent)` | e.g. Windows, Linux, Android |
| `device` | TEXT | `ua_parser(user_agent)` | Desktop, Mobile, Bot, or Unknown |
| `accept_language` | TEXT | `http_accept_language` | Full Accept-Language value |
| `request_length` | INTEGER | `request_length` | Total request size in bytes |
| `http_x_forwarded_for` | TEXT | `http_x_forwarded_for` | XFF header chain |
| `ssl_cipher` | TEXT | `ssl_cipher` | TLS cipher suite |
| `connection` | INTEGER | `connection` | nginx connection serial; `0` for rows written before V5 |
| `connection_requests` | INTEGER | `connection_requests` | Requests on this connection |
| `limit_req_status` | TEXT | `limit_req_status` | Rate limit outcome (`PASSED`/`DELAYED`/`REJECTED`) |
| `http_version` | TEXT | `http_version` | `HTTP/2.0` or `HTTP/1.1` (V4) |
| `sec_fetch_dest` | TEXT | `sec_fetch_dest` | Sec-Fetch-Dest header; `""` = no browser (V4) |
| `sec_fetch_mode` | TEXT | `sec_fetch_mode` | Sec-Fetch-Mode header (V4) |
| `sec_fetch_site` | TEXT | `sec_fetch_site` | Sec-Fetch-Site header (V4) |
| `accept_encoding` | TEXT | `accept_encoding` | Accept-Encoding header; `br` = modern browser (V4) |
| `ssl_session_reused` | TEXT | `ssl_session_reused` | `r` = reused TLS session, `.` = new (V4) |
| `created_at` | TEXT | CURRENT_TIMESTAMP | Row insertion time |

Indexes: `idx_visits_ip_timestamp (ip, timestamp)`, `idx_visits_timestamp (timestamp)`,
`idx_visits_status_path (status, path)`, `idx_visits_timestamp_ip (timestamp, ip)`,
and `idx_visits_request_identity (timestamp, connection, connection_requests)
WHERE connection > 0` — unique.

That last one is what makes a visit identifiable. `$time_iso8601` resolves to
the second, so `(time, ip, request)` cannot tell two identical requests in one
second apart from one request ingested twice, and a unique constraint over those
would silently drop real visits. `$connection` with `$connection_requests`
numbers a request uniquely for the life of the nginx process, and `insert_visit`
uses `INSERT OR IGNORE` against it — so re-reading a stretch of log (a restored
database beside a surviving file, `INGEST_EXISTING_BACKLOG=true`) recognises what
it already stored.

It is **partial** on purpose. Rows written before V5, and anything logged with
an older format, carry `connection = 0`; without the `WHERE` they would all
collide on `(timestamp, 0, 0)` and every visit after the first in a given second
would be dropped. Deduplication applies exactly where the log provides an
identity.

The last one exists for the dashboard's windowed aggregates: they filter by date
and then group by `ip`, and in that order SQLite answers them from the index
alone. Measured over 184k visits with a 90-day window, the `COUNT(DISTINCT ip)`
/ bounce / top-IPs trio drops from 218 ms to 94 ms. `(ip, timestamp)` is the
wrong way round for this and serves the per-IP lookups instead.

### 2.2 `ip_intel` (21 columns)

| Column | Type | Source | Description |
|--------|------|--------|-------------|
| `ip` | TEXT PK | — | IP address |
| `country` | TEXT | ip-api.com | Country name |
| `country_code` | TEXT | ip-api.com | ISO 3166-1 alpha-2 |
| `city` | TEXT | ip-api.com | City name |
| `lat` | REAL | ip-api.com | Latitude |
| `lon` | REAL | ip-api.com | Longitude |
| `isp` | TEXT | ip-api.com | ISP name |
| `org` | TEXT | ip-api.com | Organisation name |
| `asn` | TEXT | ip-api.com | AS number + name (e.g. `"AS15169 Google LLC"`) |
| `is_proxy` | INTEGER 0/1 | ip-api.com | Proxy / VPN / anonymizing relay |
| `is_hosting` | INTEGER 0/1 | ip-api.com | Datacenter / hosting provider |
| `is_mobile` | INTEGER 0/1 | ip-api.com | Mobile carrier network |
| `reverse_dns` | TEXT | forward-confirmed PTR, else Shodan | Verified hostname; read by the classifier ([§4.2.3](#423-pattern-lists-verbatim-srcclassifierpatternspy)) |
| `is_tor` | INTEGER 0/1 | torproject.org (daily) | Tor exit node |
| `dnsbl_listed` | INTEGER 0/1 | DNSBL lookups | Listed in ≥1 blocklist |
| `dnsbl_sources` | TEXT | DNSBL lookups | Comma-separated provider names |
| `fetched_at` | TEXT | — | ISO8601 timestamp of last enrichment |
| `visitor_class` | TEXT | classifier | Identity class (see [§4](#4-visitor-classification)) |
| `classified_at` | TEXT | classifier | When the class was last derived ([§4.2.7](#427-freshness)) |
| `classified_visit_id` | INTEGER | classifier | Newest `visits.id` the class was derived from |
| `rdns_checked_at` | TEXT | enricher | When a PTR lookup was last attempted (most IPs have no record; without this they would be retried forever) |

The multi-value Shodan fields (`open_ports`, `tags`, `hostnames`, `cpes`, `vulns`) were
normalized out into the `ip_intel_*` child tables ([§2.4](#24-ip_intel_-normalized-shodan-child-tables-migration-43)) and dropped from this table (migration 4.3).

Index: `idx_ip_intel_fetched (fetched_at)`, `idx_ip_intel_visitor_class (visitor_class)`

### 2.3 `processor_state` — key/value

| Key | Value | Description |
|-----|-------|-------------|
| `file_offset` | integer as string | Byte offset in log file; survives restarts |
| `file_inode` | integer as string | Inode number; detects rotation by rename |
| `file_fingerprint` | sha256 hex, or empty | Hash of the log's first 256 bytes. Detects a copytruncate that regrew past `file_offset`, which the inode and the size cannot see — including one that happened while the service was down. Empty while the file is shorter than 256 bytes, since a growing prefix would compare as a replacement |
| `classifier_version` | string | `CLASSIFIER_VERSION` last applied; differing value triggers a one-time `force_reclassify_all()` at startup |
| `retention.mode` | `rolling` \| `lifetime` | Retention mode, set in the UI. Absent means `rolling` |
| `retention.rolling_months` | integer as string | Months kept before the current one. Absent or unparseable means 2; clamped to 0–24 |
| `retention.archive_keep_months` | integer as string | Months an archive survives after its own month. Absent, unparseable or `0` keeps every archive; otherwise clamped to `rolling_months + 1`–120, since a shorter window would archive a month and delete it in the same pass |
| `retention.last_run` | ISO-8601 | When the daily pass last completed; `_retention_task()` uses it to decide whether a pass is due |
| `archive.pin.<YYYY-MM>` | ISO-8601 or `''` | A re-imported month is protected from re-archiving until this time. Empty means no pin |

### 2.3.1 Monthly archives

A month outside the retention window lives at `<ARCHIVE_DIR>/YYYY-MM.zip`. The
directory is the source of truth — there is no archive table, so a zip removed by
hand simply stops being listed.

| Member | Contents |
|--------|----------|
| `meta.json` | `month`, `created_at`, `schema_version`, `visits`, `ips`, `first_ts`, `last_ts` |
| `visits.jsonl` | One JSON object per visit, every column of `visits` including the original `id` |
| `ip_intel.jsonl` | `ip_intel` for the IPs seen that month; the Shodan children (`open_ports`, `tags`, `vulns`, `cpes`, `hostnames`) travel as JSON arrays |

An IP active in three months appears in all three archives. The duplication is
deliberate: each archive has to restore on its own.

`meta.json` is written **last** into the zip, and the zip is renamed into place
only after `fsync` — a file that has meta is a file that finished. Rows are
deleted only after that rename.

On restore, visits go in with `INSERT OR IGNORE` on their original `id`, and
intel is inserted **only for IPs that have none** (`insert_missing_intel`): the
archived snapshot is older than the live table by definition, so it may fill
gaps but never overwrite.

### 2.4 `ip_intel_*`: Normalized Shodan child tables (migration 4.3)

One row per value, `PRIMARY KEY (ip, <value>)`, `FOREIGN KEY (ip) → ip_intel(ip) ON DELETE
CASCADE`. Each is indexed on its value column for per-value lookups.

| Table | Columns | Former CSV column |
|-------|---------|-------------------|
| `ip_intel_ports` | `ip, port` (INTEGER) | `ip_intel.open_ports` (dropped) |
| `ip_intel_vulns` | `ip, vuln` | `ip_intel.vulns` (dropped) |
| `ip_intel_cpes` | `ip, cpe` | `ip_intel.cpes` (dropped) |
| `ip_intel_tags` | `ip, tag` | `ip_intel.tags` (dropped) |
| `ip_intel_hostnames` | `ip, hostname` | `ip_intel.hostnames` (dropped) |

These are the **sole** store for the multi-value fields. `upsert_ip_intel()` writes them via
`_sync_shodan_children()` (delete-then-insert per IP). Reads re-aggregate with `GROUP_CONCAT`
(`_shodan_agg_select()`) for display (`get_visitor_detail`, `get_shodan_hosts`); per-value
filtering (`/exposure?port=&vuln=&tag=`) and the classifier/`has_tags` `tags` lookups go
directly against the child tables. `init_db` migrates a legacy DB by backfilling the child
tables from the old CSV columns and then dropping those columns (needs SQLite ≥ 3.35).

### 2.5 `rate_limits` — Export throttle log

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | autoincrement |
| `client_ip` | TEXT | requester IP |
| `hit_at` | REAL | unix epoch of an `/api/export` hit |

---

## 3. Enrichment pipeline

### 3.1 ip-api.com

- **Endpoint:** `http://ip-api.com/batch` (HTTP only — HTTPS requires paid tier)
- **Batch size:** up to 100 IPs per request (`enrichment_batch_size`)
- **Rate limit:** free tier 15 req/min, paced at 13 by `_BATCH_INTERVAL_S`; respected via
  `X-Rl` / `X-Ttl` response headers
- **Fields populated:** `country`, `country_code`, `city`, `lat`, `lon`, `isp`, `org`, `asn`, `is_proxy`, `is_hosting`, `is_mobile`
- **Cache TTL:** `enrichment_cache_ttl_days` (default 30 days)

### 3.2 Shodan InternetDB

- **Endpoint:** `https://internetdb.shodan.io/{ip}` (per-IP, no API key needed)
- **Concurrency:** up to 10 simultaneous requests
- **404 response** = Shodan has no record of this IP. This is an *answer*: the
  fields are written empty and the child tables are cleared, because whatever we
  knew about that host's ports is no longer true.
- **No response** (timeout, connection error, 429, 5xx, unparseable body) = no
  answer. The Shodan fields are left out of the row entirely and every stored
  value survives. The two used to be the same empty result, so one failed lookup
  during a re-enrichment deleted the IP's ports, CVEs, CPEs, tags and hostnames.
- **Fields populated:** `reverse_dns`, `open_ports`, `tags`, `hostnames`, `cpes`, `vulns`

### 3.3 Tor exit nodes

- **Source:** `https://check.torproject.org/torbulkexitlist`
- **Refresh:** daily; cached for 24 hours in memory
- **On failure:** three attempts a second apart, then no retry for five minutes.
  The previous list stays in use throughout, so an outage makes the signal old
  rather than empty — the log says which, and `/settings/status` shows its age.
  Only a first start that never reached the list leaves `is_tor` unset.
- **Field populated:** `is_tor`

### 3.4 DNSBL

- **Providers:** `zen.spamhaus.org`, `bl.spamcop.net` (`DNSBL_PROVIDERS`). With
  `DNSBL_DQS_KEY` set, Spamhaus zones are queried as `<key>.zen.dq.spamhaus.net`.
- **Method:** async DNS A-record lookup of the reversed IP under each zone. IPv4 uses
  dotted-quad reversal; IPv6 uses nibble reversal (RFC 5782). Providers without IPv6
  support return NXDOMAIN, which reads as "not listed".
- **The returned address is the answer** — a listing is `127.0.0.0/8` excluding the
  `127.255.255.0/24` error range. See [§4.2.8](#428-signals) for the full return-code table and why
  accepting any resolution marked 98.7 % of all IPs as listed.
- **Fields populated:** `dnsbl_listed` (1 if any hit), `dnsbl_sources` (comma-sep provider names)

---

## 4. Visitor classification

> **These rules are calibrated, not universal.** Every threshold and needle list below was
> tuned against one site's traffic — a single low-traffic personal site — and the
> production measurements quoted throughout are the evidence for *that* profile. The four
> numeric thresholds in `src/classifier/patterns.py` (`_PROBE_404_RATE`,
> `_MALFORMED_REQUEST_RATE`, `_MIN_CONTENT_FOR_RATIO`, `_MIN_PAGES_FOR_WEAK_BROWSER`) are
> deliberately **not** settings: exposing four dials nobody can set without repeating the
> measurement would offer control that is not really there. On a site with different traffic
> they are a starting point to re-measure, not constants to trust.
>
> Three inputs to the chain *are* configurable, because they describe the observed site
> rather than the rules: `SITE_BASE_URL`, `STATIC_ASSET_PREFIXES` and `JS_ONLY_PATH_PREFIXES`.
> All three ship empty, and unset each one switches its signal **off** rather than guessing —
> see [§7](#7-config-settings-srcconfigpy).
>
> Two further assumptions are neither thresholds nor settings, and are worth knowing before
> reading a distribution that looks wrong:
>
> * **The site answers a permanent redirect on port 80.** `content_requests` — the denominator
>   under every error ratio — excludes `301` and `308` served on port 80, because that bounce
>   is half of all traffic here and counting it halves each rate. A deployment that redirects
>   with `302`/`307`, serves plain HTTP as the real thing, or terminates TLS upstream so nginx
>   never logs port 80, gets a larger denominator and correspondingly lower rates.
> * **The site is one hostname.** `SITE_BASE_URL` is matched with and without a leading `www.`,
>   and nothing else. A second domain, a subdomain such as `blog.`, or a referer carrying an
>   explicit port reads as external, so those visitors land in `humans/browser-referred`
>   instead of `humans/browser-internal-nav`. They are still humans; only the arrival story
>   changes.

### 4.1 Identity vs. signals (two orthogonal dimensions)

`visitor_class` is **identity only**. Network/reputation flags (Tor, proxy/VPN, DNSBL,
Shodan tags) are **orthogonal signals**, not classes — they layer on top of any identity.
A human on a VPN is `humans/browser-direct` *plus* a proxy signal; an identical Tor exit
with no browser/bot evidence is `unknown` plus a Tor signal.

**One reputation field is read by the chain, deliberately: `is_hosting`.** It separates
"a browser" from "a browser running in a datacenter" (`automated/headless-browser`), and
it decides whether an unverified crawler claim is credible (`bots/impersonators`).
Everything else stays a signal. Rationale and the measurements behind it are in
[§4.2.6](#426-rejected-signals-measured-not-assumed).

It cannot separate a rented server from a commercial VPN exit: NordVPN, Surfshark, M247
and iCloud Private Relay are all datacenter ranges, so from v3 to v5 the flag alone
demoted every person browsing over a VPN. Since v6 the flag only demotes an address that
*also* fails to behave like a reader — see [§4.2.2](#422-the-browser-gate-rule-8).

`_apply_priority_chain()` in `src/classifier/rules.py` assigns identity, behaviour-first. Bump
`CLASSIFIER_VERSION` (`src/classifier/patterns.py`) on any logic change to trigger a one-time
`force_reclassify_all()` at startup — see [§4.2.7](#427-freshness).

### 4.1a The taxonomy at a glance

18 classes in 5 groups. `#n` is the rule that assigns it — **first match wins, so a class
can only be reached when every rule above it failed**. Exact conditions in [§4.2.1](#421-precedence-first-match-wins).

```
visitor_class
│
├── threats/                        did something malicious, whatever else is true
│   ├── protocol-abusers      #1    non-HTTP request line carrying a shell cmd or dropper
│   └── exploit-probers       #2    traversal · /etc/passwd · SQLi · XSS · %00 · .arm dropper
│
├── bots/                           automation we can put a name to
│   ├── vulnerability-probers #3    probe path · OR 404 rate >20% · OR ≥3 missing paths
│   ├── security-researchers  #4a   named org — Censys, Shodan, Shadowserver, LeakIX, Modat
│   ├── scanning-tools        #4b   tool named, operator not — zgrab, masscan, nuclei
│   ├── search-crawlers       #5    crawler UA, confirmed by rDNS or not on cloud
│   ├── ai-crawlers           #6    GPTBot, ClaudeBot, PerplexityBot — same corroboration
│   ├── seo-tools             #7    Ahrefs, Semrush, Majestic, Screaming Frog
│   ├── impersonators         #5b   crawler UA nothing about its origin supports
│   └── generic-bots          #10   UA calls itself a bot; operator unknown
│
├── humans/                   #8    passed the browser gate, and not on cloud compute
│   ├── browser-referred            … arrived cross-site
│   ├── browser-internal-nav        … moved between our pages (referer ≠ page requested)
│   └── browser-direct              … neither
│
├── automated/                      machine, but not an identifiable bot
│   ├── headless-browser      #8    browser gate passed, but from a cloud/VPS range
│   ├── http-clients          #9    curl · wget · Go-http-client · python-requests · OkHttp
│   ├── protocol-mismatch     #11   TLS spoken to the HTTP port, or an empty request line
│   └── datacenter            #12   hosting IP and nothing above matched
│
└── other/
    └── unknown               #13   no evidence — usually never got past the 301 redirect
```

Reading the hierarchy: **the group answers "what kind of thing is this"**, the class
answers "which one". `threats` is about an action, `bots` about a named actor, `automated`
about a machine we can describe but not attribute, `humans` about a person, `unknown` about
insufficient evidence. An IP has exactly one class; Tor / proxy / hosting / DNSBL / Shodan
tags ride alongside as signals and can be combined freely.

### 4.2 The rules, exactly

18 classes across 5 groups, defined in `taxonomy.py` (`VISITOR_CATEGORIES` — the single
source of truth). `_decisive_rule()` mirrors this chain condition-for-condition to produce
the "Why this verdict" evidence on `/visitors/{ip}`; a test asserts the two never diverge.

#### 4.2.1 Precedence: first match wins

| # | Class | Condition | Signal-dict fields |
|---|-------|-----------|--------------------|
| 1 | `threats/protocol-abusers` | `payload_abuse > 0` — a non-HTTP request line carrying a shell command or dropper | `payload_abuse` |
| 2 | `threats/exploit-probers` | `exploit_probes > 0` — traversal, `/etc/passwd`, SQLi, XSS, encoded null byte, dropper filename | `exploit_probes` |
| 3a | `bots/vulnerability-probers` | `scanner_paths > 0` | `scanner_paths` |
| 3b | `bots/vulnerability-probers` | `content_requests >= 3` **and** probe-404 rate `> 0.20` | `content_requests`, `probe_404` |
| 3c | `bots/vulnerability-probers` | `distinct_404_paths >= 3` | `distinct_404_paths` |
| 4a | `bots/security-researchers` | rDNS or UA names an attributable organisation | `reverse_dns`, `all_uas_lower` |
| 4b | `bots/scanning-tools` | UA names a generic scanning tool | `all_uas_lower` |
| 5a | `bots/search-crawlers` | rDNS confirms a search engine | `reverse_dns` |
| 5b | `bots/search-crawlers` / `bots/impersonators` | search-crawler UA — the second when `is_hosting` and neither rDNS nor the network owner confirms | `all_uas_lower`, `is_hosting`, `reverse_dns`, `org`, `asn` |
| 6a | `bots/ai-crawlers` | rDNS confirms an AI crawler | `reverse_dns` |
| 6b | `bots/ai-crawlers` / `bots/impersonators` | AI-crawler UA, same corroboration rule as 5b | `all_uas_lower`, `is_hosting`, `reverse_dns`, `org`, `asn` |
| 7 | `bots/seo-tools` | SEO crawler UA (incl. `screaming` + `frog`) | `all_uas_lower` |
| 8 | `humans/*` or `automated/headless-browser` | the browser gate and its disqualifiers — see [§4.2.2](#422-the-browser-gate-rule-8) | many |
| 9 | `automated/http-clients` | UA is an HTTP client library | `all_uas_lower` |
| 10 | `bots/generic-bots` | `bot_device > 0` — the UA declares itself a bot | `bot_device` |
| 11 | `automated/protocol-mismatch` | `protocol_mismatch > 0` and no payload — TLS on the HTTP port, empty request line, binary junk | `protocol_mismatch` |
| 12 | `automated/datacenter` | `is_hosting` and nothing above matched | `is_hosting` |
| 13 | `unknown` | no rule matched | — |

Rule 11 sits *below* every behavioural rule on purpose: a scanner that also mis-speaks the
protocol is still a scanner.

#### 4.2.2 The browser gate (rule 8)

```python
disqualified = (                      # direct counter-evidence to "a person is browsing"
    scanner_paths > 0
    or bot_device > 0                 # the UA already identifies itself as a bot
    or protocol_mismatch > 0          # TLS on the plain port, empty request lines
    or probe_404 / content_requests >= 0.20
    or bad_requests / content_requests >= 0.20
)
js_browser     = js_fetch > 0 and not hosting and bot_device == 0
strong_browser = browser_navigate > 0 or js_browser
weak_browser   = has_zstd > 0 or http2_visits > 0
is_browser = not disqualified and (
    strong_browser or (weak_browser and unique_paths >= 2)
)
```

Each disqualifier was measured letting non-humans through: a bot UA (21 IPs, e.g. a
`GenomeCrawlerd` crawler labelled human), non-HTTP traffic (28), malformed-request rate
(37). `unique_paths` counts **pages** — the protocol-error pseudo-paths are excluded,
because `[handshake on HTTP port]` plus `/` used to satisfy "explored ≥ 2 pages" (18 IPs).

`hosting` here is `is_hosting` **or** an ISP name in `_CLOUD_ISP_PATTERNS` ([§4.2.3](#423-pattern-lists-verbatim-srcclassifierpatternspy)).

Then, in order:

| Outcome | Condition |
|---------|-----------|
| `automated/headless-browser` | `hosting` and not `reads_like_a_person` |
| `humans/browser-referred` | `cross_site_nav > 0` |
| `humans/browser-internal-nav` | `internal_nav > 0` |
| `humans/browser-direct` | otherwise |

- **Sec-Fetch** (`sec_fetch_mode='navigate'` + `sec_fetch_dest='document'`) is sent by real
  browsers and practically never by bots or CLI tools, so a single hit suffices.
- **`js_fetch`** — a request to a path in `JS_ONLY_PATH_PREFIXES` (no default; unset, this
  signal is simply absent). Only the site's own JavaScript requests those, so fetching one
  proves a JS-executing browser. It is the one browser signal an HTTP/1.1 client without
  Sec-Fetch can still give us. Gated on `is_hosting`/`bot_device` because headless crawlers
  run our JS too (measured: 421 datacenter IPs fetch the fragments).
- **Weak transport hints** (HTTP/2, zstd) are also sent by bots, so they additionally
  require ≥ 2 distinct paths.
- **`reads_like_a_person`** (`_reads_like_a_person()`) is the carve-out that lets a
  datacenter address stay human: `internal_nav > 0 and probe_404 == 0 and unique_paths >= 3`.
  Each condition was measured. Internal navigation is the discriminator — it holds for all
  20 addresses that pass and for 9% of the 268 that do not. Requiring no probe-404 removes
  the eight that navigate internally *and* ask for missing paths, every one a scanner on
  Google Cloud averaging 226 pages and 46 misses. The page floor drops single-page
  infrastructure: at 2 it would admit seventeen more, fifteen of them CenturyLink,
  Microsoft and DigitalOcean touching one path. A patient crawler that follows links,
  requests nothing absent and stays under the floor is indistinguishable from a reader
  here; the hosting and proxy signals stay attached either way.
- **`internal_nav`** is `sec_fetch_site='same-origin'`, **or** a referer that (a) is
  anchored at our host with an optional `www.` and either scheme, (b) continues with `/`,
  and (c) points at a *different* path than the request. All three matter: an unanchored
  `%host%` match would let `https://evil.example/?u=<host>/x` forge internal navigation,
  and without (c) our own HTTP→HTTPS redirect reads as navigation — see [§4.2.5](#425-the-signal-dict-_classify_sql).

#### 4.2.3 Pattern lists (verbatim, `src/classifier/patterns.py`)

**`_SCANNER_PATH_PATTERNS`** (rule 3a) — substring `LIKE`, case-insensitive for ASCII:

```
/.env      /.git/     actuator    wp-admin    wp-config   wp-login
/wp-json/  rest_route xmlrpc      /cgi-bin/   phpinfo     phpmyadmin
/.aws/     .sql       docker-compose  kubernetes  terraform  credentials
database.yml  /boaform/  hnap1   /geoserver  /solr/  /jenkins  /telnet
.php       /login     /admin      /mcp        /sse
```

> `.php`, `/login` and `/admin` are **site-specific**: this site is fully static and has no
> login, so they cannot match anything legitimate here. Drop them on a deployment that
> serves PHP or an admin area.

**Exploit patterns** (rule 2): `%../%`, `/etc/passwd`, `/etc/shadow`, `%SELECT%FROM%`,
`%UNION%SELECT%`, `%<script%`, `INSTR(path, '%00') > 0`, `%cmd=%`, plus `_DROPPER_SUFFIXES`
— a path ending in `.arm .arm5 .arm6 .arm7 .mips .mpsl .x86 .x86_64 .m68k .sh4 .spc .arc
.ppc` (multi-architecture botnet droppers).

**`_PAYLOAD_ABUSE_PATTERNS`** (rule 1) — matched only when
`method IN ('NON-HTTP','TLS','UNKNOWN')`: `wget`, `curl `, `chmod`, `busybox`, `/bin/sh`,
`rm+-rf`, `rm -rf`, `mozi`, `gpon`, `jsonrpc`, `/shell`, `t3 1`.

**`protocol_mismatch`** (rule 11): path is `[binary payload]`, `[handshake on HTTP port]`
or `[empty request]`, **or** the method is `NON-HTTP`/`TLS`/`UNKNOWN`.

**`_CONVENTION_404_PATTERNS`** — 404s on these are **excluded** from `probe_404`, so they
never push a visitor over the error threshold: `security.txt` (RFC 9116), `ads.txt` (IAB),
`llms.txt`, `humans.txt`, `robots.txt`, `sitemap*.xml`, anything under `/.well-known/`
(RFC 8615), `favicon.ico`, `apple-touch-icon*`. Asking where to report a vulnerability is
good citizenship; counting it labelled **42 production IPs** as vulnerability-probers.

**`_CLOUD_ISP_PATTERNS`** — operator names that supplement `is_hosting`, which ip-api
does not set for every provider: amazon, aws, google, microsoft, azure, digitalocean, ovh,
hetzner, linode, akamai, oracle, alibaba, tencent, huawei cloud, datacamp, m247, vultr,
contabo, leaseweb, choopa, scaleway, upcloud, cherry servers, server mania, purevoltage,
hostinger, ionos.

> **Cloudflare is deliberately absent.** Its ranges carry WARP, a consumer VPN: all 32
> Cloudflare IPs in the human cohort were proxy-flagged, 23 fetched the JS-only page
> fragments and 22 sent Sec-Fetch. That is a person. A bare `%cloud%` substring would have
> swept every one of them into `automated/headless-browser`.

**Identification needles**:

| Constant | Values |
|----------|--------|
| `_RESEARCHER_RDNS` | shodan, censys, shadowserver, internet-census, leakix |
| `_RESEARCHER_UAS` | censysinspect, shodan, l9explore, leakix, palo alto, expanse, modatscanner, internet-measurement, bitsight, netsystemsresearch |
| `_SCANNING_TOOL_UAS` | zgrab, masscan, libredtail, nmap, zmap, nuclei |
| `_SEARCH_RDNS` | googlebot, bingbot, yandex, duckduck, baidu, seznam, msn.com |
| `_SEARCH_UAS` | googlebot, bingbot, yandexbot, baiduspider, duckduckbot, seznambot, sogou, petalbot |
| `_AI_RDNS` | openai, anthropic, bytedance, perplexity |
| `_AI_UAS` | gptbot, claudebot, bytespider, perplexitybot, ccbot, applebot, oai-search |
| `_SEO_UAS` | ahrefsbot, semrushbot, mj12bot, dotbot, rogerbot, blexbot, seokicks |
| `_HTTP_CLIENT_UAS` | curl/, wget/, go-http-client, python-requests, python-urllib, java/, okhttp, libwww-perl, guzzlehttp, axios/, node-fetch |

UA matching is substring, against `GROUP_CONCAT(DISTINCT LOWER(user_agent))` over **all** of
that IP's visits.

#### 4.2.4 Thresholds

| Value | Where | Why |
|-------|-------|-----|
| `0.20` | probe-404 rate, rules 3b and 8 | One threshold for both, so no band exists that matches neither. It used to be `> 0.30` for probing and `< 0.20` for human, leaving 20–30 % matching nothing. |
| `3` | `content_requests` floor, rule 3b | Was 5; a 3-request all-404 scanner matched nothing. |
| `3` | `distinct_404_paths`, rule 3c | Catches low-volume scanners no ratio can. |
| `2` | `unique_paths`, weak-signal browsers | HTTP/2 and zstd are not browser-exclusive. |

#### 4.2.5 The signal dict (`_classify_sql`)

One row per IP, aggregating **every** visit it ever made within retention. There is no time
window: an IP that browsed in June and probed in August is judged on the union.

| Field | Derivation |
|-------|------------|
| `total` | `COUNT(v.id)` — all visits |
| `content_requests` | visits excluding port-80 `301`s — **the denominator for every ratio** |
| `payload_abuse`, `protocol_mismatch`, `exploit_probes`, `scanner_paths` | [§4.2.3](#423-pattern-lists-verbatim-srcclassifierpatternspy) |
| `browser_navigate` | `sec_fetch_mode='navigate' AND sec_fetch_dest='document'` |
| `js_fetch` | path starts with a `JS_ONLY_PATH_PREFIXES` entry |
| `has_zstd`, `http2_visits` | `accept_encoding LIKE '%zstd%'`, `http_version='HTTP/2.0'` |
| `err404` | every `status=404` — shown in the evidence, not used by any rule |
| `probe_404`, `distinct_404_paths` | 404s **excluding convention files** ([§4.2.3](#423-pattern-lists-verbatim-srcclassifierpatternspy)), and their distinct paths — these drive the rules |
| `bot_device` | `device='Bot'` (from `ua_parser`) |
| `bad_requests` | `status=400` count — malformed requests are tooling, not browsing |
| `isp` | `ip_intel.isp`, lowercased — checked against `_CLOUD_ISP_PATTERNS` |
| `internal_nav`, `cross_site_nav` | [§4.2.2](#422-the-browser-gate-rule-8) |
| `unique_paths` | distinct paths **excluding** `[binary payload]` / `[handshake on HTTP port]` / `[empty request]` — those are protocol errors, not pages |
| `all_uas_lower`, `reverse_dns`, `tags` | UA concat, `ip_intel.reverse_dns`, `ip_intel_tags` |
| `is_hosting`, `is_proxy` | read by rules 8 and 12 only; `is_hosting` is OR-ed with the cloud-ISP name check |
| `is_tor`, `dnsbl_listed`, `tags` | **selected but never read by the chain** — context for `explain_classification()` and the `?signal=` filter |

**Evidence limits — what the classifier cannot see:**

- **Port-80 redirects.** 52 % of production visits (231,709 of 442,073) are the HTTP→HTTPS
  `301`. They are excluded from `content_requests` but still counted in `total`.
- **The redirect referer artifact.** A client hitting `http://host/` is 301'd and
  re-requests with `Referer: http://host/` — identical to the page it lands on. 754 IPs
  carried this. `internal_nav` therefore requires the referer path to *differ* from the
  requested path; without that check a frozen-UA monitoring botnet reads as human
  navigation.
- **Pre-V4 history.** `http_version`, `sec_fetch_*` and `accept_encoding` are empty for all
  178,654 April+May 2026 visits (the nginx V4 format landed 2026-06-09). An IP whose traffic
  predates that **cannot** pass the browser gate. This ages out with retention.
- **Static-asset filtering.** `.json` is in `STATIC_EXTENSIONS`, so `/credentials.json` and
  `/.env.json` probes are dropped before the classifier sees them (`log_processor.py`).
- **rDNS coverage.** Populated by a forward-confirmed PTR lookup per enriched IP. Before
  that it came only from Shodan's `hostnames` and covered 14.5 % of IPs, which left the
  rDNS branches (5a, 6a) effectively dead.

#### 4.2.6 Rejected signals: measured, not assumed

Tested against production and **not** adopted. Do not re-propose without new data.

| Proposal | Measurement that rules it out |
|----------|-------------------------------|
| `accept_language` as human evidence | Sent by 1,113 of 2,751 datacenter IPs and 725 of 1,858 vulnerability-probers |
| Match internal referers on host alone (accept `http://`, `www.`) | Relabels the 754-IP redirect-artifact cohort as `humans/browser-internal-nav` |
| `device IN (Desktop,Mobile,Tablet)` as human evidence | 1,118 of 1,590 `unknown` IPs have it, as do most datacenter crawlers; the UA is self-declared |
| JS-fragment fetch ⇒ human regardless of origin | 421 datacenter IPs fetch them — headless crawlers running our JS |
| `is_proxy` as a VPN exemption from the hosting rule | All 61 hosting IPs in `humans/*` also carried the proxy flag, so the exemption exempted every one of them. Dropped in v4: a browser in a datacenter is automation regardless |
| Shodan `scanner`/`honeypot` tag ⇒ security researcher | Describes the services *that IP* exposes (often a compromised host), not who is visiting. 366 IPs were labelled researchers by this alone; it is now only the `has_tags` signal |

#### 4.2.7 Freshness

A class summarises an IP's whole history, so it decays as the IP keeps acting. Three
mechanisms keep labels current:

| Mechanism | Trigger | Scope |
|-----------|---------|-------|
| `set_visitor_class()` | after each enrichment (`enricher.py`) | one IP |
| `backfill_visitor_classes()` | startup | IPs with no class yet |
| `reclassify_stale_ips()` | every `RECLASSIFY_INTERVAL_MINUTES` (default 15) | IPs with visits newer than their last classification |
| `force_reclassify_all()` | startup, when `CLASSIFIER_VERSION` differs from the stored value | every IP |

`ip_intel.classified_at` records when the class was last derived and
`classified_visit_id` the newest visit it was derived from. The **id**, not the timestamp,
drives staleness: `CURRENT_TIMESTAMP` resolves only to the second, so a visit arriving in
the same second as the classification would never look newer. Before this existed, a label
was written once at enrichment and never revisited — 242 production IPs carried a verdict
their own later traffic contradicted.

#### 4.2.8 Signals

Seven filterable keys (`VALID_SIGNALS` in `taxonomy.py`), orthogonal to identity and freely
combinable — they overlap and never sum to the IP total. Six describe the network or its
reputation; `clean` is derived from their absence rather than measured.

| Signal | Source | Notes |
|--------|--------|-------|
| `is_tor` | daily Tor exit list | |
| `is_proxy` | ip-api `proxy` | consumer VPN / proxy |
| `is_hosting` | ip-api `hosting` | also read by chain rules 8 and 12 |
| `dnsbl_listed` | DNSBL query | see the return-code contract below |
| `has_tags` | `EXISTS` in `ip_intel_tags` | Shodan knows the host |
| `is_mobile` | ip-api `mobile` | says which network an IP sits on, not what is known against it — so it does not count against `clean` |
| `clean` | `_no_signals_sql()` | enriched, and none of the four flags or any tag |

`is_mobile` is the one signal that filters without affecting `clean`: an address on a carrier
network with nothing else against it is still clean.

**DNSBL return codes.** A blocklist answers in `127.0.0.0/8` and the *value* is the answer;
presence of an A record is not a listing. `127.255.255.0/24` is reserved for query errors:

| Response | Meaning |
|----------|---------|
| `127.0.0.2` / `.3` | SBL / CSS — listed |
| `127.0.0.4`–`.7` | XBL — listed |
| `127.0.0.10` / `.11` | PBL — listed |
| `127.255.255.252` | error — wrong or typo'd zone name |
| `127.255.255.254` | error — query arrived via an open/public resolver |
| `127.255.255.255` | error — quota exceeded |

Treating "it resolved" as "it is listed" marked **11,372 of 11,527 IPs (98.7 %)** as
blocklisted, 11,354 of them by `zen.spamhaus.org` alone — including Googlebot ranges —
because the container resolves through a public upstream that Spamhaus refuses.
`_dnsbl_lookup()` now returns `True` / `False` / `None`, where `None` is a provider error
and is logged once per provider rather than recorded as a listing.

Spamhaus's free **Data Query Service** avoids the refusal: set `DNSBL_DQS_KEY` and queries
go to `<key>.zen.dq.spamhaus.net`. Without a key the legacy zone is used, every lookup
errors, and `_check_dnsbl()` returns `None` — so `dnsbl_listed` is not written at all
rather than written as clean. Alternatives considered: **AbuseIPDB** (free API, 1,000 checks/day —
richer than a boolean but below our IP volume, so incremental-only), and the **Spamhaus
rsync feed** (needs a local mirroring DNS server; disproportionate here). `dnsbl.sorbs.net`
was removed — the service was retired and its zone answers nothing.

### 4.3 Mobile — orthogonal attribute

`is_mobile = 1` does not exclude an IP from any other category. On the geo map the
"Include mobile networks" toggle controls whether mobile IPs (regardless of primary
category) are shown or hidden as an overlay filter.

---

## 4.4 Free-text search (`?q=`)

One box, one parameter, every grouping and every view. A term either **names its
field** (`country:DE`) or is matched by **shape**; terms are AND-ed.

The registry lives in `src/search.py` — deliberately free of SQL, so the parsing
is unit-testable without a database and `src/queries/` stays the only place that
builds SQL. Adding a field means one entry there; the help panel, the pills and
the placeholder are all generated from it.

### 4.4.1 Fields

| Field (aliases) | Label | Column(s) | Match | Example |
|---|---|---|---|---|
| `ip` | IP | v.ip | prefix | `ip:192.0.2.` — matches a prefix |
| `country` (`cc`) | Country | i.country_code/i.country | country | `country:DE` — two-letter code exactly, or part of the name |
| `city` | City | i.city | substring | `city:Berlin` |
| `asn` | Network | i.asn | substring | `asn:AS13335` |
| `org` | Org | i.org | substring | `org:hetzner` |
| `isp` | ISP | i.isp | substring | `isp:datacamp` |
| `rdns` (`host`) | Reverse DNS | i.reverse_dns | substring | `rdns:googlebot` |
| `path` (`url`) | Path | v.path | substring | `path:/.env` |
| `ua` (`agent`) | User-Agent | v.user_agent | substring | `ua:wget` |
| `browser` | Browser | v.browser | substring | `browser:Chrome` |
| `os` | OS | v.os | substring | `os:Android` |
| `device` | Device | v.device | exact | `device:Bot` — Desktop, Mobile, Tablet, Bot, Other or Unknown |
| `referer` (`ref`) | Referrer | v.referer | substring | `referer:google` |
| `class` | Class | i.visitor_class | class | `class:threats` — a group, or a full class like humans/browser-direct |
| `signal` | Signal | — | signal | `signal:tor` — tor, proxy, hosting, dnsbl, tags or clean |
| `tag` | Shodan tag | ip_intel_tags.tag | exact | `tag:scanner` |
| `vuln` (`cve`) | CVE | ip_intel_vulns.vuln | substring | `vuln:CVE-2021` |
| `port` | Open port | ip_intel_ports.port | number | `port:22` — a port Shodan sees open on the host |
| `serverport` | Server port | v.server_port | number | `serverport:80` — the port on *our* server — only ever 80 or 443 |
| `status` | Status | v.status | status | `status:404` — a code, or 2xx–5xx |
| `method` | Method | v.method | exact | `method:POST` |
| `http` (`httpversion`) | HTTP version | v.http_version | substring | `http:2` |

An unknown field name (`foo:bar`) is **reported at the search box, not searched**
— quietly demoting it to a broad match would filter the page differently than the
reader believes. At most 8 terms per query.

### 4.4.2 Terms without a field

Only unmistakable shapes are claimed; everything else searches broadly across
`ip, country, city, asn, org, isp, rdns, path, ua, browser, os`.

| Shape | Becomes | Example |
|---|---|---|
| exactly two ASCII letters | `country` (code, exact) | `DE` |
| `AS<digits>` | `asn` | `AS13335` |
| starts with `/` | `path` | `/.env` |
| hex/dots/colons with ≥2 dots or a `:` | `ip` (prefix) | `192.0.2.` |
| three digits, 100–599 | `status` | `404` |
| anything else | broad | `hetzner` |

Naming a field overrides the shape, and a `"quoted phrase"` opts out of inference
entirely while keeping its spaces.

**Why this exists.** Every term used to be a substring against eleven columns at
once. Measured against a live log, `de` matched **3,617 of 11,564 IPs** — 1,627 of them
through `path`, because `/in`**`de`**`x.html` contains the letters, plus 470 via
reverse DNS and 453 via org names. The 961 IPs actually in Germany were 27% of
the result. `de` now returns exactly those 961; `path:de` still returns the 1,627.

### 4.4.3 Where a term is evaluated

| Surface | Treatment |
|---|---|
| `group=ip`, `view=map`, `view=timeline` | Per-IP facts (intel columns, child tables, the address) go into the `WHERE`. Per-visit facts go through `v.ip IN (SELECT ip FROM visits WHERE …)`, so the search selects **visitors** without shrinking the rows aggregated over — an IP found via `/.env` keeps its real visit count. |
| the four aggregations | The same terms inline, before `GROUP BY`. Deliberate: on `?group=path&q=ua:curl` the question is "what did curl fetch", so the row's counts should describe the matching traffic. |

### 4.4.4 Known limits

- SQLite's `LIKE` folds case for ASCII only, so `türkiye` does not match `Türkiye`.
  Exact matches (`country`, `device`, `method`, `tag`) use `COLLATE NOCASE`, which
  has the same limit.
- `port:` is the port **Shodan sees open on the host**; the port on our own server
  is `serverport:` and only ever holds 80 or 443.

---

## 5. Query functions (`src/db.py` and `src/queries/`)

| Function | Parameters | Returns | When to Use |
|----------|-----------|---------|-------------|
| `init_db` | `db_path=None` | None | App startup; creates schema + runs migrations |
| `get_conn` | `db_path=None` | context manager → Connection | Every route; WAL mode, row_factory=Row, auto-commit |
| `insert_visit` | `conn, ip, timestamp, method, path, server_port, status, bytes_sent, user_agent, referer, request_time, ssl_protocol, browser, os, device, accept_language, request_length, http_x_forwarded_for, ssl_cipher, connection_requests, limit_req_status, http_version, sec_fetch_dest, sec_fetch_mode, sec_fetch_site, accept_encoding, ssl_session_reused` | int (row id) | `log_processor.py` per log line |
| `get_visits` | `conn, page, limit, sort, order, ip_filter, country_filter` | list[dict] | Paginated raw visits table |
| `count_visits` | `conn, ip_filter, country_filter` | int | Pagination total for visits |
| `get_visitors_grouped` | `conn, page, limit, sort, order, country_filter, ip_filter, class_filter, signal_filter, min_visits, date_from, date_to, port_filter, asn_filter, path_filter, browser_filter` | list[dict] | All IPs grouped — one row per IP; `asn_filter`/`path_filter`/`browser_filter` are the aggregation drill-downs |
| `count_visitors_grouped` | `conn, …same filters…` | int | Pagination total for grouped visitors |
| `get_visitor_detail` | `conn, ip` | dict or None | Single IP detail page |
| `get_visitor_requests` | `conn, ip, page, limit, sort, order` | list[dict] | Paginated request log for one IP |
| `get_networks` / `count_networks` | `conn, page, limit, sort, order, class_filter, signal_filter, date_from, date_to, q` | list[dict] / int | `/visitors?group=asn`: grouped by ASN. Shares `_exec_agg_rows`/`_exec_agg_count` + `_AGG_BREAKDOWN_SELECT` (per-group + per-signal distinct-IP counts) with the other three; `q` searches org/ISP/ASN (`_agg_q_filter`) |
| `get_countries` / `count_countries` | same as networks | list[dict] / int | `/visitors?group=country`: grouped by `country_code`; `q` searches country name/code |
| `get_clients` / `count_clients` | same as networks | list[dict] / int | `/visitors?group=client`: grouped by `browser, os, device`; `q` searches browser/OS/device |
| `get_paths` / `count_paths` | same as networks, plus `q, status` | list[dict] / int | `/visitors?group=path`: grouped by `path`, with a 2xx/3xx/4xx/5xx status mix; `q` searches path + user_agent, `status` narrows to a 2xx–5xx class (absorbed from the removed `/visitors/requests` scanner table) |
| `get_stats` | `conn` | dict | Overview dashboard: totals, top-N lists, rates, sparkline |
| `get_geo_data` | `conn` | tuple[list[dict], dict] | `/visitors?view=map` route: markers + geo_stats |
| `get_analysis_data` | `conn, since, until` | dict | `/analysis` route: enriched-IP total, distributions (status/http-version/methods), rate limits, classifier diagnostics |
| `get_shodan_hosts` / `count_shodan_hosts` | `conn, page, limit, port, vuln, tag` | list[dict] / int | `/exposure` route: IPs with Shodan exposure; optional per-value filters (AND-combined) read the `ip_intel_*` child tables |
| `get_activity_timeline` | `conn, since, until` | list[dict] | `/` route: `[{day, total, humans, bots, automated, threats, unknown}]` daily taxonomy breakdown |
| `get_ip_intel` | `conn, ip` | dict or None | Single IP enrichment lookup |
| `get_ip_intel_bulk` | `conn, ips` | dict[str, dict\|None] | Bulk enrichment lookup |
| `upsert_ip_intel` | `conn, data` | None | Enricher writes geo/threat data |
| `get_unenriched_ips` | `conn, limit` | list[str] | Enrichment queue seed: IPs with no intel yet |
| `get_stale_ips` | `conn, ttl_days, limit` | list[str] | Enrichment refresh: IPs with old intel |
| `get_state` | `conn, key` | str or None | Read log processor state (offset/inode) |
| `set_state` | `conn, key, value` | None | Write log processor state |
| `purge_orphaned_intel` | `conn` | int (deleted rows) | Retention job: clean up orphaned ip_intel (cascades to `ip_intel_*` child rows) |
| `vacuum` | `db_path=None` | None | Retention job: reclaim disk space. Only runs when a pass actually removed rows |
| `get_visit_months` | `conn` | list[dict] | Every month in `visits`, oldest first, with visit and distinct-IP counts |
| `stream_visits_for_month` | `conn, month` | Iterator[dict] | One month's visits verbatim, oldest first, in chunks of 1000 |
| `get_intel_for_month` | `conn, month` | list[dict] | `ip_intel` for every IP seen that month, Shodan children folded in |
| `delete_visits_for_month` | `conn, month` | int (deleted rows) | Drop one month from `visits` |
| `insert_archived_visits` | `conn, rows` | int (inserted rows) | Restore visits with their original `id` (`INSERT OR IGNORE`), columns intersected with the live table |
| `insert_missing_intel` | `conn, rows` | int (inserted rows) | Restore intel only for IPs that have none — never overwrites fresher live data |
| `count_export_hits` / `record_export_hit` / `purge_old_rate_limits` | `conn, client_ip, window_s, now` (+ variants) | int / None / int | `/api/export` middleware: persistent per-IP rate limiting via `rate_limits` |
| `backfill_visitor_classes` / `force_reclassify_all` | `conn` | int (rows updated) | Startup classification: fill empty classes / reclassify ALL after a `CLASSIFIER_VERSION` bump |

---

## 6. Derived metrics

These are computed at query time — not stored in the database.

| Metric | Formula | Function | Notes |
|--------|---------|---------|-------|
| `bounce_rate` | `COUNT(IPs with exactly 1 request in the window) / COUNT(DISTINCT ip) × 100` | `get_stats()` | % — "exactly one" is a property of the selected range, not of all time |
| `https_rate` | `COUNT(ssl_protocol != '') / COUNT(*) × 100` | `get_stats()` | % |
| `error_rate` | `COUNT(status >= 400) / COUNT(*) × 100` | `get_stats()` | % |
| `browser` / `os` / `device` | `ua_parser(user_agent)` via `ua_parser.py` | `process_entry()` | Runs at ingest time |
| `geo_stats.clean_count` | `is_proxy=0 AND is_tor=0 AND is_hosting=0 AND dnsbl_listed=0` | `get_geo_data()` | Only IPs with lat/lon |
| `geo_stats.<group>_count` | markers folded by `visitor_class` group | `get_geo_data()` | Python post-processing |
| `avg_response_time` | `AVG(request_time) WHERE request_time > 0` | `get_stats()` | Seconds, rounded to 3 dp |
| `spark_visits` / `spark_errors` / `spark_bytes` | `[{day, visits, errors, bytes}]` folded into three comma-joined series | `get_daily_kpis()`, joined in `overview()` | Scoped to the shown window, not a fixed 7 days, so the sparkline covers the days the number above it does |
| `visits_delta` | `(visits − visits in the equally long window before) / that × 100` | `overview()` route | No delta for `range=all`: there is no window before it |
| `total_countries` | `COUNT(DISTINCT country_code) FROM ip_intel` | `get_stats()` | All enriched IPs, not just mapped ones |
| `visitor_class_breakdown` | `_VISITOR_GROUP_CASE` over `ip_intel` | `get_stats()` | Per-group IP counts for the Overview |

---

## 7. Config settings (`src/config.py`)

| Setting | Env Var | Default | Description |
|---------|---------|---------|-------------|
| `log_path` | `LOG_PATH` | `/logs/access.log` | nginx access log to tail |
| `db_path` | `DB_PATH` | `/data/vidar.db` | SQLite database path |
| `archive_dir` | `ARCHIVE_DIR` | `/data/archive` | Where monthly zips are written ([§2.3.1](#231-monthly-archives)). Must stay under `/data` — the container is read-only and that bind mount is its only writable path |
| `archive_restore_days` | `ARCHIVE_RESTORE_DAYS` | `7` | How long a re-imported month stays pinned in the active DB before the daily pass archives it out again |
| `retention_days` | `RETENTION_DAYS` | `90` | **Deprecated and inert.** Retention is a calendar window chosen in the UI ([§2.3.1](#231-monthly-archives)); kept only so an existing `.env` still loads |
| `enrichment_cache_ttl_days` | `ENRICHMENT_CACHE_TTL_DAYS` | `30` | Refresh ip_intel after N days |
| `demo_mode` | `DEMO_MODE` | `false` | Serve synthetic traffic instead of reading a log. Seeds `src/demo.py` into the database **only if it holds no visits**, and skips the log tailer, the enrichment worker and the daily passes — there is nothing to read, and the addresses are RFC 5737 documentation ranges no provider should be asked about. For trying the dashboard out; every page says so while it is on |
| `filter_static_assets` | `FILTER_STATIC_ASSETS` | `true` | Drop .css/.js/image requests. Note: this filters by extension *before* classification, so scanner probes to e.g. `/credentials.json` or `/config.js` are never tracked — a deliberate blind spot of the bot/threat detection |
| `filter_internal_ips` | `FILTER_INTERNAL_IPS` | `true` | Drop RFC1918 / loopback IPs |
| `site_base_url` | `SITE_BASE_URL` | *(empty)* | Its host defines which referers count as internal navigation ([§4.2.2](#422-the-browser-gate-rule-8)). **Empty by default** — describes the watched site, so there is no right default. Unset, the signal is off, not guessed: an empty host would otherwise make every referer match |
| `poll_interval_seconds` | `POLL_INTERVAL_SECONDS` | `1.0` | Log tail polling frequency |
| `shodan_requests_per_minute` | `SHODAN_REQUESTS_PER_MINUTE` | `600` | Ceiling on outbound Shodan requests. `shodan_concurrency` bounds how many run at once and nothing bounded how many run per minute — a backlog drain issued ~1,300/min at a free service that publishes no limit |
| `shodan_cooldown_seconds` | `SHODAN_COOLDOWN_SECONDS` | `300` | How long to stop calling Shodan entirely after it answers 429. Previously a 429 was swallowed as "no data" and the rate never came down |
| `dns_timeout_seconds` | `DNS_TIMEOUT_SECONDS` | `5.0` | How long the enrichment worker waits on a DNS lookup. The resolver's own timeout still governs the thread — `to_thread` work cannot be cancelled — but a black-holed resolver no longer parks a whole batch |
| `static_asset_prefixes` | `STATIC_ASSET_PREFIXES` | *(empty)* | Where the watched site's assets live. `.json` and `.map` count as static only underneath one of these: a language file fetched on every page load is an asset, `/credentials.json` is somebody looking for credentials. **Empty by default**; unset, those extensions are never treated as assets, so the request is tracked rather than discarded. CSV or JSON list |
| `ingest_existing_backlog` | `INGEST_EXISTING_BACKLOG` | `false` | Only consulted when no read position is stored — a first run, or a restored database. `false` starts at the end of the log like tail(1); `true` reads what is already there. Default `false` because `visits` has no way to recognise a duplicate: nginx timestamps resolve to the second, so two identical requests in one second are indistinguishable from one request ingested twice |
| `enrichment_batch_size` | `ENRICHMENT_BATCH_SIZE` | `100` | IPs per ip-api.com batch request |
| `dnsbl_enabled` | `DNSBL_ENABLED` | `true` | Enable DNSBL checks |
| `dnsbl_providers` | `DNSBL_PROVIDERS` | `zen.spamhaus.org,bl.spamcop.net` | DNSBL zones to query |
| `dnsbl_dqs_key` | `DNSBL_DQS_KEY` | `""` | Spamhaus free Data Query Service key. Without it the legacy zone refuses queries from public resolvers, so no DNSBL verdict is recorded at all ([§4.2.8](#428-signals)) |
| `js_only_path_prefixes` | `JS_ONLY_PATH_PREFIXES` | *(empty)* | Paths only the watched site's own JS requests — browser evidence for the classifier ([§4.2.2](#422-the-browser-gate-rule-8)). **Empty by default**; unset, the human gate loses this input while Sec-Fetch keeps working |
| `reclassify_interval_minutes` | `RECLASSIFY_INTERVAL_MINUTES` | `15` | How often to re-judge IPs that stayed active after classification ([§4.2.7](#427-freshness)) |
| `static_extensions` | `STATIC_EXTENSIONS` | `[".css",".js",".png",…]` | Extensions filtered when `filter_static_assets=true`. **JSON, not comma-separated** — the only list setting of the four that is; a CSV value aborts startup |
| `shodan_concurrency` | `SHODAN_CONCURRENCY` | `10` | Max parallel Shodan requests |
| `dnsbl_concurrency` | `DNSBL_CONCURRENCY` | `10` | Max parallel DNSBL DNS lookups |
| `tor_cache_ttl_seconds` | `TOR_CACHE_TTL_SECONDS` | `86400` | Tor exit list refresh interval (seconds) |
| `enrichment_queue_maxsize` | `ENRICHMENT_QUEUE_MAXSIZE` | `10000` | Max IPs queued for enrichment |
| `db_connection_timeout` | `DB_CONNECTION_TIMEOUT` | `10` | SQLite connection timeout (seconds) |
| `export_rate_limit` | `EXPORT_RATE_LIMIT` | `5` | Max `/api/export` calls per IP per window |
| `export_rate_limit_window_s` | `EXPORT_RATE_LIMIT_WINDOW_S` | `3600` | Rate limit window (seconds) |
| `backup_enabled` | `BACKUP_ENABLED` | `true` | Whether the daily snapshot pass runs at all |
| `backup_dir` | `BACKUP_DIR` | `/data/backup` | Where gzipped `VACUUM INTO` snapshots are written. Same volume as the database, so they cover corruption and mistaken deletion but not loss of the volume |
| `backup_keep` | `BACKUP_KEEP` | `7` | Snapshots retained; the oldest is deleted once the count is exceeded. A pass declines rather than running when free space is below 2.5x the database |
| `carto_api_key` | `CARTO_API_KEY` | *(empty)* | Key for CARTO's basemap tiles. Without one every tile arrives watermarked and the map is unreadable, though nothing fails and no other surface is affected; a wrong key is indistinguishable from none. Free for non-commercial use, and the free tier requires the CARTO and OpenStreetMap attribution the map shows. Not a secret — it travels in the tile URL — but masked on the status page so a screenshot does not carry it |
| `server_lat` | `SERVER_LAT` | *(unset)* | Latitude of the observing server, drawn as a fixed marker on the map. Blank hides the marker |
| `server_lon` | `SERVER_LON` | *(unset)* | Longitude, same |
| `server_city` | `SERVER_CITY` | *(empty)* | Label shown on the server marker |
| `server_country` | `SERVER_COUNTRY` | *(empty)* | Label shown on the server marker |
| `server_asn` | `SERVER_ASN` | *(empty)* | Label shown on the server marker |
| `server_ip` | `SERVER_IP` | *(empty)* | Label shown on the server marker. Cosmetic only — it is never matched against visit data |

---

## 8. What is stored, and where it goes

Vidar keeps IP addresses for months and hands them to four outside services. The
facts are spread across the sections above; this one collects them, because
anyone standing the service up needs them in one place before they do.

### 8.1 What the database holds

| Table | Per | Contents |
|-------|-----|----------|
| `visits` | request | The address, plus everything nginx logged about the request: path, referer, user agent, Sec-Fetch headers, TLS protocol and cipher, timings. 29 columns, listed in [§2.1](#21-visits-29-columns) |
| `ip_intel` | address | What enrichment found: country, city, coordinates, ASN, ISP, reverse DNS, open ports, CVEs, blocklist status, and the derived class. 21 columns, listed in [§2.2](#22-ip_intel-21-columns) |
| `ip_intel_*` | value | Shodan's ports, tags, hostnames, CPEs and CVEs, one row each ([§2.4](#24-ip_intel_-normalized-shodan-child-tables-migration-43)) |

Geolocation resolves to city level. It comes from a database lookup on the
address, not from the visitor, and is as accurate as ip-api's data — which for a
mobile or proxied address is often the wrong city entirely.

### 8.2 What leaves the machine

**Only the address, and never anything else.** Path, referer and user agent stay
local; no provider is told what was requested.

| Destination | Sent | Transport |
|-------------|------|-----------|
| `ip-api.com` | the addresses of a batch, as a JSON array | **HTTP** — the free tier offers no TLS (`BATCH_URL`, `enricher.py`) |
| `internetdb.shodan.io` | one address per request, in the path | HTTPS |
| DNSBL zones | the reversed address as a DNS name, e.g. `4.3.2.1.zen.spamhaus.org` | DNS |
| the system resolver | the address, for a PTR lookup | DNS |
| `check.torproject.org` | nothing — the exit list is downloaded | HTTPS |

The DNSBL query is a DNS lookup, so the recursive resolver in the path sees it
too. That is how blocklists work, and it is worth knowing before enabling one.

Enrichment can be switched off in parts: `DNSBL_ENABLED=false` stops the
blocklist queries. The others are not individually gated — a deployment that must
send nothing at all has to leave the enrichment worker without addresses to work
on, which is not currently a supported configuration.

### 8.3 How long it is kept

Retention is a calendar window, set in the dashboard, not a rolling age in days:
the current month plus the last N, where N is between 0 and 24
(`MAX_ROLLING_MONTHS`). The **Lifetime** setting keeps everything forever, and
the page warns while it is active.

A month falling out of the window is **not deleted — it is moved**. The rows are
written to `/data/archive/YYYY-MM.zip`, the file is fsynced and renamed into
place, and only then are the rows dropped ([§2.3.1](#231-monthly-archives)). The
addresses are still on disk afterwards; deleting the zip is a separate, manual
act. `purge_orphaned_intel()` then removes `ip_intel` rows for addresses with no
visits left, so an enriched address does not outlive the traffic that introduced
it.

Daily snapshots are a second copy: `BACKUP_KEEP` of them, on the same volume
([§7](#7-config-settings-srcconfigpy)).

### 8.4 Whose responsibility this is

The operator's. Vidar is a program that reads a log file someone else's server
already writes; who may run it, over which traffic, under what notice and for how
long is a question about that deployment, not about this project. The settings
above are the levers — the shortest retention window is 0 additional months, and
`DNSBL_ENABLED=false` is the one provider with an off switch.
