# API Reference

For anyone querying Vidar programmatically. Dashboard routes are listed at the end for
completeness; how to *use* those pages is [usage.md](usage.md).

Base URL `http://localhost:8080` through the SSH tunnel. There is **no authentication** — the
service binds loopback and access is whatever the tunnel grants. All responses are JSON unless
stated otherwise.

Four endpoints live under `/api`, plus `/health`.

---

There is no Swagger or ReDoc page: both load their bundle from a CDN the dashboard's CSP does
not allow, so they are disabled. `/openapi.json` is still served for tooling, and `/docs` now
belongs to the documentation pages.

## 1. `GET /api/stats`

Summary statistics for a window.

| Parameter | Description |
|---|---|
| `from` | `YYYY-MM-DD`, inclusive. Omitted means no lower bound |
| `to` | `YYYY-MM-DD`, inclusive. Omitted means no upper bound |

**Without either bound the answer is all-time.** The dashboard's own default is the last 90
days, so a caller comparing the two numbers has to name the window it wants.

| Field | Type | Description |
|---|---|---|
| `version` | string | The running Vidar version |
| `total_visits` | int | Visits in the window |
| `unique_ips` | int | Distinct IPs in the window |
| `total_countries` | int | Distinct countries among those IPs |
| `top_countries` | array | Top 5 by visit count |
| `top_ips` | array | Top 5 by visit count |
| `top_pages` | array | Top 5 paths by visit count |
| `top_referrers` | array | Top 5 referrer domains |
| `top_browsers` | array | Top 5 browsers |
| `top_oses` | array | Top 5 operating systems |
| `error_rate` | float | Percentage of 4xx and 5xx responses |
| `bounce_rate` | float | Share of IPs with exactly one request in the window |
| `https_rate` | float | Share of requests served over TLS |
| `avg_response_time` | float | Mean processing time, seconds |
| `total_bandwidth` | int | Bytes sent in the window |
| `visitor_class_breakdown` | array | IP count per identity group, for IPs seen in the window |

`visits_today`, `visits_7d`, `visits_30d` and `new_ips_today` were removed. They carried their
own fixed windows next to a caller-chosen one, which is exactly what `from`/`to` is for.

---

## 2. `GET /api/activity`

Visits per time bucket, split by identity group. This is the activity chart's data source.
The page ships its daily rows inline, so this is only requested once a reader zooms in far
enough that the chart wants hours.

| Parameter | Default | Description |
|---|---|---|
| `from`, `to` | — | Window, as above |
| `bucket` | `day` | `day` or `hour`; anything else falls back to `day` |
| `class` | — | Repeatable. Identity class or group prefix; unknown values dropped |
| `signal` | — | Repeatable. `is_tor`, `is_proxy`, `is_hosting`, `dnsbl_listed`, `has_tags`, `clean` |
| `q` | — | Free-text search, same grammar as the dashboard ([data-reference.md §4.4](data-reference.md#44-free-text-search-q)) |

Returns `{"bucket": "...", "rows": [...]}`. The filters match `/visitors?view=timeline`
exactly, so the chart and the page always describe one selection.

---

## 3. `GET /api/visits`

Paginated visit list with enrichment data joined in.

| Parameter | Default | Description |
|---|---|---|
| `page` | `1` | Page number, minimum 1 |
| `limit` | `50` | Results per page, maximum 500 |
| `sort` | `timestamp` | One of `timestamp`, `ip`, `status`, `path`, `bytes_sent`, `request_time` |
| `order` | `DESC` | `ASC` or `DESC` |
| `ip` | — | Exact IP match |
| `country` | — | Country code, for example `DE` |

Invalid `sort` values fall back to `timestamp` rather than erroring.

```json
{
  "data": [
    {
      "id": 1,
      "ip": "203.0.113.42",
      "timestamp": "2026-04-06T14:23:01+00:00",
      "method": "GET",
      "path": "/",
      "status": 200,
      "bytes_sent": 8432,
      "user_agent": "Mozilla/5.0 ...",
      "referer": "",
      "request_time": 0.012,
      "ssl_protocol": "TLSv1.3",
      "created_at": "2026-04-06T14:23:02",
      "country": "Germany",
      "country_code": "DE",
      "city": "Berlin",
      "isp": "Deutsche Telekom",
      "is_proxy": 0,
      "is_hosting": 0,
      "is_mobile": 0
    }
  ],
  "page": 1,
  "limit": 50,
  "total": 12847,
  "total_pages": 257
}
```

---

## 4. `GET /api/export`

The whole visit table as JSON or CSV, streamed.

| Parameter | Default | Description |
|---|---|---|
| `format` | `json` | `json` or `csv`; anything else is rejected |
| `from` | — | `YYYY-MM-DD`, inclusive |
| `to` | — | `YYYY-MM-DD`, inclusive |

```bash
curl http://localhost:8080/api/export
curl "http://localhost:8080/api/export?format=csv&from=2026-03-01&to=2026-03-31" -o march.csv
```

**The date range is the only filter this endpoint understands** — it does not take `class`,
`signal` or `q`. That is why no data page carries an export button: on a filtered page, a
button returning the entire table would promise something it cannot deliver. Per-month
downloads live on Settings › Storage and are always zipped.

**Rate limited to 5 requests per hour per client IP** (`export_rate_limit`,
`export_rate_limit_window_s`), enforced in middleware against the `rate_limits` table, so the
limit survives a container restart. Exceeding it answers `429`.

CSV cells are sanitized against spreadsheet formula injection before being written.

---

## 5. `GET /health`

`{"status": "ok"}`. Performs no database query, so it stays honest as a container health
check even when SQLite is busy.

---

## 6. Dashboard routes

HTML, not JSON. Listed so the URL surface is documented in one place.

| Route | Serves |
|---|---|
| `GET /` | Overview — attention list, KPI tiles with sparklines, class mix, top-N panels |
| `GET /visitors` | The single visitor surface. `?group=ip\|asn\|country\|client\|path` picks the grouping, `?view=table\|map\|timeline` the presentation |
| `GET /visitors/{ip}` | One IP in full — verdict, classifier evidence, network and exposure, request log |
| `GET /visitors/rows` | HTML **fragment**, not a page: the IPs behind one aggregation row, loaded into the slide-over |
| `GET /analysis` | Identity × signals matrix, status and HTTP-version distributions, rate limiting |
| `GET /exposure` | Shodan facets (ports, tags, CVEs) over the host set below them; `port`, `vuln`, `tag` narrow both |
| `GET /settings/status` | What the service is doing, and the configuration it loaded |
| `GET /settings/storage` | Retention mode, archives, snapshots |
| `GET /settings/api` | This endpoint list, in the UI |

The Storage page posts its actions back to these. They are form targets rather than an API —
no JSON, and each redirects to `/settings/storage` — but four of them destroy data, so they
are listed rather than left to the page that calls them.

| Route | Does |
|---|---|
| `POST /settings/storage/mode` | Switch the retention mode (`mode` form field) |
| `POST /settings/storage/window` | Set how many months stay in the database (`months`) |
| `POST /settings/storage/restore/{month}` | Read an archived month back into the database |
| `POST /settings/storage/release/{month}` | Archive a month and drop it from the database |
| `POST /settings/storage/delete-archive/{month}` | **Destructive** — delete the archive zip |
| `POST /settings/storage/delete-month/{month}` | **Destructive** — delete a month's rows |
| `POST /settings/storage/backup` | Write a snapshot of the database |
| `GET /settings/storage/download/{month}` | Download a month as a zip |
| `GET /settings/storage/snapshot/{name}` | Download a snapshot |

Common query parameters on `/visitors`: `page`, `limit`, `sort`, `order`, `class`, `signal`,
`q`, `range`, `date_from`, `date_to`. `class` accepts the 18 identity classes and their 5
group prefixes; `signal` accepts the six signal keys; unrecognised values are dropped rather
than erroring. `group=ip` additionally takes the exact-match drill-downs (`asn`, `path`,
`browser`, `country`, `ip`, `port`, `min_visits`), and `group=path` takes `status` (`2xx`–`5xx`).

**301 redirects.** Six routes became parameters — `/visitors/networks`, `/visitors/countries`,
`/visitors/clients`, `/visitors/paths` → `?group=`; `/visitors/geo` → `?view=map`;
`/visitors/analysis` and `/visitors/analyse` → `/analysis`; `/tools/shodan` → `/exposure` —
alongside older ones: `/humans`, `/not-humans`, `/visitors/humans`, `/visitors/not-humans`,
`/visitors/requests` → `?group=path&status=4xx`, `/timeline`, `/visitors/timeline`, `/geo`,
`/analyse`, `/threats`, `/settings/exports` → `/settings/storage`, and `/settings` →
`/settings/status`. Each points at its final target; a test enforces that there are no
redirect chains.
