# Deployment — TL;DR

Everything needed to install, configure and run Vidar, with no prose around it. The reasoning,
the traps and the alternatives are in [deployment_detail.md](deployment_detail.md); nothing here
depends on reading it.

## Requirements

| Where | What |
|---|---|
| Server | Linux, Docker, the Compose plugin (`docker compose`), `rsync`, a few hundred MB free |
| Server | nginx writing a **JSON** access log — step 1 |
| Server | passwordless `sudo` for the deploy user (`docker`, `mkdir`, `chown`, `chmod`) |
| Your machine | `git`, `rsync`, `ssh`, Python 3.12, `pip install -r requirements/dev.txt` |
| Your machine | the server's host key in `known_hosts` — the deploy refuses an unknown host |

Only the first two rows apply if you use the published image instead of deploying from a
checkout. Port 8080 binds to `127.0.0.1` and must stay there: there is no login.

**nginx must see the client.** Vidar identifies visitors by `$remote_addr` and never by
`X-Forwarded-For`, which any client can set — in one live log, 90,000 requests claim to come
from `127.0.0.1`. So if a CDN or reverse proxy sits in front of the *watched site*, every
visitor arrives as the edge and the whole analysis collapses onto a handful of addresses. Vidar
belongs on the origin, or behind a proxy configured to preserve the client address.

## 1. nginx

Paste [`deploy/nginx-log-format.conf`](../deploy/nginx-log-format.conf) into `nginx.conf` inside
the `http {}` block, point `access_log` at it, reload. Keep every field — the missing ones do not
error, they leave columns permanently empty. `TZ` must be UTC on the nginx host.

```bash
sudo nginx -t && sudo nginx -s reload
```

## 2. Directories

```bash
sudo mkdir -p /srv/vidar/data
sudo chown <deploy-user> /srv/vidar         # the account you deploy with
sudo chown -R 1000:1000 /srv/vidar/data     # the container's UID
sudo chmod 750 /srv/vidar/data
```

`/srv/vidar` is `DEPLOY_DIR`; the deploy script asks once and caches it in `.deploy.conf`.

## 3. Configuration

`cp .env.example .env`. The file lives at the deploy root on the server (`/srv/vidar/.env`) and
is never in git.

### Required — the deploy refuses to ship without these

| | Example | If it is wrong |
|---|---|---|
| `SITE_BASE_URL` | `https://example.com` | no request counts as internal navigation; nobody is classified as a human browsing your site |
| `STATIC_ASSET_PREFIXES` | `/assets/` | a `.json` or `.map` anywhere counts as a visit instead of an asset |
| `JS_ONLY_PATH_PREFIXES` | `/assets/pages/` | the JS-fetch browser signal is gone; HTTP/1.1 clients lose their only proof of being a browser |

### Worth setting

| | Default | |
|---|---|---|
| `DNSBL_DQS_KEY` | — | without it the DNSBL signal is **empty, not clean**: the free Spamhaus zone refuses queries from container resolvers. Free, no card: [Data Query Service](https://www.spamhaus.com/data-access/free-data-query-service/) |
| `CARTO_API_KEY` | — | without it the basemap is tiled with `API KEY REQUIRED`. Free tier, no card |
| `SERVER_LAT` / `_LON` / `_CITY` / `_COUNTRY` / `_ASN` / `_IP` | — | draws your server as a fixed marker on the map. Cosmetic |
| `NGINX_LOG_DIR` | `/srv/nginx/logs` | host path mounted at `/logs`. Set in the shell or `deploy/.env` — **not** in `/srv/vidar/.env`, which Compose never reads |
| `VIDAR_DATA_DIR` | `/srv/vidar/data` | host path mounted at `/data`. Same rule |
| `VIDAR_PORT` | `8080` | host port on `127.0.0.1`. Same rule. Change it if a tunnel to another instance already holds 8080 — loopback itself is not configurable, since the tunnel is the authentication |
| `BACKUP_KEEP` | `7` | daily snapshots kept beside the database |
| `DEMO_MODE` | `false` | fills a throwaway database with synthetic traffic and starts nothing else |

### Defaults are fine

`LOG_PATH` `/logs/access.log` · `DB_PATH` `/data/vidar.db` · `ARCHIVE_DIR` `/data/archive` ·
`BACKUP_DIR` `/data/backup` · `BACKUP_ENABLED` `true` · `ARCHIVE_RESTORE_DAYS` `7` ·
`ENRICHMENT_CACHE_TTL_DAYS` `30` · `FILTER_STATIC_ASSETS` `true` · `FILTER_INTERNAL_IPS` `true` ·
`POLL_INTERVAL_SECONDS` `1.0` · `INGEST_EXISTING_BACKLOG` `false` · `ENRICHMENT_BATCH_SIZE` `100` ·
`STATIC_EXTENSIONS` · `DNSBL_ENABLED` `true` · `DNSBL_PROVIDERS` · `RECLASSIFY_INTERVAL_MINUTES`
`15` · `SHODAN_CONCURRENCY` `10` · `SHODAN_REQUESTS_PER_MINUTE` `600` · `SHODAN_COOLDOWN_SECONDS`
`300` · `DNS_TIMEOUT_SECONDS` `5.0` · `DNSBL_CONCURRENCY` `10` · `TOR_CACHE_TTL_SECONDS` `86400` ·
`ENRICHMENT_QUEUE_MAXSIZE` `10000` · `DB_CONNECTION_TIMEOUT` `10` · `EXPORT_RATE_LIMIT` `5` ·
`EXPORT_RATE_LIMIT_WINDOW_S` `3600`

`RETENTION_DAYS` (`90`) no longer deletes anything — retention is a calendar window set in the
UI — but the variable must keep existing or an existing `.env` stops loading.

Every setting is described field by field in
[data-reference.md §7](data-reference.md#7-config-settings-srcconfigpy). An unknown name in
`.env` is rejected outright, so a typo aborts the deploy rather than being ignored.

## 4. Deploy

```bash
./deploy/deploy_remote.sh
```

Asks for SSH user, host and directory on the first run. Runs the test suite first and aborts on
failure without touching the server. If it offers to upload your `.env`, **read the `!` block**:
those keys have a value on the server and none locally, so uploading clears them.

Updating is the same command. Rolling back is `git checkout <commit>` and the same command again
— the server holds no repository, only what was last rsynced.

## 5. Verify

```bash
ssh <user>@<host> 'cd /srv/vidar && sudo docker compose -f deploy/docker-compose.yml \
    exec -T vidar python -m src.preflight'
```

Ten checks, each naming a cause and a fix. Exit 1 on failure; warnings do not fail. Run it
whenever the dashboard looks emptier than the traffic suggests — almost everything that goes
wrong here is silent.

## 6. Open it

```bash
ssh -L 8080:localhost:8080 <user>@<host>     # then http://localhost:8080
```

The tunnel is the authentication. An authenticating reverse proxy works too, as long as the port
stays on loopback and it forwards `Host` and `Sec-Fetch-Site` unmodified.

An empty dashboard immediately after installing is expected. A first start reads from the *end*
of the log the way `tail` does, so nothing that was already written appears — only requests made
from now on. Enrichment then runs in the background, and the classifier needs a few requests per
address before it says much.

## 7. Running it

```bash
ssh <user>@<host> 'sudo docker logs -f vidar'                      # follow
ssh <user>@<host> 'sudo docker ps | grep vidar'                    # is it up
ssh <user>@<host> 'du -sh /srv/vidar/data'                         # disk
ssh <user>@<host> 'sudo docker logs vidar | grep -iE "retention|snapshot"'
```

## 8. When it does not work

| Symptom | Cause |
|---|---|
| Dashboard empty right after installing | expected. A first start reads from the **end** of the log, so only requests made *after* it started appear. `INGEST_EXISTING_BACKLOG=true` to take the existing file too |
| Dashboard empty, and you are testing from your own network | internal addresses are dropped. RFC1918, loopback, and a container gateway like `192.168.65.1`. `FILTER_INTERNAL_IPS=false` to see them |
| Dashboard empty, nothing errors | run the preflight — it exists for exactly this |
| Port 8080 already in use | an SSH tunnel to another instance is holding it. Set `VIDAR_PORT` in `deploy/.env` |
| Deploy aborts naming a variable | a required key has no value, locally or on the server |
| Deploy aborts with `extra_forbidden` | your `.env` names a variable the app does not know. Nothing on the server was touched |
| Deploy hangs at "Preparing data directory" | `sudo` wants a password over a session with no TTY — configure `NOPASSWD` |
| The map lost its server marker | an upload cleared `SERVER_*`. The previous file is at `/srv/vidar/.env.bak.<timestamp>` |
| Map tiles say `API KEY REQUIRED` | set `CARTO_API_KEY` |
| The DNSBL signal is empty everywhere | set `DNSBL_DQS_KEY` |

## Without a checkout

The published image needs neither Python nor a build on the server:

```
ghcr.io/krismyslowski/vidar:1.0.0
```

A compose file with the two bind mounts and an `.env` beside it is the whole install —
[deployment_detail.md §4.6](deployment_detail.md#46-without-a-checkout-the-published-image).
