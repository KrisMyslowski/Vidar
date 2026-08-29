# Deployment — in detail

The short version, complete and without the reasoning, is
[deployment_tldr.md](deployment_tldr.md) — install from that and come here for the step that
raised a question. Reading the dashboard is [usage.md](usage.md); every setting is listed field
by field in [data-reference.md §7](data-reference.md#7-config-settings-srcconfigpy).

---

## 1. nginx: the log format

This is the contract between the two systems and the most common reason a fresh install shows
an empty dashboard. `deploy/nginx-log-format.conf` is authoritative — copy it, do not retype it.

Add the `log_format json_log …` block **inside the `http {}` block** of your `nginx.conf`, and
point `access_log` at it. On a distribution that only invites you to edit `conf.d/` or
`sites-available/`, the `log_format` still has to go in the main `nginx.conf` — a server block
cannot define one, and nginx fails to start with *unknown log format* if `access_log` names a
format it cannot see. The `access_log` line itself may live in either place. Then reload nginx and confirm the output really is JSON:

```bash
sudo nginx -t && sudo nginx -s reload
tail -1 /path/to/access.log
# {"time":"2026-08-17T12:00:00+00:00","remote_addr":"…","request":"GET / HTTP/2.0",…}
```

### 1.1 The timestamps must be UTC

Vidar compares them against UTC-derived bounds — range windows, retention and staleness cutoffs
alike — so a non-UTC `TZ` on the nginx host silently shifts every one of them. Nothing errors;
the numbers are just wrong. `$time_iso8601` writes its own offset, so the log answers the
question directly:

```bash
tail -1 /srv/nginx/logs/access.log | grep -o '"time":"[^"]*"'
# "time":"2026-08-19T12:00:00+00:00"   <- +00:00 is what you want; any other offset is not UTC

# Host nginx:
sudo timedatectl set-timezone UTC && sudo systemctl reload nginx
# Containerised nginx: set TZ=UTC on the service, or leave TZ unset — the images default to UTC.
```

### 1.2 Do not drop fields to tidy it up

`$connection` and `$connection_requests` together are what identify a request uniquely, which is
what lets a re-read of the log be recognised as a re-read rather than as new traffic. The
Sec-Fetch headers are the strongest bot/human signal available. A field removed here is a
feature removed in the dashboard.

### 1.3 One directory, both sides

The path nginx writes to and the path Vidar reads must be the same directory on the host. The
conf ships with `access_log /var/log/nginx/access.log`, and the container mounts the host
directory `/srv/nginx/logs` at `/logs`. Reconcile them in whichever way matches your setup:

- **nginx in a container** (the reference setup): bind-mount the host's `/srv/nginx/logs` to
  `/var/log/nginx` inside the nginx container. Both sides then see the same file.
- **nginx on the host**: leave `access_log` where your distribution put it and point Vidar at
  that directory instead — on Debian and Ubuntu that is `NGINX_LOG_DIR=/var/log/nginx`, which
  goes in the shell or in the compose file's own `.env`, never in the application's
  ([3.2](#32-worth-setting)). Changing `access_log` to `/srv/nginx/logs/access.log` works too
  and means arguing with logrotate.

### 1.4 The permission trap

The container runs as **UID 1000** and mounts the log directory read-only. nginx usually creates
`access.log` as `root:adm` mode `0640`, which UID 1000 **cannot read** — the app then starts
cleanly, logs nothing unusual, and simply never sees a request.

Test it exactly as the container will:

```bash
sudo -u '#1000' head -1 /srv/nginx/logs/access.log && echo "readable"
```

If that fails, make the file readable (`sudo chmod 644 …`) — and make it stick across rotation,
or the next logrotate run undoes it:

```
# /etc/logrotate.d/nginx — the create line governs the new file's mode
create 0644 www-data adm
```

---

## 2. Server directories

```bash
sudo mkdir -p /srv/vidar/data
sudo chown <deploy-user> /srv/vidar         # the account you deploy with
sudo chown -R 1000:1000 /srv/vidar/data     # the container's UID
sudo chmod 750 /srv/vidar/data
```

Two owners, and they are not the same. `sudo mkdir` creates the deploy root as **root**, but
the rsync in step 4 runs as the login user — so without that first `chown` a first install
cannot write a single file into `/srv/vidar`. `data/` is the exception: it belongs to the
container's UID rather than to whoever deploys.

`/srv/vidar` is a choice, not a requirement — it is `DEPLOY_DIR`, which the deploy script asks
for on its first run and caches in `.deploy.conf`. Every path in this document follows from that
answer; substitute your own throughout.

`/srv/vidar` is the **deploy root**: the code is rsynced here, `.env` lives here, and
`data/` holds the database, the monthly archives and the snapshots. The deploy script recreates
and re-chowns `data/` on every run, and now also claims the root for the deploy user, so this
step only matters for the very first deploy.

Give the volume room. The database grows with traffic; snapshots keep `BACKUP_KEEP` copies
(default 7) beside it, and a backup pass declines rather than filling the disk when free space
drops below 2.5× the database.

---

## 3. The `.env`

Two files, different jobs.

**`.env.example`** is the published template and the canonical list of every supported variable,
with comments. It is tracked in git, and its site-specific settings are blank on purpose, so
copying it verbatim cannot pass the deploy gate with a wrong value.

**`.env`** is the working copy of the server's configuration, at the repository root. It is
gitignored, excluded from the rsync, and uploaded only by the step described below.

Create it from the template and fill it in on your own machine:

```bash
cp .env.example .env
$EDITOR .env
```

The deploy offers to upload it ([§4](#4-deploy)). Keeping the authoritative copy here rather
than only on the server means it is edited in one place, and any drift between the two is
visible *before* a deploy rather than discovered after one.

If you would rather place it by hand — a first install without the repository checked out, say:

```bash
scp .env <user>@<host>:/tmp/vidar.env
ssh <user>@<host>
sudo mv /tmp/vidar.env /srv/vidar/.env
sudo chown root:root /srv/vidar/.env
sudo chmod 600 /srv/vidar/.env
```

The rsync never touches `/srv/vidar/.env` or any `.env.*` beside it, so a file placed this way
survives every deployment.

### 3.1 What you must change

Three settings describe the *site being watched* rather than the service. They ship **empty**,
because no default is right for a second deployment, and **the deploy refuses to run without
them**. Getting them wrong throws no error — it quietly degrades classification, which is why
the gate exists and why the app logs a warning at startup naming whatever is missing.

All three examples below describe one imaginary site:

```
https://your-site.example/
├── index.html, about.html           the pages themselves
└── assets/
    ├── css/main.css, img/logo.png   stylesheet, image
    ├── js/main.js                   your own JavaScript
    ├── lang/de.json                 translations, fetched by main.js
    └── fragments/about.html         page bodies, fetched by main.js
```

#### `SITE_BASE_URL` — your site's own address

Here `https://your-site.example`. A request carrying a referer that starts with it came from
one of your own pages, so the visitor is clicking through the site rather than arriving from a
search engine or somebody else's link. That is what separates `humans/browser-internal-nav`
from `humans/browser-direct`. Unset, the distinction is gone and every visitor looks like a
first-time arrival.

#### `STATIC_ASSET_PREFIXES` — where your own files are served from

Here `/assets/`; comma-separated if there is more than one. Requests for stylesheets and images
are dropped rather than counted as visits, and for most extensions the suffix alone decides.

`.json` and `.map` are the exception, because they are ambiguous. `/assets/lang/de.json` is one
of your pages loading a translation. `/credentials.json` is somebody hunting for secrets. The
prefix is what tells them apart: below it a `.json` is your own asset and gets dropped,
anywhere else it is a request worth recording. Unset, neither extension is ever treated as an
asset — your own translation fetches then inflate every human's visit count.

#### `JS_ONLY_PATH_PREFIXES` — paths only your own JavaScript requests

Here `/assets/fragments/`. Nobody types those, nothing links to them, so a client that fetched
one must have executed `main.js` — which makes it a real browser rather than a script. For a
client that sends no Sec-Fetch headers, which is older browsers and HTTP/1.1 traffic generally,
this is the only proof of a browser there is. Unset, the human gate loses that input and those
clients get harder to separate from bots.

### 3.2 Worth setting

#### `DNSBL_DQS_KEY` — or the DNSBL signal stays empty

Without it the signal returns nothing at all. The free Spamhaus zone refuses queries arriving
through public resolvers — which is every container — and answers "error" for every address.
The log says so once per provider if you skip it.

A key is permanently free for non-commercial use at low query volumes and needs no card. Get one
from Spamhaus' [free Data Query Service](https://www.spamhaus.com/data-access/free-data-query-service/)
([direct sign-up](https://portal.spamhaus.com/auth/account-setup?ps=free_dqs_product)); it is in
the customer portal once you have verified the address.

#### `SERVER_LAT` / `SERVER_LON` — your server on the map

Draws it as a fixed marker. Optional, purely cosmetic.

#### `NGINX_LOG_DIR` / `VIDAR_DATA_DIR` / `VIDAR_PORT` — and where they do *not* belong

Only needed if your host layout differs from `/srv/nginx/logs` and `/srv/vidar/data`, or if
`127.0.0.1:8080` is taken. It often is: `ssh -L 8080:localhost:8080` against another instance
claims the same port, so a second instance beside a tunnel needs `VIDAR_PORT`. Loopback is not
configurable — there is no login, and the tunnel is the authentication.

These three belong in the shell or in `deploy/.env`, **not** in `/srv/vidar/.env`. Compose
substitutes `${...}` from the directory the compose file is in, so a value in the deploy root is
one Compose never reads: the defaults apply instead, silently, and the container mounts a
directory nobody chose or publishes a port nobody asked for. Nothing errors — `env_file` hands its contents to the container as
environment variables, and a name the application does not recognise is ignored there.

Leave `RETENTION_DAYS` alone. It no longer deletes anything — retention is a calendar window
chosen in the UI — but the variable must keep existing, or an existing `.env` stops loading.

---

### 3.3 What leaves your server, and on whose terms

Vidar's own code is MIT. The services it enriches from are not, and each one has a limit and a
condition that the repository is otherwise silent about. Only the visitor's IP address is ever
sent, and only to the first three.

| Provider | Limit | Terms | Without it |
|---|---|---|---|
| [ip-api.com](https://ip-api.com/docs/legal) | 15 requests a minute; Vidar paces at 13 | Free endpoint is **non-commercial use only**, and plain HTTP — see their terms before pointing this at a commercial site | No country, city, ASN, ISP or proxy/hosting flag. The map and every geographic view stay empty, and the classifier loses the datacenter signal |
| [Shodan InternetDB](https://internetdb.shodan.io) | Rate-gated, 10 concurrent | Free, no key, no registration | No open ports, CVEs, CPEs or tags. The Exposure page has nothing to show |
| [Spamhaus](https://www.spamhaus.com/data-access/free-data-query-service/) | DQS free tier has its own volume ceiling | Free for non-commercial use at low volume; needs registration | The DNSBL signal returns nothing at all — see [3.2](#32-worth-setting) |
| [Tor exit list](https://check.torproject.org/torbulkexitlist) | Downloaded once per 24 h | Public list, nothing sent | The Tor signal is off; Tor exits read as ordinary addresses |
| [CARTO basemaps](https://carto.com/basemaps/apikey) | 5M tiles a month | Free for non-commercial use, needs `CARTO_API_KEY`, and the CARTO and OpenStreetMap attribution must stay visible | Every tile arrives stamped `API KEY REQUIRED`. Nothing else is affected — the markers, the panels and the facets are unchanged — but the background is unreadable |

The first four are called by the service. The last is fetched **by the operator's browser**,
along with Leaflet from unpkg: those two see whoever has the dashboard open, not a visitor, and
the CSP names both hosts explicitly. The key travels in the tile URL and is therefore visible to
anyone looking at the map, which is why it is a deployment setting rather than a secret — but it
is still yours, and the status page shows only whether it is set.

Switching a provider off is a supported state, not a broken one: every signal it fed degrades to
absent rather than to wrong. `DNSBL_ENABLED=false` covers the third; the other three are reached
by leaving the service unreachable, which is a firewall decision rather than a setting.

---

## 4. Deploy

From the repository on your machine:

```bash
./deploy/deploy_remote.sh
```

On the first run it asks for the SSH user, host and remote directory, and offers to cache them
in `.deploy.conf` at the repo root (gitignored). Then, in order:

1. **Runs the full test suite locally.** Any failure aborts before the server is touched.
2. **Handles configuration** — see below.
3. Creates and re-chowns `data/`, and claims the deploy root for the login user.
4. **Removes build artefacts and developer files from the deploy root**, then **rsyncs the
   code** with `--delete`. What is sent is what runs: `src/`, `docs/`, `deploy/`,
   `requirements/`, plus `README.md` and `LICENSE` so the directory says what it is. Tests,
   scripts, the linter and formatter config, the CI workflows and the README screenshots stay
   behind, and `.env`, `.env.*` and `data/` are never touched.

   The removal is a separate step because an `--exclude` also protects: it stops rsync sending
   a path *and* stops `--delete` removing it, so anything uploaded before its exclude existed
   would otherwise stay forever. `deploy/.env` is deliberately left alone — see
   [3.2](#32-worth-setting).

   A non-zero rsync aborts the deploy: the container keeps running the previous code rather
   than being rebuilt from a half-written tree.
5. **Rebuilds and restarts** the container on the server.
6. **Polls `/health`** for up to 30 seconds and fails loudly if it never answers.

### 4.1 Step 2 in detail

A local `.env` is first loaded **the way the application loads it**, so an unrecognised variable
or a missing required value aborts here rather than as a container that will not start once the
new configuration is already in place. Nothing on the server is touched.

Then it offers to upload, showing **key names only — never values**:

```
  Upload .env to /srv/vidar/.env? Key names only — no values are shown.

    + gains a value on the server:
        DNSBL_DQS_KEY

    ! LOSES its value on the server — set on the server, blank or absent here:
        SERVER_LAT
        SERVER_LON

  Upload .env? (y/n) [n]:
```

**Read the `!` block.** Those keys have a value on the server and none locally, so uploading
*clears* them — `SERVER_*` among them means the fixed marker disappears from the map. Answer `n`,
copy them across, deploy again:

```bash
ssh <user>@<host> 'sudo grep ^SERVER_ /srv/vidar/.env'
```

The default is `n`, the previous file is kept as `.env.bak.<timestamp>`, and with no local
`.env` the step just verifies the server's own.

### 4.2 What the gate insists on

`run_tests.sh` lets a suite *skip* when the machine lacks what it needs, which is what keeps a
laptop usable and what used to let a green deploy mean the suite never ran. The deploy now sets
`VIDAR_REQUIRE=python,black,isort,ruff,pytest,vitest`: those six have no machine-dependent
excuse, and a skip in any of them aborts before the server is touched.

The layout suite is deliberately not on that list. It needs a headless browser, and requiring it
would abort every deploy from a machine without one. Install Chrome or Chromium — or point
`VIDAR_CHROME` at one — and `VIDAR_STRICT=1 bash scripts/run_tests.sh` covers it too. CI runs
strict for exactly that reason.

### 4.3 One instance per host

The compose project, the container name, the port and the image name are all fixed rather than
derived from the deploy root, so a *second* deploy root on the same host does not give you a
second instance — it takes the first one over, and at the default `VIDAR_DATA_DIR` it writes
into the first one's database. Why, and how to run a throwaway beside a live one, is in
[architecture.md](architecture.md#one-instance-per-host).

---

### 4.4 Rehearsing it locally

Demo mode ([4.5](#45-looking-at-it-first-demo-mode)) shows the dashboard but skips the part that
actually goes wrong: nginx, the mounts and the log. Two containers rehearse the whole thing on a
laptop, and the walkthrough below is the one this document was checked against.

Build a deploy root the way the rsync in step 4 does — that also proves the subset it sends is
enough to build from, 1.2 MB with no `pyproject.toml`, tests or scripts:

```bash
rsync -a --delete --exclude '.git' --exclude '.env' --exclude 'data' --exclude 'tests' \
      --exclude 'scripts' --exclude '.venv' --exclude '__pycache__' \
      --include '/README.md' --exclude '/*.md' --exclude 'pyproject.toml' \
      ./ /tmp/lab/srv-vidar/
```

Run nginx against a copy of `nginx-log-format.conf` with `access_log` pointed into a host
directory, then start Vidar from the deploy root with that directory mounted:

```bash
cd /tmp/lab/srv-vidar && cp .env.example .env      # fill the three required keys
NGINX_LOG_DIR=/tmp/lab/logs VIDAR_DATA_DIR=/tmp/lab/srv-vidar/data \
    docker compose -f deploy/docker-compose.yml up -d --build
docker exec vidar python -m src.preflight
```

Four things behave differently here than on a server, and all four look like a broken install:

| | |
|---|---|
| The dashboard stays empty | a first start reads from the end of the log. Set `INGEST_EXISTING_BACKLOG=true`, or make the requests *after* starting |
| Still empty, with traffic arriving | your own address is internal — a container gateway is `192.168.65.1`, which is RFC1918. Set `FILTER_INTERNAL_IPS=false` |
| `Enriched 0, failed 1 / 1 IPs` | ip-api cannot resolve a private address. Expected, not a fault |
| `bind: address already in use` on 8080 | an SSH tunnel to a real instance is holding it. The compose file fixes the port, so close the tunnel or add an override with a different one |

And one that is not a fault at all: every client reaches nginx from the same container gateway,
so a browser, a crawler UA and a scanner all land on **one** address and the chain classifies
that address once, from whichever rule wins. The rehearsal proves the pipeline — nginx to log to
database to dashboard — not the classifier.

---

### 4.5 Looking at it first: demo mode

Every step so far is about a host. To see what the dashboard *is* before committing to any of
it, `DEMO_MODE=true` skips the host entirely:

```bash
docker run --rm -p 127.0.0.1:8080:8080 -e DEMO_MODE=true ghcr.io/krismyslowski/vidar:1.0.0
```

(The image is published from the first tagged release onward — see [4.6](#46-without-a-checkout-the-published-image). From a checkout today:
`DEMO_MODE=true DB_PATH=/tmp/demo.db uvicorn src.main:app --port 8080`.)

No log, no mount, no nginx. It fills an empty database with synthetic traffic from
`src/demo.py`, classifies it with the real classifier — the classes are its actual output, not
a staged picture — and serves the result at `http://localhost:8080`. Every page carries a
banner saying so, and every address is from the RFC 5737 documentation ranges, so nothing in it
can be mistaken for a visitor.

It seeds **only** a database with no visits in it. Pointing `DEMO_MODE` at a real one leaves the
data alone and says so in the log; that refusal is the same one `scripts/seed_demo.py` makes.
The log tailer, the enrichment worker and the daily passes do not start: there is nothing to
read, and no provider should be asked about an address that does not exist.

`Ctrl-C` stops it, and `--rm` removes the container with it. With no volume the database lives
at `/data/vidar.db` **inside** the container and goes when it does, which is what makes the
command repeatable: every start is a fresh dashboard. Mount `/data` if you would rather keep it,
and the second start will then find visits already there and seed nothing.

Going from here to a real deployment is not a migration — the demo shares nothing with it. Drop
`DEMO_MODE`, do steps 1 to 3 (the log format, the directories, the `.env`), and start it again
with the two mounts.

---

### 4.6 Without a checkout: the published image

> The image is built and pushed by `.github/workflows/release.yml` when a `v*` tag is pushed.
> The examples below name the newest tag at the time of writing; the current one is on the
> repository's Packages page, and a tag that does not exist fails with `manifest unknown`.

`deploy_remote.sh` deploys *your copy of the source*, which is what you want while changing the
code and more than you need to run it. From the release image, steps 1 to 3 are unchanged — the
log format, the directories and the `.env` are about the host either way — and step 4 becomes
two files in an empty directory on the server:

```bash
mkdir -p /srv/vidar && cd /srv/vidar
curl -fsSLO https://raw.githubusercontent.com/KrisMyslowski/Vidar/main/deploy/compose.example.yml
curl -fsSL  https://raw.githubusercontent.com/KrisMyslowski/Vidar/main/.env.example -o .env
mv compose.example.yml compose.yaml

$EDITOR .env                      # the three site keys from 3.1, at minimum
mkdir -p data && sudo chown 1000:1000 data

NGINX_LOG_DIR=/srv/nginx/logs docker compose up -d
```

`NGINX_LOG_DIR` has no default and Compose refuses to start without it, because there is no
directory that is right for a second host. It goes in the `.env` **beside the compose file** —
which on this route is the same file the application reads, and that is fine: Compose
substitutes its own variables from there and passes the rest to the container as environment
variables, where a name the application does not know is ignored.

The compose file also fixes the port at `127.0.0.1:8080`. If something already holds that port
— an SSH tunnel to another instance, say — Compose stops with `address already in use`; change
the left-hand side.

Updating is `docker compose pull && docker compose up -d`. Pin the tag rather than tracking
`latest`: schema migrations run forward only, so a rollback wants the database it was taken
with.

---

## 5. Verify

```bash
ssh <user>@<host> 'sudo docker logs vidar --tail 30'
```

A healthy first start says `Starting Vidar`, then a line about the read position, then
`Application startup complete`.

### 5.1 An empty dashboard is the expected first sight

Do not treat it as a fault. On a fresh install there is no stored read position, and the tailer
starts at the **end** of the log — like `tail -f`. Nothing that happened before the container
started is counted. The log says so explicitly:

```
No stored read position: starting at the end of /logs/access.log, skipping N bytes already
in the file. Set INGEST_EXISTING_BACKLOG=true to read them instead.
```

Visit the site once and the first row appears within a second or two. If you would rather import
what the log already holds, set `INGEST_EXISTING_BACKLOG=true` **before the first start** — it
only applies when no position is stored yet.

Enrichment lags ingestion by design: geo and threat data arrive in batches at the ip-api rate
cap, so a brand-new IP shows up in the tables immediately but stays uncoloured on the map for a
minute or so.

### 5.2 Open the dashboard

```bash
ssh -L 8080:localhost:8080 <user>@<host>
# then http://localhost:8080
```

### 5.3 Or put an authenticating proxy in front of it

If you already run Authelia, oauth2-proxy or plain Basic auth, put it in front — the constraint
was never "no proxy", it is that **the port stays on loopback**. `127.0.0.1:8080` does not
change; the proxy reaches it from the same host and nothing else can. The proxy *is* the login:
there is no second one behind it.

Three things to get right, none needing a code change:

- **Forward the `Host` header unmodified.** The cross-origin write guard in `src/main.py`
  compares the `Origin` header against `Host`, and refuses a state-changing request whose origin
  is a different site. A proxy that rewrites `Host` to `localhost` while the browser sends the
  public name turns every settings POST into a 403. `proxy_set_header Host $host;` in nginx;
  Caddy's `reverse_proxy` does it by default.
- **Let the browser's `Sec-Fetch-Site` through.** It is the primary half of that same guard, and
  a proxy stripping request headers it does not recognise falls the check back to `Origin`.
  Both are set by the browser and neither is forgeable by a page.
- **Do not add `X-Forwarded-For` handling expecting Vidar to read it.** It does not. The client
  address it records comes from the nginx log of the *watched site*, not from the request to the
  dashboard, so a proxy in front of the dashboard has no effect on the data — including on the
  `/api/export` rate limit, which keys on the address it sees and is therefore one shared budget
  either way.

`form-action 'self'` is unaffected either way: it constrains where the dashboard's own forms
submit, and that is the same origin through a tunnel or a proxy.

## 6. Running it

```bash
# Follow the log
ssh <user>@<host> 'sudo docker logs -f vidar'

# Is it up
ssh <user>@<host> 'sudo docker ps | grep vidar'

# Disk
ssh <user>@<host> 'du -sh /srv/vidar/data'

# Did the daily passes run (one line each per day)
ssh <user>@<host> 'sudo docker logs vidar | grep -iE "retention|snapshot"'
```

**Updating** is the same command as deploying: `./deploy/deploy_remote.sh`. Tests run first, the
container is rebuilt, the database is untouched. The `.env` changes only if you answer `y` to
the upload prompt; the rsync never touches it.

**Rolling back** works the same way, because the server holds no git repository — it holds
whatever was last rsynced. Check out the previous commit locally and deploy it:

```bash
git checkout <previous-commit>
./deploy/deploy_remote.sh
```

The database is not versioned and is not rolled back. Schema migrations in `init_db()` are
additive, so an older image against a newer database generally runs — but if a release added a
column, going back means the new column is simply unused.

**Snapshots** live in `data/backup/` and are written daily with `VACUUM INTO` plus gzip. They sit
on the same disk as the database, so they cover corruption and a mistaken delete but **not** the
loss of the volume. Copy one off the host now and then; nothing does that for you.

---

## 7. Troubleshooting

### 7.1 The preflight

Most of what goes wrong here does not raise. Nginx keeps serving, the container stays healthy,
`/health` answers ok, and the dashboard is empty with nothing to explain it. Run this first:

```bash
ssh <user>@<host> 'cd /srv/vidar && sudo docker compose -f deploy/docker-compose.yml \
    exec -T vidar python -m src.preflight'
```

Inside the container, because that is where the answers differ from the host's: the mounts are
the ones the service has, the clock is the one it compares timestamps against, and the uid
attempting the writes is the one that will attempt them at runtime.

It checks ten things — the log file exists, is readable and parses as JSON; the format carries
`connection` and `connection_requests`; the container clock and the logged offset are both UTC;
the database, archive and snapshot directories are writable, tested by writing rather than by
reading mode bits; the three site settings are set; and whether a DNSBL key is present. Each
failure names the cause and the fix rather than the symptom. Exit status is 1 if anything
failed; a warning on its own does not fail the run, because a missing DNSBL key is a signal you
do without rather than a broken install.

Worth running after the first deploy, after any nginx change, and whenever the dashboard looks
emptier than the traffic suggests.

### 7.2 Symptoms

| Symptom | First thing to check |
|---|---|
| The dashboard is empty and nothing errors | `python -m src.preflight` ([§7.1](#71-the-preflight)) — that is the whole reason it exists |
| Deploy aborts naming a variable | One of the three required keys has no value — in your local `.env` if it aborted before the upload prompt, in `/srv/vidar/.env` if after |
| Deploy aborts with `extra_forbidden` | Your local `.env` names a variable the app does not know: a typo, or a setting that was removed. The message names it. Nothing on the server was touched |
| The map lost its server marker | An upload cleared `SERVER_*`. The previous file is at `/srv/vidar/.env.bak.<timestamp>` — copy the values into your local `.env` and deploy again |
| Deploy hangs at "Preparing data directory" | `sudo` is asking for a password over a session with no TTY — configure `NOPASSWD` |
| Container will not start | `sudo docker logs vidar`. Note that an unknown key in the server's `.env` is **not** the cause: those arrive as environment variables and are ignored. It is the deploy script that rejects one, before anything is uploaded |
| Dashboard loads but stays empty | Almost always the log. Confirm nginx writes JSON, that it is the *same file* the container mounts, and that UID 1000 can read it: `sudo -u '#1000' head -1 /srv/nginx/logs/access.log` |
| Rows appear, but no countries or classes | Enrichment. `sudo docker logs vidar \| grep -iE "rate limit\|ip-api"` — the free tier allows 15 requests a minute, Vidar paces at 13, and a backlog drains slowly |
| DNSBL column always empty | Expected without `DNSBL_DQS_KEY`; the log states it once per provider |
| Timestamps look shifted | A non-UTC `TZ` on the nginx host. See step 1 |
| `database is locked` | Transient under heavy write load; `busy_timeout` covers most of it. Persisting means restarting the container |
| Disk filling | `sudo docker logs vidar \| grep -i retention`. `Retention pass (lifetime)` means nothing is being archived **by design** — switch the mode under Settings › Storage |

---

## 8. Security notes

- **Network** — bound to `127.0.0.1:8080`; an SSH tunnel is the only way in and the only
  authentication there is.
- **Filesystem** — the container is `read_only` with tmpfs for `/tmp`, `/var/log` and
  `/var/run`; the log mount is `ro` and only `/data` is writable.
- **Privileges** — `no-new-privileges`, running as non-root UID 1000.
- **Browser** — per-request CSP nonce, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  and `form-action 'self'`. There is no login, so a page the operator has open in another tab is
  the realistic threat; the CSRF checks in `main.py` are what constrain it.
- **Secrets** — `.env` never enters the image (`.dockerignore`) and is excluded from the rsync;
  the deploy's upload step is the only thing that writes it, over SSH, after an explicit `y`. On
  the server it is `root:root` and mode 600.
  Only the IP itself is ever sent to an enrichment provider, and ip-api's free tier is plain
  HTTP, so those lookups are not confidential in transit.
