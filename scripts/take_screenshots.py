#!/usr/bin/env python3
"""Retake the README's screenshots from synthetic traffic.

    bash scripts/run_layout_docker.sh python scripts/take_screenshots.py

The pictures were taken by hand once, and by the next release they showed a
version, a sidebar and badge colours the dashboard no longer had. This makes
retaking them one command: the same browser and the same harness the layout
suite measures with (tests/layout/measure.mjs), so it runs where that runs — in
the layout container, or anywhere VIDAR_CHROME and Node 21+ are available.

What it does, and why each part:

- Seeds a fresh database from src/demo.py. Every address is from the RFC 5737
  documentation ranges; the README says so above the first picture.
- Runs the app *without* DEMO_MODE, so no synthetic-data banner covers the top
  of every frame. The seed carries its own intel, so the enrichment worker finds
  nothing to look up and no provider is asked about an address.
- Reads CARTO_API_KEY, and nothing else, from a local .env if there is one.
  Without it the map comes back with "API KEY REQUIRED" tiled across it.
- Waits for the classifier to label every address before the first picture.
- Dark theme, 1600px wide, the width the README has always shown.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "img"
MEASURE = ROOT / "tests" / "layout" / "measure.mjs"
PORT = 8765
WIDTH = 1600

# page → (path, viewport height). The hero is the visitor detail page; its path is
# filled in once the seeded database says which address fits.
SHOTS = {
    "overview": ("/", 900),
    "visitors": ("/visitors", 1000),
    "map": ("/visitors?view=map", 1000),
    "analysis": ("/analysis", 900),
    "incidents": ("/incidents", 1000),
    "exposure": ("/exposure", 1000),
    "shodan": ("/shodan", 900),
    "report": ("/report", 1000),
    "detail": (None, 1000),
}

# Run inside each page before the picture: the map needs its tiles and markers,
# everything else only its own scripts.
SETTLE = """
new Promise((done) => {
  const wait = location.search.includes('view=map') ? 3000 : 800;
  setTimeout(() => done(true), wait);
})
"""


def carto_key() -> str:
    env = ROOT / ".env"
    if not env.exists():
        return ""
    for line in env.read_text().splitlines():
        if line.startswith("CARTO_API_KEY="):
            return line.split("=", 1)[1].strip().strip("'\"")
    return ""


def hero_ip(db: Path) -> str:
    """An address whose class and signals all show at once — Tor, hosting and a
    blocklist hit — because the picture above the README's argument should show
    a class and its signals side by side. The busiest address otherwise."""
    with sqlite3.connect(db) as conn:
        row = (
            conn.execute(
                """SELECT i.ip FROM ip_intel i JOIN visits v ON v.ip = i.ip
               WHERE i.is_tor = 1 AND i.is_hosting = 1 AND i.dnsbl_listed = 1
               GROUP BY i.ip ORDER BY COUNT(*) DESC LIMIT 1"""
            ).fetchone()
            or conn.execute(
                "SELECT ip FROM visits GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 1"
            ).fetchone()
        )
    return row[0]


def unclassified(db: Path) -> int:
    with sqlite3.connect(db) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM ip_intel WHERE visitor_class = '' OR visitor_class IS NULL"
        ).fetchone()[0]


def main() -> int:
    if not shutil.which("node"):
        print("node not found — run this through scripts/run_layout_docker.sh", file=sys.stderr)
        return 2

    work = Path(tempfile.mkdtemp(prefix="vidar-shots-"))
    db, log = work / "demo.db", work / "access.log"
    log.touch()

    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_demo.py"), str(db)], check=True, cwd=ROOT
    )

    env = {
        **os.environ,
        "VIDAR_ENV_FILE": "",  # never the operator's .env: only the map key is borrowed
        "DB_PATH": str(db),
        "LOG_PATH": str(log),
        "ARCHIVE_DIR": str(work / "archive"),
        "BACKUP_DIR": str(work / "backup"),
        "BACKUP_ENABLED": "false",
        "DNSBL_ENABLED": "false",
        "SITE_BASE_URL": "https://example.com",
        "CARTO_API_KEY": carto_key(),
    }
    app = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.main:app",
            "--port",
            str(PORT),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=env,
    )
    base = f"http://127.0.0.1:{PORT}"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/health", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        for _ in range(100):
            if unclassified(db) == 0:
                break
            time.sleep(0.2)

        paths = {k: (p or f"/visitors/{hero_ip(db)}", h) for k, (p, h) in SHOTS.items()}
        jobs = [
            {
                "key": name,
                "url": base + path,
                "width": WIDTH,
                "height": height,
                "colorScheme": "dark",
                "screenshot": str(OUT / f"{name}.png"),
            }
            for name, (path, height) in paths.items()
        ]
        expr = work / "settle.js"
        expr.write_text(SETTLE)
        subprocess.run(
            ["node", str(MEASURE), str(expr)],
            input=json.dumps(jobs),
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
        )
    finally:
        app.terminate()
        app.wait(timeout=10)
        shutil.rmtree(work, ignore_errors=True)

    for name in SHOTS:
        print(f"docs/img/{name}.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
