#!/usr/bin/env python3
"""Fill a database with synthetic traffic, for screenshots and for looking around.

    python3 scripts/seed_demo.py /tmp/demo.db
    DB_PATH=/tmp/demo.db LOG_PATH=/tmp/demo.log \
        SITE_BASE_URL=https://example.com uvicorn src.main:app --port 8080

The traffic itself is src/demo.py, which is where DEMO_MODE reads it from too.
This is the command-line front: it points DB_PATH somewhere, refuses a database
that already holds visits, and reports what it wrote.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("db", nargs="?", help="database to write (default: $DB_PATH)")
    ap.add_argument("--force", action="store_true", help="seed even if visits already exist")
    args = ap.parse_args()

    if args.db:
        os.environ["DB_PATH"] = args.db
    if not os.environ.get("DB_PATH"):
        print("error: pass a path or set DB_PATH", file=sys.stderr)
        return 2

    # Import only after DB_PATH is set: config reads the environment once, at import.
    from src.db import get_conn, init_db
    from src.demo import SEED, seed

    init_db()
    with get_conn() as conn:
        existing = conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
    if existing and not args.force:
        print(
            f"refusing to seed {os.environ['DB_PATH']}: {existing} visits already there.\n"
            "This writes synthetic traffic and is not meant for a database holding real "
            "visits. Point DB_PATH somewhere else, or pass --force.",
            file=sys.stderr,
        )
        return 1

    visits, addrs = seed(random.Random(SEED))
    print(f"seeded {visits} visits across {addrs} addresses in {os.environ['DB_PATH']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
