from datetime import datetime, timezone

from src.db import get_conn
from src.queries import insert_visit, purge_orphaned_intel, upsert_ip_intel


def test_purge_orphaned_intel(tmp_db):
    recent_ts = datetime.now(timezone.utc).isoformat()

    with get_conn(tmp_db) as conn:
        insert_visit(conn, ip="1.2.3.4", timestamp=recent_ts)
        upsert_ip_intel(conn, {"ip": "1.2.3.4"})
        upsert_ip_intel(conn, {"ip": "9.9.9.9"})  # no visits for this IP

    with get_conn(tmp_db) as conn:
        deleted = purge_orphaned_intel(conn)
        assert deleted == 1
