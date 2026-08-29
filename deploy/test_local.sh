#!/usr/bin/env bash
set -euo pipefail

# Vidar: local smoke test.
#
# Builds the deploy image, starts it against synthetic nginx log lines, and
# checks that the service answers *and* actually ingested them. Failing any of
# those exits non-zero — the point of a smoke test is to be able to fail.
#
# Deliberately plain `docker build` + `docker run` rather than the compose file:
# that file describes the *server*. It bind-mounts /srv/nginx/logs and
# /srv/vidar/data, loads an env_file from the deploy root, and names the container
# `vidar`. A fresh checkout has no such .env, so `docker compose` refuses to parse
# the file at all, and the container name collides with a running production
# one. Container runtime flags that matter (read_only, tmpfs, no-new-privileges)
# are mirrored below, so this still catches an image that only works writable.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="vidar:smoke"
NAME="vidar-smoke"
PORT="${VIDAR_SMOKE_PORT:-18080}"
BASE="http://127.0.0.1:${PORT}"
TEST_DIR="$(mktemp -d)"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

fail() {
    echo "[FAIL] $*"
    echo
    echo "--- container logs ---"
    docker logs "$NAME" 2>&1 | tail -40 || true
    exit 1
}

echo "=========================================="
echo " Vidar: local smoke test"
echo "=========================================="
echo ""

if ! docker info >/dev/null 2>&1; then
    echo "[FAIL] Docker daemon not reachable. Start Docker and retry."
    exit 1
fi

# ── 1. Synthetic input ───────────────────────────────────────────────────────
# Three requests from two public IPs. Public, because internal ranges are
# filtered before they are ever counted; no static-asset extensions, and no
# health-check user agent, for the same reason. If you change these lines,
# change EXPECTED_VISITS with them.
echo "[1/5] Preparing test environment..."
mkdir -p "$TEST_DIR/logs" "$TEST_DIR/data"
EXPECTED_VISITS=3
cat > "$TEST_DIR/logs/access.log" <<'EOF'
{"time":"2026-06-07T10:00:00+00:00","remote_addr":"1.2.3.4","request":"GET / HTTP/1.1","status":200,"body_bytes_sent":1024,"http_user_agent":"Mozilla/5.0","request_time":0.001,"ssl_protocol":"TLSv1.3","request_method":"GET","request_uri":"/"}
{"time":"2026-06-07T10:00:01+00:00","remote_addr":"5.6.7.8","request":"GET /about HTTP/1.1","status":200,"body_bytes_sent":2048,"http_user_agent":"curl/8.0","request_time":0.002,"ssl_protocol":"TLSv1.3","request_method":"GET","request_uri":"/about"}
{"time":"2026-06-07T10:00:02+00:00","remote_addr":"1.2.3.4","request":"POST /api HTTP/1.1","status":201,"body_bytes_sent":512,"http_user_agent":"Mozilla/5.0","request_time":0.005,"ssl_protocol":"TLSv1.3","request_method":"POST","request_uri":"/api"}
EOF
echo "[OK] ${EXPECTED_VISITS} log entries, 2 IPs"

# ── 2. Build ─────────────────────────────────────────────────────────────────
echo "[2/5] Building image..."
docker build -q -f "${ROOT_DIR}/deploy/Dockerfile" -t "$IMAGE" "$ROOT_DIR" >/dev/null
echo "[OK] ${IMAGE} built"

# ── 3. Run ───────────────────────────────────────────────────────────────────
# Same hardening as docker-compose.yml, so a change that needs a writable root
# or an extra capability fails here rather than on the server.
#
# INGEST_EXISTING_BACKLOG is required here and nowhere else: step 1 writes the
# log file *before* the container exists, and a fresh tailer defaults to starting
# at the end of the file — correct on a server, where the backlog is history
# somebody else already counted, but here it means the three lines this test is
# built around are skipped and it reports 0 visits. Without this flag the smoke
# test has no chance of passing.
echo "[3/5] Starting container on ${BASE}..."
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
    -p "127.0.0.1:${PORT}:8080" \
    -v "$TEST_DIR/logs:/logs:ro" \
    -v "$TEST_DIR/data:/data:rw" \
    -e LOG_PATH=/logs/access.log \
    -e DB_PATH=/data/vidar.db \
    -e ARCHIVE_DIR=/data/archive \
    -e INGEST_EXISTING_BACKLOG=true \
    --read-only \
    --tmpfs /tmp --tmpfs /var/run --tmpfs /var/log \
    --security-opt no-new-privileges:true \
    "$IMAGE" >/dev/null
echo "[OK] container ${NAME} started"

# ── 4. Does it answer? ───────────────────────────────────────────────────────
echo "[4/5] Waiting for /health..."
for i in $(seq 1 30); do
    if curl -fsS "${BASE}/health" 2>/dev/null | grep -q '"ok"'; then
        echo "[OK] /health answered after ${i}s"
        break
    fi
    [ "$i" -eq 30 ] && fail "/health did not answer within 30s"
    sleep 1
done

# ── 5. Did it ingest? ────────────────────────────────────────────────────────
# The tailer polls once a second, so the rows land shortly after startup. This
# is the half the old script never had: a container that boots and reads nothing
# passed it. Enrichment is not checked — it needs the public internet and is not
# what the image has to prove here.
echo "[5/5] Checking the log pipeline..."
visits=0
for i in $(seq 1 20); do
    visits="$(curl -fsS "${BASE}/api/stats" 2>/dev/null \
        | grep -o '"total_visits":[0-9]*' | cut -d: -f2 || echo 0)"
    [ "${visits:-0}" -ge "$EXPECTED_VISITS" ] && break
    sleep 1
done
[ "${visits:-0}" -eq "$EXPECTED_VISITS" ] \
    || fail "expected ${EXPECTED_VISITS} visits, got ${visits:-0}"
echo "[OK] ${visits} visits ingested"

# The dashboard itself has to render, not just the API.
curl -fsS "${BASE}/" >/dev/null 2>&1 || fail "GET / did not render"
curl -fsS "${BASE}/visitors" >/dev/null 2>&1 || fail "GET /visitors did not render"
echo "[OK] dashboard renders"

echo ""
echo "=========================================="
echo "[SUCCESS] Smoke test passed"
echo "=========================================="
echo ""
echo "The container is removed on exit. To poke at it by hand:"
echo "   docker run --rm -p 127.0.0.1:${PORT}:8080 \\"
echo "     -v <logs>:/logs:ro -v <data>:/data:rw ${IMAGE}"
echo ""
