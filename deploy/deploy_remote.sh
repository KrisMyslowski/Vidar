#!/usr/bin/env bash
set -euo pipefail

# Vidar Remote Deployment Script
# Safely deploys code to production server

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_FILE="${ROOT_DIR}/.deploy.conf"

# Load config if exists
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Interactive prompt if not configured
if [ -z "${DEPLOY_USER:-}" ] || [ -z "${DEPLOY_HOST:-}" ]; then
    echo "=========================================="
    echo "Vidar Deployment Configuration"
    echo "=========================================="
    echo ""

    read -p "SSH User: " DEPLOY_USER

    read -p "Server Host/IP: " DEPLOY_HOST

    read -p "Remote directory [/srv/vidar]: " DEPLOY_DIR
    DEPLOY_DIR=${DEPLOY_DIR:-/srv/vidar}

    read -p "Save configuration? (y/n) [y]: " SAVE_CONFIG
    if [ "${SAVE_CONFIG:-y}" = "y" ]; then
        cat > "$CONFIG_FILE" <<EOF
DEPLOY_USER=$DEPLOY_USER
DEPLOY_HOST=$DEPLOY_HOST
DEPLOY_DIR=$DEPLOY_DIR
EOF
        echo "[OK] Saved to .deploy.conf"
    fi
    echo ""
fi

# Validate required config
if [ -z "${DEPLOY_USER:-}" ] || [ -z "${DEPLOY_HOST:-}" ]; then
    echo "Error: SSH User and Host are required"
    exit 1
fi

USER=$DEPLOY_USER
HOST=$DEPLOY_HOST
DIR=${DEPLOY_DIR:-/srv/vidar}
# Requires the server's host key in known_hosts. One-time setup:
#   ssh-keyscan ${DEPLOY_HOST} >> ~/.ssh/known_hosts
# Override via SSH_OPTS env var if needed.
SSH_OPTS=${SSH_OPTS:-"-o StrictHostKeyChecking=yes"}

# Get git info
BRANCH=$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
COMMIT=$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "=========================================="
echo "Deploying Vidar"
echo "=========================================="
echo "  Server:  ${USER}@${HOST}"
echo "  Path:    ${DIR}"
echo "  Branch:  ${BRANCH}"
echo "  Commit:  ${COMMIT}"
echo "=========================================="
echo ""

# Confirmation
read -p "Continue with deployment? (y/n) [y]: " CONFIRM
if [ "${CONFIRM:-y}" != "y" ]; then
    echo "Cancelled"
    exit 0
fi
echo ""

# 0. Run tests locally before touching the server
echo "[1/7] Running tests (black + isort + pytest)..."
# </dev/null because vitest reads stdin, which would swallow the answers to
# every prompt after this one.
#
# VIDAR_REQUIRE rather than VIDAR_STRICT: strict mode fails on any skip, and the
# layout suite skips on any machine without a headless browser, so it would
# abort every deploy from this one. Named here are the suites that have no such
# excuse — a skip in one of those means something is missing that should not be.
VIDAR_REQUIRE=python,black,isort,ruff,pytest,vitest \
    bash "${ROOT_DIR}/scripts/run_tests.sh" </dev/null
echo "[OK] All checks passed"

# 1. Configuration. .env.example is the template, .env the working copy that
# gets uploaded. These three describe the watched site and have no useful
# default — unset, classification quietly gets worse instead of failing.
REQUIRED_ENV_KEYS=(SITE_BASE_URL STATIC_ASSET_PREFIXES JS_ONLY_PATH_PREFIXES)
LOCAL_ENV="${ROOT_DIR}/.env"

# Key names that carry a value, sorted for comm(1). The `..*` is what makes
# `SITE_BASE_URL=` count as unset; `|| true` because grep exits 1 on no match.
value_keys() {
    grep -oE '^[A-Za-z_][A-Za-z0-9_]*=..*' "$1" | cut -d= -f1 | sort -u || true
}
# Same expression for the server.
# sudo, because the upload below leaves the file root:root 600 — without it the
# next deploy reads nothing and reports every key as missing.
REMOTE_KEY_CMD="sudo grep -oE '^[A-Za-z_][A-Za-z0-9_]*=..*' '${DIR}/.env' | cut -d= -f1 | sort -u"

echo "[2/7] Checking configuration..."

REMOTE_KEYS=""
REMOTE_ENV_EXISTS=0
SSH_RC=0
ssh -n ${SSH_OPTS} "${USER}@${HOST}" "sudo test -f '${DIR}/.env'" 2>/dev/null || SSH_RC=$?

# ssh reports its own failures as 255 and otherwise passes the remote command's
# status through. `test -f` only ever answers 0 or 1, so 255 means the server was
# never reached — which must not be read as "it has no .env".
if [ "$SSH_RC" = 255 ]; then
    echo "[FAIL] ERROR: cannot reach ${USER}@${HOST} over SSH"
    echo "       Nothing was deployed. Check that the host is up and reachable:"
    echo "         ssh ${USER}@${HOST} true"
    exit 1
fi
if [ "$SSH_RC" = 0 ]; then
    REMOTE_ENV_EXISTS=1
    # Compare here, not over there: the version that looped remotely expanded
    # $k on the wrong side and reported every key as missing.
    REMOTE_KEYS=$(ssh -n ${SSH_OPTS} "${USER}@${HOST}" \
        "${REMOTE_KEY_CMD}" 2>/dev/null || true)
fi

if [ ! -f "$LOCAL_ENV" ] && [ "$REMOTE_ENV_EXISTS" = 0 ]; then
    echo "[FAIL] ERROR: no .env here and none at ${USER}@${HOST}:${DIR}/.env"
    echo ""
    echo "Create the working copy from the template and fill it in:"
    echo "  cp .env.example .env"
    echo "  \$EDITOR .env          # at minimum: ${REQUIRED_ENV_KEYS[*]}"
    echo ""
    echo "The next deploy offers to upload it."
    echo ""
    exit 1
fi

# Upload the local .env, if there is one
if [ -f "$LOCAL_ENV" ]; then
    # Load it the way the app does: extra='forbid' rejects an unknown key, which
    # otherwise only shows up as a container that will not start after the fact.
    ENV_PY=""
    for candidate in "${PYTHON:-}" "${ROOT_DIR}/.venv/bin/python" python3; do
        [ -n "$candidate" ] || continue
        command -v "$candidate" >/dev/null 2>&1 || [ -x "$candidate" ] || continue
        if "$candidate" -c 'import pydantic_settings' >/dev/null 2>&1; then
            ENV_PY="$candidate"
            break
        fi
    done

    if [ -n "$ENV_PY" ]; then
        if ! (cd "$ROOT_DIR" && VIDAR_ENV_FILE="" "$ENV_PY" - <<'PYEOF'
import sys

sys.path.insert(0, ".")
from src.config import Settings  # noqa: E402

try:
    s = Settings(_env_file=".env")
except Exception as exc:  # pydantic ValidationError, and anything else
    print(f"[FAIL] .env does not load: {exc}", file=sys.stderr)
    sys.exit(1)

missing = [
    name
    for name, value in (
        ("SITE_BASE_URL", s.site_base_url),
        ("STATIC_ASSET_PREFIXES", s.static_asset_prefixes),
        ("JS_ONLY_PATH_PREFIXES", s.js_only_path_prefixes),
    )
    if not value
]
if missing:
    print("[FAIL] .env has no value for: " + ", ".join(missing), file=sys.stderr)
    print("       These have no usable default — see .env.example.", file=sys.stderr)
    sys.exit(1)
PYEOF
        ); then
            echo ""
            echo "Fix .env and deploy again. Nothing on the server was touched."
            echo ""
            exit 1
        fi
        echo "[OK] Local .env loads, required keys set"
    else
        # No pydantic here: fall back to the key check, which cannot see an
        # unknown key but still catches a missing one.
        echo "[..] No interpreter with pydantic here; checking key names only"
        LOCAL_KEYS_TMP=$(value_keys "$LOCAL_ENV")
        MISSING=""
        for k in "${REQUIRED_ENV_KEYS[@]}"; do
            printf '%s\n' "$LOCAL_KEYS_TMP" | grep -qx "$k" || MISSING="${MISSING} ${k}"
        done
        if [ -n "$MISSING" ]; then
            echo "[FAIL] ERROR: .env has no value for:${MISSING}"
            echo "       These have no usable default — see .env.example."
            exit 1
        fi
    fi

    LOCAL_KEYS=$(value_keys "$LOCAL_ENV")
    GAINED=$(comm -23 <(printf '%s\n' "$LOCAL_KEYS") <(printf '%s\n' "$REMOTE_KEYS"))
    LOST=$(comm -13 <(printf '%s\n' "$LOCAL_KEYS") <(printf '%s\n' "$REMOTE_KEYS"))

    echo ""
    if [ "$REMOTE_ENV_EXISTS" = 0 ]; then
        echo "  The server has no .env yet. This uploads the local one."
    else
        echo "  Upload .env to ${DIR}/.env? Key names only — no values are shown."
        [ -n "$GAINED" ] && { echo ""; echo "    + gains a value on the server:";
                              printf '        %s\n' $GAINED; }
        if [ -n "$LOST" ]; then
            echo ""
            echo "    ! LOSES its value on the server — set on the server, blank or absent here:"
            printf '        %s\n' $LOST
            echo ""
            echo "      Uploading clears these. SERVER_LAT/LON/CITY/COUNTRY/ASN/IP among them"
            echo "      means the fixed marker disappears from the geo map. Answer n, copy the"
            echo "      values into your .env, and deploy again."
        fi
        [ -z "$GAINED" ] && [ -z "$LOST" ] && \
            echo "    Both sides carry the same keys; values are replaced by the local ones."
    fi
    echo ""
    if ! read -r -p "  Upload .env? (y/n) [n]: " PUSH_ENV; then
        PUSH_ENV=n
        echo ""
        echo "  (no answer readable — treating that as no)"
    fi
    echo ""

    if [ "${PUSH_ENV:-n}" = "y" ]; then
        # The rsync excludes .env* below, and an exclude also protects the
        # receiver's copy from --delete, so these backups survive later deploys.
        STAMP=$(date +%Y%m%d-%H%M%S)
        REMOTE_TMP="/tmp/vidar-env.${STAMP}.$$"
        if [ "$REMOTE_ENV_EXISTS" = 1 ]; then
            ssh -n ${SSH_OPTS} "${USER}@${HOST}" \
                "sudo cp -p '${DIR}/.env' '${DIR}/.env.bak.${STAMP}'"
            echo "[OK] Backed up to ${DIR}/.env.bak.${STAMP}"
        fi
        scp ${SSH_OPTS} -q "$LOCAL_ENV" "${USER}@${HOST}:${REMOTE_TMP}"
        ssh -n ${SSH_OPTS} "${USER}@${HOST}" \
            "sudo mkdir -p '${DIR}' && \
             sudo mv '${REMOTE_TMP}' '${DIR}/.env' && \
             sudo chown root:root '${DIR}/.env' && \
             sudo chmod 600 '${DIR}/.env'"
        echo "[OK] .env uploaded"
        REMOTE_ENV_EXISTS=1
        REMOTE_KEYS="$LOCAL_KEYS"
    else
        echo "[..] Left the server's .env as it is"
    fi
fi

# The upload may have been declined, or there may be no local .env at all.
if [ "$REMOTE_ENV_EXISTS" = 0 ]; then
    echo "[FAIL] ERROR: .env not found at ${USER}@${HOST}:${DIR}/.env"
    echo "       Upload was declined and the server has no configuration."
    exit 1
fi

MISSING=""
for k in "${REQUIRED_ENV_KEYS[@]}"; do
    printf '%s\n' "$REMOTE_KEYS" | grep -qx "$k" || MISSING="${MISSING} ${k}"
done
if [ -n "$MISSING" ]; then
    echo "[FAIL] ERROR: ${DIR}/.env is missing values for:"
    for k in $MISSING; do echo "         $k"; done
    echo ""
    echo "These have no usable default — see .env.example for what each one does."
    echo "Set them in your local .env and let the deploy upload it, or edit the"
    echo "server's copy directly."
    echo ""
    exit 1
fi
echo "[OK] Remote .env present, required keys set"

# 2. Ensure data directory
# The deploy root itself has to belong to the login user: `sudo mkdir` creates it
# as root, and the rsync below runs unprivileged. Without this a first install
# fails on every write into ${DIR} while reporting success. data/ is separate —
# it belongs to the container's UID, not to whoever deploys.
echo "[3/7] Preparing data directory..."
ssh -n ${SSH_OPTS} "${USER}@${HOST}" \
  "sudo mkdir -p '${DIR}/data' && \
   sudo chown '${USER}' '${DIR}' && \
   sudo chown -R 1000:1000 '${DIR}/data' && \
   sudo chmod 750 '${DIR}/data'" 2>/dev/null
echo "[OK] Data directory ready"

# 3. Sync code
echo "[4/7] Syncing code..."
# .venv and the tool caches are the developer's, not the service's: a venv built
# on a workstation carries that machine's absolute paths in every console-script
# shebang and is useless on the server, but it still rsyncs and it is large.
#
# The output is filtered down to the summary lines, so rsync's own errors are
# written to a file rather than piped: a pipeline reports grep's status, not
# rsync's, and `|| true` on top hid a failed transfer behind "[OK] Code synced"
# — a deploy root the login user cannot write to then surfaced much later as
# "failed to read dockerfile", naming nothing that was actually wrong.
# An --exclude means two things at once: do not send it, and do not delete it on
# the far side. That second half turned the exclude list into a preservation
# list. A .venv, a node_modules, a tmp/ and two linter caches sat in the deploy
# root for months — 119 MB — because each was uploaded once before its exclude
# existed and nothing was then allowed to touch it again. The .venv also went
# into every docker build context, which is why it measured 65 MB for an image
# that copies three directories.
#
# Named explicitly rather than with --delete-excluded, which is the general
# mechanism and the wrong one here: `protect /data` guards the directory entry
# and not its contents, so the obvious spelling deletes the database. A dry run
# caught it. A list that never names data/ or .env cannot lose either, whatever
# anyone gets wrong later.
# Two groups, and the difference matters. The first is what a build leaves
# behind; the second is what belongs to developing this, not to running it. The
# deploy root is not a checkout: nobody edits code there, nothing on the server
# runs a test or a linter, and an agent instruction file has no business on a
# machine serving traffic. Removing them takes the tree from 3.0 MB to 1.2 MB —
# not a resource win at that scale, but the directory then holds what runs and
# nothing else, which is the point.
#
# deploy/.env is deliberately absent: deployment_detail.md documents it as the place
# for NGINX_LOG_DIR, so deleting it on every deploy would take an operator's
# configuration with it.
STALE=(.venv node_modules tmp .pytest_cache .ruff_cache .DS_Store)
STALE+=(tests scripts .github docs/img)
# Root-level Markdown except the one that says what this directory is. Named as
# a pattern rather than one by one: it needs no maintaining when another is
# added, and the publish gate refuses any file that spells out the agent
# instruction file's name.
STALE+=($(cd "${ROOT_DIR}" && ls *.md 2>/dev/null | grep -v '^README\.md$' | tr '\n' ' '))
STALE+=(package.json package-lock.json vitest.config.js pyproject.toml)
STALE+=(.pre-commit-config.yaml .gitignore .gitattributes .deploy.conf)
ssh -n ${SSH_OPTS} "${USER}@${HOST}" \
    "cd '${DIR}' && rm -rf ${STALE[*]} && find . -name __pycache__ -type d -prune -exec rm -rf {} +" \
    || { echo "[FAIL] could not clean ${DIR}"; exit 1; }
echo "[OK] Build artefacts removed"

RSYNC_LOG=$(mktemp)
RSYNC_STATUS=0
rsync -avz -e "ssh ${SSH_OPTS}" --delete \
  --exclude '.git' \
  --exclude '.env' \
  --exclude '.env.*' \
  --exclude 'data' \
  --exclude '.pytest_cache' \
  --exclude '.ruff_cache' \
  --exclude '.venv' \
  --exclude '__pycache__' \
  --exclude '.DS_Store' \
  --exclude 'node_modules' \
  --exclude 'tmp' \
  --exclude 'tests' \
  --exclude 'scripts' \
  --exclude '.github' \
  --exclude 'docs/img' \
  --include '/README.md' \
  --exclude '/*.md' \
  --exclude 'package.json' \
  --exclude 'package-lock.json' \
  --exclude 'vitest.config.js' \
  --exclude 'pyproject.toml' \
  --exclude '.pre-commit-config.yaml' \
  --exclude '.gitignore' \
  --exclude '.gitattributes' \
  --exclude '.deploy.conf' \
  "${ROOT_DIR}/" "${USER}@${HOST}:${DIR}/" \
  > "$RSYNC_LOG" 2>&1 || RSYNC_STATUS=$?

grep -E "^(sending|receiving|deleting|sent)" "$RSYNC_LOG" || true

if [ "$RSYNC_STATUS" != 0 ]; then
    echo "[FAIL] ERROR: rsync exited ${RSYNC_STATUS} — the server's copy is incomplete."
    echo ""
    grep -vE "^(sending|receiving|deleting|sent)" "$RSYNC_LOG" | head -20
    echo ""
    echo "Exit 23 with 'Permission denied' means ${DIR} is not writable by ${USER}."
    echo "The container is untouched and still running the previous code."
    rm -f "$RSYNC_LOG"
    exit 1
fi
rm -f "$RSYNC_LOG"
echo "[OK] Code synced"

# 4. Rebuild and restart
echo "[5/7] Restarting container..."
ssh -n ${SSH_OPTS} "${USER}@${HOST}" \
  "cd '${DIR}' && \
   sudo docker compose -f deploy/docker-compose.yml down --remove-orphans 2>&1 | grep -v 'No such' || true && \
   sudo docker compose -f deploy/docker-compose.yml up -d --build"
echo "[OK] Container deployed"

# 5. Verify
echo "[6/7] Verifying..."
MAX_ATTEMPTS=30
ATTEMPT=0
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    if ssh -n ${SSH_OPTS} "${USER}@${HOST}" \
       "curl -s http://127.0.0.1:8080/health | grep -q 'ok'" 2>/dev/null; then
        echo "[OK] Container healthy and responding"
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
        sleep 1
    fi
done

if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
    echo "[FAIL] Container did not become healthy"
    echo "Check logs: ssh ${USER}@${HOST} 'sudo docker logs vidar'"
    exit 1
fi

echo ""
echo "=========================================="
echo "[SUCCESS] Deployment successful!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  View logs:"
echo "     ssh ${USER}@${HOST} 'sudo docker logs vidar -f'"
echo ""
echo "  Access dashboard:"
echo "     ssh -L 8080:localhost:8080 ${USER}@${HOST}"
echo "     Then open: http://localhost:8080"
echo ""
echo "  Database location: ${DIR}/data/vidar.db"
echo "  Monthly archives:  ${DIR}/data/archive/"
echo ""
echo "  Check the retention pass ran:"
echo "     ssh ${USER}@${HOST} 'sudo docker logs vidar | grep -i retention'"
echo ""
