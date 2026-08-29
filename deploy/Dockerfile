FROM python:3.12-slim

WORKDIR /app

# No cron: the retention pass runs as an asyncio task inside the app (see
# _retention_task in src/main.py). The cron setup that used to live here never
# ran a single time — the crontab was installed in the wrong format and the
# job's output redirect was unopenable by the user it ran as. gosu went with it,
# since without cron there is nothing left that has to start as root.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 1000 -s /usr/sbin/nologin appuser

COPY requirements/runtime.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# /data is a bind mount in every real deployment, and the mount overlays this.
# It exists for the one case that has no mount: `docker run -e DEMO_MODE=true`,
# where the non-root user cannot create a directory at the root itself.
RUN mkdir -p /data && chown appuser /data

COPY src/ src/

# Rendered at /docs by the dashboard. .dockerignore keeps docs/img/ out, so
# this is the .md files and nothing else.
COPY docs/ docs/

# COPY preserves the mode the file had on the build host, and the deploy rsyncs
# the working tree as-is. A file that entered the repo from elsewhere brings that
# elsewhere's mode with it: docs/privacy.md arrived from a zip at 0600, shipped
# at 0600, and appuser could not read it — /docs answered 500 for that one
# document while every other rendered fine. Git cannot catch it, because it
# records only the executable bit; every clone has 0644 and only the path that
# ships the working tree carries 0600.
RUN chmod -R a+rX src docs

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD curl -f http://127.0.0.1:8080/health || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
