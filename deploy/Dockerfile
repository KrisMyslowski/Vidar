# Pinned by digest, not by tag. The tag moves with every Debian and Python patch,
# so two builds of one commit were two different images, and rolling back to an
# old commit did not roll back its base. This is the multi-arch index, so the
# amd64 and arm64 builds each resolve their own platform from it. Dependabot
# proposes the new digest when the tag moves (.github/dependabot.yml).
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

WORKDIR /app

# No cron: the retention pass runs as an asyncio task inside the app (see
# _retention_task in src/main.py). The cron setup that used to live here never
# ran a single time — the crontab was installed in the wrong format and the
# job's output redirect was unopenable by the user it ran as. gosu went with it,
# since without cron there is nothing left that has to start as root.
#
# No curl either. It was installed for the healthcheck alone, which left a
# download tool in a container that already talks to the internet; the
# healthcheck asks Python, which the image has anyway.

RUN useradd -r -u 1000 -s /usr/sbin/nologin appuser

# The lock, not the ranges: every package pinned with the hash of each of its
# distributions, so a build installs exactly what was tested and pip refuses a
# file that changed under an unchanged version. scripts/lock_requirements.sh
# writes it from runtime.txt.
COPY requirements/runtime.lock requirements.lock
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock

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
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
