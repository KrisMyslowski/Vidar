# The layout suite needs a headless browser and Node 21+, and nothing else does.
# Rather than ask every contributor to install Chrome, this image carries both and
# runs the suite against a mounted checkout. It is a test image: no part of it
# reaches deploy/Dockerfile, which stays runtime-only.
#
# Built and run by scripts/run_layout_docker.sh.
FROM python:3.12-slim-bookworm

# chromium for the measurement, nodejs for measure.mjs. Debian bookworm ships
# node 18, which has no global WebSocket — measure.mjs needs 21 or newer, so node
# comes from nodesource rather than from apt.
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium ca-certificates curl gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get purge -y gnupg && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements/ requirements/
RUN pip install --no-cache-dir -r requirements/dev.txt

# measure.mjs already passes --no-sandbox, which is what lets chromium start as
# root in here; only the binary has to be pointed at.
ENV VIDAR_CHROME=/usr/bin/chromium \
    PYTHONDONTWRITEBYTECODE=1

CMD ["python", "-m", "pytest", "tests/test_layout_browser.py", "-q"]
