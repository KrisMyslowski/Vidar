"""Dashboard HTML routes — all Jinja2 template views.

Four routes carry the whole dashboard:
  GET /               — overview (stats cards, activity chart, needs attention)
  GET /visitors       — every visitor surface: ?group=ip|asn|country|client|path
                        selects the grouping, ?view=table|map the presentation
  GET /analysis       — identity×signal matrix, distributions, rate limits
  GET /exposure       — Shodan InternetDB exposure facets + host table
  GET /visitors/{ip}  — single-IP detail + paginated request log

Backward-compat redirects (301) — the six routes that became parameters:
  /visitors/networks /visitors/countries /visitors/clients /visitors/paths → ?group=
  /visitors/geo → ?view=map · /visitors/analysis → /analysis · /tools/shodan → /exposure
  /humans /not-humans /visitors/humans /visitors/not-humans /geo /analyse /threats
  /visitors/requests (merged into ?group=path&status=4xx)
  /timeline /visitors/timeline (merged into the Overview)

This module is the assembly point. One module per surface registers on its own
router; _MODULES below is the order they are included in, and FastAPI matches
in that order.

The order is a list rather than the sequence of `from . import ...` lines
because isort sorts those alphabetically, which would put visitor_detail
("visitor_") ahead of visitors ("visitors") and let /visitors/{ip} swallow
/visitors/rows. Two constraints hold it together:

  - every literal /visitors/* path — the redirects and /visitors/rows — must be
    registered before /visitors/{ip}, or the pattern matches them first;
  - visitor_detail therefore comes last of all.

tests/test_url_and_findings.py walks the redirect targets and would fail if a
literal path started resolving to the detail page instead.
"""

from __future__ import annotations

from fastapi import APIRouter

from . import (
    _cache,
    _range,
    analysis,
    docs,
    overview,
    redirects,
    settings,
    visitor_detail,
    visitors,
)

# Imported for their side effects on the Jinja environment: _cache registers the
# earliest_date and attention_count globals, _range the RANGE_PRESETS one. The
# route modules pull them in anyway; naming them here keeps that from looking
# accidental.
_GLOBALS_SIDE_EFFECTS = (_cache, _range)

# Registration order. See the module docstring before changing it.
_MODULES = (
    overview,  # /
    visitors,  # /visitors, /visitors/rows
    redirects,  # every 301, incl. the literal /visitors/* paths
    analysis,  # /analysis, /exposure
    settings,  # /settings/*
    docs,  # /docs, /docs/{slug}
    visitor_detail,  # /visitors/{ip} — catch-all, so last
)

router = APIRouter()
for _module in _MODULES:
    router.include_router(_module.router)
