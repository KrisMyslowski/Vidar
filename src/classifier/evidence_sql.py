"""The one query that turns an IP's visit history into the evidence row.

Everything the rule chain reads comes out of _classify_sql(); rules.py never
touches the database. Kept apart from patterns.py because this is the only place
in the package that speaks SQL.
"""

from __future__ import annotations

import functools
from urllib.parse import urlparse

from ..config import settings
from .patterns import (
    _CONVENTION_404_MATCH,
    _DROPPER_MATCH,
    _NON_HTTP_METHODS,
    _PAYLOAD_ABUSE_MATCH,
    _SCANNER_PATH_MATCH,
)


def _like_escape(term: str) -> str:
    r"""Escape LIKE wildcards so the term matches literally (use with ESCAPE '\').

    Copied from queries/_shared.py rather than imported: queries/__init__.py
    re-exports this module, so importing back the other way is a cycle.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@functools.lru_cache(maxsize=8)
def _classify_sql(js_prefixes: tuple[str, ...]) -> str:
    """Build the per-IP evidence query.

    Cached on the JS-fetch prefixes rather than built once at import, so a test (or a
    different deployment) can change settings.js_only_path_prefixes and have it apply.

    Only the prefix *count* reaches the SQL; the values are bound by
    _classify_params(). They used to be interpolated: `%` made the clause
    LIKE '%%' and gave every request the strongest browser signal there is.
    """
    js_match = (
        " OR ".join(rf"v.path LIKE :js{i} ESCAPE '\'" for i in range(len(js_prefixes)))
        if js_prefixes
        else "0"
    )
    return f"""
    SELECT
        COALESCE(i.is_tor,       0) AS is_tor,
        COALESCE(i.is_proxy,     0) AS is_proxy,
        COALESCE(i.is_hosting,   0) AS is_hosting,
        COALESCE(i.dnsbl_listed, 0) AS dnsbl_listed,
        COALESCE((SELECT GROUP_CONCAT(tag) FROM ip_intel_tags WHERE ip = v.ip), '') AS tags,
        COALESCE(i.reverse_dns, '') AS reverse_dns,
        LOWER(COALESCE(i.isp, '')) AS isp,
        -- Who owns the network. A crawler claim is verified against these as well
        -- as against reverse DNS, because the operators that publish no PTR record
        -- are named here instead. See _CRAWLER_ORIGINS.
        LOWER(COALESCE(i.org, '') || ' ' || COALESCE(i.asn, '')) AS network_owner,
        COUNT(v.id) AS total,
        -- Requests that actually reached the site. Half of all traffic here is
        -- the port-80 -> 443 redirect, which would otherwise halve every error
        -- ratio. Both permanent redirect codes count: 308 is what an nginx that
        -- wants the method preserved answers, and excluding one but not the
        -- other made the denominator depend on which the operator chose.
        SUM(CASE WHEN NOT (v.status IN (301, 308) AND v.server_port = 80)
                 THEN 1 ELSE 0 END) AS content_requests,
        SUM(CASE WHEN {_NON_HTTP_METHODS} AND ({_PAYLOAD_ABUSE_MATCH})
                 THEN 1 ELSE 0 END) AS payload_abuse,
        SUM(CASE WHEN v.path IN ('[binary payload]', '[handshake on HTTP port]',
                                 '[empty request]')
                      OR {_NON_HTTP_METHODS}
                 THEN 1 ELSE 0 END) AS protocol_mismatch,
        SUM(CASE WHEN v.path LIKE '%../%'
                      OR v.path LIKE '%/etc/passwd%'
                      OR v.path LIKE '%/etc/shadow%'
                      OR v.path LIKE '%SELECT%FROM%'
                      OR v.path LIKE '%UNION%SELECT%'
                      OR v.path LIKE '%<script%'
                      OR INSTR(v.path, '%00') > 0
                      OR v.path LIKE '%cmd=%'
                      OR ({_DROPPER_MATCH})
                 THEN 1 ELSE 0 END) AS exploit_probes,
        SUM(CASE WHEN {_SCANNER_PATH_MATCH} THEN 1 ELSE 0 END) AS scanner_paths,
        SUM(CASE WHEN v.sec_fetch_mode = 'navigate'
                      AND v.sec_fetch_dest = 'document'
                 THEN 1 ELSE 0 END) AS browser_navigate,
        -- Paths only our own JavaScript requests: fetching one proves the client ran it.
        SUM(CASE WHEN {js_match} THEN 1 ELSE 0 END) AS js_fetch,
        SUM(CASE WHEN v.accept_encoding LIKE '%zstd%' THEN 1 ELSE 0 END) AS has_zstd,
        SUM(CASE WHEN v.http_version = 'HTTP/2.0'     THEN 1 ELSE 0 END) AS http2_visits,
        SUM(CASE WHEN v.status = 404                  THEN 1 ELSE 0 END) AS err404,
        -- 404s that suggest probing: convention files are excluded, so asking for
        -- security.txt or robots.txt never counts against a visitor.
        SUM(CASE WHEN v.status = 404 AND NOT ({_CONVENTION_404_MATCH})
                 THEN 1 ELSE 0 END) AS probe_404,
        COUNT(DISTINCT CASE WHEN v.status = 404 AND NOT ({_CONVENTION_404_MATCH})
                            THEN v.path END) AS distinct_404_paths,
        SUM(CASE WHEN v.device = 'Bot'                THEN 1 ELSE 0 END) AS bot_device,
        -- Same-origin navigation. Three conditions, each load-bearing:
        --   1. the referer is anchored at our host — a bare '%host%' would also match
        --      'https://evil.com/?u=<host>', letting anyone forge internal navigation;
        --   2. what follows the host starts with '/', so 'https://<host>.evil.com/x'
        --      is not our site either;
        --   3. it points at a *different* page — our own HTTP->HTTPS redirect makes a
        --      client re-request the same URL with that URL as its referer, and that
        --      is a protocol hop, not navigation.
        -- (A referer carrying an explicit port is not matched; vanishingly rare here.)
        --
        -- The `:host <> ''` guard is not defensive noise. SITE_BASE_URL has no
        -- default any more, and with an empty host every LIKE below collapses to
        -- 'http://%' — which would count *every* referred visit as same-origin
        -- navigation and hand a browser verdict to anything with a referer. An
        -- unconfigured site must lose this signal, not invert it.
        SUM(CASE
              WHEN v.sec_fetch_site = 'same-origin' THEN 1
              WHEN :host <> ''
                   AND (v.referer LIKE 'http://'  || :host || '%'
                    OR v.referer LIKE 'https://' || :host || '%'
                    OR v.referer LIKE 'http://www.'  || :host || '%'
                    OR v.referer LIKE 'https://www.' || :host || '%')
                   AND SUBSTR(v.referer, INSTR(v.referer, :host) + LENGTH(:host)) LIKE '/%'
                   AND SUBSTR(v.referer, INSTR(v.referer, :host) + LENGTH(:host))
                       <> v.path
              THEN 1
              ELSE 0 END) AS internal_nav,
        SUM(CASE WHEN v.sec_fetch_site = 'cross-site' THEN 1 ELSE 0 END) AS cross_site_nav,
        -- Distinct *pages*. '[handshake on HTTP port]' and friends are protocol
        -- errors nginx could not parse, not pages: counting them let a single
        -- request plus a failed handshake look like someone exploring the site.
        COUNT(DISTINCT CASE WHEN v.path NOT IN ('[binary payload]',
                                                '[handshake on HTTP port]',
                                                '[empty request]')
                            THEN v.path END)                       AS unique_paths,
        SUM(CASE WHEN v.status = 400 THEN 1 ELSE 0 END)            AS bad_requests,
        GROUP_CONCAT(DISTINCT LOWER(v.user_agent))                        AS all_uas_lower
    FROM visits v
    LEFT JOIN ip_intel i ON v.ip = i.ip
    WHERE v.ip = :ip
    GROUP BY v.ip
"""


def _classify_params(ip: str, js_prefixes: tuple[str, ...] | None = None) -> dict[str, str]:
    """Bind parameters for _classify_sql — the site host, the IP, and the JS prefixes.

    `js_prefixes` must be the tuple _classify_sql() was built with: it decides how
    many :jsN placeholders the statement has, and sqlite3 refuses a mismatch.
    Passing it is how the two stay in step. The default re-reads the setting,
    which is right only when the caller did the same.
    """
    if js_prefixes is None:
        js_prefixes = tuple(settings.js_only_path_prefixes)
    host = urlparse(settings.site_base_url).netloc or settings.site_base_url
    host = host.removeprefix("www.")
    params = {"ip": ip, "host": host}
    for i, prefix in enumerate(js_prefixes):
        params[f"js{i}"] = f"{_like_escape(prefix)}%"
    return params
