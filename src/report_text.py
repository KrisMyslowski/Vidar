"""The monthly report as Markdown — the copy that leaves the machine.

Same data as the page, rendered for somebody who will read it in a mail client
or paste it into a ticket. Two rules follow from that:

**It has to read as plain text.** Nobody is guaranteed to render the Markdown,
so the prose carries the report and the tables only carry the detail. A reader
who sees the pipes raw still gets the month in the first three lines.

**A section with nothing in it says what would have been in it.** "No incidents"
is only informative beside the rule that defines one; without it the reader
cannot tell a quiet month from a feature that is not working. Every empty
section here names its own threshold.
"""

from __future__ import annotations

from .template_filters import fmtduration

# The identity groups as the report names them. Capitalised here rather than in
# the data, because the page needs the plain keys for its colour lookup.
_GROUP_LABEL = {
    "humans": "Humans",
    "bots": "Bots",
    "automated": "Automated",
    "threats": "Threats",
    "unknown": "Unknown",
}


def _n(value: int | None) -> str:
    """A count with thousands separators, or an em dash for nothing measured."""
    return f"{value:,}" if value is not None else "—"


def _pct(value: float | None) -> str:
    return f"{value:g} %" if value is not None else "—"


def _points(value: float | None) -> str:
    """A share's movement, in percentage points and signed.

    Points, not percent: humans going from 0.2 % to 0.1 % is a fall of 0.1
    points and also a halving, and only one of those two numbers can be printed
    beside a column of shares without inviting the other reading.
    """
    if value is None:
        return "—"
    return f"{value:+g} pt" if value else "±0"


def _s(count: int) -> str:
    return "" if count == 1 else "s"


def _headline(r: dict) -> list[str]:
    """The three lines somebody reads if they read nothing else."""
    people = r["humans"]
    verdict = (
        f"{_n(people)} of them {'was a person' if people == 1 else 'were people'}"
        if people
        else "Not one of them was a person"
    )
    lines = [
        f"{_n(r['visits'])} request{_s(r['visits'])} from {_n(r['addresses'])} "
        f"address{'' if r['addresses'] == 1 else 'es'} in "
        f"{_n(r['countries'])} countr{'y' if r['countries'] == 1 else 'ies'}. "
        f"{verdict} — {_pct(r['human_share'])} of the addresses that reached this server."
    ]
    lines.append("")
    if r["visits_delta"] is not None:
        direction = "up" if r["visits_delta"] > 0 else ("down" if r["visits_delta"] else "level")
        against = f"against {r['previous']['label']}"
        lines.append(
            f"Traffic was {direction} {abs(r['visits_delta'])} % {against}."
            if r["visits_delta"]
            else f"Traffic was level {against}."
        )
    else:
        lines.append(
            f"No comparison: {r['previous']['label']} holds no traffic, so nothing here is "
            "a rise or a fall yet."
        )
    return lines


def _composition(r: dict) -> list[str]:
    comparable = r["previous"]["comparable"]
    head = ["| Group | Addresses | Share |", "|---|---:|---:|"]
    if comparable:
        head[0] = f"| Group | Addresses | Share | vs {r['previous']['label']} |"
        head[1] = "|---|---:|---:|---:|"
    rows = []
    for row in r["composition"]:
        cells = [_GROUP_LABEL[row["group"]], _n(row["addresses"]), _pct(row["share"])]
        if comparable:
            cells.append(_points(row["delta"]))
        rows.append("| " + " | ".join(cells) + " |")
    return head + rows


def _incidents(r: dict) -> list[str]:
    rule = r["incident_rule"]
    definition = (
        f"An incident is {rule['addresses']} or more addresses asking for the same first "
        f"{rule['paths']} missing paths, in the same order, within "
        f"{fmtduration(rule['window'])} of each other — one program, run from several places."
    )
    if not r["incident_total"]:
        return [f"None. {definition}"]
    total, shown = r["incident_total"], len(r["incidents"])
    programs = r["incident_programs"]
    same = ""
    if programs < total:
        same = (
            f" They are {_n(programs)} distinct program{_s(programs)}: "
            "the same signature came back."
        )
    lead = (
        f"{_n(total)} incident{_s(total)}, {_n(r['incident_addresses'])} "
        f"address{'' if r['incident_addresses'] == 1 else 'es'} between them.{same} {definition}"
    )
    table = ["", "| Started | For | Addresses | Probes | Asked for |", "|---|---|---:|---:|---|"]
    for inc in r["incidents"]:
        # The first path of the signature stands for the run. It is what the
        # program asked for before anything else, so it names the tool to
        # anybody who recognizes it and is a searchable string to anybody who
        # does not — where a count of paths is neither.
        first = (inc["paths"] or ["—"])[0]
        table.append(
            f"| {inc['started'][:16].replace('T', ' ')} | {fmtduration(inc['duration'])} "
            f"| {_n(inc['addresses'])} | {_n(inc['probe_404'])} | `{first}` |"
        )
    if shown < total:
        table.append("")
        table.append(f"The remaining {_n(total - shown)} are on /incidents.")
    return [lead] + table


def _findings(r: dict) -> list[str]:
    total, new = r["finding_total"], r["new_findings"]
    definition = (
        "A finding is a path this server answered 2xx for that fewer than two humans or "
        "crawlers have ever fetched — something handed out that nothing legitimate asked for."
    )
    if not total:
        return [f"Nothing. {definition}"]
    lead = [
        f"{_n(total)} path{_s(total)} answered 2xx that nothing legitimate asked for. "
        + (
            f"{_n(len(new))} of them appeared for the first time this month."
            if new
            else "None of them appeared for the first time this month."
        )
    ]
    table = ["", "| Path | New | Addresses | Requests | First served |", "|---|---|---:|---:|---|"]
    for f in r["findings"]:
        table.append(
            f"| `{f['path']}` | {'yes' if f['is_new'] else '—'} | {_n(f['ips'])} "
            f"| {_n(f['hits'])} | {(f['first_ever'] or '')[:10] or '—'} |"
        )
    if len(r["findings"]) < total:
        table.append("")
        table.append(f"The remaining {_n(total - len(r['findings']))} are on /exposure.")
    return lead + table


def render_markdown(r: dict) -> str:
    """The whole report as one Markdown document."""
    if r["empty"]:
        return "\n".join(
            [
                f"# Vidar — {r['label']}",
                "",
                "No requests were logged this month.",
                "",
                "That is a statement about the log, not about the site: check that nginx is "
                "still writing to the path Vidar reads, and that the month has not been moved "
                "to an archive.",
                "",
            ]
        )
    parts = [
        f"# Vidar — {r['label']}",
        "",
        *_headline(r),
        "",
        "## Who came",
        "",
        *_composition(r),
        "",
        "## What happened",
        "",
        *_incidents(r),
        "",
        "## What this server handed out",
        "",
        *_findings(r),
        "",
        "## How to check any of this",
        "",
        f"Every figure above is the one the dashboard shows for {r['start']} to {r['end']}: "
        "the mix on /visitors, the events on /incidents, the paths on /exposure. Nothing here "
        "is computed a second way, so nothing here can disagree with the page it came from.",
        "",
        "Identity is decided by what an address did, not by the network it arrived over. "
        "Tor, VPN and blocklist entries are recorded beside an address and never change what "
        "it is counted as.",
        "",
    ]
    return "\n".join(parts)
