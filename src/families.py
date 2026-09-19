"""What a leaked path is, and what to do about it.

A finding on its own is a fright, not information. `/.DS_Store` means nothing to
most people running a website, and "your server is exposing a sensitive file" is
the kind of sentence that produces anxiety rather than a fix. Each family here
answers four questions instead: what the file is, why somebody asked for it, how
to check it yourself, and how to stop serving it.

**Families, not paths.** There are 26 609 distinct paths behind the 404s on the
reference deployment, and the 500 most-requested cover 30% of the traffic — a
catalogue of individual paths cannot work. One vulnerability explains the shape:
PHPUnit's `eval-stdin.php` is probed under more than twenty-five different
prefixes, all of them the same thing. The explanation belongs to the family.

**Scope.** These are the files a web server hands out *by accident* — the ones
that can become a finding on /exposure because they really are sitting in the
document root. That is a narrower set than everything attackers ask for, and
deliberately so: what people probe for is a different question with a different
surface, and most of it (WordPress on a site with no WordPress) can never be a
finding here.

The check is always a command the reader can run against their own site, because
"go and look" is the only advice that does not require trusting this file.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable
from typing import NamedTuple


class Family(NamedTuple):
    """One kind of accidentally served file, and what is worth knowing about it.

    `fix` is prose and `config` is not. A server directive chained into a
    sentence cannot be copied without selecting mid-paragraph, and reads as
    prose rather than as something to paste — three of them ran together in one
    line here before this field existed. Each snippet gets its own block, named
    by the server it belongs to.
    """

    key: str
    title: str
    what: str
    why: str
    check: str
    fix: str
    config: tuple[tuple[str, str], ...] = ()


# The dotfile deny rule. Three families need it, and each renders on its own —
# explain_paths() only emits the families actually present, so "deny dotfiles as
# above" pointed at nothing on a deployment whose only finding was /.git/config.
#
# nginx only, and not for lack of ambition: Vidar reads nginx's JSON log and
# nothing else. limit_req_status, request_time and server_protocol are nginx
# variables, and deploy/nginx-log-format.conf is the format contract. An Apache
# and a Caddy snippet sat here for one revision — advice for servers whose logs
# this service cannot ingest, printed to an operator who by definition runs
# nginx. They come back if a second log format ever does.
_DENY_DOTFILES: tuple[tuple[str, str], ...] = (("nginx", "location ~ /\\. {\n    deny all;\n}"),)

# The literal `{url}` in a check is replaced with the URL that was found, quoted
# as one shell word (see _url), so a reader can paste the command rather than
# adapt it.
FAMILIES: tuple[tuple[str, Family], ...] = (
    (
        r"(^|/)\.ds_store$|(^|/)thumbs\.db$|(^|/)desktop\.ini$",
        Family(
            key="os-metadata",
            title="Operating-system metadata",
            what=(
                "A file the desktop wrote, not you. macOS leaves .DS_Store in every folder it "
                "displays and Windows leaves Thumbs.db; both record what the folder contains."
            ),
            why=(
                "It lists the names of every file in its directory, including the ones not "
                "linked from anywhere. That turns a guess into a directory listing."
            ),
            check="curl -sI {url}",
            fix=(
                "Delete it from the document root and stop it being uploaded again — that is "
                "usually rsync or an FTP client carrying the whole folder. Then refuse "
                "dotfiles in the server config. Spare /.well-known: certificate renewal "
                "uses it."
            ),
            config=_DENY_DOTFILES,
        ),
    ),
    (
        r"(^|/)\.git(/|$)|(^|/)\.svn(/|$)|(^|/)\.hg(/|$)",
        Family(
            key="vcs-directory",
            title="Version control directory",
            what=(
                "The repository itself. A .git directory holds every commit ever made, which "
                "means the whole source and its entire history."
            ),
            why=(
                "It is the single highest-value thing a static site can leak. Anyone who can "
                "read .git/config can usually reconstruct the source, and history often "
                "contains credentials that were removed from the current files."
            ),
            check="curl -s {url} | head",
            fix=(
                "Do not deploy the repository. Build or copy the files rather than syncing the "
                "working tree, then deny dotfiles in the server config. If it was reachable, "
                "treat every secret that ever appeared in that history as compromised — "
                "deleting the file does not un-publish what was already fetched."
            ),
            config=_DENY_DOTFILES,
        ),
    ),
    (
        r"(^|/)\.env($|\.)|(^|/)\.envrc$",
        Family(
            key="env-file",
            title="Environment file",
            what=(
                "The file that holds a deployment's configuration, and normally its secrets: "
                "database passwords, API keys, signing tokens."
            ),
            why=(
                "It is the most-probed path on the internet after WordPress. On the reference "
                "deployment .env and its variants were asked for 9 360 times in three months, "
                "by machines, continuously."
            ),
            check="curl -s {url}",
            fix=(
                "Move it out of the document root entirely — an environment file belongs beside "
                "the application, not under it. Then rotate every credential it contained. A "
                "deny rule alone is not enough here, because you cannot know whether it was "
                "read before you added one."
            ),
        ),
    ),
    (
        # Anchored at both ends. `(^|/)backup` alone matched /backup-policy.html —
        # a page *about* backups, not a leaked one. A directory actually called
        # /backups being served is a finding; a page whose name starts with the
        # word is not.
        r"\.(sql|dump|bak|old|orig|save|swp|swo)$|(^|/)backups?(/|$)|(^|/)dumps?(/|$)|~$",
        Family(
            key="backup-file",
            title="Backup or editor leftover",
            what=(
                "A copy left behind: a database dump, a file renamed .bak before an edit, or an "
                "editor's swap file. `config.php.bak` is not executed by the server — it is "
                "served as text."
            ),
            why=(
                "The live file is protected by being interpreted; the copy is not. A .bak of a "
                "configuration file hands out exactly what the original was hiding."
            ),
            check="curl -s {url} | head",
            fix=(
                "Delete it, and keep backups outside the document root. Add the suffixes to "
                "the server's deny rules so the next one is refused rather than served."
            ),
            config=(("nginx", "location ~* \\.(bak|old|sql|swp)$ {\n    deny all;\n}"),),
        ),
    ),
    (
        r"(^|/)(docker-compose|compose)\.ya?ml$|(^|/)database\.ya?ml$|(^|/)config\.(json|ya?ml|ini)$",
        Family(
            key="config-file",
            title="Configuration file",
            what=(
                "A configuration file in a format the server does not interpret, so it is "
                "delivered verbatim — compose files, database configuration, application "
                "settings."
            ),
            why=(
                "These describe the shape of the deployment: internal hostnames, ports, service "
                "names, sometimes credentials. It is reconnaissance handed over for free."
            ),
            check="curl -s {url} | head -20",
            fix=(
                "Keep deployment configuration out of the document root. If it must live there, "
                "deny the extension explicitly — serving .yml as text is the default in most "
                "configurations, not a special case."
            ),
        ),
    ),
    (
        r"(^|/)\.ssh(/|$)|id_rsa|id_ed25519|(^|/)\.aws(/|$)|(^|/)credentials$|\.pem$|\.key$",
        Family(
            key="credentials",
            title="Keys and credentials",
            what="A private key, an SSH configuration, or a cloud credentials file.",
            why=(
                "There is no scenario in which this belongs under a document root, and no "
                "damage assessment short of assuming it was taken. A private key is not a "
                "password: rotating it means replacing every place that trusts it."
            ),
            check="curl -sI {url}",
            fix=(
                "Remove it, then rotate the key or credential — not because a fetch is proven, "
                "but because it cannot be disproven. Then find out how it got there; a key in "
                "the document root usually means the whole home directory is being served or "
                "synced."
            ),
        ),
    ),
    (
        r"(^|/)\.(idea|vscode)(/|$)|(^|/)\.htpasswd$|(^|/)\.npmrc$|(^|/)\.dockerignore$",
        Family(
            key="tooling-leftover",
            title="Developer tooling leftover",
            what=(
                "Files a development environment writes: editor project settings, package "
                "manager configuration, an htpasswd file."
            ),
            why=(
                "Individually minor, collectively a map of how the site is built and deployed — "
                "and .npmrc and .htpasswd carry credentials outright."
            ),
            check="curl -sI {url}",
            fix=(
                "One deny rule covers all of these. The underlying cause is usually the same "
                "too: a deployment that copies a working directory instead of a build output."
            ),
            config=_DENY_DOTFILES,
        ),
    ),
    (
        r"\.log$|(^|/)logs?(/|$)",
        Family(
            key="log-file",
            title="Log file",
            what="An application or server log, reachable over HTTP.",
            why=(
                "Logs contain paths, parameters, session identifiers and often the errors that "
                "reveal what software is running and where it breaks. They also record other "
                "visitors, which makes serving them a data protection question and not only a "
                "security one."
            ),
            check="curl -s {url} | tail -5",
            fix=(
                "Move logs out of the document root. If a log must be readable remotely, put it "
                "behind authentication rather than behind an unguessable name."
            ),
        ),
    ),
    (
        r"(^|/)phpinfo|(^|/)info\.php$|(^|/)test\.php$|(^|/)adminer",
        Family(
            key="diagnostic-page",
            title="Diagnostic page",
            what=(
                "A page that reports the server's own configuration — phpinfo(), a database "
                "client, or a file dropped during debugging and never removed."
            ),
            why=(
                "It hands over versions, module lists, absolute paths and environment "
                "variables. It is the page an attacker reads before choosing an exploit."
            ),
            check="curl -sI {url}",
            fix=(
                "Delete it. There is no configuration that makes a diagnostic page safe to "
                "leave in place, and 'nobody knows the URL' is not one either — every path in "
                "this list was found by somebody guessing."
            ),
        ),
    ),
)

_COMPILED = tuple((re.compile(pattern, re.I), family) for pattern, family in FAMILIES)


def family_for(path: str) -> Family | None:
    """The family a served path belongs to, or None if nothing here describes it.

    None is a normal answer and must stay one. A finding without an explanation
    is still a finding, and inventing a family to cover every case would produce
    text that says nothing — which is worse than saying nothing.
    """
    for pattern, family in _COMPILED:
        if pattern.search(path):
            return family
    return None


class Explained(NamedTuple):
    """A family, the findings it covers, and a check command for each of them.

    One command per path rather than one per family. The panel lists every path
    the family was found at, and a single command addressed to the first of them
    read as if it checked all three — the reader had to edit it for the rest,
    which is the one thing the check exists not to require.
    """

    family: Family
    paths: list[str]
    checks: list[str]


def explain_paths(paths: Iterable[str], host: str) -> list[Explained]:
    """The families present among these paths, each with the paths it covers.

    Grouped, because that is what "families, not paths" means on the page too:
    three findings under /.git/ are one thing to fix and one thing to read, and
    printing the same four paragraphs beside each of them would say so less
    clearly. In first-appearance order, so the sections follow the table.

    Each check is addressed to `host` and to one path, so it is a command rather
    than a template. A blank SITE_BASE_URL leaves a host that cannot be mistaken
    for a real one — a wrong hostname in a command the reader is invited to
    paste is worse than an obvious placeholder.
    """
    grouped: dict[str, list[str]] = {}
    families: dict[str, Family] = {}
    for path in paths:
        family = family_for(path)
        if family is None:
            continue
        grouped.setdefault(family.key, []).append(path)
        families[family.key] = family
    return [
        Explained(
            families[key],
            covered,
            [families[key].check.format(url=_url(host, path)) for path in covered],
        )
        for key, covered in grouped.items()
    ]


def _url(host: str, path: str) -> str:
    """The finding's URL as one shell word, for a command meant to be pasted.

    The path is whatever a stranger asked for, and on a site that answers every
    path with 200 it reaches the findings unchanged — `/x;$(…)` included. Pasted
    unquoted, that runs on the operator's own machine. shlex.quote leaves an
    ordinary path such as /.DS_Store as it is and single-quotes anything else.
    """
    return shlex.quote(f"https://{host}{path}")


# Headers only. A finding is by definition something already handed to strangers,
# so fetching it changes nothing — but a command that prints a database dump into
# somebody's terminal is still the wrong default.
_GENERIC_CHECK = "curl -sI {url}"


def unexplained_paths(paths: Iterable[str], host: str) -> list[tuple[str, str]]:
    """The paths no family describes, each with a command to look at it.

    A finding outside the registry still deserves the one piece of advice that
    needs no knowledge of the file: go and look. The command is derived from the
    path, so it works for a name nothing here has ever seen — which is most of
    them, and permanently so.

    What it deliberately does not get is a description. A sentence broad enough
    to cover any file says nothing about this one, and once it appears under
    every unrecognized finding the reader learns to skip it — and then skips the
    real ones too.
    """
    return [
        (path, _GENERIC_CHECK.format(url=_url(host, path)))
        for path in paths
        if family_for(path) is None
    ]
