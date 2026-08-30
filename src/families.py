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
from collections.abc import Iterable
from typing import NamedTuple


class Family(NamedTuple):
    """One kind of accidentally served file, and the four things worth knowing."""

    key: str
    title: str
    what: str
    why: str
    check: str
    fix: str


# The literal `{path}` in a check is replaced with the path that was found, so a
# reader can paste the command rather than adapt it.
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
            check="curl -sI https://{host}{path}",
            fix=(
                "Delete it from the document root and stop it being uploaded again — it is "
                "usually rsync or an FTP client carrying the whole folder. Then refuse dotfiles "
                "in the server config: nginx `location ~ /\\. { deny all; }`, Apache "
                '`<FilesMatch "^\\.">Require all denied</FilesMatch>`, Caddy `@dot path '
                "/.* respond @dot 403`. Spare /.well-known — certificate renewal uses it."
            ),
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
            check="curl -s https://{host}{path} | head",
            fix=(
                "Do not deploy the repository. Build or copy the files rather than syncing the "
                "working tree, and deny dotfiles in the server config as above. If it was "
                "reachable, treat every secret that ever appeared in that history as "
                "compromised — deleting the file does not un-publish what was already fetched."
            ),
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
            check="curl -s https://{host}{path}",
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
            check="curl -s https://{host}{path} | head",
            fix=(
                "Delete it, and keep backups outside the document root. Add the suffixes to the "
                "server's deny rules so the next one is refused rather than served: nginx "
                "`location ~* \\.(bak|old|sql|swp)$ { deny all; }`."
            ),
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
            check="curl -s https://{host}{path} | head -20",
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
            check="curl -sI https://{host}{path}",
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
            check="curl -sI https://{host}{path}",
            fix=(
                "The same deny rule that covers .DS_Store covers these. The underlying cause is "
                "usually the same too: a deployment that copies a working directory instead of "
                "a build output."
            ),
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
            check="curl -s https://{host}{path} | tail -5",
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
            check="curl -sI https://{host}{path}",
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


def explain_paths(paths: Iterable[str], host: str) -> list[tuple[Family, list[str]]]:
    """The families present among these paths, each with the paths it covers.

    Grouped, because that is what "families, not paths" means on the page too:
    three findings under /.git/ are one thing to fix and one thing to read, and
    printing the same four paragraphs beside each of them would say so less
    clearly. In first-appearance order, so the sections follow the table.

    The check is addressed to `host` and to the first path in the group, so it
    is a command rather than a template. A blank SITE_BASE_URL leaves a host
    that cannot be mistaken for a real one — a wrong hostname in a command the
    reader is invited to paste is worse than an obvious placeholder.
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
        (
            families[key]._replace(check=families[key].check.format(host=host, path=covered[0])),
            covered,
        )
        for key, covered in grouped.items()
    ]


# Headers only. A finding is by definition something already handed to strangers,
# so fetching it changes nothing — but a command that prints a database dump into
# somebody's terminal is still the wrong default.
_GENERIC_CHECK = "curl -sI https://{host}{path}"


def unexplained_paths(paths: Iterable[str], host: str) -> list[tuple[str, str]]:
    """The paths no family describes, each with a command to look at it.

    A finding outside the registry still deserves the one piece of advice that
    needs no knowledge of the file: go and look. The command is derived from the
    path, so it works for a name nothing here has ever seen — which is most of
    them, and permanently so.

    What it deliberately does not get is a description. A sentence broad enough
    to cover any file says nothing about this one, and once it appears under
    every unrecognised finding the reader learns to skip it — and then skips the
    real ones too.
    """
    return [
        (path, _GENERIC_CHECK.format(host=host, path=path))
        for path in paths
        if family_for(path) is None
    ]
