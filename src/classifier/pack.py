"""Loading, merging and checking the pattern pack.

patterns.py says what the classifier matches on; this says where those needles
come from and what makes a set of them valid. Kept apart for the same reason
evidence_sql.py is: file handling and schema checking are a different job from
deciding anything, and the one place that reads a path off disk should be
findable.

**The merge is additive and that is a design decision, not a limitation.** An
operator pack adds needles; it cannot remove one. A deployment that wants to
*stop* matching something is describing a rule change, and a rule change belongs
in a rule where it can be reasoned about — not in a data file that silently
subtracts from the shipped behaviour and leaves the code reading as though it
still applied.

**A broken pack must stop the service.** Detection that quietly falls back to
"no patterns" produces a dashboard where everything is unknown and nothing is
wrong, which is the failure this codebase has met before with cron and with the
`.env` that was read as environment rather than as a file. Every error names the
file, the table and the value.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path

SHIPPED_PACK = Path(__file__).with_name("patterns.toml")

# The schema this loader understands. A pack declaring anything else is refused
# rather than read optimistically: a shape change that a reader guesses at is a
# classifier quietly matching on the wrong thing.
SCHEMA = 1

# Every table the classifier reads, and what it holds. Membership is checked in
# both directions — a missing table breaks a rule, and an unknown one is a needle
# list nothing will ever consult, which is worse than an error because it looks
# like it worked.
LIST_TABLES = (
    "scanner_paths",
    "payload_abuse",
    "dropper_suffixes",
    "convention_404",
    "cloud_isps",
    "researcher_rdns",
    "researcher_uas",
    "scanning_tool_uas",
    "search_rdns",
    "search_uas",
    "ai_rdns",
    "ai_uas",
    "seo_uas",
    "http_client_uas",
)
# Not a list of needles but a mapping from a declared crawler to the networks it
# legitimately crawls from, so it is validated on its own terms.
MAP_TABLES = ("crawler_origins",)


class PackError(Exception):
    """A pattern pack that cannot be used, with the reason a person can act on."""


def _read(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError:
        raise PackError(f"{path}: no such file") from None
    except tomllib.TOMLDecodeError as exc:
        raise PackError(f"{path}: not valid TOML — {exc}") from None
    except OSError as exc:
        raise PackError(f"{path}: cannot be read — {exc}") from None


def _check(path: Path, raw: dict, *, complete: bool) -> None:
    """Validate one pack. `complete` is False for an operator overlay.

    The shipped pack has to carry every table; an overlay may carry any subset,
    since its whole purpose is to add to one or two of them.
    """
    schema = raw.get("schema")
    if schema != SCHEMA:
        raise PackError(
            f"{path}: schema is {schema!r}, this build reads schema {SCHEMA}"
            if schema is not None
            else f"{path}: no `schema` key — every pack has to declare its shape"
        )
    known = set(LIST_TABLES) | set(MAP_TABLES)
    for name in sorted(set(raw) - known - {"schema"}):
        raise PackError(
            f"{path}: unknown table [{name}]. Nothing reads it, so it would look "
            f"applied and never be. Known tables: {', '.join(sorted(known))}"
        )
    if complete:
        for name in sorted(known - set(raw)):
            raise PackError(f"{path}: missing table [{name}]")

    for name in LIST_TABLES:
        if name not in raw:
            continue
        table = raw[name]
        if not isinstance(table, dict) or "entries" not in table:
            raise PackError(f"{path}: [{name}] must be a table with an `entries` list")
        entries = table["entries"]
        if not isinstance(entries, list):
            raise PackError(f"{path}: [{name}].entries must be a list")
        for entry in entries:
            if not isinstance(entry, str) or not entry.strip():
                raise PackError(
                    f"{path}: [{name}].entries holds {entry!r}; needles are non-empty strings"
                )

    for name in MAP_TABLES:
        if name not in raw:
            continue
        table = raw[name]
        if not isinstance(table, dict):
            raise PackError(f"{path}: [{name}] must be a table")
        for key, value in table.items():
            if not isinstance(value, list) or not all(
                isinstance(v, str) and v.strip() for v in value
            ):
                raise PackError(f"{path}: [{name}].{key} must be a list of non-empty strings")


def _merge(base: dict, extra: dict) -> dict:
    """Append `extra`'s entries to `base`'s, keeping order and dropping repeats.

    Shipped needles stay first, which decides more than it looks like: `_hit()`
    returns the *first* needle found, and that string is what the evidence line
    shows a reader. An operator addition should not change how an existing match
    is described.
    """
    merged: dict = {"schema": base["schema"]}
    for name in LIST_TABLES:
        entries = list(base[name]["entries"]) + list(extra.get(name, {}).get("entries", []))
        merged[name] = {"entries": list(dict.fromkeys(entries))}
    for name in MAP_TABLES:
        out = {k: list(v) for k, v in base[name].items()}
        for key, value in extra.get(name, {}).items():
            out[key] = list(dict.fromkeys(out.get(key, []) + list(value)))
        merged[name] = out
    return merged


def digest(pack: dict) -> str:
    """A short, stable fingerprint of the effective pack.

    It goes into CLASSIFIER_VERSION so that editing a needle reclassifies every
    stored label. Without it an operator pack would apply to addresses seen
    after the restart and to nothing else, and the dashboard would hold two
    vintages of judgement with no way to tell which is which.

    Canonical JSON rather than the TOML text: comments and formatting must not
    change the fingerprint, and the same needles written two ways are the same
    pack.
    """
    canonical = json.dumps(pack, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:8]


def load(extra_path: str | Path | None = None) -> tuple[dict, str]:
    """The effective pack and its fingerprint. Raises PackError with a reason."""
    shipped = _read(SHIPPED_PACK)
    _check(SHIPPED_PACK, shipped, complete=True)
    if not extra_path:
        return shipped, digest(shipped)
    path = Path(extra_path)
    extra = _read(path)
    _check(path, extra, complete=False)
    merged = _merge(shipped, extra)
    return merged, digest(merged)
