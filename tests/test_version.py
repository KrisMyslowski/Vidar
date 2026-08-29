"""The version is written once, in src/__init__.py, and echoed in pyproject.toml.

deploy/Dockerfile copies requirements/runtime.txt and src/ and nothing else, so
pyproject.toml is not in the image and cannot be the runtime source. That leaves
two files carrying the same number, which is exactly how a number goes stale:
the packaging metadata says one thing and the dashboard reports another. This
binds them the way test_config.py binds .env.example to Settings.
"""

from __future__ import annotations

import re
from pathlib import Path

from src import __version__

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _declared_version() -> str | None:
    """The version from pyproject.toml's [project] table.

    Read with a regex rather than a TOML parser: tomllib would work, but the
    file is also the black/isort/ruff/pytest config and a parse error there
    would fail this test for a reason that has nothing to do with the version.
    """
    for line in PYPROJECT.read_text().splitlines():
        match = re.fullmatch(r'version\s*=\s*"([^"]+)"', line.strip())
        if match:
            return match.group(1)
    return None


def test_pyproject_declares_the_same_version():
    assert _declared_version() == __version__


def test_the_version_is_a_semantic_version():
    """Semantic versioning, optionally with a pre-release suffix.

    The dashboard renders the version into a link to the tag of the same name, so
    whatever is written here has to be exactly what `git tag` carries — a
    pre-release suffix spelled the way the tag spells it, 1.0.0-rc.1 rather than
    PEP 440's normalised 1.0.0rc1.
    """
    assert re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", __version__), __version__


def test_every_tracked_file_is_world_readable():
    """A file the container cannot read is a 500 nobody sees coming.

    Git records only the executable bit, so a mode is invisible to review and
    identical in every clone — but the deploy rsyncs this working tree as it is,
    and the image COPYs what the deploy sent. docs/privacy.md entered the repo
    from a zip at 0600, shipped at 0600, and /docs answered 500 for that one
    document while every other rendered.

    The Dockerfile now normalises modes after COPY. This checks the source of the
    problem rather than the last place it could have been caught.
    """
    import subprocess

    root = PYPROJECT.parent
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True, check=True
    ).stdout.split("\0")
    unreadable = [
        f for f in tracked if f and (root / f).is_file() and not (root / f).stat().st_mode & 0o004
    ]
    assert not unreadable, f"not world-readable: {unreadable}"
