"""Text helpers for building SQL, with no dependency on anything that queries.

Its own module because both sides need it and neither can import the other:
queries/__init__.py re-exports the classifier, and the classifier's evidence
query is where LIKE patterns are built from settings. A copy in each drifted
into two definitions of one escape, which is one too many.
"""

from __future__ import annotations


def like_escape(term: str) -> str:
    r"""Escape LIKE wildcards so the term matches literally (use with ESCAPE '\')."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
