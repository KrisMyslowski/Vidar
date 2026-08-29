"""Helpers shared across route modules."""

from __future__ import annotations


def total_pages(total: int, limit: int) -> int:
    """Number of pages needed for `total` items at `limit` per page (minimum 1)."""
    return max(1, (total + limit - 1) // limit)
