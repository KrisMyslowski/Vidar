"""Visitor classification — who an IP is, and why we say so.

    patterns.py      the literals: probe paths, UA/rDNS needles, thresholds
    evidence_sql.py  the one query that summarises an IP's history
    rules.py         the ordered chain that turns that summary into a verdict
    classify.py      the two entry points that need a connection

Split out of queries.py, which is a SQL module and had 850 lines of domain logic
in the middle of it. Writing a class back to ip_intel is still SQL and still
lives there (set_visitor_class and friends); this package only decides.
"""

from .classify import classify_ip, explain_classification
from .evidence_sql import _classify_params, _classify_sql
from .patterns import CLASSIFIER_VERSION, _scanner_path_match
from .rules import _apply_priority_chain, _decisive_rule

# The underscored names are internal to the package but reachable from outside on
# purpose: the tests drive the evidence query and the chain directly, because a
# rule is far easier to pin down on a dict than through a database round trip.
__all__ = [
    "CLASSIFIER_VERSION",
    "classify_ip",
    "explain_classification",
    "_apply_priority_chain",
    "_classify_params",
    "_classify_sql",
    "_decisive_rule",
    "_scanner_path_match",
]
