"""All SQL lives in src/queries/ — the project's stated rule, held by a test.

Routes call query functions; they never build SQL. It had three exceptions no
one had meant to make: a count in the Shodan route, the earliest-date cache and
the demo-mode guard in main.py. None was injectable. Each was the first crack in
a rule that otherwise held everywhere, which is how the old queries.py grew.
"""

import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"


def test_no_route_and_no_app_module_executes_sql():
    offenders = [
        f"{path.relative_to(SRC)}:{n}"
        for path in [*sorted((SRC / "routes").glob("*.py")), SRC / "main.py"]
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if re.search(r"\.execute(many)?\(", line)
    ]
    assert offenders == [], f"SQL outside src/queries/: {offenders}"
