"""The Jinja environment and the template globals every page reads.

No router lives here. Each route module owns its own, and dashboard.py
includes them in an explicit order — see the note there."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.templating import Jinja2Templates

from .. import __version__
from ..config import settings
from ..taxonomy import (
    CLASS_TIPS,
    GROUP_COLOR_VARS,
    GROUP_TIPS,
    GROUPS_WITH_UNKNOWN,
    SIGNAL_BADGES,
    SIGNAL_COLOR_VARS,
    SIGNAL_LABELS,
    SIGNAL_LABELS_SHORT,
    SIGNAL_TIPS,
    SIGNALS,
    VISITOR_CATEGORIES,
)
from ..template_filters import register_filters

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
templates.env.autoescape = True
register_filters(templates.env)

# Cache-buster appended to every local /static asset URL (?v=). New value per
# process start, so browsers pick up changed JS/CSS after a deploy/restart
# instead of serving stale files.
templates.env.globals["asset_v"] = str(int(time.time()))

# Shown beside the name in the sidebar, so the running build is readable off any
# page rather than only from /api/stats.
templates.env.globals["VERSION"] = __version__
# Where the sidebar's version badge points. A property of the product rather than
# of an installation, so it is a constant and not a setting — every copy of Vidar
# is released from the same place, whatever site it happens to be watching.
templates.env.globals["REPO_URL"] = "https://github.com/KrisMyslowski/Vidar"
# Every page says so while DEMO_MODE is on: synthetic traffic that looks
# entirely real is the one thing this dashboard must not serve silently.
#
# A callable, like attention_count(), not the value: a global bound at import
# freezes whatever the setting was then, which is right in production only
# because the environment is read before this module loads, and wrong the moment
# anything sets it later.
templates.env.globals["demo_mode"] = lambda: settings.demo_mode
# Same shape and the same reason: read at render time, not at import.
templates.env.globals["carto_api_key"] = lambda: settings.carto_api_key

_TAXONOMY_DATA = {
    "class_groups": {group: classes for group, classes in VISITOR_CATEGORIES},
    # The display order, so map.js does not keep its own copy of the group list.
    # `class_groups` cannot serve: it is a mapping and carries no order.
    "groups": list(GROUPS_WITH_UNKNOWN),
    "signal_labels": SIGNAL_LABELS,
    "class_tips": {k: {"what": v[0], "how": v[1]} for k, v in CLASS_TIPS.items()},
    "group_tips": {k: {"what": v[0], "how": v[1]} for k, v in GROUP_TIPS.items()},
}
templates.env.globals.update(
    {
        "CLASS_TIPS": CLASS_TIPS,
        "GROUP_TIPS": GROUP_TIPS,
        "SIGNAL_TIPS": SIGNAL_TIPS,
        "SIGNAL_BADGES": SIGNAL_BADGES,
        "SIGNAL_LABELS": SIGNAL_LABELS,
        "SIGNAL_LABELS_SHORT": SIGNAL_LABELS_SHORT,
        # The registry itself, for templates that render one column, chip or bar
        # segment per signal. One list: there was a second for signals shown but
        # not filterable, and it is empty now that Mobile filters like the rest.
        "SIGNALS": SIGNALS,
        # Whether tooltips also write a native title=. Off: the browser then
        # draws its own delayed box beside the styled one, same words, other
        # place. macros/_tip.html is the only reader.
        "TIP_TITLES": False,
        "GROUP_COLOR_VARS": GROUP_COLOR_VARS,
        "SIGNAL_COLOR_VARS": SIGNAL_COLOR_VARS,
        # The five identity groups in display order, for templates that render one
        # control per group (the heatmap's series toggle) rather than one per class.
        "TAXONOMY_GROUPS": GROUPS_WITH_UNKNOWN,
        "TAXONOMY_DATA": _TAXONOMY_DATA,
    }
)
