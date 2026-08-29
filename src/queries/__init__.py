"""SQL query layer — one module per subject, one import surface.

Split out of a single 3.4k-line queries.py. Every name it exported is still
importable from `queries`, so no caller had to change; new code can import
the module it actually needs.

    _shared       fragments the rest build on (window, filters, grouping)
    visits        raw visit rows
    visitors      per-IP aggregation
    aggregations  the four groupings of /visitors
    intel         ip_intel cache, Shodan children, state, rate limits
    stats         the Overview's numbers
    analysis      charts, facets, the exposure surface
    archive_sql   the SQL half of the monthly archive
"""

from ..classifier import CLASSIFIER_VERSION as CLASSIFIER_VERSION
from ..classifier import _apply_priority_chain as _apply_priority_chain
from ..classifier import _classify_params as _classify_params
from ..classifier import _classify_sql as _classify_sql
from ..classifier import _decisive_rule as _decisive_rule
from ..classifier import _scanner_path_match as _scanner_path_match
from ..classifier import classify_ip as classify_ip
from ..classifier import explain_classification as explain_classification
from ._shared import VISIT_SORT_MAP as VISIT_SORT_MAP
from ._shared import VISITOR_REQUEST_SORT_MAP as VISITOR_REQUEST_SORT_MAP
from ._shared import VISITOR_SORT_MAP as VISITOR_SORT_MAP
from ._shared import _apply_class_filter as _apply_class_filter
from ._shared import _apply_signal_filter as _apply_signal_filter
from ._shared import _no_signals_sql as _no_signals_sql
from ._shared import _term_sql as _term_sql
from ._shared import seen_in_window as seen_in_window
from ._shared import visit_window as visit_window
from .aggregations import CLIENTS_SORT_MAP as CLIENTS_SORT_MAP
from .aggregations import COUNTRIES_SORT_MAP as COUNTRIES_SORT_MAP
from .aggregations import NETWORKS_SORT_MAP as NETWORKS_SORT_MAP
from .aggregations import PATHS_SORT_MAP as PATHS_SORT_MAP
from .aggregations import _agg_q_filter as _agg_q_filter
from .aggregations import count_clients as count_clients
from .aggregations import count_countries as count_countries
from .aggregations import count_networks as count_networks
from .aggregations import count_paths as count_paths
from .aggregations import get_clients as get_clients
from .aggregations import get_countries as get_countries
from .aggregations import get_networks as get_networks
from .aggregations import get_paths as get_paths
from .analysis import _shodan_value_filters as _shodan_value_filters
from .analysis import count_shodan_hosts as count_shodan_hosts
from .analysis import get_activity_timeline as get_activity_timeline
from .analysis import get_analysis_data as get_analysis_data
from .analysis import get_daily_kpis as get_daily_kpis
from .analysis import get_geo_data as get_geo_data
from .analysis import get_hourly_heatmap as get_hourly_heatmap
from .analysis import get_http_version_dist as get_http_version_dist
from .analysis import get_identity_signal_matrix as get_identity_signal_matrix
from .analysis import get_rate_limit_timeline as get_rate_limit_timeline
from .analysis import get_shodan_hosts as get_shodan_hosts
from .analysis import get_status_timeline as get_status_timeline
from .analysis import get_top_ports as get_top_ports
from .analysis import get_top_tags as get_top_tags
from .analysis import get_top_vulns as get_top_vulns
from .analysis import get_unusual_methods as get_unusual_methods
from .archive_sql import delete_visits_for_month as delete_visits_for_month
from .archive_sql import get_intel_for_month as get_intel_for_month
from .archive_sql import get_visit_months as get_visit_months
from .archive_sql import insert_archived_visits as insert_archived_visits
from .archive_sql import insert_missing_intel as insert_missing_intel
from .archive_sql import purge_orphaned_intel as purge_orphaned_intel
from .archive_sql import stream_visits_for_month as stream_visits_for_month
from .intel import backfill_visitor_classes as backfill_visitor_classes
from .intel import count_export_hits as count_export_hits
from .intel import count_stale_ips as count_stale_ips
from .intel import count_unenriched_ips as count_unenriched_ips
from .intel import delete_state as delete_state
from .intel import force_reclassify_all as force_reclassify_all
from .intel import get_ip_intel as get_ip_intel
from .intel import get_ip_intel_bulk as get_ip_intel_bulk
from .intel import get_ips_without_rdns as get_ips_without_rdns
from .intel import get_stale_ips as get_stale_ips
from .intel import get_state as get_state
from .intel import get_unenriched_ips as get_unenriched_ips
from .intel import mark_enrichment_failed as mark_enrichment_failed
from .intel import purge_old_rate_limits as purge_old_rate_limits
from .intel import reclassify_stale_ips as reclassify_stale_ips
from .intel import record_export_hit as record_export_hit
from .intel import set_reverse_dns as set_reverse_dns
from .intel import set_state as set_state
from .intel import set_visitor_class as set_visitor_class
from .intel import upsert_ip_intel as upsert_ip_intel
from .stats import get_attention_items as get_attention_items
from .stats import get_stats as get_stats
from .stats import get_visitor_ip_counts as get_visitor_ip_counts
from .visitors import count_visitors_grouped as count_visitors_grouped
from .visitors import get_visitor_detail as get_visitor_detail
from .visitors import get_visitor_requests as get_visitor_requests
from .visitors import get_visitors_grouped as get_visitors_grouped
from .visits import count_visits as count_visits
from .visits import get_visits as get_visits
from .visits import insert_visit as insert_visit
from .visits import stream_visits_for_export as stream_visits_for_export
