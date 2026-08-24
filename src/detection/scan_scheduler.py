"""Small helpers for distinguishing dashboard scans from UI reruns."""

from __future__ import annotations

from typing import Optional


def should_run_dashboard_scan(
    has_previous_scan: bool,
    manual_refresh: bool,
    auto_refresh_tick: Optional[int],
    previous_auto_refresh_tick: Optional[int],
) -> bool:
    """Return whether this dashboard run should collect new telemetry.

    Initial page loads and Manual Refresh requests are scans. With auto-refresh
    enabled, only a changed timer tick is a new scan; ordinary widget reruns
    keep displaying the previous snapshot.
    """
    if not has_previous_scan or manual_refresh:
        return True

    return (
        auto_refresh_tick is not None
        and previous_auto_refresh_tick is not None
        and auto_refresh_tick != previous_auto_refresh_tick
    )
