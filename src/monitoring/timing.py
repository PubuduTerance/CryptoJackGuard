"""Shared scan timing record helpers."""

from __future__ import annotations

from typing import Dict


TIMING_FIELDS = (
    'resource_collection_ms',
    'process_collection_ms',
    'network_collection_ms',
    'scoring_anomaly_ms',
    'persistence_inspection_ms',
    'osint_refresh_ms',
    'scan_duration_ms',
)


def build_scan_timings(**durations: float) -> Dict[str, float]:
    """Create a complete, non-negative timing record in milliseconds."""
    return {
        field: max(0.0, float(durations.get(field, 0.0)))
        for field in TIMING_FIELDS
    }
