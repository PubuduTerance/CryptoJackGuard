"""Tests that dashboard UI reruns do not advance monitoring scan cycles."""

from __future__ import annotations

import unittest

from src.detection.scan_scheduler import should_run_dashboard_scan


class DashboardScanSchedulingTests(unittest.TestCase):
    def test_initial_page_load_runs_a_scan(self) -> None:
        self.assertTrue(
            should_run_dashboard_scan(
                has_previous_scan=False,
                manual_refresh=False,
                auto_refresh_tick=None,
                previous_auto_refresh_tick=None,
            )
        )

    def test_widget_rerun_without_refresh_reuses_previous_scan(self) -> None:
        self.assertFalse(
            should_run_dashboard_scan(
                has_previous_scan=True,
                manual_refresh=False,
                auto_refresh_tick=None,
                previous_auto_refresh_tick=None,
            )
        )

    def test_manual_refresh_runs_a_new_scan(self) -> None:
        self.assertTrue(
            should_run_dashboard_scan(
                has_previous_scan=True,
                manual_refresh=True,
                auto_refresh_tick=None,
                previous_auto_refresh_tick=None,
            )
        )

    def test_same_auto_refresh_tick_is_not_a_new_scan(self) -> None:
        self.assertFalse(
            should_run_dashboard_scan(
                has_previous_scan=True,
                manual_refresh=False,
                auto_refresh_tick=4,
                previous_auto_refresh_tick=4,
            )
        )

    def test_new_auto_refresh_tick_runs_a_new_scan(self) -> None:
        self.assertTrue(
            should_run_dashboard_scan(
                has_previous_scan=True,
                manual_refresh=False,
                auto_refresh_tick=5,
                previous_auto_refresh_tick=4,
            )
        )

    def test_enabling_auto_refresh_waits_for_its_first_timer_tick(self) -> None:
        self.assertFalse(
            should_run_dashboard_scan(
                has_previous_scan=True,
                manual_refresh=False,
                auto_refresh_tick=0,
                previous_auto_refresh_tick=None,
            )
        )


if __name__ == '__main__':
    unittest.main()
