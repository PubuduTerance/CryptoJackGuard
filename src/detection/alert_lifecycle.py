"""Shared sustained-alert state for CryptoJackGuard scan loops."""

from __future__ import annotations

from typing import Dict, Iterable, List, Set

from src.detection.scoring import ProcessScore
from src.privacy.redaction import redact_command_line


class AlertLifecycle:
    """Confirm sustained high-risk process episodes without duplicate alerts.

    Process identity uses PID, executable path, and command line. This matches
    the existing CLI intent while distinguishing separate process instances
    without requiring any additional collection work.
    """

    def __init__(self, alert_threshold: float, sustained_cycles: int) -> None:
        self.alert_threshold = alert_threshold
        self.sustained_cycles = max(1, sustained_cycles)
        self._consecutive_cycles: Dict[str, int] = {}
        self._confirmed_keys: Set[str] = set()

    @staticmethod
    def process_identity(score: ProcessScore) -> str:
        return f'{score.pid}:{score.path}:{score.cmdline}'

    def update(self, scores: Iterable[ProcessScore]) -> List[ProcessScore]:
        """Record one scan cycle and return only newly confirmed alerts."""
        current_keys: Set[str] = set()
        newly_confirmed: List[ProcessScore] = []

        for score in scores:
            if score.risk_score < self.alert_threshold:
                continue

            identity = self.process_identity(score)
            if identity in current_keys:
                continue
            current_keys.add(identity)
            self._consecutive_cycles[identity] = self._consecutive_cycles.get(identity, 0) + 1

            if (
                self._consecutive_cycles[identity] >= self.sustained_cycles
                and identity not in self._confirmed_keys
            ):
                newly_confirmed.append(score)
                self._confirmed_keys.add(identity)

        stale_keys = set(self._consecutive_cycles) - current_keys
        for identity in stale_keys:
            self._consecutive_cycles.pop(identity, None)
            self._confirmed_keys.discard(identity)

        return newly_confirmed


def build_alert_record(score: ProcessScore, sustained_cycles: int) -> Dict[str, object]:
    """Create a logger-compatible record without exposing sensitive CLI values.

    ``ProcessScore.cmdline`` remains raw in memory so scoring and lifecycle
    identity retain their current behavior. Only this output record is redacted.
    """
    return {
        'pid': score.pid,
        'name': score.name,
        'path': score.path,
        'cmdline': redact_command_line(score.cmdline),
        'score': score.risk_score,
        'reasons': score.reasons,
        'sustained_cycles': sustained_cycles,
    }
