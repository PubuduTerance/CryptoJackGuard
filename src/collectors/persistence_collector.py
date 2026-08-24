"""Bounded, read-only Windows persistence inspection for investigation scans."""

from __future__ import annotations

import csv
import os
import subprocess
from dataclasses import dataclass, field
from io import StringIO
from time import monotonic
from typing import Any, Iterable, List, Optional, Sequence, Set, Tuple

from src.detection.scoring import is_suspicious_execution_location

try:
    import winreg
except ImportError:  # pragma: no cover - depends on the host platform
    winreg = None


RUN_KEY_PATH = r'Software\Microsoft\Windows\CurrentVersion\Run'
MINER_COMMAND_INDICATORS = {
    'stratum',
    'stratum+tcp',
    'stratum+ssl',
    'randomx',
    'rx/0',
    'xmrig',
    '--algo',
    '--coin',
    '--pool',
    'donate-level',
}
SYSTEM_LOOKALIKE_NAMES = {
    'svchost.exe',
    'lsass.exe',
    'services.exe',
    'winlogon.exe',
    'csrss.exe',
    'smss.exe',
}


@dataclass(frozen=True)
class PersistenceFinding:
    source: str
    name: str
    command: str
    reason: str
    risk_relevance: int = 10


@dataclass
class PersistenceScanResult:
    findings: List[PersistenceFinding] = field(default_factory=list)
    duration_ms: float = 0.0
    supported: bool = False
    performed: bool = False


def is_windows() -> bool:
    return os.name == 'nt'


def _read_run_registry_entries() -> List[Tuple[str, str, str]]:
    if winreg is None:
        return []

    entries: List[Tuple[str, str, str]] = []
    hives = (
        ('HKCU Run', winreg.HKEY_CURRENT_USER),
        ('HKLM Run', winreg.HKEY_LOCAL_MACHINE),
    )
    for source, hive in hives:
        key = None
        try:
            key = winreg.OpenKey(hive, RUN_KEY_PATH, 0, winreg.KEY_READ)
            index = 0
            while True:
                try:
                    value_name, value, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                entries.append((source, str(value_name), str(value)))
                index += 1
        except OSError:
            continue
        finally:
            close_key = getattr(key, 'Close', None)
            if callable(close_key):
                close_key()

    return entries


def _read_scheduled_task_entries() -> List[Tuple[str, str, str]]:
    """Read task commands with schtasks CSV output; localized headers are skipped."""
    try:
        result = subprocess.run(
            ['schtasks', '/query', '/fo', 'csv', '/v'],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    entries: List[Tuple[str, str, str]] = []
    for row in csv.DictReader(StringIO(result.stdout)):
        task_name = row.get('TaskName') or row.get('Task Name') or ''
        command = row.get('Task To Run') or row.get('Actions') or ''
        if task_name and command:
            entries.append(('Scheduled Task', task_name, command))
    return entries


def _persistence_reason(command: str, indicators: Set[str]) -> Optional[str]:
    command_lower = command.lower()
    if any(indicator in command_lower for indicator in indicators | MINER_COMMAND_INDICATORS):
        return 'mining indicator in persistence command'
    if (
        any(name in command_lower for name in SYSTEM_LOOKALIKE_NAMES)
        and is_suspicious_execution_location(command)
    ):
        return 'system-looking executable configured from suspicious location'
    return None


def collect_persistence_findings(
    indicators: Set[str],
    command_indicators: Iterable[str] = (),
) -> PersistenceScanResult:
    """Inspect bounded Windows persistence sources without changing system state."""
    if not is_windows():
        return PersistenceScanResult(supported=False, performed=False)

    start = monotonic()
    all_indicators = {indicator.lower() for indicator in indicators}
    all_indicators.update(indicator.lower() for indicator in command_indicators)
    findings: List[PersistenceFinding] = []
    seen_entries: Set[Tuple[str, str, str]] = set()

    for source, name, command in _read_run_registry_entries() + _read_scheduled_task_entries():
        entry_identity = (source, name, command)
        if entry_identity in seen_entries:
            continue
        seen_entries.add(entry_identity)

        reason = _persistence_reason(command, all_indicators)
        if reason:
            findings.append(PersistenceFinding(source, name, command, reason))

    return PersistenceScanResult(
        findings=findings,
        duration_ms=(monotonic() - start) * 1000.0,
        supported=True,
        performed=True,
    )


class PersistenceInspectionCache:
    """Cache centralized persistence checks until another investigation is due."""

    def __init__(self, cache_seconds: float = 300.0) -> None:
        self.cache_seconds = max(0.0, cache_seconds)
        self._last_result: Optional[PersistenceScanResult] = None
        self._last_inspection_time: Optional[float] = None

    def inspect_if_triggered(
        self,
        scores: Sequence[Any],
        investigation_threshold: float,
        indicators: Set[str],
        command_indicators: Iterable[str] = (),
    ) -> PersistenceScanResult:
        """Run only for an investigation-worthy scan, otherwise return quickly."""
        if not any(score.risk_score >= investigation_threshold for score in scores):
            return PersistenceScanResult(supported=is_windows(), performed=False)

        now = monotonic()
        if (
            self._last_result is not None
            and self._last_inspection_time is not None
            and now - self._last_inspection_time < self.cache_seconds
        ):
            return self._last_result

        self._last_result = collect_persistence_findings(indicators, command_indicators)
        self._last_inspection_time = now
        return self._last_result


def apply_persistence_findings(scores: Iterable[Any], findings: Iterable[PersistenceFinding]) -> None:
    """Add one modest signal when a suspicious persistence entry matches a process."""
    for score in scores:
        score_path = str(getattr(score, 'path', '')).lower()
        score_cmdline = str(getattr(score, 'cmdline', '')).lower()
        for finding in findings:
            command_lower = finding.command.lower()
            if not (
                (score_path and score_path in command_lower)
                or (score_cmdline and score_cmdline == command_lower)
            ):
                continue

            reason = f'suspicious persistence entry matches process: {finding.name}'
            if reason not in score.reasons:
                score.risk_score = min(100.0, score.risk_score + finding.risk_relevance)
                score.reasons.append(reason)
            break
