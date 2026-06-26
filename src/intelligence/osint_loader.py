from __future__ import annotations
from pathlib import Path
from typing import Set


def load_mining_indicators(indicator_file: Path) -> Set[str]:
    indicators: Set[str] = set()

    if not indicator_file.exists():
        return indicators

    try:
        with indicator_file.open('r', encoding='utf-8') as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue
                indicators.add(line.lower())
    except OSError:
        return indicators

    return indicators


def load_allowlisted_processes(allowlist_file: Path) -> Set[str]:
    allowlist: Set[str] = set()

    if not allowlist_file.exists():
        return allowlist

    try:
        with allowlist_file.open('r', encoding='utf-8') as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue
                allowlist.add(line.lower())
    except OSError:
        return allowlist

    return allowlist
