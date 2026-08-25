from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from typing import Any, Callable, Dict, Optional, Union

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class ResponseManager:
    """Manages mitigation response workflows, user prompt cooldowns, and audit logging."""

    def __init__(
        self,
        cooldown_seconds: float = 120.0,
        audit_file: Union[Path, str] = 'logs/response_audit.jsonl',
        time_func: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the ResponseManager with configurable cooldown and audit file.

        Args:
            cooldown_seconds: Minimum seconds between repeated termination prompts for the same PID.
            audit_file: Filepath where response audit events are appended as JSON Lines.
            time_func: Time function returning monotonic seconds (useful for deterministic tests).
        """
        self.cooldown_seconds: float = max(0.0, float(cooldown_seconds))
        self.audit_file: Path = Path(audit_file)
        self._time_func: Callable[[], float] = time_func
        self.cooldowns: Dict[int, float] = {}

        # Ensure destination directory for audit log exists
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)

    def should_prompt(self, pid: int) -> bool:
        """Check whether a process with the given PID is eligible for a prompt.

        Returns:
            True if the PID has never been prompted or if the cooldown period has elapsed.
        """
        last_prompt_time = self.cooldowns.get(pid)
        if last_prompt_time is None:
            return True
        now = self._time_func()
        return (now - last_prompt_time) >= self.cooldown_seconds

    def mark_prompted(self, pid: int) -> None:
        """Record a prompt event timestamp for the given PID to start its cooldown."""
        self.cooldowns[pid] = self._time_func()

    def record_action(
        self,
        pid: int,
        name: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a structured action record to the response audit file.

        Args:
            pid: Process ID.
            name: Executable name.
            action: Action summary (e.g. 'Terminated', 'Protected - skipped', 'User declined').
            details: Optional dictionary with extra context (score, reasons, path, etc.).

        Returns:
            The recorded audit entry dictionary.
        """
        record: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'pid': pid,
            'name': name,
            'action': action,
            'details': details or {},
        }

        try:
            self.audit_file.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_file.open('a', encoding='utf-8') as handle:
                handle.write(json.dumps(record) + '\n')
        except OSError:
            pass

        return record
