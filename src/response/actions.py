from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any

import psutil


CRITICAL_PROCESS_NAMES = {
    'explorer.exe',
    'svchost.exe',
    'wininit.exe',
    'services.exe',
    'lsass.exe',
    'csrss.exe',
    'smss.exe',
    'winlogon.exe',
    'code.exe',
    'chrome.exe',
    'msedge.exe',
}
CRITICAL_PROCESS_PIDS = {0, 4}


@dataclass(frozen=True)
class TerminationResult:
    success: bool
    status: str


def is_protected_process(pid: int, process_name: str) -> bool:
    """Return whether a process must never be terminated by this tool."""
    return pid in CRITICAL_PROCESS_PIDS or process_name.lower() in CRITICAL_PROCESS_NAMES


def terminate_process(pid: int, process_name: str) -> TerminationResult:
    """Terminate only an unprotected process after caller confirmation."""
    if is_protected_process(pid, process_name):
        return TerminationResult(False, 'protected process - no termination')

    try:
        process = psutil.Process(pid)
        process.terminate()
        process.wait(timeout=5)
        return TerminationResult(True, 'terminated')
    except psutil.NoSuchProcess:
        return TerminationResult(False, 'no such process')
    except psutil.AccessDenied:
        return TerminationResult(False, 'access denied')
    except psutil.TimeoutExpired:
        return TerminationResult(False, 'timeout expired')
    except Exception as exc:
        return TerminationResult(False, str(exc))


def list_safe_action_options() -> Dict[str, str]:
    return {
        'ignore': 'Ignore the alert and continue monitoring',
        'investigate': 'Open detailed alerts for manual review',
        'log': 'Log the alert and keep monitoring',
    }


def action_description(action: str) -> str:
    options = list_safe_action_options()
    return options.get(action, 'Unknown safe action')


def respond_to_alert(alert: Dict[str, Any], action: str = 'log') -> None:
    if action not in list_safe_action_options():
        action = 'log'

    if action == 'log':
        return
