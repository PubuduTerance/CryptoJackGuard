from __future__ import annotations
from typing import Dict, Any


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
