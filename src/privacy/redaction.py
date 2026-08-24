"""Redact sensitive command-line argument values before output or storage."""

from __future__ import annotations

import re


_SENSITIVE_ARGUMENT_PATTERN = re.compile(
    r'''(?P<name>--(?:
        password|pass|token|api-key|api_key|apikey|secret|
        access-token|access_token|auth-token|auth_token|
        db-password|db_password|database-password|database_password
    ))(?P<separator>=|\s+)(?P<value>"[^"]*"|'[^']*'|(?!-)\S+)''',
    re.IGNORECASE | re.VERBOSE,
)


def redact_command_line(command_line: str) -> str:
    """Mask sensitive option values while retaining useful command structure."""
    if not command_line:
        return command_line

    def replace(match: re.Match[str]) -> str:
        separator = '=' if match.group('separator') == '=' else ' '
        return f"{match.group('name')}{separator}<redacted>"

    return _SENSITIVE_ARGUMENT_PATTERN.sub(replace, command_line)
