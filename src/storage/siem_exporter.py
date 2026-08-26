from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import sys
from typing import Any, Dict, Optional, Union

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.privacy.redaction import redact_command_line

# Syslog Facilities
FACILITY_LOCAL0 = 16  # 16 = local0 (standard for enterprise security appliances)

# Syslog Severities (RFC 5424)
SEVERITY_EMERGENCY = 0
SEVERITY_ALERT = 1
SEVERITY_CRITICAL = 2
SEVERITY_ERROR = 3
SEVERITY_WARNING = 4
SEVERITY_NOTICE = 5
SEVERITY_INFORMATIONAL = 6
SEVERITY_DEBUG = 7


def _resolve_severity(score: float) -> int:
    """Map numerical risk score to Syslog RFC 5424 severity level."""
    if score >= 85.0:
        return SEVERITY_CRITICAL
    elif score >= 60.0:
        return SEVERITY_WARNING
    elif score >= 40.0:
        return SEVERITY_NOTICE
    else:
        return SEVERITY_INFORMATIONAL


def _severity_name(severity: int) -> str:
    mapping = {
        SEVERITY_EMERGENCY: "EMERGENCY",
        SEVERITY_ALERT: "ALERT",
        SEVERITY_CRITICAL: "CRITICAL",
        SEVERITY_ERROR: "ERROR",
        SEVERITY_WARNING: "WARNING",
        SEVERITY_NOTICE: "NOTICE",
        SEVERITY_INFORMATIONAL: "INFORMATIONAL",
        SEVERITY_DEBUG: "DEBUG",
    }
    return mapping.get(severity, "NOTICE")


def format_siem_event(
    alert_record: Dict[str, Any],
    facility: int = FACILITY_LOCAL0,
    severity: Optional[int] = None,
    rfc5424: bool = False,
) -> str:
    """Format an alert record into a JSON payload or RFC 5424 Syslog message for SIEM ingestion.

    Args:
        alert_record: Dictionary containing alert telemetry.
        facility: Syslog facility code (default: 16 / local0).
        severity: Optional explicit severity code; computed from risk score if omitted.
        rfc5424: If True, prefixes JSON payload with RFC 5424 Syslog header (<PRI>1 ...).

    Returns:
        Formatted string representation of the SIEM event.
    """
    timestamp = alert_record.get("timestamp")
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "localhost"

    score = float(alert_record.get("score") or alert_record.get("risk_score") or 0.0)
    resolved_sev = severity if severity is not None else _resolve_severity(score)
    pri = (facility * 8) + resolved_sev

    # Ensure command line is sanitized/redacted
    cmdline = alert_record.get("cmdline")
    if isinstance(cmdline, str):
        redacted_cmd = redact_command_line(cmdline)
    else:
        redacted_cmd = ""

    event_type = "CRYPTOJACKING_RESPONSE_ACTION" if "response_action" in alert_record else "CRYPTOJACKING_ALERT"

    structured_payload: Dict[str, Any] = {
        "event_type": event_type,
        "timestamp": timestamp,
        "hostname": hostname,
        "source_app": "CryptoJackGuard",
        "severity": _severity_name(resolved_sev),
        "severity_code": resolved_sev,
        "facility": facility,
        "score": score,
        "pid": alert_record.get("pid"),
        "name": alert_record.get("name"),
        "path": alert_record.get("path"),
        "cmdline": redacted_cmd,
        "reasons": alert_record.get("reasons", []),
    }

    # Add optional response actions or metrics if present
    if "response_action" in alert_record:
        structured_payload["response_action"] = alert_record["response_action"]
    if "sustained_cycles" in alert_record:
        structured_payload["sustained_cycles"] = alert_record["sustained_cycles"]
    if "ml_confidence" in alert_record:
        structured_payload["ml_confidence"] = alert_record["ml_confidence"]

    json_str = json.dumps(structured_payload, ensure_ascii=False)

    if rfc5424:
        # RFC 5424 header: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        pid_str = str(alert_record.get("pid") or "-")
        return f"<{pri}>1 {timestamp} {hostname} CryptoJackGuard {pid_str} ID-{event_type} - {json_str}"

    return json_str


def export_to_siem(
    alert_record: Dict[str, Any],
    syslog_host: str = "127.0.0.1",
    port: int = 514,
    protocol: str = "udp",
    timeout: float = 2.0,
    facility: int = FACILITY_LOCAL0,
    severity: Optional[int] = None,
    rfc5424: bool = False,
) -> bool:
    """Forward a security alert record to an enterprise SIEM or Syslog server.

    Supported transport protocols:
    - UDP (default for Syslog port 514)
    - TCP (for stream-oriented SIEM endpoints like Logstash / Splunk / Sentinel)

    Args:
        alert_record: Dictionary containing alert fields (pid, name, path, score, reasons, etc.).
        syslog_host: Hostname or IP address of SIEM/Syslog receiver (default: "127.0.0.1").
        port: Port number for SIEM/Syslog receiver (default: 514).
        protocol: Transport protocol ('udp' or 'tcp', default: 'udp').
        timeout: Socket operation timeout in seconds (default: 2.0).
        facility: Syslog facility code (default: 16 = local0).
        severity: Optional explicit severity code.
        rfc5424: If True, wraps JSON in standard RFC 5424 Syslog framing.

    Returns:
        True if the event payload was successfully transmitted, False otherwise.
    """
    if not alert_record:
        return False

    formatted_msg = format_siem_event(
        alert_record=alert_record,
        facility=facility,
        severity=severity,
        rfc5424=rfc5424,
    )
    raw_payload = formatted_msg.encode("utf-8")
    proto_lower = protocol.strip().lower()

    try:
        if proto_lower == "tcp":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((syslog_host, int(port)))
                sock.sendall(raw_payload + b"\n")
                return True
        else:  # UDP (default)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(raw_payload, (syslog_host, int(port)))
                return True
    except (socket.error, OSError, TimeoutError) as exc:
        print(f"[!] SIEM export failed ({proto_lower.upper()} {syslog_host}:{port}): {exc}", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"[!] Unexpected error during SIEM export: {exc}", file=sys.stderr)
        return False
