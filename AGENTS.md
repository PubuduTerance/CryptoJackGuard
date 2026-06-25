# CryptoJackGuard - Codex Instructions

This is a defensive cybersecurity research prototype for detecting cryptojacking on personal computers.

Project goal:
Build a lightweight endpoint-based cryptojacking detection and prevention system using Python.

Important rules:
- This project is defensive only.
- Do not create malware, persistence malware, exploit code, or cryptojacking code.
- Do not automatically kill or block processes without user confirmation.
- Prefer privacy-preserving monitoring.
- Avoid packet payload inspection unless explicitly needed for evaluation.
- Use simple, readable Python suitable for a final-year research project.
- Keep modules small and well-commented.

Architecture:
- src/collectors/resource_collector.py: CPU, memory, GPU usage
- src/collectors/process_collector.py: process name, PID, path, command line, CPU, memory
- src/collectors/network_collector.py: process network connections using psutil
- src/intelligence/osint_loader.py: load mining indicators from data/mining_iocs.txt
- src/detection/scoring.py: combine signals into a risk score
- src/response/actions.py: safe response actions
- src/storage/alert_logger.py: save alerts to logs/alerts.jsonl
- main.py: CLI dashboard and program loop

Coding style:
- Use type hints.
- Add basic error handling.
- Do not crash if permission is denied.
- Log alerts as JSON Lines.
- Keep the MVP Windows-first, but avoid Windows-only code unless necessary.

Testing:
- Use benign CPU stress tests first.
- Do not require real malware.
- Add simple scripts later for evaluation metrics.