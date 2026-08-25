# Security Policy & Ethical Statement 🛡️

## 🎓 Academic Research & Ethical Purpose

**CryptoJackGuard** is a defensive cybersecurity research prototype developed as part of a final-year academic thesis project. Its purpose is to study, demonstrate, and evaluate lightweight endpoint detection algorithms for cryptojacking threats on modern personal computers.

### Core Ethical Principles:
1. **Defensive Only:** This software is purely defensive. The repository does **not** contain any cryptojacking miners, malware binaries, remote persistence exploits, or botnet command-and-control (C2) logic.
2. **Safe Evaluation Testbeds:** All evaluation and test suites use benign, deterministic mathematical operations (`tests/cpu_stress_test.py`) and simulated command-line mock data (`tests/run_thesis_evaluation.py`) to test detection efficacy safely without risking host stability.
3. **No Automated Destructive Actions:** CryptoJackGuard does not automatically terminate or suspend system processes without explicit user confirmation. Critical OS components and protected binaries are shielded from accidental termination.

---

## 🔒 Privacy-Preserving Monitoring

Unlike intrusive endpoint monitoring solutions or deep-packet inspection (DPI) agents, CryptoJackGuard is designed with strict **privacy-by-design** principles:

- **No Packet Payload Inspection:** Network analysis is restricted to standard endpoint connection metadata (local port, remote IP/domain, remote port, socket state) collected via non-intrusive operating system APIs (`psutil`). Network payloads, TLS streams, and unencrypted packet bodies are never captured or examined.
- **No Browser Profile or Content Snooping:** Detection of in-browser cryptojacking relies entirely on OS-level process compute telemetry (sustained renderer CPU load, process parentage, and outbound Stratum pool sockets). The agent **never** accesses browser profiles, cached files, cookies, search histories, form inputs, or page content.
- **Local Telemetry Storage:** All logs (`logs/alerts.jsonl`, `logs/system_metrics.csv`, `logs/response_audit.jsonl`) are stored locally on the user's workstation. No telemetry is transmitted to third-party cloud servers.

---

## ⚠️ Safe Usage Guidelines

- **Authorized Environments:** Only run this prototype on systems you own or have explicit authorization to monitor.
- **Non-Production Testing:** While designed to be lightweight, CryptoJackGuard is an academic research prototype and is not certified as an enterprise-grade commercial Antivirus/EDR replacement.

---

## 📬 Reporting Security Issues & Vulnerabilities

If you discover a security vulnerability, unintended privilege escalation, or edge case in CryptoJackGuard, please practice responsible disclosure:

1. Do not open public GitHub issues for critical security vulnerabilities.
2. Reach out via email to the project maintainers with a detailed description, reproduction steps, and proof-of-concept.
3. Allow reasonable time for remediation before publishing any findings.
