# CryptoJackGuard User Guide 📖

This guide explains how to operate, configure, and interpret results from **CryptoJackGuard**.

---

## 🖥️ Running the Application

CryptoJackGuard provides two distinct operational interfaces:

### Option 1: Terminal CLI Dashboard
The CLI dashboard is a terminal UI built with `rich`. It displays live CPU/memory telemetry, loaded IOC indicators, and a prioritized table of processes sorted by computed risk score.

```powershell
python main.py
```

- **Scan Interval:** Refreshes every 3 seconds (configurable in `config.json`).
- **Interactive Prompt:** If a non-whitelisted process reaches High Risk (score ≥ 60), the CLI displays an interactive prompt asking for user confirmation before terminating the process.
- **Exit:** Press `Ctrl+C` to terminate cleanly.

---

### Option 2: Enterprise Web Dashboard
The Streamlit Web Dashboard provides an interactive graphical interface with real-time graphs, detailed process breakdowns, forensic logs, and process management.

```powershell
streamlit run dashboard_app.py
```

The browser will open at `http://localhost:8501`.

#### Web Dashboard Features:
1. **System Health Metrics:** Real-time host CPU, memory, active process count, and threat indicators.
2. **Suspicious Activity Feed:** Automatically highlights processes that exceed risk thresholds.
3. **ML Engine Deep Dive:** Displays the extracted 5-feature vector, Machine Learning classification confidence, and explainability reasons.
4. **Interactive Action Center:** Enables one-click process termination with protected system process safety checks.

---

## 🧠 Understanding Scoring & Machine Learning Confidence

CryptoJackGuard uses a **Hybrid Risk Fusion** model that combines heuristic signals with a Random Forest Machine Learning model:

### 1. Heuristic Risk Score (0–100)
Calculated from multiple weighted telemetry layers:
- **CPU & Memory Load:** Sustained high utilization without legitimate reason (+25 pts).
- **Execution Path Anomaly:** Execution from user-writable directories like `Temp` or `AppData` (+10 pts).
- **Process Masquerading:** Binary named `svchost.exe` or `explorer.exe` running outside `System32` (+25 pts).
- **OSINT & CLI Indicators:** Known miner keywords (`stratum`, `randomx`, `xmrig`, `--algo`, `--pool`) (+10 to +45 pts).
- **Network Sockets:** Outbound connections to common mining ports (`3333`, `4444`, `7777`) or threat intel IP/domain matches (+25 pts).
- **Persistence:** Startup registry run keys or scheduled tasks (+15 pts).

### 2. Machine Learning Confidence (`ML Confidence`)
The pre-trained Random Forest model evaluates a 5-dimensional runtime feature vector:
1. `cpu_percent`
2. `memory_percent`
3. `cmdline_length`
4. `network_connections_count`
5. `suspicious_keyword_count`

It outputs a probability value from `0.0%` to `100.0%`.

### 3. Hybrid Risk Fusion
To avoid double-counting while maintaining sensitivity:
$$\text{Final Risk Score} = \max(\text{Heuristic Score}, \text{ML Confidence} \times 100)$$

If the ML confidence is $\ge 70\%$, an explainability reason (`ML Detection: High Confidence`) is attached to the audit record.

---

## 🛡️ Response Tiers & Cooldown Management

CryptoJackGuard enforces a **human-in-the-loop, tiered mitigation strategy** to prevent disruptive false positives:

| Risk Tier | Risk Score Range | Action Taken |
|:---|:---:|:---|
| **🟢 Low Risk (Safe)** | `0.0 – 39.9` | Passive continuous monitoring. No action or user interruption. |
| **🟡 Medium Risk (Suspicious)** | `40.0 – 59.9` | Forensic audit logging to `logs/alerts.jsonl`. Elevated telemetry collection. |
| **🔴 High Risk (Critical)** | `60.0 – 100.0` | User confirmation requested for process termination. Protected system processes are shielded. |

### Cooldown Suppression Mechanism
To prevent alert fatigue and CPU consumption during ongoing mining activity:
- The `ResponseManager` enforces a **120-second cooldown** per process ID (PID).
- Once prompted or logged, subsequent alerts for the same PID are suppressed until the cooldown expires, unless the risk state significantly escalates.

---

## ⚙️ Configuration Options (`config.json`)

You can customize detection sensitivity by modifying `config.json`:

```json
{
  "high_cpu_threshold": 30.0,
  "high_memory_threshold": 20.0,
  "alert_threshold": 60.0,
  "refresh_interval": 3.0,
  "deep_inspection_threshold": 40.0,
  "persistence_cache_seconds": 300.0,
  "suspicious_ports": [3333, 4444, 7777],
  "safe_process_names": [
    "system", "explorer.exe", "chrome.exe", "msedge.exe", "code.exe", "java.exe"
  ]
}
```

---

## 📁 Audit & Telemetry Logs

- **`logs/alerts.jsonl`**: Machine-readable JSON Lines log recording every detected high/medium-risk event with full process telemetry and detection reasons.
- **`logs/response_audit.jsonl`**: Audit log recording user response decisions (e.g., terminated, ignored, whitelisted).
- **`logs/system_metrics.csv`**: Time-series log of overall system resource consumption and scan cycle performance.
