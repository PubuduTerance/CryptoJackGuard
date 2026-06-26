# CryptoJackGuard

CryptoJackGuard is a defensive research prototype for detecting cryptojacking and suspicious miner-like activity on Windows systems.

## Research background

Cryptojacking is the unauthorized use of a victim's CPU/GPU resources to mine cryptocurrency. This project was designed as a lightweight endpoint monitoring system for a final-year thesis, focusing on benign detection and privacy-preserving evaluation rather than active remediation.

The goal is to identify suspicious processes by combining system telemetry, process metadata, network indicators, and threat intelligence, while minimizing false positives and avoiding intrusive behavior.

## Features

- Real-time process risk dashboard with CPU and memory usage
- Alerting for sustained suspicious process behavior
- OSINT-based miner indicator matching from `data/mining_iocs.txt`
- Optional GPU monitoring using `GPUtil` when available
- Evaluation logging to `logs/system_metrics.csv` and `logs/alerts.jsonl`
- Privacy-friendly operation: no browser history or packet payload logging

## Architecture

- `main.py` — primary dashboard loop and scan orchestration
- `src/collectors/resource_collector.py` — CPU, memory, and optional GPU usage collection
- `src/collectors/process_collector.py` — process enumeration and metadata
- `src/collectors/network_collector.py` — process network connection collection
- `src/intelligence/osint_loader.py` — loads mining-related indicators
- `src/detection/scoring.py` — combines signals into process risk scores
- `src/response/actions.py` — safe response helpers
- `src/storage/alert_logger.py` — alert logging and evaluation metrics logging
- `data/mining_iocs.txt` — mining indicator list
- `logs/alerts.jsonl` — alert history log
- `logs/system_metrics.csv` — scan evaluation metrics log

## Installation

1. Clone or copy the repository to your workstation.
2. Create and activate a Python environment.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Install dependencies.

```powershell
pip install -r requirements.txt
```

> Note: `GPUtil` is optional. If it is not installed or a GPU is not present, CryptoJackGuard continues normally and reports `GPU: N/A`.

## How to run

Start the dashboard:

```powershell
python main.py
```

The dashboard refreshes every few seconds, showing process risk scores, overall CPU/memory usage, and loaded indicator count.

Use `Ctrl+C` to stop the program safely.

## How to test safely

This project includes two benign test scripts for evaluation:

- `tests/cpu_stress_test.py` — generates safe CPU load only
- `tests/simulated_miner_args.py` — simulates a miner-like command line and CPU-bound workload without real mining or networking

Run them in a controlled environment and observe how CryptoJackGuard responds.

```powershell
python tests/cpu_stress_test.py
python tests/simulated_miner_args.py --algo randomx --pool stratum+tcp://example.com:3333 --user test
```

### Safe testing guidance

- Use these scripts only for defensive evaluation.
- Do not modify them to perform actual mining or network activity.
- Avoid running them on production systems.
- The scripts are designed to stop automatically after 60 seconds.

## Explanation of `cpu_stress_test.py`

`tests/cpu_stress_test.py` is a harmless CPU stress test script. It performs deterministic math operations for 60 seconds and prints progress every 10 seconds.

This script is useful for generating benign system load so the detection system can be validated against high CPU utilization without any network or persistence behavior.

## Explanation of `simulated_miner_args.py`

`tests/simulated_miner_args.py` is a harmless miner-like simulation script.

- It accepts common miner-style command-line arguments such as `--algo`, `--pool`, `--user`, and `--threads`.
- It uses `parse_known_args()` so unknown flags do not crash the script.
- It performs CPU-bound workload for 60 seconds and prints the parsed arguments.
- It does not connect to the network, does not mine cryptocurrency, and does not hide itself.

This script is intended to simulate the appearance of a miner process for detection evaluation.

## Evaluation logging

CryptoJackGuard writes scan evaluation data to `logs/system_metrics.csv` and alert events to `logs/alerts.jsonl`.

The CSV contains the exact header:

```csv
timestamp,cpu_percent,memory_percent,gpu_percent,gpu_memory_percent,processes_scanned,alerts,scan_duration_ms
```

Each scan records:

- `timestamp` — UTC timestamp for the scan event
- `cpu_percent` — overall system CPU usage
- `memory_percent` — system memory usage
- `gpu_percent` — GPU load if available, otherwise `N/A`
- `gpu_memory_percent` — GPU memory usage if available, otherwise `N/A`
- `processes_scanned` — number of processes evaluated
- `alerts` — number of currently suspicious alerts
- `scan_duration_ms` — scan time in milliseconds

The `logs/alerts.jsonl` file stores one JSON alert record per line with a UTC timestamp and process details.

## GPU monitoring

GPU monitoring is optional and uses `GPUtil` only if it is installed and a GPU is detected.

- If `GPUtil` is not installed or no GPU is found, CryptoJackGuard continues normally.
- If GPU detection fails, the dashboard shows `GPU: N/A` and logging writes `N/A` or empty GPU values.
- The feature is lightweight and does not change core CPU, memory, process, or network scanning logic.

## Limitations

- This prototype is not a production-ready anti-malware product.
- Detection is heuristic and may produce false positives or false negatives.
- It currently targets Windows-like process data and may have limited cross-platform coverage.
- It does not perform active remediation or automated process termination.
- It does not inspect browser history or packet payload contents.
- GPU statistics depend on `GPUtil` and available GPU drivers.

## Ethical use statement

CryptoJackGuard is intended for defensive research and testing only.

- Do not use this project to attack or compromise other systems.
- Do not deploy it as a malware component.
- Use it only for learning, thesis evaluation, and authorized security testing.

## Thesis demo instructions

1. Start CryptoJackGuard:

```powershell
python main.py
```

2. Observe the dashboard refresh and note CPU/memory usage.

3. Generate benign load with the safe stress test:

```powershell
python tests/cpu_stress_test.py
```

4. Simulate a miner-like process:

```powershell
python tests/simulated_miner_args.py --algo randomx --pool stratum+tcp://example.com:3333 --user defender
```

5. Open `logs/system_metrics.csv` to review evaluation metrics, and `logs/alerts.jsonl` for any alert records.

6. Explain that GPU metrics are optional and appear only when `GPUtil` and a GPU are available; otherwise the dashboard shows `N/A`.

7. Emphasize the privacy-first design: no browsing or packet payload logging, only system and process telemetry used for detection.
