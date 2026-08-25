# CryptoJackGuard: Thesis Evaluation & Controlled Scenario Report

**Generated on:** 2026-08-25 05:57:18 UTC  
**Evaluation Summary:** 10 / 10 Scenarios Passed (100.0% Accuracy)  

## Executive Summary

This evaluation report validates the detection fidelity, heuristic scoring, machine learning inference, and false-positive suppression capabilities of the **CryptoJackGuard** defense prototype across 10 controlled workload scenarios.

## Scenario Results Matrix

| # | Scenario | Process Name | CPU % | ML Confidence | Final Risk Score | Expected | Actual Status |
|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|
| 1 | Normal Windows workload | `explorer.exe` | 2.0% | 0.0% | 0.0 | BENIGN | **PASS** |
| 2 | High CPU legitimate workload | `video_render.exe` | 85.0% | 0.0% | 25.0 | BENIGN/LOW | **PASS** |
| 3 | Simulated CPU miner | `xmrig.exe` | 95.0% | 99.2% | 100.0 | HIGH | **PASS** |
| 4 | Miner-like CLI + high CPU | `unknown.exe` | 80.0% | 0.0% | 100.0 | HIGH | **PASS** |
| 5 | Miner + mining network IOC | `miner.exe` | 90.0% | 0.2% | 100.0 | VERY HIGH | **PASS** |
| 6 | Masqueraded process | `svchost.exe` | 75.0% | 0.0% | 60.0 | HIGH | **PASS** |
| 7 | Persistence + miner evidence | `updater.exe` | 80.0% | 0.0% | 100.0 | HIGH | **PASS** |
| 8 | Browser sustained CPU + mining IOC | `chrome.exe` | 60.0% | 0.0% | 60.0 | HIGH | **PASS** |
| 9 | False-positive Java server | `java.exe` | 90.0% | 1.0% | 10.0 | BENIGN | **PASS** |
| 10 | Normal Chrome high CPU | `chrome.exe` | 85.0% | 0.2% | 0.2 | BENIGN/LOW | **PASS** |

## Detailed Scenario Findings

### Scenario 1: Normal Windows workload [PASS]
- **Target Process:** `explorer.exe` (CPU: 2.0%)
- **Expected Classification:** `BENIGN`
- **Final Computed Risk Score:** `0.0/100.0` (ML Confidence: `0.0%`)
- **Outcome:** BENIGN (Low Risk)
- **Triggered Evidence / Reasons:**
  - None (Normal baseline execution)
- **Scenario Context & Notes:** Legitimate Windows shell process running from System directory.

### Scenario 2: High CPU legitimate workload [PASS]
- **Target Process:** `video_render.exe` (CPU: 85.0%)
- **Expected Classification:** `BENIGN/LOW`
- **Final Computed Risk Score:** `25.0/100.0` (ML Confidence: `0.0%`)
- **Outcome:** BENIGN (Low Risk)
- **Triggered Evidence / Reasons:**
  - high CPU usage (85.0%)
- **Scenario Context & Notes:** Legitimate high CPU usage alone should not trigger false cryptojacking alerts.

### Scenario 3: Simulated CPU miner [PASS]
- **Target Process:** `xmrig.exe` (CPU: 95.0%)
- **Expected Classification:** `HIGH`
- **Final Computed Risk Score:** `100.0/100.0` (ML Confidence: `99.2%`)
- **Outcome:** HIGH RISK
- **Triggered Evidence / Reasons:**
  - high CPU usage (95.0%)
  - known miner executable name
  - mining indicator found in process path or command line
  - suspicious binary path
  - suspicious user-writable execution location
  - 2 miner-like CLI indicators: ['stratum+tcp', 'xmrig']
  - additional weak CLI indicators: ['--pass', '--url', '--user']
  - combined: miner-like args + CPU 95.0%
  - suspicious remote mining port(s): [3333]
  - combined: mining network connection + CPU 95.0%
  - suspicious execution location combined with miner indicators
  - ML Detection: High Confidence (99.2%)
- **Scenario Context & Notes:** Known miner binary name + CLI stratum indicators + Stratum port 3333 + 95% CPU.

### Scenario 4: Miner-like CLI + high CPU [PASS]
- **Target Process:** `unknown.exe` (CPU: 80.0%)
- **Expected Classification:** `HIGH`
- **Final Computed Risk Score:** `100.0/100.0` (ML Confidence: `0.0%`)
- **Outcome:** HIGH RISK
- **Triggered Evidence / Reasons:**
  - high CPU usage (80.0%)
  - suspicious user-writable execution location
  - 3 miner-like CLI indicators: ['--algo', '--coin', 'randomx']
  - combined: miner-like args + CPU 80.0%
  - suspicious execution location combined with miner indicators
- **Scenario Context & Notes:** Suspicious writable path + RandomX mining algorithms + multiple mining CLI flags.

### Scenario 5: Miner + mining network IOC [PASS]
- **Target Process:** `miner.exe` (CPU: 90.0%)
- **Expected Classification:** `VERY HIGH`
- **Final Computed Risk Score:** `100.0/100.0` (ML Confidence: `0.2%`)
- **Outcome:** VERY HIGH RISK
- **Triggered Evidence / Reasons:**
  - high CPU usage (90.0%)
  - suspicious binary path
  - 2 miner-like CLI indicators: ['--pool', 'stratum+tcp']
  - combined: miner-like args + CPU 90.0%
  - suspicious remote mining port(s): [3333]
  - combined: mining network connection + CPU 90.0%
- **Scenario Context & Notes:** Correlated multi-vector evidence: mining name + CLI + Stratum protocol port 3333.

### Scenario 6: Masqueraded process [PASS]
- **Target Process:** `svchost.exe` (CPU: 75.0%)
- **Expected Classification:** `HIGH`
- **Final Computed Risk Score:** `60.0/100.0` (ML Confidence: `0.0%`)
- **Outcome:** HIGH RISK
- **Triggered Evidence / Reasons:**
  - high CPU usage (75.0%)
  - suspicious user-writable execution location
  - system-looking process running outside expected System32 path
  - safe process name; no reduction due to strong mining evidence
- **Scenario Context & Notes:** Masquerading system process path anomaly combined with suspicious high CPU consumption.

### Scenario 7: Persistence + miner evidence [PASS]
- **Target Process:** `updater.exe` (CPU: 80.0%)
- **Expected Classification:** `HIGH`
- **Final Computed Risk Score:** `100.0/100.0` (ML Confidence: `0.0%`)
- **Outcome:** HIGH RISK
- **Triggered Evidence / Reasons:**
  - high CPU usage (80.0%)
  - suspicious user-writable execution location
  - 3 miner-like CLI indicators: ['--algo', '--pool', 'randomx']
  - combined: miner-like args + CPU 80.0%
  - suspicious execution location combined with miner indicators
  - persistence finding: user startup registry key detected
- **Scenario Context & Notes:** Combines RandomX mining args with simulated registry run key persistence finding.

### Scenario 8: Browser sustained CPU + mining IOC [PASS]
- **Target Process:** `chrome.exe` (CPU: 60.0%)
- **Expected Classification:** `HIGH`
- **Final Computed Risk Score:** `60.0/100.0` (ML Confidence: `0.0%`)
- **Outcome:** HIGH RISK
- **Triggered Evidence / Reasons:**
  - high CPU usage (60.0%)
  - suspicious remote mining port(s): [3333]
  - combined: mining network connection + CPU 60.0%
  - safe process name and allowlisted process; no reduction due to strong mining evidence
- **Scenario Context & Notes:** Browser process exhibiting sustained compute paired with outbound Stratum pool connection.

### Scenario 9: False-positive Java server [PASS]
- **Target Process:** `java.exe` (CPU: 90.0%)
- **Expected Classification:** `BENIGN`
- **Final Computed Risk Score:** `10.0/100.0` (ML Confidence: `1.0%`)
- **Outcome:** BENIGN (Low Risk)
- **Triggered Evidence / Reasons:**
  - high CPU usage (90.0%)
  - high memory usage (25.0%)
  - safe process name and allowlisted process; normal behavior de-emphasized
- **Scenario Context & Notes:** High CPU and high memory server workloads without mining IOCs should remain benign.

### Scenario 10: Normal Chrome high CPU [PASS]
- **Target Process:** `chrome.exe` (CPU: 85.0%)
- **Expected Classification:** `BENIGN/LOW`
- **Final Computed Risk Score:** `0.2/100.0` (ML Confidence: `0.2%`)
- **Outcome:** BENIGN (Low Risk)
- **Triggered Evidence / Reasons:**
  - high CPU usage (85.0%)
  - safe process name and allowlisted process; normal behavior de-emphasized
- **Scenario Context & Notes:** Legitimate browser multimedia decoding de-emphasized via allowlist heuristics.

## Evaluation Methodology & Thresholds

- **Benign / Legitimate Threshold:** Risk Score < 40.0 (No alert generated, system monitoring continues passively).
- **Elevated Suspicion Threshold:** 40.0 <= Risk Score < 60.0 (Telemetry logged, deep inspection initiated).
- **Alert / Mitigation Threshold:** Risk Score >= 60.0 (High-risk confirmation, automated cooldown management, and safe response prompted).
- **Critical Alert Threshold:** Risk Score >= 80.0 (Multi-vector confirmation combining ML inference, Stratum network telemetry, and CPU load).

---
*Report generated automatically by CryptoJackGuard Thesis Evaluation Framework.*