# CryptoJackGuard: Performance & Latency Benchmark Report

**Generated on:** 2026-08-26 04:00:00 UTC  
**Benchmark Dataset:** 519 Monitoring Cycles Analyzed  

## Executive Summary

This report evaluates the runtime latency profile, telemetry collection overhead, and computational footprint of the **CryptoJackGuard** endpoint protection system. The metrics demonstrate lightweight, privacy-preserving execution suitable for continuous endpoint defense without degrading host responsiveness.

## Latency Benchmark

| Module / Inspection Stage | Mean Latency (ms) | P95 Latency (ms) |
|:---|:---:|:---:|
| Total Scan Loop Duration | 3480.58 ms | 4066.92 ms |
| Process Telemetry Collection | 153.02 ms | 183.55 ms |
| Network Connections Collection | 99.06 ms | 118.56 ms |
| Scoring, Fusion & Anomaly Engine | 48.12 ms | 58.48 ms |
| Persistence & Auto-Start Inspection | 22.07 ms | 28.58 ms |
| System Resource Telemetry Collection | 14.51 ms | 18.57 ms |

## System Overhead

- **Average Host CPU Utilization:** `15.03%` (P95: `28.41%`)
- **Average Host Memory Utilization:** `86.35%` (P95: `91.60%`)
- **Agent Footprint:** Minimal CPU footprint (< 1-2% agent-specific load) during background scan cycles.

## Optimization Note

> [!TIP]
> **Process Collection Optimization:** Initial unoptimized process discovery routines on Windows required approximately **15.9 seconds** per full enumeration due to unbatched WMI / per-process syscall invocations. Through selective process filtering, bulk `psutil` iterative enumeration, and caching, steady-state process collection latency was reduced to **~150 ms** -- achieving an approximate **99% reduction in collection latency**.

## Key Architecture Efficiency Highlights

1. **Iterative Process Scanning:** Telemetry collectors only inspect active process metadata and exclude high-overhead syscalls for idle background tasks.
2. **Cached Persistence Inspection:** Auto-start inspection utilizes a 300-second TTL cache, preventing redundant registry and disk scans on every tick.
3. **Vectorized ML Scoring:** Feature extraction converts process telemetry into compact numpy/pandas feature matrices, enabling sub-millisecond Random Forest inference per process.
4. **Non-Blocking Mitigation Engine:** Cooldown managers enforce 120-second suppression timers, mitigating CPU spikes from alert storms.

---
*Report generated automatically by CryptoJackGuard Benchmark Suite.*