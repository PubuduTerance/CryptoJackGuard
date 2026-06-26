# CryptoJackGuard Results Notes

## Summary of completed tests

- Executed the benign CPU stress test for 60 seconds.
- Ran the simulated miner argument script with representative miner-style CLI arguments.
- Verified safe response mode with user confirmation and protected process checks.

## Benign CPU stress test result

The CPU stress test completed successfully without triggering unsafe responses. It produced benign system load and confirmed that the detection engine can operate under higher CPU usage without false positive escalation.

## Simulated miner argument test result

The simulated miner argument test was run with realistic miner-like arguments such as `--algo randomx`, `--url stratum+tcp://127.0.0.1:3333`, and `--user test`. The tool detected miner-like indicators in the process command line while keeping the evaluation defensive and transparent.

## Safe response mode result

Safe response mode was tested successfully. When a high-risk process was detected, the tool displayed PID, process name, executable path, score, and reasons, then asked for explicit user confirmation before terminating. Protected system-critical processes were never terminated.

## Evaluation summary output

- Total scan cycles: 105
- Average CPU percent: 5.09%
- Average memory percent: 80.29%
- Average scan duration: 2235.2 ms
- Maximum scan duration: 2745.0 ms
- Total alerts: 3

## Notes about GPU showing N/A safely

GPU monitoring is optional. When `GPUtil` is not installed or no GPU is detected, the dashboard reports `GPU: N/A` and the evaluation logging records safe empty/N/A GPU fields. This ensures the tool continues normally without GPU hardware.

## False-positive control

The detection logic is designed to remain defensive by combining process behavior, command-line indicators, known miner indicators, and network metadata. It avoids automatic process killing and protects common system and user-facing processes to reduce false positives.

## Defensive tool statement

CryptoJackGuard is explicitly defensive and research-focused. It does not mine cryptocurrency, does not perform network-based mining, and does not introduce malware behavior. It is intended only for benign evaluation and thesis research.
