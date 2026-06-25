"""
Harmless simulated miner-like process for defensive testing.

WARNING: This script is for thesis / defensive testing only. It does NOT
perform any mining or networking. It does NOT create persistence or hide
itself. Use it only to simulate command-line arguments and CPU-bound
work that might resemble a miner process so detection logic can be
validated against benign workloads.

Behaviors:
- Parses common miner-like command-line arguments but does not act on them.
- Runs a CPU-bound workload for 60 seconds.
- Prints that it is a harmless simulation and echoes the provided args.

Do NOT modify this script to perform real mining or network activity.
"""

import argparse
import time
import math
import sys

# Total runtime for the simulation in seconds
DURATION = 60
# How often to report progress (seconds)
REPORT_INTERVAL = 10


def busy_work(deadline: float) -> float:
    """Perform CPU-bound math until `deadline`.

    Returns an accumulator to prevent trivial loop optimization.
    """
    acc = 0.0
    while time.time() < deadline:
        for i in range(1_000):
            acc += math.sqrt(i + 1) * math.cos(i)
    return acc


def parse_args():
    """Parse known miner-like arguments and allow unknowns.

    Uses `parse_known_args()` so that additional arbitrary arguments
    commonly found in miner command-lines do not cause the script to
    exit with an error. Returns a tuple `(args, unknown)` where `unknown`
    is a list of remaining CLI tokens.
    """
    parser = argparse.ArgumentParser(
        description="Harmless simulated miner-like process for defensive testing",
        add_help=True,
    )

    # Miner-like arguments (accepted but deliberately not acted upon)
    parser.add_argument("--algo", help="(simulated) algorithm name", default="")
    parser.add_argument("--coin", help="(simulated) coin name", default="")
    parser.add_argument("--url", help="(simulated) mining pool URL", default="")
    parser.add_argument("--pool", help="(simulated) pool address", default="")
    parser.add_argument("--user", help="(simulated) worker user", default="")
    parser.add_argument("--pass", dest="password", help="(simulated) password", default="")
    parser.add_argument("--threads", type=int, help="(simulated) threads", default=1)
    parser.add_argument("--donate-level", type=int, help="(simulated) donate percent", default=0)
    parser.add_argument("--config", help="(simulated) config file path", default="")
    parser.add_argument("--help-detect", action="store_true", help="print detection hint and exit")

    # Use parse_known_args so unknown flags don't crash the script
    args, unknown = parser.parse_known_args()
    return args, unknown


def main() -> None:
    args, unknown = parse_args()

    # Clearly state that this is a harmless simulation.
    print("Harmless simulation: this process does NOT mine or connect to the internet.")
    print("Echoing parsed arguments:")
    # Print each parsed (known) argument to make detection via CLI parsing easier.
    for k, v in vars(args).items():
        print(f"  {k}: {v}")

    # Print unknown / extra CLI tokens so detectors can inspect them too.
    if unknown:
        print("Unknown / extra CLI tokens:")
        for token in unknown:
            print(f"  {token}")

    if getattr(args, "help_detect", False):
        print("Detection hint: miner-like arguments were supplied.")

    start = time.time()
    end_time = start + DURATION
    next_report = start + REPORT_INTERVAL

    # Perform CPU work until the time limit is reached; no networking.
    try:
        while time.time() < end_time:
            busy_work(min(end_time, time.time() + 1))
            now = time.time()
            if now >= next_report:
                elapsed = int(now - start)
                print(f"Elapsed: {elapsed} seconds (harmless simulation)")
                next_report += REPORT_INTERVAL

        print(f"Simulation complete: ran for {DURATION} seconds. Exiting.")
    except KeyboardInterrupt:
        print("Simulation interrupted by user; exiting early.")
        sys.exit(1)


if __name__ == "__main__":
    main()
