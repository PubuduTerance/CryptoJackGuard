"""
Benign CPU stress test (defensive testing only).

This script performs a deterministic, CPU-bound workload for 60 seconds
and prints progress every 10 seconds. It is intentionally simple and
transparent:
- No networking
- No persistence or hiding
- Stops automatically after 60 seconds

Use this script only to generate benign CPU activity for testing
false positives in monitoring/detection systems.
"""

import time
import math
import sys

# Duration of the stress test in seconds
DURATION = 60
# How often to print progress (seconds)
REPORT_INTERVAL = 10


def busy_work(deadline: float) -> float:
    """Run CPU-bound math operations until `deadline`.

    Returns a numeric accumulator so the interpreter cannot optimize
    the loop away.
    """
    acc = 0.0
    while time.time() < deadline:
        # Do a small batch of math ops to keep the CPU busy but allow
        # periodic checks of the time.
        for i in range(1_000):
            acc += math.sqrt(i) * math.sin(i)
    return acc


def main() -> None:
    start = time.time()
    end_time = start + DURATION
    next_report = start + REPORT_INTERVAL

    print(f"Starting benign CPU stress test for {DURATION} seconds.")
    try:
        # Continue doing work until the overall end time is reached.
        # We break work into short windows so we can print progress
        # at the requested interval.
        while time.time() < end_time:
            # Run busy work for up to one second at a time.
            busy_work(min(end_time, time.time() + 1))

            now = time.time()
            if now >= next_report:
                elapsed = int(now - start)
                print(f"Elapsed: {elapsed} seconds")
                next_report += REPORT_INTERVAL

        print(f"Completed: {DURATION} seconds elapsed. Exiting.")
    except KeyboardInterrupt:
        # Allow the user to stop the test with Ctrl+C.
        print("Interrupted by user; exiting early.")
        sys.exit(1)


if __name__ == "__main__":
    main()
