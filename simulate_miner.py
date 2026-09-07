import time
import os
import sys

def simulate_cryptominer():
    print(f"[*] Starting CryptoJackGuard Threat Simulation (PID: {os.getpid()})...")
    print("[*] Simulating high CPU usage for live detection demo...")
    
    counter = 0
    try:
        while True:
            # Heavy mathematical loop to spike CPU utilization
            _ = [i ** 2 for i in range(50000)]
            counter += 1
            if counter % 200 == 0:
                print(f"[!] Simulated mining workload active. Iteration: {counter}")
    except KeyboardInterrupt:
        print("\n[-] Simulation stopped.")

if __name__ == "__main__":
    simulate_cryptominer()