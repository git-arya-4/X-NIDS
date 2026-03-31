# ==============================================================================
# main.py — Entry Point for X-NIDS
# ==============================================================================

import config
import sys
import os
import argparse
import threading
from capture import packet_sniffer 
from dashboard.app import run_dashboard

def main():
    parser = argparse.ArgumentParser(description="X-NIDS - Intelligent Intrusion Detection System")
    parser.add_argument('--train', action='store_true', help='Run in Baseline Training Mode')
    args, _ = parser.parse_known_args()

    # 1. Print the Banner
    print("=" * 60)
    print("  X-NIDS — Intelligent Intrusion Detection System")
    print("=" * 60)
    
    # 2. Check for Root/Sudo Privileges (Required for Sniffing)
    if os.geteuid() != 0:
        print("\n[!] CRITICAL ERROR: Root privileges required.")
        print("    Please run with: sudo python3 main.py")
        sys.exit(1)

    # 3. Load Configuration
    print(f"  [>] Interface        : {config.INTERFACE}")
    print(f"  [>] Time Window      : {config.TIME_WINDOW}s")
    print(f"  [>] Baseline Period  : {config.BASELINE_DURATION}s")
    print("=" * 60)
    print("\n[*] Initializing modules...")

    # 4. Start Dashboard Thread Safely alongside Capture
    if not args.train:
        ui_thread = threading.Thread(target=run_dashboard, daemon=True)
        ui_thread.start()

    # 5. Start the Sniffer
    try:
        packet_sniffer.start_sniffer(train_mode=args.train)
    except KeyboardInterrupt:
        print("\n\n[!] User interrupted. Stopping X-NIDS...")
        if args.train and packet_sniffer.trainer:
            print("[*] Attempting to save baseline before exiting...")
            packet_sniffer.trainer.save_baseline()
        sys.exit(0)

if __name__ == "__main__":
    main()