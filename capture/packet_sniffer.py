# ==============================================================================
# capture/packet_sniffer.py - Network Traffic Capture Module
# ==============================================================================

import scapy.all as scapy
import config
import sys
# IMPORT THE NEW EXTRACTOR
from features.feature_extractor import extractor
from baseline.trainer import BaselineTrainer

trainer = None

def process_packet(packet):
    """
    Callback function that runs for EVERY single packet captured.
    """
    global trainer
    if trainer is not None:
        trainer.process_packet(packet)
        if trainer.is_training_complete():
            trainer.save_baseline()
            print("[*] Exiting training mode. Run normally to begin detection.")
            sys.exit(0)
    else:
        # Instead of printing raw packets, we send them to the extractor
        extractor.process_packet(packet)

def start_sniffer(train_mode=False):
    global trainer
    
    if train_mode:
        print(f"[*] Starting in TRAINING MODE...")
        print(f"[*] Gathering baseline data for {config.BASELINE_DURATION} seconds...")
        trainer = BaselineTrainer()
    else:
        print(f"[*] Sniffer started on interface: {config.INTERFACE}")
        print("[*] Collecting packets for Feature Extraction...")
        print(f"[*] Analyzing in {config.TIME_WINDOW} second windows...")
        
    print("[*] Press Ctrl+C to stop...")
    
    try:
        bpf_filter = getattr(config, "BPF_FILTER", "")
        if bpf_filter:
            print(f"[*] Applying BPF Filter: {bpf_filter}")
            scapy.sniff(iface=config.INTERFACE, store=0, prn=process_packet, filter=bpf_filter)
        else:
            scapy.sniff(iface=config.INTERFACE, store=0, prn=process_packet)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)