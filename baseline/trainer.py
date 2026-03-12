import json
import time
import os
from collections import defaultdict
import config

class BaselineTrainer:
    def __init__(self):
        self.start_time = time.time()
        self.packet_count = 0
        self.protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        
        self.src_ips = defaultdict(int) 
        self.window_start = time.time()
        
        self.window_packet_counts = []
        self.window_unique_ports = []
        self.current_window_ports = set()
        self.current_window_packets = 0

    def process_packet(self, packet):
        self.packet_count += 1
        self.current_window_packets += 1
        
        if packet.haslayer('IP'):
            src = packet['IP'].src
            self.src_ips[src] += 1
            
        if packet.haslayer('TCP'):
            self.protocols['TCP'] += 1
            if hasattr(packet['TCP'], 'dport'):
                self.current_window_ports.add(packet['TCP'].dport)
        elif packet.haslayer('UDP'):
            self.protocols['UDP'] += 1
            if hasattr(packet['UDP'], 'dport'):
                self.current_window_ports.add(packet['UDP'].dport)
        elif packet.haslayer('ICMP'):
            self.protocols['ICMP'] += 1
        else:
            self.protocols['Other'] += 1
            
        current_time = time.time()
        
        # Track window metrics for averages
        if current_time - self.window_start >= config.TIME_WINDOW:
            self.window_packet_counts.append(self.current_window_packets)
            self.window_unique_ports.append(len(self.current_window_ports))
            self.current_window_packets = 0
            self.current_window_ports.clear()
            self.window_start = current_time

    def is_training_complete(self):
        return (time.time() - self.start_time) >= config.BASELINE_DURATION
        
    def save_baseline(self):
        # Capture the last partial window if it has data
        if self.current_window_packets > 0:
            self.window_packet_counts.append(self.current_window_packets)
            self.window_unique_ports.append(len(self.current_window_ports))
            
        duration = time.time() - self.start_time
        avg_pps = self.packet_count / duration if duration > 0 else 0
        
        avg_unique_ports = (sum(self.window_unique_ports) / len(self.window_unique_ports)) if self.window_unique_ports else 0
        
        avg_conns_per_ip = (self.packet_count / len(self.src_ips)) if self.src_ips else 0
        
        total = sum(self.protocols.values())
        protocol_dist = {}
        for proto, count in self.protocols.items():
            protocol_dist[proto] = (count / total * 100) if total > 0 else 0
            
        baseline_data = {
            "duration_seconds": duration,
            "total_packets": self.packet_count,
            "avg_packets_per_sec": avg_pps,
            "avg_unique_ports_per_window": avg_unique_ports,
            "avg_connections_per_ip": avg_conns_per_ip,
            "protocol_distribution_percentage": protocol_dist,
            "history_packet_counts": self.window_packet_counts,
            "history_unique_ports": self.window_unique_ports
        }
        
        baseline_dir = "/home/cybersec/pro/X-NIDS/baseline"
        os.makedirs(baseline_dir, exist_ok=True)
        filepath = os.path.join(baseline_dir, "baseline.json")
        with open(filepath, "w") as f:
            json.dump(baseline_data, f, indent=4)
            
        print("\n" + "="*60)
        print("[+] Baseline Training Complete!")
        print(f"    Saved to: {filepath}")
        print(f"    Average PPS: {avg_pps:.2f}")
        print(f"    Avg Unique Ports/Window: {avg_unique_ports:.2f}")
        print(f"    Avg Conns/IP: {avg_conns_per_ip:.2f}")
        print(f"    Protocol Dist: {protocol_dist}")
        print("="*60)
