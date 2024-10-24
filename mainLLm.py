from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
import time
import json
from datetime import datetime
import requests
import re

class SimpleNetworkMonitor:
    def __init__(self):
        self.flows = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        
        
    def packet_callback(self, packet):
        if IP in packet:
            flow_key = f"{packet[IP].src}->{packet[IP].dst}"
            
            # Update flow statistics
            self.flows[flow_key]['packets'] += 1
            self.flows[flow_key]['bytes'] += len(packet)
            
          
            self.analyze_payload(packet, flow_key)
            
    
    def analyze_payload(self, packet, flow_key):
        """Analyze packet payload for suspicious content"""
        if Raw in packet:
            raw_data = packet[Raw].load
            try:
                decoded_data = raw_data.decode('utf-8', errors='ignore')

                protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Unknown"

                packet_info = {
                    "input":{

                    "Source IP": packet[IP].src,
                    "Destination IP": packet[IP].dst,
                    "Source Port": packet[TCP].sport,
                    "Destination Port": packet[TCP].dport,
                    "Flow Key": flow_key,
                    "Timestamp": datetime.now().isoformat(),
                    "Flow Data": {
                        "packets": self.flows[flow_key]['packets'],
                        "bytes": self.flows[flow_key]['bytes'],
                        "protocol": protocol
                    },
                    "Payload": decoded_data,
                    },
                    "instruction":"---------------------------",
                    "output":{
                        "decision": "SUSPICIOUS",  
                        "category": "-----",  
                        "reasons": [               
                            "------",
                            "---------"
                        ]
                    }
                }
                self.send_to_model(packet_info)

            except UnicodeDecodeError:
                print("\nPayload (hex):", raw_data.hex()[:100])
    

    def send_to_model(self, packet_info):
        url = "http://"
        response = requests.post(url, json=packet_info)
        print("Model response:", response.text)
        
    def start_monitoring(self, interface="eth0"):
        print(f"Starting monitoring on {interface}...")
        print("Monitoring for suspicious activities...")
        sniff(prn=self.packet_callback, store=0, iface=interface)

if __name__ == "__main__":
    monitor = SimpleNetworkMonitor()
    monitor.start_monitoring(interface="lo0")