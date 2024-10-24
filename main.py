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

                print("new package"+"-"*50)

                print(f"Source IP: {packet[IP].src}")
                print(f"Destination IP: {packet[IP].dst}")
                print(f"Source Port: {packet[TCP].sport}")
                print(f"Destination Port: {packet[TCP].dport}")
                print(f"Flow Key: {flow_key}")
                print(f"Timestamp: {datetime.now().isoformat()}")
                print("flow key")
                print(flow_key)
                print(self.flows[flow_key])
                print("data",decoded_data)

                """
                {
    "input": {
        "Source IP": "127.0.0.1",
        "Destination IP": "127.0.0.1",
        "Source Port": 51391,
        "Destination Port": 8888,
        "Flow Key": "127.0.0.1->127.0.0.1",
        "Timestamp": "2024-10-24T13:05:25.232704",
        "Flow Data": {
            "packets": 5,
            "bytes": 449,
            "protocol": "TCP"  
        },
        "Payload": "GET / HTTP/1.1\r\nHost: 127.0.0.1:8888\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
    },
    "instruction": "Analyze this network traffic for suspicious behavior",  // More specific instruction
    "output": {
        "decision": "SUSPICIOUS",  // Standardized output
        "confidence": 0.85,        // Added confidence score
        "category": "ANOMALOUS_HTTP_REQUEST",  // Added category
        "reasons": [               // Multiple reasons as array
            "Unusual port number for HTTP traffic",
            "Suspicious User-Agent string"
        ]
    }
}
                
                
                """
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
                
                with open("packet_dump.json", "a") as f:
                    json.dump(packet_info, f)
                    f.write(",\n")
                
                
                    
            except UnicodeDecodeError:
                print("\nPayload (hex):", raw_data.hex()[:100])
    
        
    def start_monitoring(self, interface="eth0"):
        print(f"Starting monitoring on {interface}...")
        print("Monitoring for suspicious activities...")
        sniff(prn=self.packet_callback, store=0, iface=interface)

if __name__ == "__main__":
    monitor = SimpleNetworkMonitor()
    monitor.start_monitoring(interface="lo0")