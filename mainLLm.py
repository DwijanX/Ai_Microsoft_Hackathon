from scapy.all import sniff, IP, TCP, UDP, Raw, IFACES
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
        try:
            if Raw in packet:
                raw_data = packet[Raw].load
                try:
                    decoded_data = raw_data.decode('utf-8', errors='ignore')
                    
                    # Determine protocol safely
                    protocol = "Unknown"
                    src_port = dst_port = None
                    
                    if TCP in packet:
                        protocol = "TCP"
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                    elif UDP in packet:
                        protocol = "UDP"
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                    
                    packet_info = {
                        "input": {
                            "Source IP": packet[IP].src,
                            "Destination IP": packet[IP].dst,
                            "Source Port": src_port,
                            "Destination Port": dst_port,
                            "Flow Key": flow_key,
                            "Timestamp": datetime.now().isoformat(),
                            "Flow Data": {
                                "packets": self.flows[flow_key]['packets'],
                                "bytes": self.flows[flow_key]['bytes'],
                                "protocol": protocol
                            },
                            "Payload": decoded_data,
                        },
                        "instruction": "---------------------------",
                        "output": {
                            "decision": "SUSPICIOUS",
                            "category": "-----",
                            "reasons": [
                                "------",
                                "---------"
                            ]
                        }
                    }
                    packetInput={
                            "Source IP": packet[IP].src,
                            "Destination IP": packet[IP].dst,
                            "Source Port": src_port,
                            "Destination Port": dst_port,
                            "Flow Key": flow_key,
                            "Timestamp": datetime.now().isoformat(),
                            "Flow Data": {
                                "packets": self.flows[flow_key]['packets'],
                                "bytes": self.flows[flow_key]['bytes'],
                                "protocol": protocol
                            },
                            "Payload": decoded_data,
                        }
                    self.send_to_model(packetInput)
                    #print(f"Captured {protocol} packet: {flow_key}")
                    
                except UnicodeDecodeError:
                    print(f"\nPayload decode error for {flow_key} (hex):", raw_data.hex()[:100])
                    
        except Exception as e:
            print(f"Error processing packet: {str(e)}")
            
    def send_to_model(self, packet_info):
        url = "http://127.0.0.1/query"
        jsonReq={
            "query":packet_info
        }
        response = requests.post(url, json=jsonReq)
        if response.status_code == 200:
            try:
                model_response = response.json()

                # Remove <|eot_id|> if it exists
                cleaned_response = model_response.replace("<|eot_id|>", "")
                
                # Convert the string to a JSON object
                model_response_obj = json.loads(cleaned_response)
                
                print("Cleaned Model response:", model_response_obj)



            except json.JSONDecodeError:
                print("Error decoding JSON response from model")
        else:
            print(f"Error from model server: {response.status_code} - {response.text}")
        print("Model response:", response.text)
        print("Packet Info:", packet_info)
        
    def start_monitoring(self, interface="eth0"):
        try:
            print(f"Starting monitoring on {interface}...")
            print("Monitoring for suspicious activities...")
            # Add filter to capture only IP packets
            sniff(prn=self.packet_callback, store=0, iface=interface, filter="ip")
        except Exception as e:
            print(f"Error starting monitoring: {str(e)}")
            
    def show_interfaces(self):
        try:
            return IFACES.show()
        except Exception as e:
            print(f"Error showing interfaces: {str(e)}")

if __name__ == "__main__":
    monitor = SimpleNetworkMonitor()
    #monitor.show_interfaces()
    monitor.start_monitoring(interface=r'Realtek PCIe GbE Family Controller')