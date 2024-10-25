from scapy.all import sniff, IP, TCP, UDP, Raw,IFACES
from collections import defaultdict
import time
import json
from datetime import datetime
import requests
import re
import base64
class SimpleNetworkMonitor:
    def __init__(self):
        self.flows = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.suspicious_patterns = {
            'port_scan': set(),
            'large_transfers': set(),
            'unusual_protocols': set(),
            'command_execution': set(),
            'data_exfiltration': set()
        }
        
        # Common suspicious commands and patterns
        self.suspicious_commands = [
            r'(?i)cmd\.exe',
            r'(?i)powershell',
            r'(?i)bash',
            r'(?i)wget\s+http',
            r'(?i)curl\s+http',
            r'(?i)/bin/sh',
            r'(?i)nc\s+-[el]',  # netcat execution
            r'(?i)python\s+-c',  # Python command execution
            r'(?i)exec\(',
            r'(?i)eval\(',
            r'(?i)system\(',
            r'(?i)shell_exec',
            r'(?i)base64 -d',    # base64 decode commands
        ]
        
        # Data exfiltration patterns
        self.exfil_patterns = [
            r'(?i)password',
            r'(?i)credit_card',
            r'(?i)social_security',
            r'(?i)\.ssh/',
            r'(?i)\.bash_history',
            r'\.(db|sql|mdb|sqlite)$',  # Database files
            r'\.env$',           # Environment files
            r'config\.',         # Configuration files
        ]
        
    def packet_callback(self, packet):
        if IP in packet:
            flow_key = f"{packet[IP].src}->{packet[IP].dst}"
            
            # Update flow statistics
            self.flows[flow_key]['packets'] += 1
            self.flows[flow_key]['bytes'] += len(packet)
            
            # Print basic flow info
            #print(f"\nFlow: {flow_key}")
            ##print(f"Packets: {self.flows[flow_key]['packets']}, Bytes: {self.flows[flow_key]['bytes']}")
            
            # Print IP layer details
            #print("\nIP Layer:")
            #print(f"Version: {packet[IP].version}")
            #print(f"TTL: {packet[IP].ttl}")
            #print(f"Protocol: {packet[IP].proto}")
            
            # Enhanced payload analysis
            self.analyze_payload(packet, flow_key)
            
            #print("-" * 50)
            
            # Comprehensive analysis
            #self.analyze_packet(packet, flow_key)
    
    def analyze_payload(self, packet, flow_key):
        """Analyze packet payload for suspicious content"""
        if Raw in packet:
            raw_data = packet[Raw].load
            try:
                decoded_data = raw_data.decode('utf-8', errors='ignore')

                hex_data = raw_data.hex()  # For hexadecimal representation
                base64_data = base64.b64encode(raw_data).decode('utf-8')

                print("new package"+"-"*50)

                print(decoded_data)
                # print(f"Source IP: {packet[IP].src}")
                # print(f"Destination IP: {packet[IP].dst}")
                # print(f"Source Port: {packet[TCP].sport}")
                # print(f"Destination Port: {packet[TCP].dport}")
                # print(f"Flow Key: {flow_key}")
                # print(f"Timestamp: {datetime.now().isoformat()}")
                # print("flow key")
                # print(flow_key)
                # print(self.flows[flow_key])
                # Get MAC addresses
                
                # Check for file type based on content
                if decoded_data.startswith('%PDF-'):
                    print("File Type: PDF")
                elif decoded_data.startswith('\x89PNG\r\n\x1a\n'):
                    print("File Type: PNG")
                elif decoded_data.startswith('GIF89a') or decoded_data.startswith('GIF87a'):
                    print("File Type: GIF")
                elif decoded_data.startswith('\xff\xd8\xff'):
                    print("File Type: JPEG")
                elif decoded_data.startswith('PK\x03\x04'):
                    print("File Type: ZIP")
                elif decoded_data.startswith('MZ'):
                    print("File Type: EXE")
                elif decoded_data.startswith('This is a text file') or decoded_data.startswith('Sample text'):
                    print("File Type: TXT")
                else:
                    print("File Type: Unknown")
                # Check for command execution
                #for pattern in self.suspicious_commands:
                #    if re.search(pattern, decoded_data):
                #        self.suspicious_patterns['command_execution'].add(flow_key)
                #        print("\n[!] ALERT: Potential command execution detected!")
                #        print(f"Pattern matched: {pattern}")
                #        print(f"Content: {decoded_data[:100]}...")
                
                # Check for data exfiltration
                #for pattern in self.exfil_patterns:
                #    if re.search(pattern, decoded_data):
                #        self.suspicious_patterns['data_exfiltration'].add(flow_key)
                #        print("\n[!] ALERT: Potential data exfiltration detected!")
                #        print(f"Pattern matched: {pattern}")
                
                # Print payload info
                #print("\nPayload Analysis:")
                #if len(decoded_data) > 100:
                #    print(f"Content (first 100 chars): {decoded_data[:100]}...")
                #else:
                #    print(f"Content: {decoded_data}")
                    
            except UnicodeDecodeError:
                print("\nPayload (hex):", raw_data.hex()[:100])
    
    def analyze_packet(self, packet, flow_key):
        """Enhanced packet analysis"""
        print("\nfull flow:")
        print(self.flows[flow_key])
        
        # if TCP in packet:
        #     print("\nTCP Layer:")
        #     print(packet)
        #     # Check for potential port scanning
        #     if packet[TCP].flags == 2:  # SYN packets
        #         self.suspicious_patterns['port_scan'].add(packet[IP].src)
            
        #     # Check for suspicious ports
        #     suspicious_ports = {21, 22, 23, 445, 3389, 4444, 4445, 5554, 5555}
        #     if packet[TCP].dport in suspicious_ports:
        #         print(f"\n[!] Connection attempt to suspicious port {packet[TCP].dport}")
        
        # # Check for large transfers
        # if self.flows[flow_key]['bytes'] > 1000000:  # 1MB
        #     self.suspicious_patterns['large_transfers'].add(flow_key)
        
        # # Generate alert if suspicious
        # if self.is_suspicious(packet, flow_key):
        #     self.generate_alert(packet, flow_key)
    
    def is_suspicious(self, packet, flow_key):
        """Enhanced suspicious activity check"""
        return any([
            packet[IP].src in self.suspicious_patterns['port_scan'],
            flow_key in self.suspicious_patterns['large_transfers'],
            flow_key in self.suspicious_patterns['command_execution'],
            flow_key in self.suspicious_patterns['data_exfiltration']
        ])
    
    def generate_alert(self, packet, flow_key):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': packet[IP].src,
            'destination_ip': packet[IP].dst,
            'flow_key': flow_key,
            'suspicious_patterns': [
                pattern for pattern, ips in self.suspicious_patterns.items()
                if packet[IP].src in ips or flow_key in ips
            ],
            'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Unknown',
            'ports': {
                'source': packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None,
                'destination': packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None
            }
        }
        print("\n[!] SECURITY ALERT:")
        print(json.dumps(alert, indent=2))
        
    def start_monitoring(self, interface="eth0"):
        print(f"Starting monitoring on {interface}...")
        print("Monitoring for suspicious activities...")
        capture = sniff(prn=self.packet_callback, store=0, iface=interface)
    def show_interfaces(self):
        print(IFACES.show())

if __name__ == "__main__":
    monitor = SimpleNetworkMonitor()
    monitor.show_interfaces()
    #monitor.start_monitoring(interface=r'Realtek PCIe GbE Family Controller')