import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
from datetime import datetime
import json
import argparse
import binascii
from threading import Event
from collections import defaultdict

class NetworkMonitor:
    def __init__(self, interface="eth0", packet_limit=None):
        self.flows = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.interface = interface
        self.packet_limit = packet_limit
        self.packet_count = 0
        self.stop_sniffing = Event()

    def decode_payload(self, payload_data):
        """Attempt to decode payload data in various formats."""
        try:
            # Try UTF-8 first
            return payload_data.decode('utf-8')
        except:
            try:
                # Try ASCII, ignoring errors
                return payload_data.decode('ascii', errors='ignore')
            except:
                # If all else fails, return hex representation
                return binascii.hexlify(payload_data).decode()

    def extract_payload(self, packet):
        """Extract raw payload from packet."""
        try:
            if TCP in packet:
                return bytes(packet[TCP].payload)
            elif UDP in packet:
                return bytes(packet[UDP].payload)
            return b""
        except:
            return b""

    def format_payload(self, packet):
        """Format the payload with protocol detection."""
        try:
            if TCP in packet:
                dst_port = packet[TCP].dport
                payload = self.extract_payload(packet)
                
                if payload:
                    decoded_payload = self.decode_payload(payload)
                    return decoded_payload
                
                return {"type": "TCP", "data": "No payload"}
            
            elif UDP in packet:
                payload = self.extract_payload(packet)
                if payload:
                    return {"type": "UDP", "data": self.decode_payload(payload)}
                return {"type": "UDP", "data": "No payload"}
            
            return {"type": "Unknown", "data": None}
        
        except Exception as e:
            return {"type": "Error", "data": f"Error processing payload: {str(e)}"}

    def get_packet_info(self, packet):
        """Extract basic packet information."""
        info = {
            "protocol": None,
            "src_port": None,
            "dst_port": None,
            "length": len(packet)
        }
        
        if TCP in packet:
            info["protocol"] = "TCP"
            info["src_port"] = packet[TCP].sport
            info["dst_port"] = packet[TCP].dport
            if packet[TCP].flags:
                info["flags"] = {
                    "SYN": packet[TCP].flags.S,
                    "ACK": packet[TCP].flags.A,
                    "FIN": packet[TCP].flags.F,
                    "RST": packet[TCP].flags.R,
                    "PSH": packet[TCP].flags.P
                }
        elif UDP in packet:
            info["protocol"] = "UDP"
            info["src_port"] = packet[UDP].sport
            info["dst_port"] = packet[UDP].dport
        
        return info

    def format_packet_for_llm(self, packet):
        """Format packet data into LLM-friendly structure."""
        if IP not in packet:
            return None

        packet_info = self.get_packet_info(packet)
        if not packet_info["protocol"]:
            return None

        flow_key = f"{packet[IP].src}:{packet_info['src_port']}->{packet[IP].dst}:{packet_info['dst_port']}"
        flow_data = {
            "input": {
                "Source IP": packet[IP].src,
                "Destination IP": packet[IP].dst,
                "Source Port": packet_info["src_port"],
                "Destination Port": packet_info["dst_port"],
                "Flow Key": flow_key,
                "Timestamp": datetime.now().isoformat(),
                "Flow Data": {
                    "packets": self.flows[flow_key]['packets'],
                    "bytes": packet_info["length"],
                    "protocol": packet_info["protocol"],
                    "flags": packet_info.get("flags", {})
                },
                "Payload": self.format_payload(packet)
            },
            "instruction": "Analyze the network traffic pattern for suspicious behavior"
        }
        
        return flow_data

    def packet_callback(self, packet):
        """Process each captured packet."""
        if self.stop_sniffing.is_set():
            return
        packet_info = self.get_packet_info(packet)
        flow_key = f"{packet[IP].src}:{packet_info['src_port']}->{packet[IP].dst}:{packet_info['dst_port']}"
        self.flows[flow_key]['packets'] += 1
        self.flows[flow_key]['bytes'] += len(packet)
        formatted_data = self.format_packet_for_llm(packet)
        
        if formatted_data:
            print("\nCaptured Packet:")
            print(json.dumps(formatted_data, indent=2))
            print("\n" + "-"*50)

        if self.packet_limit and self.packet_count >= self.packet_limit:
            self.stop_sniffing.set()

    def start_monitoring(self):
        """Start the packet capture process."""
        print(f"Starting network monitoring on interface {self.interface}")
        print("Press Ctrl+C to stop monitoring...")
        interface="lo0"#"Software Loopback Interface 1"#self.interface
        try:
            scapy.sniff(
                iface=interface,#self.interface,
                prn=self.packet_callback,
                stop_filter=lambda _: self.stop_sniffing.is_set()
            )
        except KeyboardInterrupt:
            print("\nStopping network monitoring...")
        except Exception as e:
            print(f"Error during monitoring: {e}")

def main():
    parser = argparse.ArgumentParser(description='Network Packet Monitor for LLM Analysis')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-l', '--limit', type=int, help='Limit of packets to capture')
    parser.add_argument('--list-interfaces', action='store_true', help='List available interfaces')
    args = parser.parse_args()

    if args.list_interfaces:
        print("Available interfaces:")
        for iface in scapy.get_if_list():
            print(f"- {iface}")
        return

    interface = args.interface or scapy.conf.iface
    monitor = NetworkMonitor(interface=interface, packet_limit=args.limit)
    monitor.start_monitoring()

if __name__ == "__main__":
    main()