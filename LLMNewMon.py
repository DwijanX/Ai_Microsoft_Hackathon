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
import asyncio
import websockets
import logging
from aiohttp import web
import threading
import queue
import json
from datetime import datetime
import requests
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebSocketServer:
    def __init__(self, host="localhost", port=8080):
        self.host = host
        self.port = port
        self.clients = set()
        self.message_queue = queue.Queue()
        self.app = web.Application()
        self._setup_routes()

    def _setup_routes(self):
        self.app.router.add_static('/', path='public', name='static')

    async def register(self, websocket):
        self.clients.add(websocket)
        logger.info(f"New client connected. Total clients: {len(self.clients)}")
        
        welcome_message = {
            "input": {"message": "Connected successfully"},
            "instruction": "Welcome message",
            "output": {
                "decision": "Connection established",
                "category": "System",
                "reasons": ["WebSocket handshake completed", "Client registered"]
            }
        }
        await websocket.send(json.dumps(welcome_message))

    async def unregister(self, websocket):
        self.clients.remove(websocket)
        logger.info(f"Client disconnected. Total clients: {len(self.clients)}")

    def broadcast_sync(self, message):
        """Synchronous method to add message to queue"""
        self.message_queue.put(message)

    async def process_queue(self):
        """Asynchronously process messages from queue"""
        while True:
            try:
                # Check queue for new messages
                while not self.message_queue.empty():
                    message = self.message_queue.get_nowait()
                    if self.clients:
                        try:
                            # Ensure message is JSON serializable
                            if isinstance(message, str):
                                try:
                                    json.loads(message)  # Validate JSON string
                                except json.JSONDecodeError:
                                    logger.error("Invalid JSON string")
                                    continue
                            else:
                                message = json.dumps(message)

                            # Broadcast to all clients
                            for client in self.clients.copy():
                                try:
                                    await client.send(message)
                                except websockets.exceptions.WebSocketException:
                                    await self.unregister(client)
                        except Exception as e:
                            logger.error(f"Error broadcasting message: {e}")
                
                # Small delay to prevent CPU overuse
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"Error in queue processing: {e}")
                await asyncio.sleep(1)

    async def ws_handler(self, websocket, path):
        try:
            await self.register(websocket)
            async for message in websocket:
                # Handle incoming messages if needed
                logger.info(f"Received message from client: {message[:100]}...")
        except websockets.exceptions.ConnectionClosed:
            logger.info("Client connection closed unexpectedly")
        finally:
            await self.unregister(websocket)

    async def start(self):
        # Start WebSocket server
        self.ws_server = await websockets.serve(self.ws_handler, self.host, self.port)
        logger.info(f"WebSocket server started on ws://{self.host}:{self.port}")
        
        # Start queue processor
        asyncio.create_task(self.process_queue())
        
        # Keep the server running
        await asyncio.Future()  # run forever

    def run_server(self):
        """Run the server in a separate thread"""
        asyncio.run(self.start())

    def start_in_thread(self):
        """Start the server in a background thread"""
        self.server_thread = threading.Thread(target=self.run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        logger.info("WebSocket server thread started")

# Global server instance
ws_server = None

def get_server():
    global ws_server
    if ws_server is None:
        ws_server = WebSocketServer()
        ws_server.start_in_thread()
    return ws_server




#Monitor
class NetworkMonitor:
    def __init__(self, interface="eth0", packet_limit=None):
        self.server = get_server()
        self.flows = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.interface = interface
        self.packet_limit = packet_limit
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
                
                return "No payload"
            
            elif UDP in packet:
                payload = self.extract_payload(packet)
                if payload:
                    return self.decode_payload(payload)
                return "No payload"
            
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
                },
                "Payload": self.format_payload(packet)
        }
        
        return flow_data

    def send_to_model(self, packet_info):
        print(packet_info["Flow Key"])
        url = "https://crn290tw-5000.brs.devtunnels.ms/query"
        jsonReq={
            "query":str(packet_info)
        }
        response = requests.post(url, json=jsonReq)
        if response.status_code == 200:
            try:
                model_response = response.json()

                cleanedJson=model_response["response"].replace("'", "\"")
    
                responseJson=json.loads(cleanedJson)

                self.sendToFront(packet_info,responseJson)

            except json.JSONDecodeError:
                print("Error decoding JSON response from model")
        else:
            print(f"Error from model server: {response.status_code} - {response.text}")

    def show_interfaces(self):
        try:
            return IFACES.show()
        except Exception as e:
            print(f"Error showing interfaces: {str(e)}")

    def sendToFront(self, input,message):
        """Send message to all connected WebSocket clients"""
        try:
            # If message is a string, try to parse it as JSON
            if isinstance(message, str):
                try:
                    message = json.loads(message)
                except json.JSONDecodeError as e:
                    logger.error(f"Error decoding JSON message: {e}")
                    return


            message={
                "input":input,
                "output": message
            }
            # Send message to WebSocket server
            
            self.server.broadcast_sync(message)
            logger.info("Message sent to WebSocket server")
            
        except Exception as e:
            logger.error(f"Error in sendToFront: {e}")


    
    def packet_callback(self, packet):
        """Process each captured packet."""
        if self.stop_sniffing.is_set():
            return
        # Check if packet has IP layer before processing
        if IP not in packet:
            logger.debug("Skipping non-IP packet")
            return
        packet_info = self.get_packet_info(packet)
        flow_key = f"{packet[IP].src}:{packet_info['src_port']}->{packet[IP].dst}:{packet_info['dst_port']}"
        self.flows[flow_key]['packets'] += 1
        self.flows[flow_key]['bytes'] += len(packet)
        formatted_data = self.format_packet_for_llm(packet)
        
        if formatted_data and formatted_data["Payload"] != "No payload":
            print("\nCaptured Packet:")
            print(json.dumps(formatted_data, indent=2))

            print("\nSending to model for analysis...")
            self.send_to_model(formatted_data)
            print("\n" + "-"*50)

        if self.packet_limit and self.packet_count >= self.packet_limit:
            self.stop_sniffing.set()

    def start_monitoring(self):
        """Start the packet capture process."""
        print(f"Starting network monitoring on interface {self.interface}")
        print("Press Ctrl+C to stop monitoring...")
        interface="en0"#r'Realtek PCIe GbE Family Controller'#="Software Loopback Interface 1"#self.interface
        try:
            scapy.sniff(
                iface=interface,#self.interface,
                prn=self.packet_callback,
                stop_filter=lambda _: self.stop_sniffing.is_set(),
                filter="ip",
                store=0
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
    # monitor.start_monitoring()


    testMessage={
       "input": {
      "Source IP": "192.168.1.110",
      "Destination IP": "192.168.1.5",
      "Source Port": 49255,
      "Destination Port": 389,
      "Flow Key": "192.168.1.110->192.168.1.5",
      "Timestamp": "2024-10-24T14:40:00.345678",
      "Flow Data": { "packets": 6, "bytes": 840, "protocol": "TCP" },
      "Payload": "LDAP bind request for user=jsmith"
    },
    "output": {
      "decision": "NORMAL",
      "category": "LDAP Authentication",
      "reasons": [
        "Internal LDAP query",
        "Standard bind request",
        "Expected packet size"
      ]
    }
    }
    try:
        while True:
            time.sleep(10)
            monitor.sendToFront(testMessage["input"],testMessage["output"])


    except KeyboardInterrupt:
        print("Shutting down...")

if __name__ == "__main__":
    main()