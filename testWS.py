import asyncio
import websockets
import json
import logging
from aiohttp import web
import threading
import queue
from scapy.all import sniff, IP, TCP, UDP, Raw, IFACES
from collections import defaultdict
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

# Modified SimpleNetworkMonitor class
class SimpleNetworkMonitor:
    def __init__(self):
        self.flows = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.server = get_server()
        


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
                    print(decoded_data)
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




        
    def start_monitoring(self, interface="eth0"):
        try:
            print(f"Starting monitoring on {interface}...")
            print("Monitoring for suspicious activities...")
            # Add filter to capture only IP packets
            sniff(prn=self.packet_callback, store=0, iface=interface)
            #sniff(prn=self.packet_callback, store=0, iface=interface, filter="ip")
        except Exception as e:
            print(f"Error starting monitoring: {str(e)}")
            
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


if __name__ == "__main__":
    # Example usage
    monitor = SimpleNetworkMonitor()
    monitor.start_monitoring(interface="lo0")

    
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
            #monitor.sendToFront(testMessage["input"],testMessage["output"])


    except KeyboardInterrupt:
        print("Shutting down...")