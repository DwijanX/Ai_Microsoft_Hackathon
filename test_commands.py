# visible_test.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import requests
import time
import sys

class TestHTTPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(f"Server received: {post_data.decode('utf-8')}")
        
        # Send a larger response to make traffic more visible
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        response = b"Received your data: " + post_data
        self.wfile.write(response)
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Test server is running!")

def run_test_server(port=8888):  # Changed port to 8888
    server = HTTPServer(('127.0.0.1', port), TestHTTPHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server

def send_test_traffic(port=8888):
    base_url = f'http://127.0.0.1:{port}'
    
    suspicious_payloads = [
        # Make payloads longer and more visible
        {
            "type": "command_execution",
            "payload": "cmd.exe /c whoami && dir && systeminfo" * 5
        },
        {
            "type": "data_exfiltration",
            "payload": "password=admin123&credit_card=4111111111111111&ssn=123-45-6789" * 3
        },
        {
            "type": "file_access",
            "payload": "GET /.ssh/id_rsa HTTP/1.1\nHost: target.com\nUser-Agent: Mozilla/5.0" * 4
        }
    ]
    
    print("\nStarting visible test traffic generation...")
    print(f"To see this traffic in Wireshark:")
    print(f"1. Capture filter: 'port {port}'")
    print(f"2. Display filter: 'tcp.port == {port}'")
    print(f"3. Make sure you're capturing on the loopback interface")
    
    try:
        # First send a GET request to verify connection
        print("\nSending initial GET request...")
        requests.get(base_url)
        time.sleep(1)
        
        for i, payload_data in enumerate(suspicious_payloads, 1):
            print(f"\nSending test payload {i}/{len(suspicious_payloads)}")
            print(f"Type: {payload_data['type']}")
            
            # Send each payload multiple times to make it more visible
            for _ in range(3):
                try:
                    response = requests.post(
                        base_url,
                        data=payload_data['payload'],
                        headers={
                            'User-Agent': 'Test-Traffic-Generator',
                            'X-Test-Type': payload_data['type'],
                            'Content-Type': 'text/plain'
                        }
                    )
                    print(f"Sent payload, server responded with: {response.status_code}")
                    time.sleep(2)  # Longer delay between requests
                    
                except requests.exceptions.RequestException as e:
                    print(f"Error sending payload: {e}")
                    continue
        
        # Generate high-volume traffic
        print("\nGenerating high-volume traffic...")
        large_payload = "X" * 100000  # 100KB of data
        for _ in range(5):  # Send it 5 times
            requests.post(base_url, data=large_payload)
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nTest traffic generation interrupted")
        return

def main():
    port = 8888  # Using a distinct port
    
    print("\nNetwork Traffic Generation Tool for Wireshark Analysis")
    print("\nBefore starting, please ensure:")
    print("1. Wireshark is running and capturing on loopback interface")
    print(f"2. Your display filter is set to: tcp.port == {port}")
    print("3. Your network monitor is running in another terminal")
    
    input("\nPress Enter when ready to start...")
    
    print("\nStarting test server...")
    server = run_test_server(port)
    
    try:
        print(f"\nServer running on http://127.0.0.1:{port}")
        print("Starting to generate test traffic in 3 seconds...")
        time.sleep(3)
        
        send_test_traffic(port)
        
    except KeyboardInterrupt:
        print("\nShutting down test environment...")
    finally:
        server.shutdown()
        print("Test environment shutdown complete")

if __name__ == '__main__':
    main()