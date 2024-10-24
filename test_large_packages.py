import socket
import os
import time
import argparse
from tqdm import tqdm
import random
import json

class TrafficGenerator:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        
        # Test patterns that might trigger your monitor
        self.test_commands = [
            'cmd.exe /c dir',
            'powershell -encodedcommand',
            'wget http://test.com/file',
            'nc -e /bin/bash',
            'python -c "import os; os.system(\'id\')"'
        ]
        
        self.test_data_patterns = [
            'password=secret123',
            'credit_card=4111111111111111',
            'config.json',
            '.ssh/id_rsa'
        ]

    def send_normal_file(self, filename, chunk_size=1024):
        """Sends a regular file in chunks"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.host, self.port))
            file_size = os.path.getsize(filename)
            
            with open(filename, 'rb') as f:
                pbar = tqdm(total=file_size, unit='B', unit_scale=True,
                          desc=f'Sending {filename}')
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    sock.send(chunk)
                    pbar.update(len(chunk))
                    time.sleep(0.001)  # Small delay between chunks
                
                pbar.close()
        finally:
            sock.close()

    def send_suspicious_command(self):
        """Sends traffic containing suspicious command patterns"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.host, self.port))
            command = random.choice(self.test_commands)
            print(f"Sending suspicious command pattern: {command}")
            sock.send(command.encode())
            time.sleep(0.1)
        finally:
            sock.close()

    def send_data_exfil(self):
        """Simulates data exfiltration patterns"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.host, self.port))
            sensitive_data = random.choice(self.test_data_patterns)
            fake_data = {
                "type": "user_data",
                "content": sensitive_data,
                "timestamp": time.time()
            }
            print(f"Sending suspicious data pattern")
            sock.send(json.dumps(fake_data).encode())
            time.sleep(0.1)
        finally:
            sock.close()

    def port_scan_simulation(self, ports_range=(1000, 1010)):
        """Simulates a basic port scan"""
        print(f"Simulating port scan on ports {ports_range[0]}-{ports_range[1]}")
        for port in range(ports_range[0], ports_range[1] + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.host, port))
                print(f"Port {port} open")
            except:
                pass
            finally:
                sock.close()
            time.sleep(0.05)

    def large_transfer(self, size_mb=5):
        """Generates and sends a large amount of data"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.host, self.port))
            bytes_to_send = size_mb * 1024 * 1024  # Convert MB to bytes
            
            pbar = tqdm(total=bytes_to_send, unit='B', unit_scale=True,
                       desc=f'Sending large transfer ({size_mb}MB)')
            
            chunk_size = 1024
            bytes_sent = 0
            
            while bytes_sent < bytes_to_send:
                remaining = min(chunk_size, bytes_to_send - bytes_sent)
                chunk = os.urandom(remaining)  # Generate random bytes
                sock.send(chunk)
                bytes_sent += len(chunk)
                pbar.update(len(chunk))
                time.sleep(0.001)
            
            pbar.close()
        finally:
            sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate test traffic patterns')
    parser.add_argument('--host', default='127.0.0.1', help='Target host')
    parser.add_argument('--port', type=int, default=12345, help='Target port')
    parser.add_argument('--mode', choices=['file', 'command', 'exfil', 'portscan', 'large'],
                       required=True, help='Traffic pattern to generate')
    parser.add_argument('--file', help='File to send (for file mode)')
    parser.add_argument('--size', type=int, default=5,
                       help='Size in MB for large transfer mode')
    
    args = parser.parse_args()
    
    generator = TrafficGenerator(args.host, args.port)
    
    if args.mode == 'file' and args.file:
        generator.send_normal_file(args.file)
    elif args.mode == 'command':
        generator.send_suspicious_command()
    elif args.mode == 'exfil':
        generator.send_data_exfil()
    elif args.mode == 'portscan':
        generator.port_scan_simulation()
    elif args.mode == 'large':
        generator.large_transfer(args.size)