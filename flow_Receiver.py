import socket
import threading
from datetime import datetime

class FlowReceiver:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow port reuse
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[*] Listening on {host}:{port}")

    def handle_client(self, client_socket, addr):
        print(f"[+] Accepted connection from {addr[0]}:{addr[1]}")
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                # Log received data size
                print(f"[*] Received {len(data)} bytes from {addr[0]}:{addr[1]}")
        except Exception as e:
            print(f"[!] Error handling client: {e}")
        finally:
            client_socket.close()
            print(f"[-] Connection closed from {addr[0]}:{addr[1]}")

    def start(self):
        try:
            while True:
                client, addr = self.server_socket.accept()
                # Handle each client in a separate thread
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client, addr)
                )
                client_handler.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down server")
            self.server_socket.close()

if __name__ == "__main__":
    receiver = FlowReceiver()
    receiver.start()