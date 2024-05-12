import socket

running = True
def start_udpproxy():
    try:
        global running

        # Ports that will be opened
        source_port = 2222
        dest_port   = 1111

        # Proxy server setup
        proxy_source_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        proxy_dest_socket   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bind the proxy socket to listen for incoming packets
        proxy_source_socket.bind(('127.0.0.1', source_port))
        print(f"Proxy server is listening on 127.0.0.1:{source_port}")
        
        proxy_dest_socket.bind(('127.0.0.1', dest_port))
        print(f"Proxy server is listening on 127.0.0.1:{dest_port}")

        # Keep the proxy running indefinitely
        while running:
            # Receive data from the client along with the source address and port
            data, source_addr = proxy_source_socket.recvfrom(1024)
            data2, source_addr = proxy_dest_socket.recvfrom(1024)
            
    except KeyboardInterrupt:
        print("\nReceived KeyboardInterrupt. Stopping the proxy...")
        sys.exit()

def stop_udpproxy():
    global running
    running = False
    
if __name__ == "__main__":
    start_udpproxy()