import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import threading
import random
import string
from tabulate import tabulate
import ipaddress
import sys
import os
import termios
import tty
import select
import time
from tqdm import tqdm
import requests

# Add the functions directory to the Python path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'functions'))

# Now import the functions
from func import get_free_port, get_local_ip, parse_message, create_sip_message
from config_parser import ConfigParser

exit_event = threading.Event()

class SipServerScanner:
    def __init__(self, target_ip, port=5060, proto='udp', packet_type='OPTIONS', threads=10, enable_threading=True, verbose=0):
        self.target_ip = target_ip
        self.port = port
        self.proto = proto
        self.packet_type = packet_type
        self.threads = threads
        self.enable_threading = enable_threading
        self.verbose = verbose
        self.results = {}
        self.results_lock = threading.Lock()
        self.thread_lock = threading.Lock()
        self.exit_event = threading.Event()
        self.interface = 'eth0'  # Add default interface
        self.interface_ip = get_local_ip()  # Get interface IP
        self.responses = defaultdict(list)
        self.lock = threading.Lock()
        self.from_user = 1000
        self.responses_lock = threading.Lock()
        self.from_ip = ''
        self.use_tls = False
        self.to_user = "1000"
        self.should_exit = False
        
        # Load configuration from file
        self.load_config()

    def load_config(self):
        """Load configuration from the config file"""
        config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.txt')
        try:
            config_parser = ConfigParser(config_path)
            config = config_parser.parse()
            
            # Update instance attributes with config values
            self.target_ip = config.get('ip_range', self.target_ip)
            self.port = config_parser.get_int('port', self.port)
            self.proto = config.get('proto', self.proto)
            self.packet_type = config.get('packet_type', self.packet_type).upper()
            self.from_user = config.get('from_user', self.from_user)
            self.verbose = min(config_parser.get_int('verbose', self.verbose), 2)
            self.to_usker = config.get('to_user', self.to_user)
            self.from_ip = config.get('from_ip', self.from_ip)
            self.threads = config_parser.get_int('threads', self.threads)
            self.use_tls = config_parser.get_bool('use_tls', self.use_tls)
            self.enable_threading = config_parser.get_bool('use_threading', self.enable_threading)
            
            if self.verbose >= 1:
                print("Configuration loaded successfully")
        except FileNotFoundError:
            print(f"Warning: Configuration file not found at {config_path}")
            print("Using default configuration values")
        except Exception as e:
            print(f"Error loading configuration: {e}")
            print("Using default configuration values")

    def get_key(self):
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

    def check_for_space_stop(self):
        """Check if space bar was pressed to stop the scan"""
        key = self.get_key()
        if key == ' ':  # Space bar
            return True
        return False

    def get_wan_ip(self):
        """Get the WAN IP address"""
        try:
            # Try to get WAN IP from a public service
            response = requests.get('https://api.ipify.org', timeout=5)
            return response.text.strip()
        except:
            try:
                # Fallback to another service
                response = requests.get('https://ifconfig.me/ip', timeout=5)
                return response.text.strip()
            except:
                return None

    def generate_ip_addresses(self):
        """Generate IP addresses from CIDR notation efficiently"""
        try:
            network = ipaddress.ip_network(self.target_ip)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            print(f"Error parsing CIDR: {e}")
            return []

    def scan_ip_range(self, ip, exit_event, pbar):
        # Get local IP from config
        local_ip = self.from_ip if self.from_ip else self.interface_ip
        
        # Skip if the IP is our local IP
        if ip == local_ip:
            with self.thread_lock:
                pbar.update(1)
            return []

        call_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        user_agent = "Theta/1.0"
        parsed_headers = defaultdict(list)
        sock = None

        try:
            # Create and configure socket once
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Get a random local port
            local_port = get_free_port()
            
            # Bind to 0.0.0.0 for faster sending
            sock.bind(('0.0.0.0', local_port))
            
            # Set a very short timeout for faster scanning
            sock.settimeout(0.1)  # Reduced timeout

            # Use the imported create_sip_message function
            message = create_sip_message(
                self.packet_type,
                ip,
                local_ip,
                local_port,
                call_id,
                user_agent
            )

            # Send the message
            try:
                sock.sendto(message.encode(), (ip, self.port))

                # Quick check for response
                try:
                    data, addr = sock.recvfrom(4096)
                    response = data.decode()
                    
                    # Parse the response
                    response_lines = response.split('\r\n')
                    parsed_headers['Response'] = [response_lines[0]]

                    for line in response_lines[1:]:
                        if ':' in line:
                            header_name, header_value = line.split(':', 1)
                            parsed_headers[header_name.strip()].append(header_value.strip())

                    # Store the results
                    with self.results_lock:
                        self.results[ip] = parsed_headers
                        if self.verbose >= 1:
                            print(f"\nFound SIP service on {ip}")

                except socket.timeout:
                    pass

            except socket.error:
                pass

        except Exception as e:
            if self.verbose >= 2:
                print(f"Error scanning {ip}: {e}")
        finally:
            if sock:
                sock.close()
            with self.thread_lock:
                pbar.update(1)

        return []

    def display_results(self):
        headers = ["IP address", "Port", "Proto", "Response", "Server", "User-Agent"]
        table_data = []

        for ip, parsed_headers in self.results.items():
            # Check if there are headers with data (excluding 'Response')
            has_data = any(value for key, value in parsed_headers.items() if key != 'Response')

            if has_data:
                response_messages = parsed_headers.get('Response', ['N/A'])
                server = parsed_headers.get('Server', ['N/A'])[0]
                user_agent = parsed_headers.get('User-Agent', ['N/A'])[0]

                # Extract and format the response code from the response message
                response_code = None
                for response_message in response_messages:
                    if response_message.startswith("SIP/2.0 "):
                        response_parts = response_message.split(" ")
                        if len(response_parts) >= 2:
                            response_code = response_parts[1]

                response_info_str = response_code if response_code else 'N/A'

                table_data.append([ip, self.port, self.proto, response_info_str, server, user_agent])

        table_data.sort(key=lambda x: x[0])

        if table_data:
            print("\n" + tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
            print(f"\nFound {len(table_data)} responsive SIP servers")
        else:
            print("\n❌ No responsive SIP servers found.")

    def scan_ip_range_threaded(self):
        # Generate IP addresses once
        ip_addresses = self.generate_ip_addresses()
        total_ips = len(ip_addresses)
        
        if total_ips == 0:
            print("❌ No valid IP addresses generated from CIDR")
            return False
        
        local_ip = self.from_ip if self.from_ip else self.interface_ip
        
        print(f"\n🔍 Starting scan of {total_ips} IP addresses")
        print(f"📡 Protocol: {self.proto}, Type: {self.packet_type}")
        print(f"🔢 Threads: {self.threads}, Source IP: {local_ip}")
        
        exit_event.clear()
        scan_completed = False

        # Threaded scanning with larger batches
        if self.enable_threading:
            with tqdm(total=total_ips, desc="Scanning", unit="ip") as pbar:
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    batch_size = 50
                    futures = []
                    
                    for i in range(0, len(ip_addresses), batch_size):
                        if exit_event.is_set():
                            break
                        
                        batch = ip_addresses[i:i + batch_size]
                        for ip in batch:
                            if not exit_event.is_set():
                                future = executor.submit(self.scan_ip_range, ip, exit_event, pbar)
                                futures.append(future)
                    
                    for future in futures:
                        try:
                            if not future.cancelled():
                                future.result(timeout=0.5)
                        except (TimeoutError, Exception):
                            pass
                    
                    scan_completed = True
        else:
            # Sequential scanning
            with tqdm(total=total_ips, desc="Scanning", unit="ip") as pbar:
                for ip in ip_addresses:
                    if exit_event.is_set():
                        break
                    
                    self.scan_ip_range(ip, exit_event, pbar)
                
                scan_completed = True

        # Just return the completion status - don't display results here
        if scan_completed and not exit_event.is_set():
            found_count = len(self.results)
            print(f"\n✅ Scan completed! Found {found_count} SIP services")
        else:
            print("\n⚠️ Scan was interrupted")

        return scan_completed

def main():
    """Main function to run the SIP mass scanner"""
    print("\n=== SIP Mass Scanner Module ===")
    print("-----------------------------")
    
    # Create scanner instance
    scanner = SipServerScanner("192.168.50.0/24")
    
    print("\nConfiguration loaded from config file")
    print("Press Enter to start the scan")
    print("Press Space to stop")
    print("-----------------------------")
    
    try:
        input()  # Wait for Enter key
        scan_completed = scanner.scan_ip_range_threaded()
        if scan_completed:
            scanner.display_results()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
    
    input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    main()

