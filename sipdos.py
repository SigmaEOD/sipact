import socket
from collections import defaultdict
import random
import string
import ssl
from tabulate import tabulate
import argparse
import ipaddress
from functions.func import generate_call_id, get_free_port, get_local_ip, random_public_ip, generate_cseq
import time
import socks
import sys
import threading
import signal
from decimal import Decimal
import struct

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
        self.interface_ip=''
        self.cseq = 'method+sequence'
        self.custom_cseq = ''
        self.packet_type = 'random'
        self.cseq_counter = defaultdict(int)
        self.call_id = ''
        self.requests_sent = 0
        self.total_data = 0
        self.user_agent = "Theta 1.0"
        self.should_exit = False
        self.use_threading = True  # Variable to control threading
        self.requests_sent_lock = threading.Lock()
        self.num_threads = 10  # Number of threads (default)
        self.known_packet_types = {
            'INVITE',
            'REGISTER',
            'OPTIONS',
            'ACK',
            'BYE',
            'CANCEL',
            'UPDATE',
            'REFER',
            'PRACK',
            'SUBSCRIBE',
            'NOTIFY',
            'PUBLISH',
            'MESSAGE',
            'INFO',
            'OPTIONS',
        }


    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='SIP Packet Crafter')

        # Add flag for IP range in CIDR format
        parser.add_argument('--ip', default=self.ip, help='Specify the IP (e.g., 192.168.50.1)')

        # Add flags for other options
        parser.add_argument('--port', type=int, default=self.port, help='Specify the port number')
        parser.add_argument('--proto', choices=['UDP', 'TCP', 'RAW'], default=self.proto, help='Specify the protocol (UDP, TCP, RAW)')
        parser.add_argument('--packet-type', choices=list(self.known_packet_types) + ['random'], required=True, help='Specify the packet type (e.g., INVITE, REGISTER, OPTIONS, RANDOM)')
        parser.add_argument('--from-user', default=self.from_user, help='Specify the SIP From User')
        parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity level (up to 2 times)')
        parser.add_argument("--to-user", default=self.to_user, required=True, help="To user")
        parser.add_argument('--from-ip', default='random', help='Specify the source IP address for sending SIP messages')
        parser.add_argument('--interface-ip', default='', help='Specify an interface to bind with')
        parser.add_argument('--cseq', choices=['method+sequence', 'custom'], default='method+sequence', help='Specify CSeq header type (method+sequence or custom)')
        parser.add_argument('--custom-cseq', default='', help='Specify a custom CSeq value')
        parser.add_argument('--call-id', default='', help='Specify a custom Call-ID (default is auto-generated)')
        parser.add_argument('--x-header', default='', help='Specify an X-Header for the SIP packet')
        parser.add_argument('--payload-file', default='', help='Specify a text file containing the custom payload for the SIP packet')
        parser.add_argument('--num-threads', type=int, default=self.num_threads, help='Specify the number of threads (default is 10)')
        args = parser.parse_args()

        # Update instance attributes with parsed values
        self.ip = args.ip
        self.port = args.port
        self.proto = args.proto
        self.packet_type = args.packet_type.upper()  # Ensure it's in uppercase
        self.from_user = args.from_user  # Store the extension option
        self.verbose = min(args.verbose, 2)
        self.to_user = args.to_user
        self.from_ip = args.from_ip
        self.interface_ip = args.interface_ip
        self.cseq = args.cseq
        self.custom_cseq = args.custom_cseq
        self.x_header = args.x_header  # Store the X-Header argument
        self.payload_file = args.payload_file  # Store the payload file argument
        self.num_threads = args.num_threads
        
    def scanner(self):
        # Create a list to store thread objects
        threads = []

        if self.verbose >= 1:
            print(f"Processing IP: {self.ip}")

        # Modify the loop to create threads for sending requests if use_threading is True
        while True:
            if self.use_threading:
                for _ in range(self.num_threads):
                    thread = threading.Thread(target=self.scan_ip, args=(self.ip,))
                    threads.append(thread)
                    thread.start()
                    self.requests_sent += 1  # Increment the requests_sent count

                # Set up a signal handler to catch Ctrl+C
                signal.signal(signal.SIGINT, self.signal_handler)

                # Wait for all threads to complete
                for thread in threads:
                    thread.join()

    # Display results after all threads (or requests) finish
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
                if self.verbose >=1:
                    print("Setting up UDP Socket")

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                if self.verbose >= 1:
                    print("[DEBUG]: Created UDP Socket")
            elif self.proto == 'TCP':
                if self.verbose >=1:
                    print("[DEBUG]: Setting up TCP Socket")  

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                if self.verbose >= 1:
                    print("[DEBUG]: TCP Socket Created")
            
            else:
                raise ValueError("Invalid protocol. Supported protocols are UDP and TCP.")
        except socket.error as e:
            print(f"Failed to create socket: {e}")
            sys.exit(10)

        local_port = get_free_port()
        ip_address = self.interface_ip
        if self.verbose >= 1:
            print(f"Binding to IP: {self.interface_ip}, Port: {local_port}")  # Add this line for debugging
        bind = (ip_address, local_port)
        try:
            sock.bind(bind)
            if self.verbose >= 1:
                print(f"Socket is listening on {bind[0]}:{bind[1]}")
        except Exception as e:
            print(f"Failed to bind socket: {e}")
            sys.exit(1)

        return sock, local_port

              
    def def_request_message(self, local_port):
    # Generate a random call_id
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
    # Generate and return the SIP request message
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
Content-Length: {len(self.load_custom_payload())}\r
\r
{self.load_custom_payload()}
"""


    def scan_ip(self, ip):
        local_ip = self.from_ip
        ip = self.ip
        if self.verbose >= 1:
            print(f"[DEBUG] Scanning IP: {ip}")
        max_retries = 1
        retry_count = 0 
        sock = None
        while retry_count < max_retries:
            if self.proto == "RAW":
                try:
                    # Create a raw socket
                    local_port = get_free_port()
                    if self.from_ip == "random":
                        from_ip = random_public_ip()
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

                    # Define the IP header fields
                    ip_version = 4
                    ip_header_length = 5
                    ip_tos = 0
                    ip_total_length = 0  # Will be calculated automatically
                    ip_id = 54321
                    ip_flags = 0
                    ip_ttl = 255
                    ip_protocol = socket.IPPROTO_UDP  # Specify the protocol you want to use (e.g., TCP)
                    ip_checksum = 0  # Will be calculated automatically
                    ip_src = socket.inet_aton(from_ip)  # Use your source IP here
                    ip_dst = socket.inet_aton(ip)  # Use the target IP here

                    sip_message = self.def_request_message(local_port)

                    # Calculate the total length including IP header, UDP header, and SIP message
                    ip_header_length = len(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 0, 0, 0, 0, 0, 0, b'\x00\x00\x00\x00', b'\x00\x00\x00\x00'))
                    udp_header_length = 8
                    ip_total_length = ip_header_length + udp_header_length + len(sip_message)

                    # Construct the IP header
                    ip_header = struct.pack(
                        "!BBHHHBBH4s4s",
                        0x45,             # Version and header length
                        0,                # TOS (Type of Service)
                        ip_total_length,     # Total length (calculated dynamically)
                        0,                # Identification
                        0,                # Flags and fragment offset
                        255,              # TTL (Time to Live)
                        socket.IPPROTO_UDP,  # Protocol (UDP)
                        0,                # Checksum (calculated automatically)
                        socket.inet_aton(from_ip),  # Source IP
                        socket.inet_aton(ip),       # Destination IP
                    )
                    # Create the complete packet (IP header + payload)
                    packet = ip_header + struct.pack("!HHHH", self.port, self.port, ip_total_length - ip_header_length, 0) + sip_message.encode()

                    # Send the packet
                    s.sendto(packet, (ip, self.port))

                    with self.requests_sent_lock:
                        self.requests_sent += 1
                    
                except Exception as e:
                    print(f"Error sending raw IP packet: {e}")

            else:
                sock, local_port = self.setup_socket()
                message = self.def_request_message(local_port)
                try:
                    sock.settimeout(0)
                    if self.proto == 'UDP':
                        sock.connect((ip, self.port))
                        sock.sendto(message.encode(), (ip, self.port))
                        if self.verbose >= 2:
                            print("Sent UDP SIP message.")
                            print(message)
                    elif self.proto == 'TCP':
                        sock.connect((ip, self.port))
                        sock.send(message.encode())
                        if self.verbose >= 2:
                            print("Sent TCP SIP message:")
                            print(message)
                except socket.timeout:
                    if self.verbose >= 2:
                        print(f"Timeout receiving response from {ip}:{self.port} for user {self.from_user}")
                    sock.close()
                except socket.error as e:
                    if e.errno == 32:
                        sock.close()
                        if self.verbose >= 2:
                            print(f"Socket error: [Errno 32] Broken pipe. Check if the socket is closed prematurely.")
                            print("Connection Closed")
                    elif e.errno == 111:
                        sock.close()
                        if self.verbose >= 2:
                            print(f"Connection Refused for {ip}")
                finally:
                    retry_count += 1
                    sock.close()
                


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






if __name__ == "__main__":
    try:
        #print("[DEBUG] Script started.")
        sip_scanner = SipServerScanner()
        sip_scanner.parse_arguments()
        sip_scanner.scanner()
        sip_scanner.display_results()

    except Exception as e:
        print(f"[ERROR] Exception occurred: {e}")

