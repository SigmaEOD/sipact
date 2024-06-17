import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import threading
import random
import string
import ssl
from tabulate import tabulate
import argparse
import ipaddress
from functions.func import get_free_port, parse_message, get_local_ip, get_local_wan_ip
import time
from tqdm import tqdm
import socks
import sys


exit_event = threading.Event()

class SipServerScanner:
    def __init__(self):
        self.ip = ""
        self.ip_range = "192.168.50.0/24"  # Default IP range in CIDR format
        self.port = 5060
        self.threads = 1
        self.responses = defaultdict(list)
        self.lock = threading.Lock()
        self.results = {}
        self.verbose = 2
        self.from_user = 1000
        self.proto = ''
        self.responses_lock = threading.Lock()
        self.results_lock = threading.Lock()
        self.fom_ip = ''
        self.use_tls = False  # Default is to not use TLS
        self.tls_cert_file = '/home/epsilon/Desktop/sipact/tls/certificate.pem'  # Path to TLS certificate file
        self.tls_key_file = '/home/epsilon/Desktop/sipact/tls/private-key.pem'  # Path to TLS private key file
        self.enable_threading = True
        self.thread_lock = threading.Lock()
        self.to_user = "1000"
        self.interface_ip=''

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='SIP Server Scanner')

        # Add flag for IP range in CIDR format
        parser.add_argument('--ip', default=self.ip_range, help='Specify the IP range in CIDR format (e.g., 192.168.50.0/24)')

        # Add flags for other options
        parser.add_argument('--port', type=int, default=self.port, help='Specify the port number')
        parser.add_argument('--threads', type=int, default=self.threads, help='Specify the number of threads')
        parser.add_argument('--proto', choices=['UDP', 'TCP'], default=self.proto, help='Specify the protocol (UDP or TCP)')
        parser.add_argument('--packet-type', choices=['OPTIONS', 'INVITE', 'REGISTER'], required=True,
                            help='Specify the packet type (OPTIONS, INVITE, or REGISTER)')
        parser.add_argument('--from-user', default=self.from_user, help='Specify the SIP From User')
        parser.add_argument('--use-tls', action='store_true', help='Use TLS for scanning')
        parser.add_argument('--tls-cert-file', default=self.tls_cert_file, help='Path to TLS certificate file')
        parser.add_argument('--tls-key-file', default=self.tls_key_file, help='Path to TLS private key file')
        parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity level (up to 2 times)')
        parser.add_argument('--no-threading', action='store_true', help='Disable threading')
        parser.add_argument("--to-user", default=self.to_user, required=True, help="To user")
        parser.add_argument('--from-ip', default='', help='Specify the source IP address for sending SIP messages')
        parser.add_argument('--interface-ip', default='', help='Specify an interface to bind with')
        args = parser.parse_args()

        # Update instance attributes with parsed values
        self.ip_range = args.ip
        self.port = args.port
        self.threads = args.threads
        self.proto = args.proto
        self.packet_type = args.packet_type.upper()  # Ensure it's in uppercase
        self.from_user = args.from_user  # Store the extension option
        self.use_tls = args.use_tls
        self.tls_cert_file = args.tls_cert_file
        self.tls_key_file = args.tls_key_file
        self.verbose = min(args.verbose, 2)
        self.enable_threading = not args.no_threading
        self.to_user = args.to_user
        self.from_ip = args.from_ip
        self.interface_ip = args.interface_ip

    def generate_ip_addresses(self):
        try:
            ip_network = ipaddress.IPv4Network(self.ip_range, strict=False)
            # Filter out IP addresses ending in .255
            ip_addresses = [str(ip) for ip in ip_network if ip.packed[-1] != 255]
            return ip_addresses
        except ValueError as e:
            print(f"Invalid IP range: {e}")
            sys.exit(1)
            

    def scan_ip_range_threaded(self):
        ip_addresses = self.generate_ip_addresses()

        # Check if threading should be enabled
        if self.enable_threading:
            # Create a tqdm progress bar with the total number of IP addresses
            with tqdm(total=len(ip_addresses)) as pbar:
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = [executor.submit(self.scan_ip_range, ip, exit_event, pbar) for ip in ip_addresses]

                # Wait for all threads to finish and collect results
                for future in futures:
                    # Collect the results from each future
                    responses = future.result()
                    # Process responses if needed
                    for response in responses:
                        # Handle the response data
                        pass
        else:
            # Threading is disabled, scan IP addresses sequentially without threads
            pbar = tqdm(total=len(ip_addresses))  # Create a tqdm progress bar

            # List to store all responses
            all_responses = []

            # Iterate through IP addresses sequentially
            for ip in ip_addresses:
                if self.verbose >= 1:
                    print(f"Processing IP: {ip}")  # Display the scanning IP
                parsed_headers = self.scan_ip_range(ip, exit_event, pbar)  # Pass pbar as an argument
                # Close the socket here if threading is disabled
                all_responses.append(parsed_headers)  # Store the response for this IP
                pbar.update(1)  # Update the progress bar

            pbar.close()

            # Now you have all the responses in the 'all_responses' list to process as needed
            for response in all_responses:
                # Handle the response data
                pass

    def setup_socket(self):
        try:
            if self.proto == 'UDP':
                if self.verbose >=1:
                    print("Setting up UDP Socket")

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                if self.verbose >= 1:
                    print("[DEBUG]: Created UDP Socket")
            elif self.proto == 'TCP':
                print("Setting up TCP Socket")  # Add this line for TCP debugging
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.verbose >= 1:
                    print("[DEBUG] TCP Socket Created")
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

            

    def scan_ip_range(self, ip, exit_event, pbar):
        local_ip = self.from_ip# Use self.source_ip instead of source_ip
        if self.verbose >= 1:
            print(f"[DEBUG] Scanning IP: {ip}")
        call_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        user_agent = "Theta/1.0"

        # Create a list to store responses for the current IP
        responses = []
        max_retries = 1 # Maximum number of retries
         # Initialize the retry count
        retry_count = 0 
        parsed_headers = defaultdict(list)  # Initialize parsed_headers here
        sock = None
        while retry_count < max_retries:
            
            sock, local_port = self.setup_socket() # Use self.source_ip

            if self.packet_type == "INVITE":
                message = f"""INVITE sip:{ip} SIP/2.0\r
Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK{call_id}\r
Max-Forwards: 70\r
From: <sip:{self.from_user}@{local_ip}>;tag={call_id}\r
To: <sip:{self.to_user}@{ip}>\r
Call-ID: {call_id}@{local_ip}\r
CSeq: 1 INVITE\r
User-Agent: {user_agent}\r
Contact: <sip:{self.from_user}@{local_ip}:{local_port}>\r
Content-Length: 0\r
\r
"""
            elif self.packet_type == "REGISTER":
                message = f"""REGISTER sip:{ip} SIP/2.0\r
Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK{call_id}\r
Max-Forwards: 70\r
From: <sip:{self.from_user}@{local_ip}>;tag={call_id}\r
To: <sip:{self.to_user}@{ip}>\r
Call-ID: {call_id}@{local_ip}\r
CSeq: 1 REGISTER\r
User-Agent: {user_agent}\r
Contact: <sip:{self.from_user}@{local_ip}:{local_port}>\r
Content-Length: 0\r
\r
"""
            elif self.packet_type == "OPTIONS":
                message = f"""OPTIONS sip:{ip} SIP/2.0\r
Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK{call_id}\r
Max-Forwards: 70\r
From: <sip:{self.from_user}@{local_ip}>;tag={call_id}\r
To: <sip:{self.to_user}@{ip}>\r
Call-ID: {call_id}@{local_ip}\r
CSeq: 1 OPTIONS\r
User-Agent: {user_agent}\r
Contact: <sip:{self.from_user}@{local_ip}:{local_port}>\r
Content-Length: 0\r
\r
"""
            else:
                raise ValueError("Invalid packet type. Supported types are INVITE, REGISTER, and OPTIONS.")

            sock.settimeout(1)

            try:
                if self.proto == 'UDP':
                    sock.connect((ip, self.port))  # Use sock instead of s
                    sock.sendto(message.encode(), (ip, self.port))  # Use sock instead of s

                    if self.verbose >= 2:
                        print("Sent UDP SIP message.")
                        print(message)
                elif self.proto == 'TCP':
                    sock.connect((ip, self.port))  # Use sock instead of s

                    # Enable SSL/TLS debugging
                    if self.use_tls:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.load_cert_chain(certfile=self.tls_cert_file, keyfile=self.tls_key_file)
                        sock = context.wrap_socket(sock, server_hostname=self.ip_range)
                    else:
                        sock.send(message.encode())  # Use sock instead of s

                    # Print the TCP message before it's encrypted and sent
                    if self.verbose >= 2:
                        print("Sent TCP SIP message:")
                        print(message)

                response_buffer = ""  # Buffer to accumulate response lines

                while True:
                    if self.proto == "UDP":
                        data, _ = sock.recvfrom(4096)  # Use sock instead of s
                    if self.proto == "TCP":
                        data = sock.recv(4096)  # Use sock instead of s
                    response_buffer += data.decode()

                    # Split the response_buffer into lines
                    response_lines = response_buffer.split("\r\n")

                    # Check if we have received the complete response
                    if "\r\n\r\n" in response_buffer:
                        response_parts = response_buffer.split("\r\n\r\n")
                        response_buffer = response_parts[1]  # Store any remaining data in the buffer

                        response_message = response_parts[0]  # Get the first part (e.g., "SIP/2.0 200 OK")

                        # Split the response message into lines
                        response_lines = response_message.split("\r\n")

                        # Store the entire response message
                        parsed_headers['Response'] = [response_message]

                        for line in response_lines[1:]:
                            # Check if the line contains a colon (indicating it's a header)
                            if ':' in line:
                                header_name, header_value = line.split(':', 1)
                                header_name = header_name.strip()
                                header_value = header_value.strip()

                                # Append the header value to the dictionary under the header name
                                parsed_headers.setdefault(header_name, []).append(header_value)
                                self.results[ip] = parsed_headers
                        print(parsed_headers)
            except socket.timeout:
                if self.verbose >= 2:
                    print(f"Timeout receiving response from {ip}:{self.port} for user {self.from_user}")
                    sock.close()
                # Optionally, handle the timeout here (e.g., retry or log)
            except socket.error as e:
                if e.errno == 32:  # Check for Broken Pipe error
                    sock.close()  # Use sock instead of s
                    if self.verbose >= 2:
                        print(f"Socket error: [Errno 32] Broken pipe. Check if the socket is closed prematurely.")
                        print("Connection Closed")
                elif e.errno == 111:
                    sock.close()  # Use sock instead of s
                    if self.verbose >= 2:
                        print(f"Connection Refused for {ip}")
            finally:
                # Increment the retry count
                retry_count += 1

                # Close the socket here (outside of the loop)
                sock.close()  # Use sock instead of s

                # Store the response in the responses list for the current IP
                responses.append(parsed_headers)
                with self.thread_lock:
                    pbar.update(1)

                # Return the responses for the current IP
                return responses
                print(responses)

                


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
            print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
        else:
            print("No responses with data found.")





if __name__ == "__main__":
    try:
        #print("[DEBUG] Script started.")
        sip_scanner = SipServerScanner()
        sip_scanner.parse_arguments()
        sip_scanner.scan_ip_range_threaded()
        sip_scanner.display_results()

    except Exception as e:
        print(f"[ERROR] Exception occurred: {e}")

