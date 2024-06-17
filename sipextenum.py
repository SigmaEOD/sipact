import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from functions.func import parse_message, get_free_port, get_local_ip
import time
import threading
import random
import string
import requests
import sys 
from tabulate import tabulate
import argparse


class SipExtenEnum:
    def __init__(self):
        self.ip = ""
        self.port = 5060
        self.start_ext = 1000
        self.end_ext = 1010
        self.threads = 1
        self.responses = defaultdict(list)
        self.lock = threading.Lock()
        self.results = {}
        self.verbose = 2
        self.cseq = 'method+sequence'
        self.from_user = "1000"
        self.proto = 'UDP'
        self.from_ip = ""
        self.packet_type = 'OPTIONS'
        self.interface_ip=''
        self.responses_lock = threading.Lock()
        self.results_lock = threading.Lock()
        self.cseq_counter = defaultdict(int)

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='SIP Extension Enumerator')

        # Add flags for IP and Port
        parser.add_argument('--ip', default=self.ip, help='Specify the IP address')
        parser.add_argument('--port', type=int, default=self.port, help='Specify the port number')
        parser.add_argument('--verbose', type=int, default=self.verbose, help='Verbocity (1, 2)')
        parser.add_argument('--from-ip', default=self.from_ip, help='Local LAN/WAN IP address to send from')
        parser.add_argument('--start-ext', type=int, default=self.start_ext, help='Specify the start of the extension range')
        parser.add_argument('--end-ext', type=int, default=self.end_ext, help='Specify the end of the extension range')
        parser.add_argument('--proto', choices=['UDP', 'TCP'], default=self.proto, help='Specify the protocol (UDP or TCP)')
        parser.add_argument('--from-user', type=int, default=self.from_user, help='From User(INT Extention)')
        # Add a flag for the number of threads
        parser.add_argument('--threads', type=int, default=self.threads, help='Specify the number of threads')
        parser.add_argument('--interface-ip', default='', help='Specify an interface to bind with')
        # Add an argument for the packet type (unchanged)
        parser.add_argument('--packet-type', required=True, default=self.packet_type, help='Specify the packet type (OPTIONS, INVITE, or REGISTER)')

        args = parser.parse_args()

        # Update instance attributes with parsed values
        self.ip = args.ip
        self.from_ip = args.from_ip
        self.port = args.port
        self.start_ext = args.start_ext
        self.end_ext = args.end_ext
        self.threads = args.threads
        self.packet_type = args.packet_type.upper()  # Ensure it's in uppercase
        self.verbose = args.verbose
        self.from_user = args.from_user
        self.interface_ip = args.interface_ip

    def known_packet_types(self):
        return {
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

    def generate_cseq(self):
        if self.packet_type not in self.known_packet_types():
            raise ValueError("Invalid packet type. Supported types are INVITE, REGISTER, and OPTIONS.")

        # Increment the CSeq counter for the current packet type
        self.cseq_counter[self.packet_type] += 1

        # Construct the CSeq header with the incremented counter
        cseq_header = f"{self.cseq_counter[self.packet_type]} {self.packet_type}"

        if self.cseq == 'method+sequence':
            return cseq_header
        elif self.cseq == 'custom':
            # Use the custom CSeq value provided by the user, if any
            return self.custom_cseq or cseq_header
        else:
            raise ValueError("Invalid CSeq header type. Supported types are method+sequence and custom.")

    def setup_socket(self):
        try:
            if self.proto == 'UDP':
                if self.verbose >=1:
                    print("[DEBUG] Setting up UDP Socket")

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
            print(f"[DEBUG] Binding to IP: {self.interface_ip}, Port: {local_port}")  # Add this line for debugging
        bind = (ip_address, local_port)
        try:
            sock.bind(bind)
            if self.verbose >= 1:
                print(f"[DEBUG] Socket is listening on {bind[0]}:{bind[1]}")
        except Exception as e:
            print(f"Failed to bind socket: {e}")
            sys.exit(1)

        return sock, local_port

    def scan_host(self, to_user, packet_type, parsed_headers_by_extension, ext):
        local_ip = self.from_ip
        ip = self.ip
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
            print("[DEBUG] creating socket")
            sock, local_port = self.setup_socket()
            print ("[DEBUG] checking packet type")
            if self.packet_type not in self.known_packet_types():
                raise ValueError("Invalid packet type. Supported packet types are: " + ", ".join(self.known_packet_types()))
            
            print("[DEBUG] Creating Message")
            try:
                message = f"""{self.packet_type} sip:{ip} SIP/2.0\r
Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK{call_id}\r
Max-Forwards: 70\r
From: <sip:{self.from_user}@{self.from_ip}>;tag={call_id}\r
To: <sip:{ext}@{self.ip}>\r
Call-ID: {call_id}@{local_ip}\r
CSeq: {self.generate_cseq()}\r
User-Agent: {user_agent}\r
Contact: <sip:{self.from_user}@{local_ip}:{local_port}>\r
Content-Length: 0\r
\r
"""
            except Exception as e:
                print(f"Exception occurred in scan_host: {e}")
            print("[DEBUG] Message Created")
            sock.settimeout(2)
            print("[DEBUG] Starting Connection")
            try:
                if self.proto == 'UDP':
                    print("Socket Connecting")
                    sock.connect((ip, self.port))  # Use sock instead of s
                    print("Sending Message")
                    sock.sendto(message.encode(), (ip, self.port))  # Use sock instead of s

                    if self.verbose >= 2:
                        print("Sent UDP SIP message.")
                        print(message)
                elif self.proto == 'TCP':
                    sock.connect((ip, self.port))  # Use sock instead of          
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

    def enumerate_extensions(self):
        print("enumerate_extensions started")
        packet_type = self.packet_type
        parsed_headers_by_extension = {}  
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for ext in range(self.start_ext, self.end_ext + 1):
                executor.submit(self.scan_host, str(ext), packet_type, parsed_headers_by_extension, ext)

        self.display_results(parsed_headers_by_extension)
        

    def display_results(self, parsed_headers_by_extension):
        headers = ["IP address", "Port", "Proto", "Extension", "Response", "Server"]
        table_data = []

        for ext, parsed_headers in parsed_headers_by_extension.items():
            response_messages = parsed_headers.get('Response', ['N/A'])  # Get the response message(s)
            response_message = '\n'.join(response_messages)

            user_agent = parsed_headers.get('User-Agent', ['N/A'])[0]  # Check for 'User-Agent' key
            server = parsed_headers.get('Server', ['N/A'])[0]  # Check for 'Server' key

            # Extract and join the "Allow" values
            allowed = ', '.join(parsed_headers.get('Allow', ['N/A']))

            table_data.append([self.ip, self.port, self.proto, ext, response_message, server])

        # Sort the table_data by extension
        table_data.sort(key=lambda x: int(x[3]))

        # Print the tabulated data
        print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
if __name__ == "__main__":
    sip_enum = SipExtenEnum()
    sip_enum.parse_arguments()
    sip_enum.enumerate_extensions()

