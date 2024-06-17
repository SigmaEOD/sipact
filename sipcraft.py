import socket
from collections import defaultdict
import random
import string
import ssl
from tabulate import tabulate
import argparse
import ipaddress
from functions.func import get_free_port, parse_message, get_local_ip
import time
import socks
import sys


class SipServerScanner:
    def __init__(self):
        self.ip = "192.168.50.0"  # Default IP in CIDR format
        self.port = 5060
        self.responses = defaultdict(list)
        self.results = {}
        self.verbose = 2
        self.from_user = 1000
        self.proto = ''
        self.from_ip = ''
        self.to_user = "1000"
        self.interface_ip=''
        self.cseq = 'method+sequence'
        self.custom_cseq = ''
        self.packet_type = None
        self.cseq_counter = defaultdict(int)
        self.call_id = ''

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='SIP Packet Crafter')

        # Add flag for IP range in CIDR format
        parser.add_argument('--ip', default=self.ip, help='Specify the IP (e.g., 192.168.50.1)')

        # Add flags for other options
        parser.add_argument('--port', type=int, default=self.port, help='Specify the port number')
        parser.add_argument('--proto', choices=['UDP', 'TCP'], default=self.proto, help='Specify the protocol (UDP or TCP)')
        parser.add_argument('--packet-type', required=True, help='Specify the packet type (e.g., INVITE, REGISTER, OPTIONS)')
        parser.add_argument('--from-user', default=self.from_user, help='Specify the SIP From User')
        parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity level (up to 2 times)')
        parser.add_argument("--to-user", default=self.to_user, required=True, help="To user")
        parser.add_argument('--from-ip', default='', help='Specify the source IP address for sending SIP messages')
        parser.add_argument('--interface-ip', default='', help='Specify an interface to bind with')
        parser.add_argument('--cseq', choices=['method+sequence', 'custom'], default='method+sequence', help='Specify CSeq header type (method+sequence or custom)')
        parser.add_argument('--custom-cseq', default='', help='Specify a custom CSeq value')
        parser.add_argument('--call-id', default='', help='Specify a custom Call-ID (default is auto-generated)')
        parser.add_argument('--x-header', default='', help='Specify an X-Header for the SIP packet')
        parser.add_argument('--payload-file', default='', help='Specify a text file containing the custom payload for the SIP packet')

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
        
    def scanner(self):
        all_responses = []
        if self.verbose >= 1:
            print(f"Processing IP: {self.ip}")  # Display the scanning IP
        parsed_headers = self.scan_ip(self.ip)  # Pass pbar as an argument
        # Close the socket here if threading is disabled
        all_responses.append(parsed_headers)  # Store the response for this IP

            # Now you have all the responses in the 'all_responses' list to process as needed
        for response in all_responses:
            # Handle the response data
            pass

    def load_custom_payload(self):
        if self.payload_file:
            try:
                with open(self.payload_file, 'r') as payload_file:
                    return payload_file.read()
            except FileNotFoundError:
                raise FileNotFoundError(f"Payload file '{self.payload_file}' not found.")
        else:
            return ''

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

            
    def generate_call_id(self):
        if self.call_id:
            return self.call_id  # Use the custom Call-ID if provided
        else:
            # Generate a random alphanumeric string as the identifier part
            random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
            return random_id

    def scan_ip(self, ip):
        local_ip = self.from_ip# Use self.source_ip instead of source_ip
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
            
            sock, local_port = self.setup_socket() # Use self.source_ip

            if self.packet_type not in self.known_packet_types():
                raise ValueError("Invalid packet type. Supported packet types are: " + ", ".join(self.known_packet_types()))

            
            message = f"""{self.packet_type} sip:{ip} SIP/2.0\r
Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK{call_id}\r
Max-Forwards: 70\r
From: <sip:{self.from_user}@{local_ip}>;tag={call_id}\r
To: <sip:{self.to_user}@{ip}>\r
Call-ID: {call_id}@{local_ip}\r
CSeq: {self.generate_cseq()}\r
User-Agent: {user_agent}\r
Contact: <sip:{self.from_user}@{local_ip}:{local_port}>\r
Content-Type: application/sdp\r
Content-Length: {len(self.load_custom_payload())}\r
\r
{self.load_custom_payload()}
"""


            sock.settimeout(3)

            try:
                if self.proto == 'UDP':
                    sock.connect((ip, self.port))  # Use sock instead of s
                    sock.sendto(message.encode(), (ip, self.port))  # Use sock instead of s

                    if self.verbose >= 2:
                        print("Sent UDP SIP message.")
                        print(message)
                elif self.proto == 'TCP':
                    sock.connect((ip, self.port))  # Use sock instead of s

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
                        if self.verbose >= 2:
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
        sip_scanner.scanner()
        sip_scanner.display_results()

    except Exception as e:
        print(f"[ERROR] Exception occurred: {e}")

