import random
from random import randint
import re
import netifaces
import socket
import subprocess
import struct
import os
import hashlib
import platform
import requests
import ipaddress
import string


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    finally:
        s.close()

def generate_cseq(ip, packet_type, cseq_counter, cseq_type, custom_cseq):
    # Increment the CSeq counter for the current packet type
    cseq_counter[packet_type] += 1

    # Construct the CSeq header with the incremented counter
    cseq_header = f"{cseq_counter[packet_type]} {packet_type}"

    if cseq_type == 'method+sequence':
        return cseq_header
    elif cseq_type == 'custom':
        # Use the custom CSeq value provided by the user, if any
        return custom_cseq or cseq_header
    else:
        raise ValueError("Invalid CSeq header type. Supported types are method+sequence and custom.")

def generate_call_id(call_id):
    if call_id:
        return call_id  # Use the custom Call-ID if provided
    else:
        # Generate a random alphanumeric string as the identifier part
        random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
        return random_id

def random_public_ip():
    while True:
        # Generate a random IPv4 address
        random_ip = ipaddress.IPv4Address(random.randint(0x0A000000, 0xFFFFFFFF))  # Exclude private IP ranges

        # Check if the generated IP address is public (not in private IP ranges)
        if not random_ip.is_private:
            return str(random_ip)

def get_free_port(min_port=20000, max_port=65535, num_attempts=100):
    for _ in range(num_attempts):
        port = random.randint(min_port, max_port)
        try:
            # Attempt to create a socket and bind it to the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', port))
            sock.close()
            return port
        except socket.error as e:
            # Port is already in use, try the next one
            continue

    raise Exception(f"No free ports available in the specified range ({min_port}-{max_port}).")

def parse_message(buffer, is_request=True):
    # Initialize an empty dictionary to store SIP headers
    parsed_data = {}
    
    # Initialize variables to keep track of the current header name and value
    current_header_name = None
    current_header_value = ""

    headers = buffer.split('\r\n')

    for header in headers:
        # Parsing logic for each header
        header = header.strip()  # Remove leading/trailing whitespaces
        if not header:
            continue  # Skip empty lines

        # Check if this line starts with whitespace, indicating it's a continuation of the previous header
        if header[0].isspace():
            # Append this line to the current header value
            current_header_value += " " + header.strip()
        else:
            # Split the header into name and value using the first colon ':'
            parts = header.split(':', 1)
            if len(parts) == 2:
                current_header_name, current_header_value = parts
                parsed_data.setdefault(current_header_name.strip(), []).append(current_header_value.strip())

    return parsed_data
























