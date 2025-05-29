#!/usr/bin/env python3

import socket
import logging
import json
from datetime import datetime
from typing import Dict, Any, List
import threading
import re
from collections import deque
from threading import Semaphore
import time
import os
import netifaces
import platform

class SIPHoneypot:
    def __init__(self, config_path: str = None):
        # Load configuration
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.txt')
        
        print(f"Loading configuration from: {config_path}")
        
        # Parse config file
        self.config = {}
        with open(config_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '::' not in line:
                    continue
                key, value = line.split('::', 1)
                key = key.strip()
                value = value.strip()
                
                # Convert value to appropriate type
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value.isdigit():
                    value = int(value)
                elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
                    value = float(value)
                
                self.config[key] = value
                print(f"Loaded config: {key} = {value}")
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, self.config['log_level']),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['log_file']),
                logging.StreamHandler()
            ]
        )
        
        # Initialize server with interface configuration
        self.port = self.config['port']
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Set socket options
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if platform.system() == 'Windows':
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Get bind address from config
        bind_address = self.config.get('bind_address', '0.0.0.0')
        print(f"Using bind address: {bind_address}")
        
        # Print all available interfaces and their IPs
        print("\nAvailable network interfaces:")
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    print(f"Interface: {interface}, IP: {addr['addr']}")
        
        # Handle interface binding
        if self.config.get('use_interface', False):
            interface_name = self.config.get('interface', '')
            print(f"Using interface: {interface_name}")
            
            try:
                # Get interface IP if bind_address is not specified
                if not bind_address or bind_address == '0.0.0.0':
                    print(f"Getting IP for interface {interface_name}")
                    addrs = netifaces.ifaddresses(interface_name)
                    if netifaces.AF_INET in addrs:
                        bind_address = addrs[netifaces.AF_INET][0]['addr']
                        print(f"Got interface IP: {bind_address}")
                    else:
                        raise ValueError(f"No IPv4 address found for interface {interface_name}")
                
                # Try different binding methods based on platform
                if platform.system() == 'Linux':
                    try:
                        # Try SO_BINDTODEVICE first (requires root)
                        print(f"Attempting to bind to interface {interface_name} using SO_BINDTODEVICE")
                        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface_name.encode())
                    except (AttributeError, PermissionError) as e:
                        print(f"SO_BINDTODEVICE not available or permission denied: {str(e)}")
                        print("Falling back to direct IP binding")
                
                # Bind to the specific IP address
                print(f"Binding to {bind_address}:{self.port}")
                self.sock.bind((bind_address, self.port))
                logging.info(f"Bound to {bind_address}:{self.port}")
                
            except Exception as e:
                logging.error(f"Failed to bind to interface {interface_name}: {str(e)}")
                print(f"Interface binding failed: {str(e)}")
                # Fallback to default binding
                print("Falling back to default binding")
                self.sock.bind(('0.0.0.0', self.port))
                logging.info(f"Falling back to default binding on 0.0.0.0:{self.port}")
        else:
            # Direct binding to specified address
            print(f"Binding directly to {bind_address}:{self.port}")
            try:
                self.sock.bind((bind_address, self.port))
                logging.info(f"Bound to {bind_address}:{self.port}")
                print(f"Successfully bound to {bind_address}:{self.port}")
            except Exception as e:
                print(f"Direct binding failed: {str(e)}")
                logging.error(f"Failed to bind to {bind_address}:{self.port}: {str(e)}")
                # Try binding to all interfaces as last resort
                print("Trying to bind to all interfaces")
                self.sock.bind(('0.0.0.0', self.port))
                logging.info(f"Bound to all interfaces on port {self.port}")
                print(f"Successfully bound to all interfaces on port {self.port}")
        
        # Security configurations
        self.max_message_size = self.config['max_message_size']
        self.max_threads = self.config['max_threads']
        self.thread_semaphore = Semaphore(self.max_threads)
        self.attack_log = deque(maxlen=self.config['max_log_entries'])
        self.rate_limit = {}
        self.rate_limit_window = self.config['rate_limit_window']
        self.max_requests_per_window = self.config['max_requests_per_window']
        
        # New security features
        self.blacklist = set()  # IP blacklist
        self.blacklist_duration = self.config.get('blacklist_duration', 3600)  # 1 hour default
        self.blacklist_threshold = self.config.get('blacklist_threshold', 5)  # Number of violations before blacklisting
        self.ip_violations = {}  # Track violations per IP
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # Clean up old entries every 5 minutes
        
        # Enhanced attack patterns
        self.attack_patterns = {
            'brute_force': [
                r'(?i)(auth|digest|md5|password)',
                r'(?i)(admin|root|user|pass)',
                r'(?i)(login|credential|secret)'
            ],
            'scanning': [
                r'(?i)(scan|probe|detect)',
                r'(?i)(sipvicious|sipscan)',
                r'(?i)(user-agent:.*scanner)',
                r'(?i)(OPTIONS.*\r\n.*\r\n.*\r\n)'
            ],
            'exploit': [
                r'(?i)(exploit|vulnerability|attack)',
                r'(?i)(overflow|injection|sql)',
                r'(?i)(\.\.\/|\.\.\\|%00|%0a)',
                r'(?i)(<script|javascript:|onerror=)'
            ],
            'malformed': [
                r'[\x00-\x08\x0b\x0c\x0e-\x1f]',  # Control characters
                r'(?i)(content-length:\s*\d+\s*\r\n.*\r\n.*\r\n)',  # Content-Length mismatch
                r'(?i)(via:.*via:.*via:)',  # Multiple Via headers
                r'(?i)(from:.*from:.*from:)'  # Multiple From headers
            ]
        }
        
        # Compile patterns
        self.compiled_patterns = {}
        for attack_type, patterns in self.attack_patterns.items():
            self.compiled_patterns[attack_type] = [re.compile(pattern) for pattern in patterns]
        
        # Enhanced attack tracking
        self.attack_stats = {
            'total_attacks': 0,
            'attack_types': {},
            'top_attackers': {},
            'attack_timeline': []
        }
        
        # Response strategies
        self.response_strategies = {
            'brute_force': {
                'delay': 2,
                'response_code': 401,
                'fake_credentials': True
            },
            'scanning': {
                'delay': 1,
                'response_code': 503,
                'fake_services': True
            },
            'exploit': {
                'delay': 3,
                'response_code': 400,
                'fake_vulnerabilities': True
            },
            'flood': {
                'delay': 0,
                'response_code': 429,
                'rate_limit': True
            }
        }
        
        # Automated reporting
        self.report_interval = 3600  # 1 hour
        self.last_report = time.time()
        self.report_threshold = 10  # Minimum attacks before reporting

    def is_rate_limited(self, source_ip: str) -> bool:
        """Check if an IP is rate limited"""
        current_time = time.time()
        if source_ip not in self.rate_limit:
            self.rate_limit[source_ip] = []
        
        # Clean old entries
        self.rate_limit[source_ip] = [
            t for t in self.rate_limit[source_ip]
            if current_time - t < self.rate_limit_window
        ]
        
        # Check if rate limit exceeded
        if len(self.rate_limit[source_ip]) >= self.max_requests_per_window:
            return True
        
        # Add new request
        self.rate_limit[source_ip].append(current_time)
        return False

    def log_attack(self, source_ip: str, attack_type: str, details: Dict[str, Any]):
        """Log potential attack attempts"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'source_ip': source_ip,
            'attack_type': attack_type,
            'details': details
        }
        self.attack_log.append(log_entry)
        logging.warning(f"Potential attack detected: {json.dumps(log_entry)}")

    def is_blacklisted(self, source_ip: str) -> bool:
        """Check if an IP is blacklisted"""
        if source_ip in self.blacklist:
            # Check if blacklist duration has expired
            if time.time() - self.ip_violations.get(source_ip, {}).get('blacklist_time', 0) > self.blacklist_duration:
                self.blacklist.remove(source_ip)
                if source_ip in self.ip_violations:
                    del self.ip_violations[source_ip]
                return False
            return True
        return False

    def update_violations(self, source_ip: str, violation_type: str):
        """Update violation count for an IP"""
        if source_ip not in self.ip_violations:
            self.ip_violations[source_ip] = {
                'count': 0,
                'types': set(),
                'last_violation': time.time()
            }
        
        self.ip_violations[source_ip]['count'] += 1
        self.ip_violations[source_ip]['types'].add(violation_type)
        self.ip_violations[source_ip]['last_violation'] = time.time()
        
        # Check if IP should be blacklisted
        if self.ip_violations[source_ip]['count'] >= self.blacklist_threshold:
            self.blacklist.add(source_ip)
            self.ip_violations[source_ip]['blacklist_time'] = time.time()
            logging.warning(f"IP {source_ip} blacklisted due to multiple violations")

    def cleanup_old_entries(self):
        """Clean up old entries from violation tracking"""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            # Clean up old violations
            for ip in list(self.ip_violations.keys()):
                if current_time - self.ip_violations[ip]['last_violation'] > self.rate_limit_window:
                    del self.ip_violations[ip]
            
            # Clean up expired blacklist entries
            for ip in list(self.blacklist):
                if current_time - self.ip_violations.get(ip, {}).get('blacklist_time', 0) > self.blacklist_duration:
                    self.blacklist.remove(ip)
                    if ip in self.ip_violations:
                        del self.ip_violations[ip]
            
            self.last_cleanup = current_time

    def analyze_sip_message(self, message: str) -> Dict[str, Any]:
        """Enhanced analysis of SIP message for potential attacks"""
        analysis = {
            'is_attack': False,
            'attack_type': None,
            'details': {
                'matched_patterns': [],
                'suspicious_headers': [],
                'malformed_syntax': False
            }
        }
        
        # Check for malformed syntax
        if not message.endswith('\r\n\r\n'):
            analysis['is_attack'] = True
            analysis['attack_type'] = 'malformed'
            analysis['details']['malformed_syntax'] = True
            analysis['details']['reason'] = 'Missing message terminator'
            return analysis
        
        # Check for suspicious headers
        suspicious_headers = ['X-Attack', 'X-Exploit', 'X-Scan']
        for header in suspicious_headers:
            if header.lower() in message.lower():
                analysis['details']['suspicious_headers'].append(header)
        
        # Check all attack patterns
        for attack_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(message):
                    analysis['is_attack'] = True
                    analysis['attack_type'] = attack_type
                    analysis['details']['matched_patterns'].append(pattern.pattern)
        
        return analysis

    def update_attack_stats(self, source_ip: str, attack_type: str, details: Dict[str, Any]):
        """Update attack statistics"""
        self.attack_stats['total_attacks'] += 1
        
        # Update attack type counts
        if attack_type not in self.attack_stats['attack_types']:
            self.attack_stats['attack_types'][attack_type] = 0
        self.attack_stats['attack_types'][attack_type] += 1
        
        # Update top attackers
        if source_ip not in self.attack_stats['top_attackers']:
            self.attack_stats['top_attackers'][source_ip] = {
                'count': 0,
                'types': set(),
                'first_seen': time.time(),
                'last_seen': time.time()
            }
        
        self.attack_stats['top_attackers'][source_ip]['count'] += 1
        self.attack_stats['top_attackers'][source_ip]['types'].add(attack_type)
        self.attack_stats['top_attackers'][source_ip]['last_seen'] = time.time()
        
        # Add to timeline
        self.attack_stats['attack_timeline'].append({
            'timestamp': time.time(),
            'source_ip': source_ip,
            'attack_type': attack_type,
            'details': details
        })
        
        # Generate report if needed
        self.check_report_threshold()

    def check_report_threshold(self):
        """Check if we should generate a report"""
        current_time = time.time()
        if (current_time - self.last_report >= self.report_interval and 
            self.attack_stats['total_attacks'] >= self.report_threshold):
            self.generate_attack_report()
            self.last_report = current_time

    def generate_attack_report(self):
        """Generate a detailed attack report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_attacks': self.attack_stats['total_attacks'],
                'attack_types': self.attack_stats['attack_types'],
                'top_attackers': self.get_top_attackers(5),
                'recent_attacks': self.attack_stats['attack_timeline'][-10:]
            },
            'recommendations': self.generate_recommendations()
        }
        
        # Save report to file
        filename = f"attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        logging.info(f"Generated attack report: {filename}")
        return report

    def get_top_attackers(self, limit: int = 5) -> List[Dict]:
        """Get top attackers by attack count"""
        attackers = []
        for ip, data in self.attack_stats['top_attackers'].items():
            attackers.append({
                'ip': ip,
                'count': data['count'],
                'types': list(data['types']),
                'first_seen': datetime.fromtimestamp(data['first_seen']).isoformat(),
                'last_seen': datetime.fromtimestamp(data['last_seen']).isoformat()
            })
        
        return sorted(attackers, key=lambda x: x['count'], reverse=True)[:limit]

    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on attack patterns"""
        recommendations = []
        
        # Check for brute force patterns
        if self.attack_stats['attack_types'].get('brute_force', 0) > 0:
            recommendations.append(
                "Consider implementing stronger authentication mechanisms and "
                "rate limiting for authentication attempts"
            )
        
        # Check for scanning patterns
        if self.attack_stats['attack_types'].get('scanning', 0) > 0:
            recommendations.append(
                "Consider implementing IP-based access controls and "
                "monitoring for scanning patterns"
            )
        
        # Check for flood attacks
        if self.attack_stats['attack_types'].get('flood', 0) > 0:
            recommendations.append(
                "Consider implementing DDoS protection and "
                "connection rate limiting"
            )
        
        return recommendations

    def handle_sip_message(self, data: bytes, addr: tuple):
        """Enhanced handling of incoming SIP messages"""
        try:
            with self.thread_semaphore:  # Limit concurrent threads
                source_ip = addr[0]
                
                # Clean up old entries
                self.cleanup_old_entries()
                
                # Check blacklist
                if self.is_blacklisted(source_ip):
                    logging.warning(f"Blocked blacklisted IP: {source_ip}")
                    return
                
                # Check rate limiting
                if self.is_rate_limited(source_ip):
                    logging.warning(f"Rate limit exceeded for IP: {source_ip}")
                    self.update_violations(source_ip, 'rate_limit')
                    return
                
                # Validate message size
                if len(data) > self.max_message_size:
                    logging.warning(f"Message too large from {source_ip}: {len(data)} bytes")
                    self.update_violations(source_ip, 'message_size')
                    return
                
                try:
                    message = data.decode('utf-8')
                except UnicodeDecodeError:
                    logging.warning(f"Invalid UTF-8 encoding from {source_ip}")
                    self.update_violations(source_ip, 'encoding')
                    return
                
                # Log full message if not rate limited
                if not self.is_rate_limited(source_ip):
                    logging.info(f"Received SIP message from {source_ip}:{addr[1]}")
                    logging.info("Full message:")
                    for line in message.split('\r\n'):
                        logging.info(f"  {line}")
                else:
                    # Just log a summary for rate-limited IPs
                    logging.info(f"Received SIP message from rate-limited IP {source_ip}: {message[:200]}...")
                
                # Analyze for potential attacks
                analysis = self.analyze_sip_message(message)
                if analysis['is_attack']:
                    self.log_attack(source_ip, analysis['attack_type'], analysis['details'])
                    self.update_violations(source_ip, analysis['attack_type'])
                    self.update_attack_stats(source_ip, analysis['attack_type'], analysis['details'])
                
                # Generate appropriate response based on analysis
                response = self.generate_fake_response(message, analysis)
                try:
                    self.sock.sendto(response.encode('utf-8'), addr)
                    logging.info(f"Sent response to {source_ip}")
                except Exception as e:
                    logging.error(f"Failed to send response to {source_ip}: {str(e)}")
                
        except Exception as e:
            logging.error(f"Error handling message: {str(e)}")
            print(f"Error handling message: {str(e)}")

    def generate_fake_response(self, original_message: str, analysis: Dict[str, Any]) -> str:
        """Generate appropriate fake response based on message analysis"""
        try:
            # Parse original message headers
            headers = {}
            for line in original_message.split('\r\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Extract key information from original message
            method = original_message.split()[0]
            target = headers.get('To', '').strip('<>')
            source = headers.get('From', '').strip('<>')
            call_id = headers.get('Call-ID', '')
            cseq = headers.get('CSeq', '')
            via = headers.get('Via', '')
            
            # Generate realistic server details
            server_name = "Asterisk PBX 18.5.0"
            server_ip = self.config.get('bind_address', '0.0.0.0')
            server_port = self.config.get('port', 5060)
            
            # Generate realistic timestamps and tags
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            branch = f"z9hG4bK-{timestamp}"
            tag = f"{timestamp}-{hash(call_id) % 1000000}"
            
            if analysis['is_attack']:
                # For attacks, send a delayed response to waste attacker's time
                time.sleep(2)
                
                if analysis['attack_type'] == 'brute_force':
                    # For brute force attempts, pretend authentication failed with realistic challenge
                    nonce = f"{timestamp}-{hash(call_id) % 1000000}"
                    return (
                        f"SIP/2.0 401 Unauthorized\r\n"
                        f"Via: {via};received={server_ip};branch={branch}\r\n"
                        f"From: {source}\r\n"
                        f"To: {target};tag={tag}\r\n"
                        f"Call-ID: {call_id}\r\n"
                        f"{cseq}\r\n"
                        f"Server: {server_name}\r\n"
                        f"WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"{nonce}\", algorithm=MD5, qop=\"auth\"\r\n"
                        f"Content-Length: 0\r\n\r\n"
                    )
                elif analysis['attack_type'] == 'scanning':
                    # For scanning attempts, pretend server is busy with realistic retry time
                    retry_after = 3600 + (hash(call_id) % 1800)  # Random retry between 1-1.5 hours
                    return (
                        f"SIP/2.0 503 Service Unavailable\r\n"
                        f"Via: {via};received={server_ip};branch={branch}\r\n"
                        f"From: {source}\r\n"
                        f"To: {target};tag={tag}\r\n"
                        f"Call-ID: {call_id}\r\n"
                        f"{cseq}\r\n"
                        f"Server: {server_name}\r\n"
                        f"Retry-After: {retry_after}\r\n"
                        f"Warning: 399 {server_ip} \"System maintenance in progress\"\r\n"
                        f"Content-Length: 0\r\n\r\n"
                    )
                else:
                    # For other attacks, send a generic error with realistic details
                    return (
                        f"SIP/2.0 400 Bad Request\r\n"
                        f"Via: {via};received={server_ip};branch={branch}\r\n"
                        f"From: {source}\r\n"
                        f"To: {target};tag={tag}\r\n"
                        f"Call-ID: {call_id}\r\n"
                        f"{cseq}\r\n"
                        f"Server: {server_name}\r\n"
                        f"Warning: 399 {server_ip} \"Invalid message format\"\r\n"
                        f"Content-Length: 0\r\n\r\n"
                    )
            else:
                # For normal requests, send a success response with realistic details
                return (
                    f"SIP/2.0 200 OK\r\n"
                    f"Via: {via};received={server_ip};branch={branch}\r\n"
                    f"From: {source}\r\n"
                    f"To: {target};tag={tag}\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"{cseq}\r\n"
                    f"Server: {server_name}\r\n"
                    f"Contact: <sip:{server_ip}:{server_port}>\r\n"
                    f"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH\r\n"
                    f"Supported: replaces, timer\r\n"
                    f"Content-Length: 0\r\n\r\n"
                )
        except Exception as e:
            logging.error(f"Error generating response: {str(e)}")
            # Fallback to basic response if something goes wrong
            return (
                "SIP/2.0 500 Internal Server Error\r\n"
                "Via: SIP/2.0/UDP {client_ip}:{client_port}\r\n"
                "From: <sip:attacker@example.com>\r\n"
                "To: <sip:fake_pbx@example.com>\r\n"
                "Call-ID: fake-call-id\r\n"
                "CSeq: 1 INVITE\r\n"
                "Content-Length: 0\r\n\r\n"
            )

    def start(self):
        """Start the honeypot server"""
        bind_address = self.config.get('bind_address', '0.0.0.0')
        logging.info(f"Starting SIP honeypot on {bind_address}:{self.port}")
        print(f"\nStarting SIP honeypot on {bind_address}:{self.port}")
        print("Waiting for incoming SIP packets...")
        print("Press Ctrl+C to stop the server")
        
        try:
            while True:
                print("\nWaiting for packet...")
                data, addr = self.sock.recvfrom(self.max_message_size)
                print(f"\nReceived packet from {addr[0]}:{addr[1]}")
                print(f"Packet size: {len(data)} bytes")
                print(f"First 100 bytes: {data[:100]}")
                
                # Handle each connection in a separate thread
                thread = threading.Thread(
                    target=self.handle_sip_message,
                    args=(data, addr)
                )
                thread.daemon = True  # Make thread daemon so it exits when main thread exits
                thread.start()
        except KeyboardInterrupt:
            logging.info("Shutting down honeypot...")
            print("\nShutting down honeypot...")
            self.sock.close()
        except Exception as e:
            logging.error(f"Error in main loop: {str(e)}")
            print(f"\nError in main loop: {str(e)}")
            self.sock.close()
            raise

def main():
    """Main function to run the honeypot"""
    print("\n=== SIP Honeypot Module ===")
    print("Starting SIP honeypot server...")
    print("Press Ctrl+C to stop the server")
    
    try:
        honeypot = SIPHoneypot()
        honeypot.start()
    except KeyboardInterrupt:
        print("\nShutting down honeypot...")
    except Exception as e:
        print(f"\nError: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    main()
