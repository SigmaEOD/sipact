#!/usr/bin/env python3

import socket
import threading
import time
from functions.func import get_local_ip, get_free_port, parse_message

class SipProxy:
    def __init__(self, config):
        self.config = config
        self.running = False
        self.local_ip = get_local_ip()
        self.local_port = get_free_port()
        
    def start(self):
        self.running = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((self.local_ip, self.local_port))
        print(f"[*] SIP Proxy listening on {self.local_ip}:{self.local_port}")
        
        while self.running:
            try:
                data, addr = self.server.recvfrom(4096)
                threading.Thread(target=self.handle_request, args=(data, addr)).start()
            except Exception as e:
                if self.running:
                    print(f"Error: {e}")
                break
                
    def handle_request(self, data, addr):
        try:
            message = data.decode('utf-8')
            parsed = parse_message(message)
            print(f"[*] Received {parsed['method']} from {addr[0]}:{addr[1]}")
            # Forward to target
            target = (self.config['target_ip'], int(self.config['target_port']))
            self.server.sendto(data, target)
        except Exception as e:
            print(f"Error handling request: {e}")
            
    def stop(self):
        self.running = False
        try:
            self.server.close()
        except:
            pass

def main():
    config = {
        'target_ip': '127.0.0.1',
        'target_port': '5060'
    }
    
    proxy = SipProxy(config)
    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\n[*] Stopping proxy...")
        proxy.stop()
