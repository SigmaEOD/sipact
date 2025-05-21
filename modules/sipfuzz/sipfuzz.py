#!/usr/bin/env python3

import os
import time
from typing import Dict, Any
from functions.config_parser import parse_config, save_config

class SipFuzzer:
    def __init__(self):
        self.module_name = 'sipfuzz'
        self.config = parse_config(self.module_name)
        self.stats = {
            'requests_sent': 0,
            'responses_received': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None
        }

    def display_stats(self):
        """Display current statistics in a table format."""
        if self.stats['start_time']:
            duration = time.time() - self.stats['start_time']
            duration_str = f"{duration:.2f}s"
        else:
            duration_str = "N/A"
            
        print("\nCurrent Statistics:")
        print("+------------------+------------------+")
        print("| Statistic        | Value            |")
        print("+------------------+------------------+")
        print(f"| Requests Sent    | {self.stats['requests_sent']:<16} |")
        print(f"| Responses        | {self.stats['responses_received']:<16} |")
        print(f"| Errors          | {self.stats['errors']:<16} |")
        print(f"| Duration        | {duration_str:<16} |")
        print("+------------------+------------------+")

    def display_attack_types(self):
        """Display available attack types."""
        print("\nAvailable Attack Types:")
        print("+------------------+------------------+")
        print("| ID              | Attack Type      |")
        print("+------------------+------------------+")
        print("| 1               | Basic Fuzzing    |")
        print("| 2               | Header Fuzzing   |")
        print("| 3               | Method Fuzzing   |")
        print("| 4               | Parameter Fuzzing|")
        print("+------------------+------------------+")

    def start_attack(self, attack_type: int):
        """Start the selected attack type."""
        self.stats['start_time'] = time.time()
        self.stats['requests_sent'] = 0
        self.stats['responses_received'] = 0
        self.stats['errors'] = 0
        
        print(f"\nStarting Attack Type {attack_type}...")
        print(f"Target: {self.config.get('ip_addr')}:{self.config.get('port')}/{self.config.get('proto')}")
        
        try:
            # Add your attack logic here based on attack_type
            # This is where you'd implement the actual fuzzing
            pass
            
        except KeyboardInterrupt:
            print("\nAttack interrupted by user.")
        finally:
            self.stats['end_time'] = time.time()
            self.display_stats()

def main():
    """Main entry point for the SIP fuzzer module."""
    print("SIP Fuzzer Module")
    print("----------------")
    
    fuzzer = SipFuzzer()
    
    while True:
        print("\nOptions:")
        print("1. Show Statistics")
        print("2. Start Attack")
        print("3. Return to Main Menu")
        
        try:
            choice = input("\nSelect an option: ").strip()
            
            if choice == '1':
                fuzzer.display_stats()
            elif choice == '2':
                fuzzer.display_attack_types()
                attack_type = input("\nSelect attack type (1-4): ").strip()
                if attack_type in ['1', '2', '3', '4']:
                    fuzzer.start_attack(int(attack_type))
                else:
                    print("Invalid attack type!")
            elif choice == '3':
                return True
            else:
                print("Invalid option. Please try again.")
                
        except KeyboardInterrupt:
            print("\nReturning to main menu...")
            return True

if __name__ == "__main__":
    main() 