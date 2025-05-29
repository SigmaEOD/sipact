# SIPACT - SIP Testing Toolkit

SIPACT is a comprehensive toolkit for testing and analyzing SIP (Session Initiation Protocol) implementations. It provides various modules for different testing scenarios.

## Modules

### 1. SIP Mass Scanner (`sipmass`)
- Scans IP ranges for SIP servers
- Supports multiple scanning methods (OPTIONS, REGISTER, etc.)
- Multi-threaded scanning capabilities
- Configurable scanning parameters
- Real-time progress tracking
- Space bar to stop scanning

### 2. SIP Registration Scanner (`sipregister`)
- Tests SIP registration credentials
- Multi-threaded credential testing
- Support for username/password wordlists
- Configurable authentication parameters
- Real-time progress tracking
- Space bar to stop scanning

### 3. SIP Sniffer (`sipsniff`)
- Captures and analyzes SIP traffic
- Real-time packet inspection
- Protocol analysis capabilities
- Space bar to stop sniffing

### 4. SIP DoS Module (`sipdos`)
- Tests SIP server resilience
- Configurable attack parameters
- Multiple attack vectors
- Space bar to stop attack

### 5. SIP Fuzzer (`sipfuzz`)
- Tests SIP implementation robustness
- Multiple fuzzing strategies:
  - Basic Fuzzing
  - Header Fuzzing
  - Method Fuzzing
  - Parameter Fuzzing
- Real-time statistics tracking
- Configurable fuzzing parameters

### 6. SIP Brute Force (`sipbrute`)
- Simple credential testing
- Support for username/password wordlists
- Basic authentication testing

## Configuration

Each module has its own configuration file located in its respective `config` directory. Configuration files use a simple `key::value` format.

## Requirements

- Python 3.x
- Required Python packages:
  - tabulate
  - tqdm
  - requests
  - scapy (for sniffing)

## Usage

1. Run the main script:
```bash
python main.py
```

2. Select a module from the menu
3. Configure the module parameters
4. Start the test/scan

## Features

- Modular design
- Configurable parameters
- Multi-threading support
- Real-time progress tracking
- Space bar to stop operations
- Comprehensive error handling
- User-friendly interface

## Note

This tool is for testing and educational purposes only. Always ensure you have proper authorization before testing any SIP systems.

## License

[Your License Here]
