# Python Cybersecurity Tools

This repository contains a collection of Python-based cybersecurity tools for various purposes, including hash cracking, port scanning, and packet sniffing.

## Tools Overview

### 1. Hashcracker
A tool for cracking hashed passwords using a wordlist.

- **File**: [Hashcracker.py](Hashcracker.py)
- **Features**:
  - Supports multiple hash algorithms: MD5, SHA1, SHA224, SHA256, SHA384, SHA512.
  - Progress tracking with `tqdm`.
  - Option to save cracked passwords to a file.
  - Verbose mode for debugging skipped lines.

- **Usage**:
  ```bash
  python Hashcracker.py -h <hash_value> -t <hash_type> [-w <wordlist_path>] [--ignore-case] [--verbose] [--save]

  ```

Example:
```
python Hashcracker.py -h 5d41402abc4b2a76b9719d911017c592 -t md5 -w password.txt --verbose --save
```

### 2. Port Scanner
A multithreaded port scanner to identify open ports on a target host.

- **File**: portscan.py
- **Features**:
    - Scans a range of ports on a target host.
    - Multithreaded for faster scanning.
    - Verbose mode to display closed ports.

- **Usage**:
```
python portscan.py <host> [-p <port_range>] [-t <threads>] [-v]
```

Example:
```
python portscan.py 192.168.1.1 -p 1-1000 -t 50 -v
```

### 3. Packet Sniffer
A packet sniffer for capturing and analyzing network traffic.

- **File**: netspy.py
- **Features**:
    - Captures Ethernet, IPv4, TCP, UDP, ICMP, and ARP packets.
    - Filters packets by protocol.
    = Displays packet payloads in hex format.

- **Usage**:
```
python netspy.py [-i <interface>] [-p <protocol>] [-c <count>] [--payload]
```

Example:
```
python netspy.py -i eth0 -p TCP --payload
```

Requirements
Python 3.6 or higher
Install dependencies:
```
pip install -r requirements.txt
```

Dependencies
colorama: For colorized terminal output.
tqdm: For progress bars in Hashcracker.py.
Notes
Hashcracker: Ensure the wordlist file exists and is accessible.
Port Scanner: Requires network access to the target host.
Packet Sniffer: Requires root/admin privileges to capture packets.
License
This project is licensed under the MIT License. See the LICENSE file for details.

Author
Developed by Michael Mireku.