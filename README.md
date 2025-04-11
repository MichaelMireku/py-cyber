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
