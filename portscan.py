
import socket
import argparse
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Function to scan a single port
def scan_port(host, port, verbose=False):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"[+] Port {port:5d} is OPEN")
            elif verbose:
                print(f"[-] Port {port:5d} is closed")
    except socket.error as err:
        print(f"Socket error on port {port}: {err}")
    except Exception as e:
        print(f"Unexpected error on port {port}: {e}")

# Argument parser for command-line options
def parse_args():
    parser = argparse.ArgumentParser(description="Simple multithreaded port scanner.")
    parser.add_argument("host", help="Target host to scan (IP or domain name)")
    parser.add_argument("-p", "--ports", help="Port range, e.g., 1-1000 (default: 1-5000)", default="1-5000")
    parser.add_argument("-t", "--threads", help="Number of threads (default: 100)", type=int, default=100)
    parser.add_argument("-v", "--verbose", help="Verbose mode (shows closed ports too)", action="store_true")
    return parser.parse_args()

def main():
    args = parse_args()

    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Error: Could not resolve host '{args.host}'")
        sys.exit(1)

    # Parse port range
    try:
        port_start, port_end = map(int, args.ports.split("-"))
        if port_start < 1 or port_end > 65535 or port_start >= port_end:
            raise ValueError
    except ValueError:
        print("Error: Invalid port range. Use format like 1-1000.")
        sys.exit(1)

    print("\n" + "_" * 60)
    print(f"Scanning host: {args.host} ({target_ip})")
    print(f"Port range  : {port_start}-{port_end}")
    print(f"Threads     : {args.threads}")
    print(f"Verbose     : {'ON' if args.verbose else 'OFF'}")
    print("_" * 60 + "\n")

    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for port in range(port_start, port_end + 1):
            executor.submit(scan_port, target_ip, port, args.verbose)

    duration = datetime.now() - start_time
    print(f"\nScan completed in: {duration}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting.")
        sys.exit(0)
