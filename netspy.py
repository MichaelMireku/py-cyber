import socket
import struct
import argparse
import sys
import os
import textwrap
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

def get_mac_addr(mac_raw):
    return ':'.join(format(b, '02x') for b in mac_raw)

def ipv4(addr):
    return '.'.join(map(str, addr))

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(b) for b in string)
        if size % 4: size += 4 - size % 4
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.ntohs(proto), data[14:]

def ipv4_packet(data):
    version_header_len = data[0]
    header_length = (version_header_len & 15) * 4
    proto = data[9]
    src = ipv4(data[12:16])
    target = ipv4(data[16:20])
    return proto, src, target, data[header_length:]

def tcp_segment(data):
    src_port, dest_port = struct.unpack('! H H', data[:4])
    return src_port, dest_port, data[20:]

def udp_segment(data):
    src_port, dest_port = struct.unpack('! H H', data[:4])
    return src_port, dest_port, data[8:]

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def arp_packet(data):
    htype, ptype, hlen, plen, operation = struct.unpack('! H H B B H', data[:8])
    src_mac = get_mac_addr(data[8:14])
    src_ip = ipv4(data[14:18])
    dest_mac = get_mac_addr(data[18:24])
    dest_ip = ipv4(data[24:28])
    return htype, ptype, hlen, plen, operation, src_mac, src_ip, dest_mac, dest_ip

def sniff(args):
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        if args.interface:
            conn.bind((args.interface, 0))
    except PermissionError:
        sys.exit("Run with sudo/admin privileges.")

    print(Fore.YELLOW + "[*] Packet sniffer started. Press Ctrl+C to stop.\n")

    count = 0
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if args.protocol and args.protocol != 'ALL':
            if args.protocol == 'ARP' and eth_proto != ETH_P_ARP:
                continue
            if args.protocol != 'ARP' and eth_proto != ETH_P_IP:
                continue

        print(Fore.CYAN + f"[+] Ethernet Frame {count + 1}")
        print(f"{Style.BRIGHT}    - Source MAC: {Fore.GREEN}{src_mac} {Style.RESET_ALL}| Destination MAC: {Fore.RED}{dest_mac}")
        print(f"{Style.BRIGHT}    - Protocol: {Fore.MAGENTA}{eth_proto}")

        if eth_proto == ETH_P_IP:
            ip_proto, src_ip, dest_ip, ip_data = ipv4_packet(data)
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip_proto, "Other")
            print(f"{Fore.BLUE}    - IPv4 Packet: {Fore.GREEN}{src_ip}{Fore.RESET} -> {Fore.RED}{dest_ip} {Fore.YELLOW}| Protocol: {proto_name}")

            if args.protocol in ['TCP', 'ALL'] and ip_proto == IP_PROTO_TCP:
                src_port, dest_port, payload = tcp_segment(ip_data)
                print(f"{Fore.MAGENTA}        - TCP Segment: {src_port} -> {dest_port}")

            elif args.protocol in ['UDP', 'ALL'] and ip_proto == IP_PROTO_UDP:
                src_port, dest_port, payload = udp_segment(ip_data)
                print(f"{Fore.CYAN}        - UDP Segment: {src_port} -> {dest_port}")

            elif args.protocol in ['ICMP', 'ALL'] and ip_proto == IP_PROTO_ICMP:
                icmp_type, code, checksum, icmp_data = icmp_packet(ip_data)
                print(f"{Fore.LIGHTBLUE_EX}        - ICMP Packet: Type={icmp_type}, Code={code}, Checksum={checksum}")
                payload = icmp_data
            else:
                payload = ip_data

            if args.payload:
                print(Fore.LIGHTBLACK_EX + format_multi_line("        - Payload: ", payload))

        elif eth_proto == ETH_P_ARP:
            htype, ptype, hlen, plen, operation, smac, sip, dmac, dip = arp_packet(data)
            print(Fore.YELLOW + "    - ARP Packet:")
            print(f"{Fore.LIGHTGREEN_EX}        - Operation: {operation}")
            print(f"{Style.BRIGHT}        - Sender: {smac} ({sip}) -> Target: {dmac} ({dip})")

        count += 1
        if args.count and count >= args.count:
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Packet Sniffer with Colorized Output")
    parser.add_argument("-i", "--interface", help="Network interface (e.g., eth0, wlan0)")
    parser.add_argument("-p", "--protocol", choices=["TCP", "UDP", "ICMP", "ARP", "ALL"], default="ALL", help="Protocol filter")
    parser.add_argument("-c", "--count", type=int, help="Packet capture limit")
    parser.add_argument("--payload", action="store_true", help="Display packet payload in hex")

    args = parser.parse_args()
    sniff(args)
