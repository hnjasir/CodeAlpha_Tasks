## 💻 Source Code

<details>
<summary><b>Click to expand and view the full Python sniffer code</b></summary>

```python
import socket
import struct
import textwrap

def get_mac_addr(bytes_addr):
    """Format binary MAC address into readable string (XX:XX:XX:XX:XX:XX)."""
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ethernet_frame(data):
    """Unpack Ethernet Frame (Layer 2)."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def format_ipv4(addr):
    """Format binary IP address into dot-decimal string."""
    return '.'.join(map(str, addr))

def ipv4_packet(data):
    """Unpack IPv4 Packet (Layer 3)."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ipv4(src), format_ipv4(target), data[header_length:]

def icmp_packet(data):
    """Unpack ICMP Packet."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    """Unpack TCP Segment (Layer 4)."""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    """Unpack UDP Segment (Layer 4)."""
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    """Format and wrap raw byte payloads into multi-line strings."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    # Cross-platform raw socket binding (Linux AF_PACKET vs Windows AF_INET)
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        is_linux = True
    except (AttributeError, OSError):
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((socket.gethostbyname(socket.gethostname()), 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        is_linux = False

    print("[*] Sniffer engine active. Capturing raw traffic... (Press Ctrl+C to terminate)\n")

    try:
        while True:
            raw_data, _ = conn.recvfrom(65536)

            # Process Ethernet Frame on Linux/Unix systems
            if is_linux:
                dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
                print('=' * 80)
                print("[+] ETHERNET FRAME")
                print(f"    ├── Destination MAC : {dest_mac}")
                print(f"    ├── Source MAC      : {src_mac}")
                print(f"    └── Protocol        : {eth_proto}")
            else:
                data = raw_data
                eth_proto = 8  # Default IPv4 handling for Windows raw sockets

            # IPv4 Protocol Handling
            if eth_proto == 8:
                version, header_length, ttl, proto, src, target, payload = ipv4_packet(data)
                print("\n    [+] IPv4 PACKET")
                print(f"        ├── Version     : {version}")
                print(f"        ├── Header Len  : {header_length} Bytes")
                print(f"        ├── TTL         : {ttl}")
                print(f"        ├── Protocol    : {proto}")
                print(f"        ├── Source IP   : {src}")
                print(f"        └── Target IP   : {target}")

                # ICMP (Protocol 1)
                if proto == 1:
                    icmp_type, code, checksum, icmp_payload = icmp_packet(payload)
                    print("\n        [+] ICMP PACKET")
                    print(f"            ├── Type     : {icmp_type}")
                    print(f"            ├── Code     : {code}")
                    print(f"            └── Checksum : {checksum}")
                    if icmp_payload:
                        print("\n        [+] PAYLOAD DATA:")
                        print(format_multi_line("            ", icmp_payload))

                # TCP (Protocol 6)
                elif proto == 6:
                    src_port, dest_port, sequence, ack, offset, urg, flags_ack, psh, rst, syn, fin, tcp_payload = tcp_segment(payload)
                    print("\n        [+] TCP SEGMENT")
                    print(f"            ├── Source Port : {src_port}")
                    print(f"            ├── Dest Port   : {dest_port}")
                    print(f"            ├── Sequence    : {sequence}")
                    print(f"            ├── Ack         : {ack}")
                    print(f"            └── Flags       : URG={urg}, ACK={flags_ack}, PSH={psh}, RST={rst}, SYN={syn}, FIN={fin}")
                    if tcp_payload:
                        print("\n        [+] PAYLOAD DATA:")
                        print(format_multi_line("            ", tcp_payload))

                # UDP (Protocol 17)
                elif proto == 17:
                    src_port, dest_port, length, udp_payload = udp_segment(payload)
                    print("\n        [+] UDP SEGMENT")
                    print(f"            ├── Source Port : {src_port}")
                    print(f"            ├── Dest Port   : {dest_port}")
                    print(f"            └── Length      : {length}")
                    if udp_payload:
                        print("\n        [+] PAYLOAD DATA:")
                        print(format_multi_line("            ", udp_payload))

                # Other Protocols
                else:
                    if payload:
                        print("\n        [+] RAW PAYLOAD:")
                        print(format_multi_line("            ", payload))

    except KeyboardInterrupt:
        print("\n[*] Shutting down sniffer gracefully...")
        if not is_linux:
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()
