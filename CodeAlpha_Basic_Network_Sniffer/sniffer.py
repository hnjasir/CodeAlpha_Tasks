from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime


def process_packet(packet):
    print("=" * 60)
    print(f"Time: {datetime.now()}")

    # Check if the packet contains an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")
        print(f"Packet Length  : {len(packet)} bytes")

        # TCP Packet
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Protocol Name  : TCP")
            print(f"Source Port    : {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")

        # UDP Packet
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Protocol Name  : UDP")
            print(f"Source Port    : {udp.sport}")
            print(f"Destination Port: {udp.dport}")

        # ICMP Packet
        elif packet.haslayer(ICMP):
            print("Protocol Name  : ICMP")

        # Display payload if present
        payload = bytes(packet.payload)

        if payload:
            print("\nPayload (first 64 bytes):")
            print(payload[:64])

    else:
        print("Non-IP Packet")


print("Starting Packet Sniffer...")
print("Press Ctrl+C to stop.\n")

sniff(prn=process_packet, store=False)