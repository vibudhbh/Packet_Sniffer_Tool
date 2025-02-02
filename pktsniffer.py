import argparse
import ipaddress
from scapy.all import rdpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP

def parse_arguments():

    parser = argparse.ArgumentParser(description='Packet Sniffer that reads a PCAP file and filters\prints packet details')
    parser.add_argument('-r', '--read', required=True, help='Path to the PCAP file')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to analyze')

    return parser.parse_args()

def print_packet_summary(index, pkt):

    print(f"\nPacket #{index}")
    print("-"*60)
    # Packet size
    print(f"Packet size: {len(pkt)} bytes")

    # Ethernet header
    if pkt.haslayer(Ether):
        ether = pkt[Ether]
        print("Ethernet Header:")
        print(f"Source MAC: {ether.src}")
        print(f"Destination MAC: {ether.dst}")
        print(f"EtherType: {hex(ether.type)}")
        print("-" * 60)

    # IP header
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        print("IP Header:")
        print(f"Version: {ip_layer.version}")
        print(f"Header Length: {ip_layer.ihl}")
        print(f"Type of Service: {ip_layer.tos}")
        print(f"Total Length: {ip_layer.len}")
        print(f"ID: {ip_layer.id}")
        print(f"Flags: {ip_layer.flags}")
        print(f"Fragment Offset: {ip_layer.frag}")
        print(f"Time to Live: {ip_layer.ttl}")
        print(f"Protocol: {ip_layer.proto}")
        print(f"Checksum: {ip_layer.chksum}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print("-" * 60)

    # TCP header
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        print("TCP Header:")
        print(f"Source Port: {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")
        print(f"Sequence Number: {tcp.seq}")
        print(f"Acknowledgment Number: {tcp.ack}")
        print(f"Flags: {tcp.flags}")
        print("-" * 60)

    # UDP header
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        print("UDP Header:")
        print(f"Source Port: {udp.sport}")
        print(f"Destination Port: {udp.dport}")
        print(f"Length: {udp.len}")
        print(f"Checksum: {udp.chksum}")
        print("-" * 60)

    # ICMP header
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        print("ICMP Header:")
        print(f"Type: {icmp.type}")
        print(f"Code: {icmp.code}")
        print(f"Checksum: {icmp.chksum}")
        print("-" * 60)


def main():

    #1 Get command line arguments
    args = parse_arguments()

    #2 Read the PCAP file
    packets = rdpcap(args.read)

    #3 Limit packets if -c is specified
    if args.count and args.count > 0:
        packets = packets[:args.count]

    #4 Print packet summary
    for index, pkt in enumerate(packets):
        print_packet_summary(index, pkt)

if __name__ == "__main__":
    main()


