import argparse
import ipaddress
from email.policy import strict

from scapy.all import rdpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP

def parse_arguments():

    parser = argparse.ArgumentParser(description='Packet Sniffer that reads a PCAP file and filters or prints packet details')
    parser.add_argument('-r', '--read', required=True, help='Path to the PCAP file')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to analyze')
    parser.add_argument('-host', help='Filter by specific host IP address')
    parser.add_argument('-port', type=int, help='Filter by specific port number')
    parser.add_argument('-ip', action='store_true', help='Show only IP packets')
    parser.add_argument('-tcp', action='store_true', help='Show only TCP packets')
    parser.add_argument('-udp', action='store_true', help='Show only UDP packets')
    parser.add_argument('-icmp', action='store_true', help='Show only ICMP packets')
    parser.add_argument('-net', help='Filter by specific network address')

    return parser.parse_args()

def packet_filter(pkt, args):

    #IP-only filter
    if args.ip and not pkt.haslayer(IP):
        return False

    #TCP-only filter
    if args.tcp and not pkt.haslayer(TCP):
        return False

    #UDP-only filter
    if args.udp and not pkt.haslayer(UDP):
        return False

    #ICMP-only filter
    if args.icmp and not pkt.haslayer(ICMP):
        return False

    #Host filter
    if args.host:
        if not pkt.haslayer(IP):
            return False
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if args.host not in (src_ip, dst_ip):
            return False

    #Port filter
    if args.port:
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            if (tcp_layer.sport != args.port) and (tcp_layer.dport != args.port):
                return False
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            if (udp_layer.sport != args.port) and (udp_layer.dport != args.port):
                return False
        else:
            return False

    #Network filter (assume /24 unless user modifies logic)
    if args.net:
        if not pkt.haslayer(IP):
            return False
        try:
            # convert user provided network into a /24
            net = ipaddress.ip_network(args.net+'/24', strict=False)
            src_ip = ipaddress.ip_address(pkt[IP].src)
            dst_ip = ipaddress.ip_address(pkt[IP].dst)
            if not (src_ip in net or dst_ip in net):
                return False
        except ValueError:
            # Invalid network address
            return False

    return True


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


    # TCP header
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        print("TCP Header:")
        print(f"Source Port: {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")
        print(f"Sequence Number: {tcp.seq}")
        print(f"Acknowledgment Number: {tcp.ack}")
        print(f"Flags: {tcp.flags}")


    # UDP header
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        print("UDP Header:")
        print(f"Source Port: {udp.sport}")
        print(f"Destination Port: {udp.dport}")
        print(f"Length: {udp.len}")
        print(f"Checksum: {udp.chksum}")


    # ICMP header
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        print("ICMP Header:")
        print(f"Type: {icmp.type}")
        print(f"Code: {icmp.code}")
        print(f"Checksum: {icmp.chksum}")



def main():

    #1 Get command line arguments
    args = parse_arguments()

    #2 Read the PCAP file
    packets = rdpcap(args.read)

    #3 Limit packets if -c is specified (used for debugging)
    if args.count and args.count > 0:
        packets = packets[:args.count]

    #4 Filter packets
    filtered_packets = [pkt for pkt in packets if packet_filter(pkt, args)]

    #5 Print packet summary for each packet that passes the filter
    for index, pkt in enumerate(filtered_packets, start=1):
        print_packet_summary(index, pkt)

if __name__ == "__main__":
    main()


