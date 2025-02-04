# Packet Sniffer

## Overview
`pktsniffer.py` is a Python-based packet sniffer that reads `.pcap` files and analyzes network traffic by displaying Ethernet, IP, TCP, UDP, and ICMP headers. It includes filtering options to focus on specific packet types, host IP addresses, ports, and networks.

## Requirements

### Prerequisites
Ensure you have Python 3 installed along with the required dependencies:

```sh
pip install scapy
```

## How to Compile and Run

### Running the Packet Sniffer
To run the packet sniffer, execute the following command:

```sh
python pktsniffer.py -r <pcap_file> [options]
```

Where `<pcap_file>` is the path to the `.pcap` file you want to analyze.

## Command-Line Usage Examples

### 1. Analyze All Packets in a `.pcap` File
```sh
python pktsniffer.py -r traffic.pcap
```

### 2. Show Only TCP Traffic
```sh
python pktsniffer.py -r traffic.pcap -tcp
```

### 3. Show Traffic From or To a Specific Host
```sh
python pktsniffer.py -r traffic.pcap -host 192.168.1.1
```

### 4. Filter by Port Number
```sh
python pktsniffer.py -r traffic.pcap -port 80
```

### 5. Analyze a Limited Number of Packets (e.g., First 10 Packets)
```sh
python pktsniffer.py -r traffic.pcap -c 10
```

### 6. Filter by Network Address
```sh
python pktsniffer.py -r traffic.pcap -net 192.168.1.0/24
```

### 7. Show Only IP Packets
```sh
python pktsniffer.py -r traffic.pcap -ip
```

### 8. Show Only UDP Packets
```sh
python pktsniffer.py -r traffic.pcap -udp
```

### 9. Show Only ICMP Packets
```sh
python pktsniffer.py -r traffic.pcap -icmp
```



## Notes
- If an invalid network address is provided, the script will discard the filter.
- If multiple filters are specified, packets must match **all** criteria to be displayed.


