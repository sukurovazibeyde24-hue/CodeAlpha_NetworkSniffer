# CodeAlpha Network Sniffer

Basic network sniffer written in Python using Scapy.
It captures network packets and displays source/destination IPs,
protocols, ports and payloads.

## Requirements
- Python 3
- Scapy (`sudo apt install python3-scapy`)
- Root privileges

## Usage
sudo python3 sniffer.py -c 20
sudo python3 sniffer.py -i eth0 -f "tcp port 80"
sudo python3 sniffer.py -c 30 -o capture.pcap

## Options
- `-i`  network interface
- `-c`  number of packets to capture
- `-f`  BPF filter
- `-o`  save packets to a .pcap file

For educational use only. Run it only on networks you own or have permission to test.
