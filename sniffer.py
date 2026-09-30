#!/usr/bin/env python3
"""
CodeAlpha Task 1 - Basic Network Sniffer
Captures packets with scapy and shows source/destination IPs,
protocol, ports and payload.

Usage (root lazımdır):
    sudo python3 sniffer.py                      # bütün paketlər
    sudo python3 sniffer.py -i eth0 -c 50        # eth0, 50 paket
    sudo python3 sniffer.py -f "tcp port 80"     # BPF filter
    sudo python3 sniffer.py -o capture.pcap      # pcap faylına yaz

Yalnız öz maşınınızda / icazəniz olan şəbəkədə istifadə edin.
"""

import argparse
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, Raw

captured = []

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def format_payload(packet, max_len=60):
    """Payload-ı oxunaqlı formada göstərir."""
    if packet.haslayer(Raw):
        data = bytes(packet[Raw].load)[:max_len]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return f"{text}  ({len(packet[Raw].load)} bytes)"
    return "-"


def process_packet(packet):
    captured.append(packet)
    now = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(ARP):
        arp = packet[ARP]
        print(f"[{now}] ARP  {arp.psrc} -> {arp.pdst}  (op={arp.op})")
        return

    if packet.haslayer(IP):
        ip = packet[IP]
        src, dst = ip.src, ip.dst
        proto = PROTOCOLS.get(ip.proto, f"OTHER({ip.proto})")
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        src, dst = ip6.src, ip6.dst
        proto = f"IPv6/{ip6.nh}"
    else:
        return

    ports = ""
    if packet.haslayer(TCP):
        ports = f"{packet[TCP].sport} -> {packet[TCP].dport}  flags={packet[TCP].flags}"
    elif packet.haslayer(UDP):
        ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
    elif packet.haslayer(ICMP):
        ports = f"type={packet[ICMP].type} code={packet[ICMP].code}"

    print(f"[{now}] {proto:<5} {src} -> {dst}  {ports}")
    print(f"           payload: {format_payload(packet)}")


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer")
    parser.add_argument("-i", "--interface", help="şəbəkə interfeysi (məs. eth0)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="paket sayı (0 = dayandırana qədər)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter (məs. 'tcp port 80')")
    parser.add_argument("-o", "--output", help="pcap faylına saxla")
    args = parser.parse_args()

    print("Sniffer başladı... dayandırmaq üçün Ctrl+C\n")
    try:
        sniff(iface=args.interface, filter=args.filter or None,
              prn=process_packet, count=args.count, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Xəta: sudo ilə işlədin.")
        return

    print(f"\nCəmi {len(captured)} paket tutuldu.")
    if args.output and captured:
        wrpcap(args.output, captured)
        print(f"Paketlər {args.output} faylına yazıldı (Wireshark ilə aça bilərsiniz).")


if __name__ == "__main__":
    main()
