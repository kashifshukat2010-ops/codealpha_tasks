#!/usr/bin/env python3
"""
Basic Network Sniffer — CodeAlpha Cyber Security Internship (Task 1)
--------------------------------------------------------------------
Captures live network traffic and displays useful per-packet information:
  * timestamp, protocol (TCP/UDP/ICMP)
  * source / destination IPs and ports
  * packet length and a short payload preview
At the end it prints a summary: protocol counts and top talker IPs.

Requirements:
  * Python 3
  * scapy  (install:  pip install scapy   OR   sudo apt install python3-scapy)
  * root privileges (run with sudo) — packet capture needs it.

Usage examples:
  sudo python3 sniffer.py                      # 20 packets, all IP traffic
  sudo python3 sniffer.py -c 50 -f tcp         # 50 TCP packets
  sudo python3 sniffer.py -i eth0 -f "port 80"  # HTTP-ish traffic on eth0
  sudo python3 sniffer.py --no-payload          # hide payload preview
"""

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
except ImportError:
    print("[!] scapy is not installed.")
    print("    Install it with:  pip install scapy")
    print("    or on Kali/Debian:  sudo apt install python3-scapy")
    raise SystemExit(1)

import argparse
from collections import Counter
from datetime import datetime

# Running counters for the end-of-capture summary
protocol_stats = Counter()
top_talkers = Counter()


def protocol_name(pkt):
    """Return a short protocol label for the packet."""
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "Other"


def ports_of(pkt):
    """Return (src_port, dst_port) or ('-', '-') when not TCP/UDP."""
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    if pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    return "-", "-"


def payload_preview(pkt, max_bytes=64):
    """Return a printable preview of the packet payload."""
    if not pkt.haslayer(Raw):
        return None
    raw = bytes(pkt[Raw].load)
    head = raw[:max_bytes]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in head)
    return len(raw), text


def handle_packet(pkt, show_payload):
    """Called by scapy for every captured packet: analyse + display it."""
    if not pkt.haslayer(IP):      # we only analyse IPv4 packets here
        return

    ip = pkt[IP]
    proto = protocol_name(pkt)
    sport, dport = ports_of(pkt)
    ts = datetime.now().strftime("%H:%M:%S")

    # Main one-line summary of the packet
    print(f"[{ts}] {proto:5} {ip.src}:{sport} -> {ip.dst}:{dport}  len={len(pkt)}")

    # Optional payload peek — shows what data is actually travelling
    if show_payload:
        prev = payload_preview(pkt)
        if prev:
            total, text = prev
            print(f"       payload({total}B): {text}")

    protocol_stats[proto] += 1
    top_talkers[ip.src] += 1


def print_summary():
    print("\n===== Capture Summary =====")
    print("Packets by protocol:")
    for proto, count in protocol_stats.most_common():
        print(f"  {proto:5} : {count}")
    print("Top talker IPs:")
    for ip, count in top_talkers.most_common(5):
        print(f"  {ip} : {count} packets")


def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer — CodeAlpha Cyber Security Task 1")
    parser.add_argument("-i", "--iface", default=None,
                        help="interface to sniff on (default: scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=20,
                        help="how many packets to capture (default: 20)")
    parser.add_argument("-f", "--filter", default="ip",
                        help="BPF filter, e.g. 'tcp', 'udp', 'icmp', 'port 80' (default: 'ip')")
    parser.add_argument("--no-payload", action="store_true",
                        help="hide the payload preview lines")
    args = parser.parse_args()

    print(f"[*] Sniffing on {args.iface or 'default interface'} "
          f"| filter='{args.filter}' | count={args.count}")
    print("[*] Press Ctrl+C to stop early\n")

    try:
        sniff(iface=args.iface,
              filter=args.filter,
              prn=lambda p: handle_packet(p, not args.no_payload),
              count=args.count,
              store=False)          # store=False keeps memory usage low
    except PermissionError:
        print("[!] Permission denied — run with sudo:  sudo python3 sniffer.py")
        return
    except OSError as e:
        print(f"[!] Capture failed: {e}")
        print("    Tip: run with sudo and check the interface name.")
        return
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")

    print_summary()


if __name__ == "__main__":
    main()
