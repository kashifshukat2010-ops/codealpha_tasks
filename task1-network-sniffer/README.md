# Basic Network Sniffer 🐍📡

**CodeAlpha — Cyber Security Internship, Task 1**

A Python program that captures live network traffic and analyses each packet:
source/destination IPs, protocol (TCP/UDP/ICMP), ports, packet length and a short
payload preview — plus a summary of protocol counts and top talker IPs.

## Requirements

- Python 3
- `scapy` — `pip install scapy` (or `sudo apt install python3-scapy` on Kali/Debian)
- Root privileges (packet capture needs them) → run with `sudo`

## Usage

```bash
sudo python3 sniffer.py                       # 20 packets, all IP traffic
sudo python3 sniffer.py -c 50 -f tcp          # 50 TCP packets only
sudo python3 sniffer.py -i eth0 -f "port 80"  # web traffic on eth0
sudo python3 sniffer.py --no-payload          # hide payload preview
```

| Option | Meaning |
|---|---|
| `-i / --iface` | Network interface to listen on (default: scapy's default) |
| `-c / --count` | How many packets to capture (default: 20) |
| `-f / --filter` | BPF filter — e.g. `tcp`, `udp`, `icmp`, `port 443` |
| `--no-payload` | Hide the payload preview lines |

## Sample output

```
[*] Sniffing on default interface | filter='ip' | count=20
[*] Press Ctrl+C to stop early

[14:02:11] TCP   192.168.1.10:443 -> 192.168.1.5:51234  len=66
[14:02:11] UDP   192.168.1.5:53 -> 8.8.8.8:53  len=74
       payload(32B): ........example.com............
[14:02:12] ICMP  192.168.1.5:- -> 192.168.1.1:-  len=98

===== Capture Summary =====
Packets by protocol:
  TCP   : 14
  UDP   : 5
  ICMP  : 1
Top talker IPs:
  192.168.1.5 : 12 packets
  192.168.1.10 : 6 packets
```

## How it works

1. `scapy.sniff()` puts the interface into capture mode and hands every packet
   matching the BPF filter to `handle_packet()`.
2. `handle_packet()` checks for an IPv4 layer, identifies the protocol
   (TCP/UDP/ICMP), extracts source/destination IPs and ports, and prints a
   one-line summary plus an optional printable payload preview.
3. Counters track protocol distribution and per-IP packet counts, printed as a
   summary when the capture ends. `store=False` keeps memory usage low.

## What this demonstrates (task requirements)

- ✅ Packet capture with `scapy`
- ✅ Packet structure analysis (IP/TCP/UDP/ICMP layers)
- ✅ Data flow observation — who talks to whom
- ✅ Protocol basics in practice
- ✅ Useful output: src/dst IPs, protocols, ports, payloads

## Notes

- Only IPv4 packets are analysed in this basic version.
- Payload preview shows the first 64 bytes with non-printable bytes as `.`
- For learning only — capture traffic on networks you own or have permission to monitor.
