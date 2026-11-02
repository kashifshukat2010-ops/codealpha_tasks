#!/usr/bin/env python3
"""
Simple Network Intrusion Detection System — CodeAlpha Cyber Security (Task 4)
-----------------------------------------------------------------------------
Watches live traffic and raises alerts for suspicious activity:

  1. PORT SCAN      — one IP touches many ports in a short window
  2. SYN FLOOD      — burst of SYN packets toward one host (DoS pattern)
  3. ICMP FLOOD     — burst of ping packets (ping flood / sweep pattern)
  4. RISKY PORTS    — connection attempts to commonly-abused ports
                      (23 telnet, 2323, 445 SMB, 135 RPC, 3389 RDP)

Alerts print to the console and are appended to alerts.log as JSON lines,
so they can be reviewed later or fed into a dashboard.

Requirements:
  * Python 3, scapy  (pip install scapy  /  sudo apt install python3-scapy)
  * root privileges → run with sudo

Usage:
  sudo python3 nids.py
  sudo python3 nids.py -i eth0 --log myalerts.log
"""

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    print("[!] scapy is not installed.")
    print("    Install it with:  pip install scapy")
    print("    or on Kali/Debian:  sudo apt install python3-scapy")
    raise SystemExit(1)

import argparse
import json
import time
from collections import defaultdict, deque
from datetime import datetime

# ---------------------------------------------------------------------------
# Tuning — thresholds for the detectors (events per time window)
# ---------------------------------------------------------------------------
PORTSCAN_PORTS = 15     # distinct ports from one IP in 10s  -> port scan
PORTSCAN_WINDOW = 10

SYNFLOOD_COUNT = 50     # SYN packets to one host in 5s      -> SYN flood
SYNFLOOD_WINDOW = 5

ICMPFLOOD_COUNT = 30    # ICMP packets from one IP in 5s     -> ICMP flood
ICMPFLOOD_WINDOW = 5

RISKY_PORTS = {23, 2323, 135, 445, 3389}   # telnet, alt-telnet, RPC, SMB, RDP

# Sliding-window event stores: key -> deque of timestamps
portscan_hits = defaultdict(deque)   # src_ip -> deque[(timestamp, dst_port)]
syn_hits = defaultdict(deque)        # dst_ip -> deque[timestamp]
icmp_hits = defaultdict(deque)       # src_ip -> deque[timestamp]

# Remember what we already alerted on, so we don't spam one alert per packet
alerted = set()

LOG_FILE = "alerts.log"


def now():
    return time.time()


def prune(dq, window):
    """Drop timestamps older than <window> seconds from the left of the deque."""
    cutoff = now() - window
    while dq and dq[0] < cutoff:
        dq.popleft()


def raise_alert(alert_type, severity, src, dst, detail):
    """Print an alert and append it to the log file (JSON lines)."""
    key = (alert_type, src, dst)
    if key in alerted:          # one alert per attacker/victim pair per run
        return
    alerted.add(key)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
    reset = "\033[0m"
    c = colors.get(severity, "")
    print(f"{c}[{ts}] [{severity}] {alert_type}: {src} -> {dst} | {detail}{reset}")

    entry = {"time": ts, "severity": severity, "type": alert_type,
             "src": src, "dst": dst, "detail": detail}
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Detectors — each inspects one packet and updates its sliding window
# ---------------------------------------------------------------------------
def detect_portscan(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    src, dst = pkt[IP].src, pkt[IP].dst
    dq = portscan_hits[src]
    dq.append((now(), pkt[TCP].dport))
    prune(dq, PORTSCAN_WINDOW)
    # count DISTINCT destination ports inside the window
    distinct_ports = {port for _, port in dq}
    if len(distinct_ports) >= PORTSCAN_PORTS:
        raise_alert("PORT SCAN", "HIGH", src, dst,
                    f"{len(distinct_ports)} distinct ports in {PORTSCAN_WINDOW}s")


def detect_synflood(pkt):
    # SYN set, ACK not set  => fresh connection attempt (SYN scan / SYN flood)
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    flags = pkt[TCP].flags
    if flags & 0x02 and not (flags & 0x10):
        dst = pkt[IP].dst
        dq = syn_hits[dst]
        dq.append(now())
        prune(dq, SYNFLOOD_WINDOW)
        if len(dq) >= SYNFLOOD_COUNT:
            raise_alert("SYN FLOOD", "HIGH", pkt[IP].src, dst,
                        f"{len(dq)} SYNs in {SYNFLOOD_WINDOW}s")


def detect_icmpflood(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return
    src = pkt[IP].src
    dq = icmp_hits[src]
    dq.append(now())
    prune(dq, ICMPFLOOD_WINDOW)
    if len(dq) >= ICMPFLOOD_COUNT:
        raise_alert("ICMP FLOOD", "MEDIUM", src, pkt[IP].dst,
                    f"{len(dq)} ICMP packets in {ICMPFLOOD_WINDOW}s")


def detect_risky_ports(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    dport = pkt[TCP].dport
    if dport in RISKY_PORTS:
        raise_alert("RISKY PORT", "LOW", pkt[IP].src, pkt[IP].dst,
                    f"connection attempt to port {dport}")


def analyse(pkt):
    """Run every detector on the packet (the NIDS 'detection engine')."""
    if not pkt.haslayer(IP):
        return
    detect_portscan(pkt)
    detect_synflood(pkt)
    detect_icmpflood(pkt)
    detect_risky_ports(pkt)


def main():
    global LOG_FILE
    ap = argparse.ArgumentParser(
        description="Simple NIDS — CodeAlpha Cyber Security Task 4")
    ap.add_argument("-i", "--iface", default=None, help="interface to monitor")
    ap.add_argument("--log", default="alerts.log", help="alert log file")
    args = ap.parse_args()
    LOG_FILE = args.log

    print("[*] NIDS running — monitoring for scans, floods and risky ports")
    print(f"[*] Alerts go to console + {LOG_FILE} | Press Ctrl+C to stop\n")
    try:
        sniff(iface=args.iface, filter="ip", prn=analyse, store=False)
    except PermissionError:
        print("[!] Run with sudo:  sudo python3 nids.py")
    except OSError as e:
        print(f"[!] Capture failed: {e} (try sudo / check interface)")
    except KeyboardInterrupt:
        print("\n[*] NIDS stopped.")


if __name__ == "__main__":
    main()
