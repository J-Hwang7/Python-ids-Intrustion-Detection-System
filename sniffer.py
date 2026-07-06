from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

# --- Detection settings (tune these later) ---
TIME_WINDOW = 10      # seconds we "remember" activity for
PORT_THRESHOLD = 15   # distinct ports from one IP that counts as a scan

scan_tracker = defaultdict(list)
already_alerted = set()

def is_syn_scan_packet(packet):
    # Only TCP packets can be SYN packets
    if not packet.haslayer(TCP):
        return False
    flags = packet[TCP].flags
    # 'S' = SYN is set, and we want ACK ('A') NOT set.
    # A bare SYN is the "knock" a scanner sends.
    return flags & 0x02 and not (flags & 0x10)

def detect_port_scan(src_ip, dst_port):
    now = time.time()
    scan_tracker[src_ip].append((dst_port, now))

    # Keep only recent activity
    scan_tracker[src_ip] = [
        (port, ts) for (port, ts) in scan_tracker[src_ip]
        if now - ts <= TIME_WINDOW
    ]

    recent_ports = {port for (port, ts) in scan_tracker[src_ip]}

    if len(recent_ports) >= PORT_THRESHOLD and src_ip not in already_alerted:
        print(f"\n[!!! ALERT !!!] Possible SYN port scan from {src_ip} "
              f"— {len(recent_ports)} ports in {TIME_WINDOW}s\n")
        already_alerted.add(src_ip)

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if packet.haslayer(TCP):
        proto = "TCP"
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        dst_port = packet[UDP].dport
    else:
        return

    print(f"[{proto}] {src_ip} -> {dst_ip}:{dst_port}")

    # Only feed the detector genuine SYN "knocks"
    if is_syn_scan_packet(packet):
        detect_port_scan(src_ip, dst_port)

print("Starting capture... press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)