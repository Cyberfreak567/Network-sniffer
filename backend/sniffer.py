# sniffer.py
import time
import re
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

captured_packets = []
live_data = []

def get_protocol(packet):
    if ICMP in packet:
        return "ICMP"
    elif TCP in packet:
        if Raw in packet:
            try:
                data = packet[Raw].load.decode(errors='ignore')
                if data.startswith("GET") or data.startswith("POST") or "HTTP" in data:
                    return "HTTP"
            except:
                pass
        if packet[TCP].dport == 443 or packet[TCP].sport == 443:
            return "HTTPS"
        return "TCP"
    elif UDP in packet:
        return "UDP"
    else:
        return "Other"

def get_info(packet):
    if Raw in packet:
        try:
            raw_data = packet[Raw].load[:200]  # Get first 200 bytes of payload
            decoded = raw_data.decode(errors='ignore')
            cleaned = re.sub(r'[^ -~]+', '', decoded)  # Keep only printable characters
            return cleaned.strip() or "-"
        except:
            return "Unreadable Payload"
    return "-"

def packet_callback(packet):
    if IP in packet:
        packet_data = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "protocol": get_protocol(packet),
            "payload": len(packet),
        }
        live_data.append(packet_data)
        captured_packets.append(packet)

def start_sniffing(iface="Wi-Fi"):
    sniff(iface=iface, prn=packet_callback, store=False)
