from datetime import datetime

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

captured_packets = []
packet_count = 0

def process_packet(packet):
    global packet_count

    if not packet.haslayer(IP):
        return

    packet_count += 1
    captured_packets.append(packet)

    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = "Other"

    print("=" * 30)
    print(f"Packet Number   : {packet_count}")
    print(f"Time            : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Source IP       : {packet[IP].src}")
    print(f"Destination IP  : {packet[IP].dst}")
    print(f"Protocol        : {protocol}")

    
    if packet.haslayer(TCP):
        print(f"Source Port     : {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

    elif packet.haslayer(UDP):
        print(f"Source Port     : {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")


    print(f"Packet Length   : {len(packet)} bytes")
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        print(f"Payload         : {payload}")
    else:
        print("Payload         : No Payload")


print("=" * 30)
print("Capturing packets :")


sniff(prn=process_packet,store=False)
