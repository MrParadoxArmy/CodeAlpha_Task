from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

# Function to process each captured packet
def process_packet(packet):
    print("=" * 80)
    print("📦 New Packet Captured")
    print("Timestamp:", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    # Check for IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        print(f"🔹 IP Layer: {src_ip} ➜ {dst_ip}")
        print(f"    ├─ Version: {ip_layer.version}")
        print(f"    ├─ Header Length: {ip_layer.ihl * 4} bytes")
        print(f"    ├─ TTL: {ip_layer.ttl}")
        print(f"    └─ Protocol: {proto} ({get_protocol_name(proto)})")

        # Check for TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("🔸 TCP Segment")
            print(f"    ├─ Src Port: {tcp.sport}")
            print(f"    ├─ Dst Port: {tcp.dport}")
            print(f"    ├─ Sequence #: {tcp.seq}")
            print(f"    ├─ Acknowledgment #: {tcp.ack}")
            print(f"    └─ Flags: {tcp.flags}")
            if tcp.payload:
                print("    └─ Payload:", bytes(tcp.payload).decode(errors="ignore"))

        # Check for UDP
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("🔸 UDP Datagram")
            print(f"    ├─ Src Port: {udp.sport}")
            print(f"    ├─ Dst Port: {udp.dport}")
            print(f"    └─ Length: {udp.len}")

        # Check for ICMP
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            print("🔸 ICMP Packet")
            print(f"    ├─ Type: {icmp.type}")
            print(f"    └─ Code: {icmp.code}")

        else:
            print("🔸 Other IP-based Protocol")

    else:
        print("🚫 Non-IP Packet")

# Helper to convert protocol number to name
def get_protocol_name(proto_num):
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    return protocols.get(proto_num, "Unknown")

# Start sniffing
print("🚀 Starting advanced network sniffer...")
print("📌 Press Ctrl+C to stop.\n")

try:
    sniff(filter="ip", prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\n🛑 Sniffer stopped by user.")
