from scapy.all import sniff
from scapy.layers.inet import IP


# Callback function to process captured packets
def packet_callback(packet):
    if IP in packet:  # Filter out only IP packets
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")


if __name__ == "__main__":
    print("Starting Basic Network Sniffer...")

    # Sniff packets and invoke packet_callback for each captured packet
    sniff(prn=packet_callback, store=0)
