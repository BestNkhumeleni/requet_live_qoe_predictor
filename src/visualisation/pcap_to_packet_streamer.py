from scapy.all import rdpcap
from live_tester import pkt_len, is_web_port, get_local_addrs,build_direction_checker

def print_packets(pcap_file):
    packets = rdpcap(pcap_file)
    for i, pkt in enumerate(packets, 1):
        print(f"Packet {i}:")
        pkt.show()
        print("-" * 40)


def packet_analyze(pkt):
    # Only consider IP packets on web ports
    if not is_web_port(pkt):
        return
    
    length = pkt_len(pkt)
    if length <= 0:
        return

    global total_packets, uplink_packets, downlink_packets, uplink_size, downlink_size, prev_packet, fistpacket, got_first_packet, interpacket_spacing_intime
    total_packets += 1

    dirn = direction_of(pkt)
    prev_dir = direction_of(prev_packet) if prev_packet else None
    if not got_first_packet:
        fistpacket = pkt
        got_first_packet = True

    if prev_packet and prev_dir == "downlink" and dirn == "uplink":
        print_chunk_summary(fistpacket, pkt,interpacket_spacing_intime)
        total_packets = uplink_packets = downlink_packets = uplink_size = downlink_size = 0
        got_first_packet = False

    elif dirn == "uplink":
        # pkt.time - prev_packet.time if prev_packet else 0
        interpacket_spacing_intime += pkt.time - prev_packet.time if prev_packet else 0
        uplink_packets += 1
        uplink_size += length
        # if not args.quiet:
            # print(f"↑ {length} bytes")
    elif dirn == "downlink":
        interpacket_spacing_intime += pkt.time - prev_packet.time if prev_packet else 0
        downlink_packets += 1
        downlink_size += length
        # if not args.quiet:
            # print(f"↓ {length} bytes")
    else:
        # If direction is unknown (e.g., IPv6 without exact local addr), still count in totals.
        if not args.quiet:
            print(f"• {length} bytes (unknown direction)")
    
    prev_packet = pkt



if __name__ == "__main__":
    pcap_path = "/home/best/Desktop/final_qoe_predictor/requet_live_qoe_predictor/Chunk_detection.pcap"  # Replace with your pcap file path
    direction_of = build_direction_checker(local_ipv4)
    print_packets(pcap_path)
