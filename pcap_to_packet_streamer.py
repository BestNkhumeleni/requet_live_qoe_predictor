from scapy.all import rdpcap
from Visualiser import Visualiser
import sys
import os

from live_tester import pkt_len, is_web_port, get_local_addrs, build_direction_checker, human_iface_or_default

# from live_tester import pkt_len, is_web_port, get_local_addrs,build_direction_checker, human_iface_or_default
total_packets = 0
uplink_packets = 0
downlink_packets = 0
uplink_size = 0
downlink_size = 0
prev_packet = None
fistpacket = None
got_first_packet = False
video_started = False
interpacket_spacing_intime = 0
stop_sniffing = False
visuals = None

def print_packets(pcap_file):
    packets = rdpcap(pcap_file) 
    global visuals
    visuals = Visualiser(packets[0].time)  # Initialize with the time of the first packet

    for i, pkt in enumerate(packets, 1):    
        packet_analyze(pkt)


def packet_analyze(pkt):
    global visuals
    # Only consider IP packets on web ports
    if not is_web_port(pkt):        
        return
    
    length = pkt_len(pkt)
    if length <= 0:
        return
    
    global total_packets, uplink_packets, downlink_packets, uplink_size, downlink_size, prev_packet, fistpacket, got_first_packet, interpacket_spacing_intime
    total_packets += 1

    # print("Packet #: ", total_packets)
    visuals.add_packet(pkt)

    dirn = direction_of(pkt)
    prev_dir = direction_of(prev_packet) if prev_packet else None
    if not got_first_packet:
        fistpacket = pkt
        got_first_packet = True

    if prev_packet and prev_dir == "downlink" and dirn == "uplink":
        # print_chunk_summary(fistpacket, pkt,interpacket_spacing_intime)
        # visuals.create_visuals(fistpacket, pkt,interpacket_spacing_intime,uplink_size, downlink_size, total_packets)
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
    
    prev_packet = pkt



if __name__ == "__main__":
    pcap_path = "/home/best/Desktop/final_qoe_predictor/requet_live_qoe_predictor/Chunk_detection.pcap"  # Replace with your pcap file path
    # txt_df = parse_merged_txt("Chunk_detection_merged.txt")
    # client_ip = txt_df["Network Info 1"][0][0]
    # iface = human_iface_or_default("")
    iface = None
    local_ipv4, local_ipv6 = None, None
    direction_of = build_direction_checker(local_ipv4)
    print_packets(pcap_path)
