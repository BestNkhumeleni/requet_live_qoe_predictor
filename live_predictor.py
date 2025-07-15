#!/usr/bin/env python3
"""
sniff_traffic.py

Capture live network traffic filtered by the host's IP on port 443.
Processes packets as they arrive: starts a chunk on detecting a GET uplink, computes metrics
and predicts resolution on the first downlink packet, all in real time.
"""

import argparse
from scapy.all import sniff, conf, get_if_addr, IP, TCP
import joblib

# Thresholds (bytes)
REQ_THRESHOLD = 300    # detect uplink start
RESP_THRESHOLD = 300   # detect first downlink response

# Load pretrained model and encoder
rf_model = joblib.load('chunk_rf_model.pkl')
label_encoder = joblib.load('chunk_label_encoder.pkl')

def live_stream(interface=None, packet_limit=0):
    iface = interface or conf.iface
    client_ip = get_if_addr(iface)
    print(f"[*] Live sniff on {iface}, host {client_ip} (port 443)...")

    # State variables
    uplink_bytes = {}         # flow_key -> bytes counted for current GET
    chunk_active = False      # True after GET threshold crossed
    got_first_down = False    # True after first downlink of chunk
    start_ts = 0.0            # timestamp when GET detected
    prev_get_ts = None        # timestamp of previous GET (for duration)
    last_slack_ts = None      # timestamp when last chunk ended
    down_bytes = 0            # accumulated downlink payload bytes
    chunk_type = 0            # 0=audio,1=video
    duration = 0.0            # duration between GETs
    slack = 0.0   
    request_size = 0 
    download_time = 0   
    ttfb = 0        # slack time

    def process(pkt):
        res = "unknown"  # default resolution
        nonlocal request_size, download_time, ttfb
        nonlocal uplink_bytes, chunk_active, got_first_down
        nonlocal start_ts, prev_get_ts, last_slack_ts, down_bytes, chunk_type
        nonlocal duration, slack
        getting_uplink = False

        if not (IP in pkt and TCP in pkt):
            return

        ts = pkt.time
        payload_len = len(bytes(pkt[TCP].payload))
        src, dst = pkt[IP].src, pkt[IP].dst
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        flow = (src, dst, sport, dport, pkt[IP].proto)
        

        # Initialize last_slack_ts on first packet
        if last_slack_ts is None:
            last_slack_ts = ts

        # Uplink detection (client -> server)
        if src == client_ip and dport == 443:
            if not getting_uplink:
                # Start a new GET request
                features = [start_ts, duration, ttfb, slack, download_time, down_bytes, chunk_type]
                # print(f"[=] Chunk complete | features={features} | Predicted Resolution: {res}")
                # predict resolution
                encoded = rf_model.predict([features])[0]
                res = label_encoder.inverse_transform([encoded])[0]
                #print feature labels
                print("start_ts, duration, ttfb, slack, download_time, down_bytes, chunk_type")
                print(f"{start_ts:.6f}, {duration:.6f}, {ttfb:.6f}, {slack:.6f}, {download_time:.6f}, {down_bytes}, {chunk_type}")
                
                # print(f"[=] Chunk complete | features={features} | Predicted Resolution: {res}")
                duration = ts - start_ts
                start_ts = ts
                slack = ts - last_slack_ts
                down_bytes = 0
                request_size = payload_len
                # download_time = duration - slack - ttfb
                got_first_down = False
                getting_uplink = True
                print(f"[>] Chunk started | start={start_ts:.6f}, duration={duration:.6f}s, slack={slack:.6f}s, type={chunk_type}")

            request_size += payload_len
            return

        # Downlink detection (server -> client)
        if dst == client_ip and sport == 443 and chunk_active:
            

            getting_uplink = False
            if not got_first_down:
                ttfb = ts - start_ts
                download_time = ts
                down_bytes = payload_len
                got_first_down = True

                if request_size < 700: #if request size is less than 900B, we assume it is audio
                    chunk_type = 0
                else: #else we assume it is video
                    chunk_type = 1
        
            down_bytes += payload_len
            last_slack_ts = ts
            download_time = ts - download_time  
            request_size = 0
            return

    sniff(
        iface=iface,
        prn=process,
        store=False,
        count=packet_limit,
        filter=f"tcp port 443 and host {client_ip}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Live chunk-based resolution prediction from port 443 traffic."
    )
    parser.add_argument("--iface", "-i", help="Network interface (default primary)")
    parser.add_argument("--count", "-c", type=int, default=0,
                        help="Packet count (0=infinite)")
    args = parser.parse_args()
    live_stream(interface=args.iface, packet_limit=args.count)

if __name__ == '__main__':
    main()
