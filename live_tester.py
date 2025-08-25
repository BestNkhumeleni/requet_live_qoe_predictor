#!/usr/bin/env python3
# capture_web_traffic.py
#
# Requires: scapy (pip install scapy)
# Run with sudo/admin on Linux/macOS:
#   sudo python3 capture_web_traffic.py --iface wlp4s0
#
# Stop with Ctrl+C to see the summary.

import argparse
import signal
import sys
from scapy.all import sniff, conf, get_if_addr, get_if_list, IP, IPv6, TCP, UDP

# Global counters
total_packets = 0
uplink_packets = 0
downlink_packets = 0
uplink_size = 0
downlink_size = 0
prev_packet = None
fistpacket = None
got_first_packet = False

stop_sniffing = False

def human_iface_or_default(iface_arg: str | None):
    """Pick interface: use provided one or the default route's interface."""
    if iface_arg:
        return iface_arg
    # Default interface via routing table (IPv4)
    return conf.route.route("0.0.0.0")[0]

def get_local_addrs(iface: str):
    """Return (ipv4, ipv6) string addresses for the interface if available."""
    ipv4 = None
    ipv6 = None
    try:
        ipv4 = get_if_addr(iface)
    except Exception:
        pass
    # scapy doesn't have a direct get_if_addr6; we’ll gather at runtime inside callback by checking packet's source/dst matching the iface’s L3
    return ipv4, ipv6

def pkt_len(pkt):
    """Robust byte length of a packet."""
    try:
        return len(bytes(pkt))
    except Exception:
        try:
            return len(pkt)
        except Exception:
            return 0

def is_web_port(pkt):
    """Return True if packet is TCP/UDP on web ports (80/443 for TCP, 443 for UDP)."""
    if TCP in pkt:
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        return sport in (80, 443) or dport in (80, 443)
    if UDP in pkt:
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        # QUIC (HTTP/3) typically on UDP 443
        return sport == 443 or dport == 443
    return False

def make_bpf():
    # BPF keeps capture efficient
    # HTTP (80), HTTPS (443/TCP), QUIC (443/UDP)
    return "(tcp port 80 or tcp port 443 or udp port 443)"

def handler(signum, frame):
    global stop_sniffing
    stop_sniffing = True
    # scapy will stop after current packet when prn returns False
    # We also exit gracefully in main when sniff returns.

def build_direction_checker(local_ipv4: str | None):
    """
    Build a function that decides whether a packet is uplink or downlink
    with respect to our local host. We use IPv4 if available; for IPv6
    we fall back to comparing by route ownership when possible.
    """
    def direction(pkt):
        """
        Returns 'uplink' if packet is from us to the internet,
                'downlink' if to us from the internet,
                None if not attributable (e.g., no IP layer or no match).
        """
        # Prefer IPv4 path
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if local_ipv4 is not None:
                if src == local_ipv4:
                    return "uplink"
                if dst == local_ipv4:
                    return "downlink"
            # As a fallback, if the default route interface matches, infer direction by routing
            # (this is a weak heuristic; most systems will have local_ipv4 above anyway)
            default_if = conf.route.route(dst)[0]
            if default_if:
                # If the packet is leaving via our default interface, assume uplink
                if src != dst and default_if:
                    # If source isn't our local IP, we still can't be sure — return None
                    return None
        elif IPv6 in pkt:
            # If you want IPv6 precision, consider using netifaces/psutil to enumerate iface v6 addresses.
            # Here we do a light heuristic: if the destination route goes out the same iface, likely uplink.
            src6 = pkt[IPv6].src
            dst6 = pkt[IPv6].dst
            try:
                default_if = conf.route6.route(dst6)[0]
                if default_if:
                    # Without knowing our exact v6 on iface, we can’t be 100% sure. Skip ambiguous IPv6.
                    return None
            except Exception:
                return None
        return None
    return direction

def main():
    parser = argparse.ArgumentParser(description="Capture web traffic to/from this machine and print a summary.")
    parser.add_argument("--iface", help="Network interface to listen on (e.g., wlp4s0, eth0). Defaults to system default.")
    parser.add_argument("--duration", type=int, default=30, help="Capture duration in seconds (0 = until Ctrl+C).")
    parser.add_argument("--quiet", action="store_true", help="Don’t print per-packet logs.")
    args = parser.parse_args()

    iface = human_iface_or_default(args.iface)
    if iface not in get_if_list():
        print(f"[!] Interface '{iface}' not found. Available: {', '.join(get_if_list())}")
        sys.exit(1)

    local_ipv4, _ = get_local_addrs(iface)
    if not local_ipv4:
        print(f"[!] Could not determine IPv4 address on {iface}. Uplink/downlink detection may be incomplete.")

    direction_of = build_direction_checker(local_ipv4)

    bpf = make_bpf()

    print(f"[*] Capturing on: {iface}")
    print(f"[*] Local IPv4: {local_ipv4 if local_ipv4 else 'unknown'}")
    print(f"[*] Filter: {bpf}")
    if args.duration > 0:
        print(f"[*] Duration: {args.duration} seconds")
    print("[*] Press Ctrl+C to stop and show summary.\n")

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    def print_chunk_summary(first_pkt, last_pkt):
        #takes the first pkt (an uplink) and the last pkt also an uplink
        total_size = uplink_size + downlink_size
        if total_packets > 0:
            print("\nChunk Summary")
            print("Total packets: ", total_packets)
            # print("Uplink packets: ", uplink_packets)
            # print("Uplink size: ", uplink_size)
            print("Downlink packets: ", downlink_packets)
            print("Downlink size: ", downlink_size)
            print("Total size: ", total_size)
            print("Chunk duration: ", last_pkt.time - first_pkt.time)
            #duration of chunk

            print("-" * 20)


    def _cb(pkt):
        # Stop if signaled
        if stop_sniffing:
            sys.exit(0)
            return False

        # Only consider IP packets on web ports
        if not is_web_port(pkt):
            return

        length = pkt_len(pkt)
        if length <= 0:
            return

        global total_packets, uplink_packets, downlink_packets, uplink_size, downlink_size, prev_packet, fistpacket, got_first_packet
        total_packets += 1

        dirn = direction_of(pkt)
        prev_dir = direction_of(prev_packet) if prev_packet else None
        if not got_first_packet:
            fistpacket = pkt
            got_first_packet = True

        if prev_packet and prev_dir == "downlink" and dirn == "uplink":
            print_chunk_summary(fistpacket, pkt)
            total_packets = uplink_packets = downlink_packets = uplink_size = downlink_size = 0
            got_first_packet = False

        if dirn == "uplink":
            uplink_packets += 1
            uplink_size += length
            # if not args.quiet:
                # print(f"↑ {length} bytes")
        elif dirn == "downlink":
            downlink_packets += 1
            downlink_size += length
            # if not args.quiet:
                # print(f"↓ {length} bytes")
        else:
            # If direction is unknown (e.g., IPv6 without exact local addr), still count in totals.
            if not args.quiet:
                print(f"• {length} bytes (unknown direction)")
        
        prev_packet = pkt

    try:
        sniff(
            iface=iface,
            filter=bpf,
            prn=_cb,
            store=False,
            timeout=args.duration if args.duration > 0 else None,
        )
    except PermissionError:
        print("[!] Permission denied. Try running with sudo/admin privileges.")
        sys.exit(1)
    except OSError as e:
        print(f"[!] OS error: {e}")
        sys.exit(1)
    finally:
        # Print the requested summary format
        total_size = uplink_size + downlink_size
        print("\nSummary")
        print("Total packets: ", total_packets)
        print("Uplink packets: ", uplink_packets)
        print("Uplink size: ", uplink_size)
        print("Downlink packets: ", downlink_packets)
        print("Downlink size: ", downlink_size)
        print("Total size: ", total_size)

if __name__ == "__main__":
    main()
