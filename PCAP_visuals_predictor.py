from collections import defaultdict, Counter
from scapy.layers.inet import IP, TCP
from scapy.arch import get_if_raw_addr
from scapy.utils import PcapReader
from socket import AF_INET, inet_ntop
import joblib
import re
import matplotlib.pyplot as plt
import time
import argparse
import os

def get_if_addr(iff):
    """Returns the IPv4 of an interface or '0.0.0.0' if not available."""
    try:
        return inet_ntop(AF_INET, get_if_raw_addr(iff))
    except Exception:
        return "0.0.0.0"

def detect_client_ip_from_pcap(pcap_path, sample_pkts=20000):
    """
    Heuristic: the client is the source IP in flows where dport==443 (client->server).
    We scan up to `sample_pkts` packets for speed and pick the most common.
    """
    counts = Counter()
    scanned = 0
    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                if pkt[TCP].dport == 443:  # uplink to TLS server
                    counts[pkt[IP].src] += 1
            scanned += 1
            if scanned >= sample_pkts:
                break
    if not counts:
        # fallback: choose IP that appears most often overall as src on TCP
        counts2 = Counter()
        with PcapReader(pcap_path) as pr:
            for pkt in pr:
                if pkt.haslayer(IP) and pkt.haslayer(TCP):
                    counts2[pkt[IP].src] += 1
        return counts2.most_common(1)[0][0] if counts2 else None
    return counts.most_common(1)[0][0]

class ChunkDetector:
    def __init__(self,
                 client_ip,
                 model_path="rf_qoe_model.pkl",
                 encoder_path="rf_label_encoder.pkl",
                 get_thresh=300,
                 down_thresh=300,
                 min_chunk_size=600):
        # load
        self.client_ip     = client_ip
        self.rf_model      = joblib.load(model_path)
        self.label_encoder = joblib.load(encoder_path)

        # thresholds & state
        self.GET_THRESH      = get_thresh
        self.DOWN_THRESH     = down_thresh
        self.MIN_CHUNK_SIZE  = min_chunk_size

        # timestamps
        self.stream_start_ts  = None
        self.start_time_epoch = None
        self.slacktime        = 0

        # features
        self.chunk_size          = 0
        self.ttfb                = 0.0
        self.we_got_first_uplink = False
        self.first_downlink      = False

        # flow buffers
        self.uplink   = defaultdict(list)  # key -> list of payload lengths
        self.downlink = defaultdict(list)

        # live-ish plot (also works for pcap replay)
        plt.ion()
        self.fig, self.ax = plt.subplots()
        self.times, self.resolutions = [], []
        self.clean_resolutions = []
        
        self.line, = self.ax.plot(self.times, self.resolutions, marker='o')
        self.ax.set_xlabel('Stream Time (s)')
        self.ax.set_ylabel('Resolution (p)')
        self.ax.set_title('Resolution Prediction')

    def _pkt_fields(self, pkt):
        """Extract ts, payload-len, src, dst, sport, dport, proto."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return None
        ts    = float(pkt.time)
        ip    = pkt[IP]
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        plen  = len(pkt[TCP].payload)  # payload only
        return ts, plen, ip.src, ip.dst, sport, dport, 6

    def _sum(self, lst):
        return sum(lst)

    def running_average(self, x, N):
        """Return the mode of the last N values (or last if <N)."""
        if not x:
            return None
        if len(x) < N:
            return x[-1]
        window = x[-N:]
        return max(set(window), key=window.count)

    def process_packet(self, pkt):
        f = self._pkt_fields(pkt)
        if f is None:
            return
        ts, plen, src, dst, sport, dport, proto = f

        # initialize stream anchors
        if self.stream_start_ts is None:
            self.stream_start_ts  = ts
            self.start_time_epoch = ts

        rel_ts = ts - self.stream_start_ts
        flow_key = (src, dst, sport, dport)

        # ── CLIENT → SERVER (uplink GET)
        if src == self.client_ip and dport == 443:
            self.uplink[flow_key].append(plen)
            upl_size = self._sum(self.uplink[flow_key])

            if not self.we_got_first_uplink and upl_size > self.GET_THRESH:
                ts0           = self.start_time_epoch
                duration      = ts - ts0
                slack         = ts - self.slacktime
                download_time = duration - slack - self.ttfb

                raw_features = [
                    rel_ts,                    # [0] chunk start (relative)
                    duration,                  # [1] chunk duration
                    self.ttfb,                 # [2] TTFB
                    slack,                     # [3] slack time
                    download_time,             # [4] download time
                    self.chunk_size,           # [5] downlink bytes
                    0 if upl_size < 700 else 1 # [6] audio/video flag
                ]

                if self.chunk_size >= self.MIN_CHUNK_SIZE:
                    code    = self.rf_model.predict([raw_features])[0]
                    res_lbl = self.label_encoder.inverse_transform([code])[0]

                    m = re.search(r'(\d+)', str(res_lbl))
                    res_num = int(m.group(1)) if m else 0
                    self.times.append(rel_ts)
                    self.resolutions.append(res_num)
                    self.clean_resolutions.append(self.running_average(self.resolutions, 3))

                    self.line.set_data(self.times, self.clean_resolutions)
                    self.ax.relim(); self.ax.autoscale_view()
                    plt.pause(0.001)

                    full = raw_features + [res_lbl]
                    print(f"Chunk: {full} | Predicted Resolution: {res_lbl}")

                # reset for next chunk
                self.chunk_size          = upl_size
                self.start_time_epoch    = ts
                self.slacktime           = ts
                self.ttfb                = 0.0
                self.we_got_first_uplink = True
                self.first_downlink      = False

        # ── SERVER → CLIENT (downlink response)
        elif dst == self.client_ip and sport == 443:
            self.we_got_first_uplink = False

            self.downlink[flow_key].append(plen)
            down_size = self._sum(self.downlink[flow_key])

            if not self.first_downlink and down_size > self.DOWN_THRESH:
                self.chunk_size     += down_size
                self.first_downlink  = True
                self.ttfb            = ts - self.start_time_epoch

            # update slack marker for pacing
            self.slacktime = ts

    # ====== NEW: offline PCAP replay ======
    def run_pcap(self, pcap_path, realtime=False, speed=1.0):
        """
        Replay packets from a PCAP file.
        - realtime=False: process as fast as possible.
        - realtime=True: sleep to simulate original inter-packet gaps (scaled by `speed`).
        """
        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(pcap_path)

        first_ts = None
        with PcapReader(pcap_path) as pr:
            for pkt in pr:
                if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                    continue
                ts = float(pkt.time)
                if first_ts is None:
                    first_ts = ts
                    wall = time.time()
                # pacing to original timing if requested
                if realtime:
                    target = (ts - first_ts) / max(speed, 1e-6)
                    now = time.time() - wall
                    if target > now:
                        time.sleep(target - now)
                self.process_packet(pkt)

        # keep the plot open at the end of replay
        plt.ioff()
        plt.show()

    # ====== (still available) live capture via sniff, if you want ======
    def start_live(self, iface="wlp4s0"):
        from scapy.sendrecv import sniff  # import here to avoid dependency for offline use
        sniff(
            iface=iface,
            prn=self.process_packet,
            filter="tcp port 443",
            store=False
        )

def main():
    parser = argparse.ArgumentParser(description="Resolution predictor from live or PCAP.")
    parser.add_argument("--pcap", type=str, default=None, help="Path to .pcap to replay")
    parser.add_argument("--iface", type=str, default="wlp4s0", help="Interface for live mode")
    parser.add_argument("--client-ip", type=str, default=None, help="Client IPv4 (auto-detect for PCAP if omitted)")
    parser.add_argument("--model", type=str, default="rf_qoe_model.pkl", help="Path to model .pkl")
    parser.add_argument("--encoder", type=str, default="rf_label_encoder.pkl", help="Path to label encoder .pkl")
    parser.add_argument("--realtime", action="store_true", help="Replay PCAP with original timing")
    parser.add_argument("--speed", type=float, default=1.0, help="Speed factor for realtime replay (1.0=normal)")
    args = parser.parse_args()

    if args.pcap:
        # PCAP mode
        client_ip = args.client_ip
        if client_ip is None:
            client_ip = detect_client_ip_from_pcap(args.pcap)
            if client_ip is None:
                raise RuntimeError("Could not auto-detect client IP; please pass --client-ip")
            print(f"[info] Auto-detected client IP from PCAP: {client_ip}")

        det = ChunkDetector(
            client_ip=client_ip,
            model_path=args.model,
            encoder_path=args.encoder
        )
        print(f"[info] Replaying PCAP '{args.pcap}' for client {client_ip} (realtime={args.realtime}, speed={args.speed})")
        det.run_pcap(args.pcap, realtime=args.realtime, speed=args.speed)
    else:
        # Live mode (unchanged behavior)
        client_ip = args.client_ip or get_if_addr(args.iface)
        print("Starting capture in...")
        for i in range(10, 0, -1):
            print(i)
            time.sleep(1)
        print("Capture starting now!\n")
        print(f"Starting capture on '{args.iface}' for client IP {client_ip}…")
        det = ChunkDetector(
            client_ip=client_ip,
            model_path=args.model,
            encoder_path=args.encoder
        )
        det.start_live(args.iface)

if __name__ == "__main__":
    main()
