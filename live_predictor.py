from scapy.sendrecv import sniff
from scapy.layers.inet import IP, TCP
from scapy.arch import get_if_raw_addr
from socket import AF_INET, inet_ntop
from collections import defaultdict
import joblib
import matplotlib.pyplot as plt
import re

# Helper to retrieve the IPv4 address of a given interface
def get_if_addr(iff):
    """
    Returns the IPv4 of an interface or "0.0.0.0" if not available
    """
    try:
        return inet_ntop(AF_INET, get_if_raw_addr(iff))
    except Exception:
        return "0.0.0.0"

class LiveChunkDetector:
    def __init__(self, client_ip,
                 model_path="rf_qoe_model.pkl", encoder_path="rf_label_encoder.pkl"):
        self.client_ip = client_ip
        # load predictive model and encoder
        self.rf_model = joblib.load(model_path)
        self.label_encoder = joblib.load(encoder_path)

        # buffers for uplink/downlink flows
        self.uplink = defaultdict(list)
        self.downlink = defaultdict(list)

        # timestamps for stream and chunks
        self.stream_start_ts = None    # first packet timestamp reference
        self.start_time_epoch = None   # timestamp when current chunk started
        self.slacktime = None          # timestamp of last slack marker

        # chunk tracking state
        self.chunk_size = 0
        self.ttfb = 0.0
        self.we_got_first_uplink = False
        self.first_downlink = False

        # live plotting setup
        plt.ion()
        self.fig, self.ax = plt.subplots()
        self.times = []
        self.resolutions = []  # numeric resolution values
        self.line, = self.ax.plot(self.times, self.resolutions, marker='o')
        self.ax.set_xlabel('Stream Time (s)')
        self.ax.set_ylabel('Resolution (p)')
        self.ax.set_title('Live Resolution Prediction')

    def _flow_size(self, pkts):
        return sum(len(p) for p in pkts)

    def process_packet(self, pkt):
        # only consider IPv4 TCP packets
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        ts = pkt.time
        # set stream start reference at very first packet
        if self.stream_start_ts is None:
            self.stream_start_ts = ts

        # relative timestamp since start of stream
        rel_ts = ts - self.stream_start_ts

        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flow_key = (src, dst, sport, dport)

        # initialize chunk start and slack on first packet
        if self.start_time_epoch is None:
            self.start_time_epoch = ts
            self.slacktime = ts

        # CLIENT → SERVER (uplink)
        if src == self.client_ip and dport == 443:
            self.uplink[flow_key].append(pkt)
            upl_size = self._flow_size(self.uplink[flow_key])

            if not self.we_got_first_uplink and upl_size > 300:
                duration = ts - self.start_time_epoch
                slack = ts - self.slacktime
                download_time = duration - self.ttfb - slack

                # prepare feature vector
                features = [
                    rel_ts,                   # relative start time of this chunk
                    duration,
                    self.ttfb,
                    slack,
                    download_time,
                    self.chunk_size,
                    0 if upl_size < 700 else 1
                ]

                # predict resolution label (e.g., '720p')
                encoded = self.rf_model.predict([features])[0]
                res_label = self.label_encoder.inverse_transform([encoded])[0]
                # extract numeric part for plotting
                match = re.search(r"(\d+)", str(res_label))
                res_num = int(match.group(1)) if match else 0

                # record for live plot
                self.times.append(rel_ts)
                self.resolutions.append(res_num)
                self.line.set_data(self.times, self.resolutions)
                self.ax.relim()
                self.ax.autoscale_view()
                plt.pause(0.01)

                # print chunk info with label
                chunk = features + [res_label]
                if self.chunk_size >= 600:
                    print(f"Chunk: {chunk} | Predicted Resolution: {res_label}")

                # reset for next chunk
                self.chunk_size = upl_size
                self.start_time_epoch = ts
                self.slacktime = ts
                self.we_got_first_uplink = True
                self.first_downlink = False

        # SERVER → CLIENT (downlink)
        elif dst == self.client_ip and sport == 443:
            self.downlink[flow_key].append(pkt)
            down_size = self._flow_size(self.downlink[flow_key])

            if not self.first_downlink and down_size > 300:
                self.chunk_size += down_size
                self.ttfb = ts - self.start_time_epoch
                self.first_downlink = True

            # update slack marker and allow next uplink
            self.slacktime = ts
            self.we_got_first_uplink = False


def main():
    iface = "wlp4s0"
    client_ip = get_if_addr(iface)
    detector = LiveChunkDetector(client_ip)

    print(f"Starting capture on '{iface}' for client IP {client_ip}...")
    sniff(
        iface=iface,
        prn=detector.process_packet,
        filter="tcp port 443",
        store=False
    )

if __name__ == "__main__":
    main()
