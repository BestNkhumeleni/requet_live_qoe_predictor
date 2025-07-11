from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from collections import Counter

# Scapy for PCAP parsing
from scapy.all import rdpcap, IP, TCP, UDP

def parse_to_2d(bracketed_strings):
    """
    Convert a list of strings like "[a,b,c,...]" into a 2D list.
    
    Args:
        bracketed_strings (list of str): each item is a string of the form
            "[elem1,elem2,elem3,...]".
    
    Returns:
        list of list: a 2D list where each inner list corresponds to one
        of the original bracketed strings. Numeric-looking entries are cast
        to int; everything else remains a str.
    """
    result = []
    for s in bracketed_strings:
        # Remove any surrounding whitespace, then strip leading '[' and trailing ']'
        s = s.strip()
        if s.startswith('[') and s.endswith(']'):
            content = s[1:-1]
        else:
            content = s
        
        # Split on commas
        parts = content.split(',')
        row = []
        for p in parts:
            p = p.strip()
            # If the string is all digits, convert to int; otherwise keep as str
            if p.isdigit():
                row.append(int(p))
            else:
                row.append(p)
        result.append(row)
    return result



def parse_merged_txt(filename):
    with open (filename, "r") as file:
        grid = []
        for line in file:
            if line == "\n" or line == "" or line == None:
                continue

            parts = line.strip()

          
            double_brac_1 = parts.find("[[")
            first_part = parts[1:double_brac_1-2].strip()
            double_brac_2 = parts.find("]]")
            second_part = parts[double_brac_1 + 1:double_brac_2+1]

            
            last_part = parts[double_brac_2 + 5:-2]

            first_part = first_part.split(", ")
            # print(first_part)
            second_part = second_part.split(", ")
            second_part = parse_to_2d(second_part)
            # print(second_part)

            third_part_1 = last_part[last_part.find("[") + 1:last_part.find("]")]
            third_part_2 = last_part[last_part.find("],")+2:last_part.find(",[")]
            third_part_2 = third_part_2.split(",")
            third_part_3 = last_part[last_part.find(",[")+2: last_part.rfind("],")]
            third_part_4 = last_part[last_part.find(third_part_3)+len(third_part_3)+2:]
            third_part_4 = third_part_4.split(",")

          
            final_part = []
            final_part.append(third_part_1.split(", "))
            final_part+=third_part_2
            final_part.append(third_part_3.split(", "))
            final_part+= third_part_4

            # print(last_part)

            full_array = []
            full_array = full_array + first_part
            full_array+= second_part
            full_array.append(final_part)
            grid.append(full_array)
    
    columns = [
    "Relative Time", "Packets Sent", "Packets Received", "Bytes Sent", "Bytes Received",
    *[f"Network Info {i}" for i in range(1, 27)],  # 25 Network Info fields
    "Playback Info"
    ]
    # # Ensure we have exactly 31 columns
    # if len(records) > 0 and len(records[0]) != 31:
    #     raise ValueError(f"Expected 31 columns in merged.txt, found {len(records[0])}.")
    # Convert to DataFrame
    df = pd.DataFrame(grid, columns=columns)
    return df

def load_pcap_packets(pcap_path):
    """
    Load packets from a PCAP file using Scapy.
    Returns a list of tuples: (timestamp, payload_len, src_ip, dst_ip, src_port, dst_port, protocol).
    """
    packets = rdpcap(pcap_path)
    pkt_list = []
    for pkt in packets:
        if IP in pkt:
            ts = float(pkt.time)
            ip_layer = pkt[IP]
            payload_len = len(ip_layer.payload)  # payload excludes IP header
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto  # 6=TCP, 17=UDP
            sport = None
            dport = None
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            pkt_list.append((ts, payload_len, src_ip, dst_ip, sport, dport, proto))
    return pkt_list

def group_packets_by_flow(pkt_list, client_ip):
    """
    Group packets into uplink and downlink dictionaries keyed by flow.
    Flow key: (src_ip, dst_ip, src_port, dst_port, protocol).
    """
    uplink = defaultdict(list)
    downlink = defaultdict(list)

    for ts, plen, src, dst, sport, dport, proto in pkt_list:
        if src == client_ip:
            flow_key = (src, dst, sport, dport, proto)
            uplink[flow_key].append((ts, plen))
        elif dst == client_ip:
            flow_key = (src, dst, sport, dport, proto)
            downlink[flow_key].append((ts, plen))
    return uplink, downlink

def detect_av_chunk_metrics(uplink_pkts, downlink_pkts, GET_thresh=300, Down_thresh=300):
    """
    Given lists of uplink and downlink packets for a single flow (each sorted by timestamp),
    detect audio/video chunks according to Requet’s heuristic:
      - An uplink packet with payload > GET_thresh indicates an HTTP GET.
      - Downlink packets with payload > Down_thresh belong to a chunk.
    Returns a list of chunk dictionaries, each with computed metrics.
    """
    chunks = []
    uplink_pkts.sort(key=lambda x: x[0])
    downlink_pkts.sort(key=lambda x: x[0])

    # Precompute indices of downlink packets for traversal
    down_idx = 0
    cur_chunk = None

    for i, (get_ts, get_len) in enumerate(uplink_pkts):
        if get_len <= GET_thresh:
            continue
        # Finalize previous chunk (if any)
        if cur_chunk is not None:
            chunks.append(cur_chunk)

        # Start new chunk
        cur_chunk = {
            "get_ts": get_ts,
            "get_len": get_len,
            "down_start": None,
            "down_end": None,
            "down_size": 0,
        }

        # Consume downlink pkts until next GET
        # Advance down_idx until the first downlink >= get_ts
        while down_idx < len(downlink_pkts) and downlink_pkts[down_idx][0] < get_ts:
            down_idx += 1

        # Accumulate downlink packets while payload > Down_thresh
        j = down_idx
        while j < len(downlink_pkts):
            d_ts, d_len = downlink_pkts[j]
            if d_len <= Down_thresh:
                j += 1
                continue
            # If this downlink occurs before the next GET
            # Peek next GET timestamp (if exists)
            next_get_ts = None
            if i + 1 < len(uplink_pkts):
                next_get_ts = uplink_pkts[i + 1][0]
            # If this packet is after next GET, break
            if next_get_ts and d_ts >= next_get_ts:
                break
            # Record first/last downlink times
            if cur_chunk["down_start"] is None:
                cur_chunk["down_start"] = d_ts
            cur_chunk["down_end"] = d_ts
            cur_chunk["down_size"] += d_len
            j += 1
        # Move down_idx forward
        down_idx = j

    # Append final chunk
    if cur_chunk is not None:
        chunks.append(cur_chunk)

    # Classify each chunk as audio (0), video (1), or drop (-1)
    filtered_chunks = []
    for c in chunks:
        down_size = c["down_size"]
        protocol = None  # Not strictly used here, but could be helpful
        # Drop small background transfers
        if down_size < 80 * 1024:
            c["av_flag"] = -1
        else:
            # Heuristic: assume TCP GET size threshold ~900B for audio vs. video
            if c["get_len"] < 900:
                c["av_flag"] = 0  # audio
            else:
                c["av_flag"] = 1  # video
        # Compute TTFB and download time if not dropped
        if c["av_flag"] != -1 and c["down_start"] is not None:
            c["ttfb"] = c["down_start"] - c["get_ts"]
            c["download_time"] = c["down_end"] - c["down_start"]
        else:
            c["ttfb"] = None
            c["download_time"] = None
        filtered_chunks.append(c)

    return filtered_chunks


def plot_array(array, title="Array Plot", xlabel="Index", ylabel="Value"):
    """
    Plot a 1D array using matplotlib.
    
    Args:
        array (list or np.ndarray): The data to plot.
        title (str): Title of the plot.
        xlabel (str): Label for the x-axis.
        ylabel (str): Label for the y-axis.
    """
    plt.figure(figsize=(10, 5))
    plt.plot(array, marker='o', linestyle='-', color='b')
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.grid()
    plt.show()

def getsize_from_flow(packet_list):
    """
    Calculate the total size of packets in a flow.
    Flow is a list of (timestamp, payload_length) tuples.

    """
    size = 0
    for pkt in packet_list:
        ts, plen = pkt
        size += plen

    return size

def get_playback_info(stream_name):
    stream_name_txt = stream_name + "_merged.txt"
    
    merge_df = parse_merged_txt(stream_name_txt)
    #print playback info, playback qulity fully
    
    # create playback info df
    playback_info_df = pd.DataFrame(merge_df["Playback Info"].tolist(), columns=["Playback Event", "Epoch Time", "Start Time", "Playback Progress","Video Length", "Playback Quality", "Buffer Health", "Buffer Progress", "Buffer Valid"])
    #merge_df["Playback Info"]
    return playback_info_df

def get_resolution_from_playback_info(stream_name):

    QUALITY_LABELS = [
    "unlabelled",  # index 0
    "144p",        # index 1
    "240p",        # index 2
    "360p",        # index 3
    "480p",        # index 4
    "720p",        # index 5
    "1080p",       # index 6
    "1440p",       # index 7
    "2160p"        # index 8
    ]

    playback_df = get_playback_info(stream_name)
    quality_df = playback_df["Playback Quality"]

    # Initialize a counter for each index (0-8)
    counts = [0] * 9

    # Iterate through each row in the column
    for row in quality_df:
        # print(row)
        # Ensure the row is a list of length 9
        for i in range(len(row)):
            if row[i] == "1":
                counts[i] += 1

    # Find the index with the highest count of 1s
    most_common_index = counts.index(max(counts))
    # print(f"Index with most 1s: {most_common_index} (count: {counts[most_common_index]})")
    # print(f"Counts per index: {counts}")

    return QUALITY_LABELS[most_common_index]

def getChunks(pkt_list, client_ip,uplink,downlink, resolution):
    #a chunk can be defined as you meet you first uplink, wait until a downlink happends

    # uplink, downlink = group_packets_by_flow(pkt_list, client_ip)
    global start_time_epoch
    chunk_size = 0
    ttfb = 0
    we_got_the_first_uplink = False
    first_downlink = False
    slacktime = 0
    first_upload_timestamp = 0
    chunks = [] # time_stamp,Chunk Duration,ttfb,slacktime,Download time,chunk_size,Audio(0) or vidoe(1)
    request_size = 0
    downlink_pkts = None
    size = []
    
    
    for pkt in pkt_list:
        chunky = [0,0,0,0,0,0,0,0] # time_stamp,Chunk Duration,ttfb,slacktime,Download time,chunk_size,Audio(0) or vidoe(1)
        ts, plen, src, dst, sport, dport, proto = pkt
        # 6=TCP, 17=UDP
        chunky[0] = start_time_epoch
        flow_key = (src, dst, sport, dport, proto)

        if src == client_ip and dport == 443: #this is an uplink packet, likely a GET request
            # find corresponding upflow packet using flow_key
            first_downlink = False
            if flow_key in uplink:
                uplink_pkts = uplink[flow_key]
                      
            
            if (not we_got_the_first_uplink and getsize_from_flow(uplink_pkts) > 300): #
                
                request_size = getsize_from_flow(uplink_pkts)
                
                we_got_the_first_uplink = True
                #prev packet
                chunky[1] = ts - chunky[0] #chunk duration
                slacktime = ts - slacktime
                chunky[3] = slacktime
                chunky[4] = chunky[1] - chunky[3] -chunky[2] #download time
                #write chunk size 
                chunky[5] = chunk_size
                #write audio or video
                # size.append(request_size)

                if request_size < 700: #if request size is less than 900B, we assume it is audio
                    chunky[6] = 0
                else: #else we assume it is video
                    chunky[6] = 1

                if chunky[5] >= 600: #if chunk size is less than 80KB, we drop it
                    chunky[7] = resolution #write resolution
                    chunks.append(chunky)
                #reset request size
               
                #reset params
                chunk_size = getsize_from_flow(uplink_pkts) #reset chunk size to the size of the uplink packets

                #current packet
                
                start_time_epoch = ts
                # first_upload_timestamp = ts
                # chunky[1] = first_upload_timestamp
                #ttfb = ts
           

        elif dst == client_ip and sport == 443: #this is a downlink packet, likely a response to the GET request
            we_got_the_first_uplink = False
            request_size = 0

            if flow_key in downlink:
                downlink_pkts = downlink[flow_key]
                # print("downlink_pkts:", downlink_pkts)
            
            if (not first_downlink) and getsize_from_flow(downlink_pkts) > 300: #if we have not seen the first downlink packet and the size is greater than 300B
                chunk_size += getsize_from_flow(downlink_pkts) #add the size of the downlink packets to the chunk size
                first_downlink = True
                ttfb = ts - start_time_epoch
                chunky[2] = ttfb
                #print ttfb to the 20th decimal place
                # print(f"TTFB: {ttfb:.20f}")
                
            # chunky[3] = chunk_size
            slacktime = ts
        # start_time_epoch = ts

    # plot_array(size, title="Request Size per Uplink Packet", xlabel="Packet Index", ylabel="Size (Bytes)")
    return chunks


def train_resolution_model(
    all_chunks,
    test_size=0.2,
    random_state=42,
    model_path='rf_model.pkl',
    encoder_path='label_encoder.pkl'
):
    """
    Train a Random Forest to predict video resolution per chunk and aggregate predictions per stream.
    
    Parameters:
    - all_chunks: list of streams; each stream is a list of chunks;
                  each chunk is [time_stamp, chunk_duration, ttfb, slacktime,
                                 download_time, chunk_size, audio_video, resolution]
    - test_size: fraction of streams to reserve for testing (default 0.2)
    - random_state: seed for reproducibility (default 42)
    - model_path: filepath to save the trained Random Forest (default 'rf_model.pkl')
    - encoder_path: filepath to save the LabelEncoder (default 'label_encoder.pkl')
    
    Returns:
    - clf: trained RandomForestClassifier
    - le: fitted LabelEncoder for resolution labels
    - stream_acc: accuracy of stream-level resolution prediction
    """
    # Flatten chunk-level data and track stream IDs
    X, y, stream_ids = [], [], []
    for sid, chunks in enumerate(all_chunks):
        for chunk in chunks:
            features = chunk[:7]             # use first 7 entries as features
            label = chunk[7]                 # resolution label
            X.append(features)
            y.append(label)
            stream_ids.append(sid)
    X = np.array(X, dtype=float)
    y = np.array(y)

    # Encode resolution labels
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # Split streams for train/test at the chunk level, preserving stream grouping
    X_train, X_test, y_train, y_test, train_ids, test_ids = train_test_split(
        X, y_enc, stream_ids, test_size=test_size, random_state=random_state, stratify=y_enc
    )

    # Train the Random Forest
    clf = RandomForestClassifier(n_estimators=100, random_state=random_state)
    clf.fit(X_train, y_train)

    # Save the model and encoder
    joblib.dump(clf, model_path)
    joblib.dump(le, encoder_path)

    # Evaluate stream-level accuracy by majority vote
    true_by_stream, pred_by_stream = {}, {}
    for xi, yi_true, sid in zip(X_test, y_test, test_ids):
        yi_pred = clf.predict([xi])[0]
        true_by_stream.setdefault(sid, []).append(yi_true)
        pred_by_stream.setdefault(sid, []).append(yi_pred)

    stream_true_labels = {}
    stream_pred_labels = {}
    for sid in true_by_stream:
        stream_true_labels[sid] = Counter(true_by_stream[sid]).most_common(1)[0][0]
        stream_pred_labels[sid] = Counter(pred_by_stream[sid]).most_common(1)[0][0]

    stream_acc = sum(
        1 for sid in stream_true_labels
        if stream_true_labels[sid] == stream_pred_labels[sid]
    ) / len(stream_true_labels)

    print(f"Stream-level resolution prediction accuracy: {stream_acc:.2%}")
    return clf, le, stream_acc

#print the full DataFrame
# Uncomment the line below to see the DataFrame output'
txt_df = parse_merged_txt("Chunk_detection_merged.txt")
client_ip = txt_df["Network Info 1"][0][0]
global start_time_epoch
first_rel_ms = float(txt_df.iloc[0, 0])
start_time_epoch = first_rel_ms
# print(txt_df.head())
pkt_list = load_pcap_packets("Chunk_detection.pcap")
uplink, downlink = group_packets_by_flow(pkt_list, client_ip)

#get resolution from playback info
stream_name = "Chunk_detection"
resolution = get_resolution_from_playback_info(stream_name)
print(f"Resolution for {stream_name}: {resolution}")

# 3. Chunk detection per flow
all_chunks = []
all_chunks = getChunks(pkt_list, client_ip,uplink, downlink, resolution)

# 4. Train & CV on groupA
print("[INFO] Training & evaluating on groupA (4-fold CV)...")
clf, le, stream_acc = train_resolution_model([all_chunks]) 
# Print the trained model and encoder


print("Total Chunks Detected:", len(all_chunks))
# Convert to DataFrame for easier analysis
chunk_df = pd.DataFrame(all_chunks, columns=["time_stamp","Chunk Duration","ttfb","slacktime","Download time","chunk_size","Audio(0) or vidoe(1)", "resolution"])

# print(len(all_chunks))  # Print the first chunk for verification
#print a bunch of rows in the DataFrame

print(chunk_df.head())