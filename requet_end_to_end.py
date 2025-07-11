#requet_env/bin/activate
"""
requet_end_to_end.py

Combined script to train and evaluate Requet QoE prediction models:
 - Loads RequetDataSet repository
 - Parses merged.txt logs for buffer/playback metadata
 - Parses PCAP files with Scapy to detect audio/video chunks
 - Extracts sliding-window features for audio/video chunks
 - Generates labels: buffer warning, video state, resolution
 - Trains Random Forest classifiers with 4-fold CV on group A
 - Evaluates on external groups B1, B2, C, D
"""

import os
import subprocess
from collections import defaultdict

import numpy as np
import pandas as pd

# Scapy for PCAP parsing
from scapy.all import rdpcap, IP, TCP, UDP

# scikit-learn for model training
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import KFold

# =============================================================================
# 1. CONFIGURATION AND REQUET DATASET CLONING
# =============================================================================

# Path to clone the RequetDataSet repo (if not already present)
REPO_URL = "https://github.com/Wimnet/RequetDataSet.git"
DATASET_DIR = "RequetDataSet"

def clone_requet_dataset():
    """
    Clone the RequetDataSet repository if it does not already exist.
    """
    if not os.path.isdir(DATASET_DIR):
        print(f"[INFO] Cloning RequetDataSet into ./{DATASET_DIR}/ ...")
        subprocess.run(["git", "clone", REPO_URL], check=True)
    else:
        print(f"[INFO] RequetDataSet directory already exists at './{DATASET_DIR}/'.")


# =============================================================================
# 2. MERGED.TXT PARSING UTILITIES
# =============================================================================
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
            if line == "\n":
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


# =============================================================================
# 3. PCAP PARSING AND CHUNK DETECTION
# =============================================================================

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


# =============================================================================
# 4. SLIDING-WINDOW FEATURE EXTRACTION & LABEL GENERATION
# =============================================================================

def extract_features_and_labels(chunks, merged_df, window_sizes=[10,20,30,40,50,60,70,80,90,100,110,120,130,140,150,160,170,180,190,200]):
    """
    From a list of chunk dicts and the corresponding merged_df (100 ms intervals),
    extract:
      - X: feature matrix (N_chunks × (window_features + current_chunk_features))
      - Y_bw: buffer warning labels (0/1)
      - Y_vs: video state labels (0=Stall,1=Decay,2=Steady,3=Increase)
      - Y_res: resolution labels (0=144p,…,5=1080p)
    """
    N = len(chunks)
    num_windows = len(window_sizes)
    X = np.zeros((N, num_windows * 6 + 7), dtype=float)
    Y_bw = np.zeros(N, dtype=int)
    Y_vs = np.zeros(N, dtype=int)
    Y_res = np.full(N, -1, dtype=int)

    # Helper: find nearest interval index in merged_df for a given timestamp (seconds)
    def find_interval_idx(ts_sec):
        # merged_df['Relative Time'] is in ms since start
        rel_ms = (ts_sec - start_time_epoch) * 1000.0
        idx = np.argmin(np.abs(merged_df[0].values - rel_ms))
        return idx

    # Precompute smooth buffer & state labels over entire trace
    #print third from last item in playback info
    # print("Playback Info columns in merged_df:")
    # playback_info_col = merged_df["Playback Info"].iloc[0]
    # print(merged_df["Playback Info"])
    playback_info_third_last = merged_df["Playback Info"].apply(lambda x: x[-3] if isinstance(x, list) and len(x) >= 0 else None)
    # print(playback_info_third_last)
    buffer_health = playback_info_third_last.astype(float).values  # BufferHealth (s)

    # For demonstration, we assign state = 2 (Steady) when BufferHealth > 10, else 0 (Stall)
    # (In practice, implement Requet’s Alg. 2 with smoothing and slopes)
    state_labels = np.where(buffer_health > 10.0, 2, 0)

    for i, c in enumerate(chunks):
        t_i = c["get_ts"]
        # Skip if we have no downlink (dropped chunk)
        if c["av_flag"] == -1:
            continue

        # Sliding-window features
        for w_idx, W in enumerate(window_sizes):
            t_start = t_i - W
            # Audio/video chunk lists
            aud_sizes = []
            aud_dl_times = []
            vid_sizes = []
            vid_dl_times = []

            for other in chunks:
                if other["av_flag"] == 0 and other["get_ts"] >= t_start and other["get_ts"] < t_i:
                    aud_sizes.append(other["down_size"])
                    aud_dl_times.append(other["download_time"] or 0.0)
                elif other["av_flag"] == 1 and other["get_ts"] >= t_start and other["get_ts"] < t_i:
                    vid_sizes.append(other["down_size"])
                    vid_dl_times.append(other["download_time"] or 0.0)

            base = w_idx * 6
            X[i, base + 0] = len(aud_sizes)
            X[i, base + 1] = np.mean(aud_sizes) if aud_sizes else 0.0
            X[i, base + 2] = np.mean(aud_dl_times) if aud_dl_times else 0.0
            X[i, base + 3] = len(vid_sizes)
            X[i, base + 4] = np.mean(vid_sizes) if vid_sizes else 0.0
            X[i, base + 5] = np.mean(vid_dl_times) if vid_dl_times else 0.0

        # Current video chunk features (7)
        idx7 = num_windows * 6
        X[i, idx7 + 0] = c["down_size"]
        X[i, idx7 + 1] = c["download_time"] or 0.0
        # Slack_time and chunk_duration require knowing next GET → approximate as zero for simplicity
        X[i, idx7 + 2] = 0.0  # slack_time placeholder
        X[i, idx7 + 3] = 0.0  # chunk_duration placeholder
        X[i, idx7 + 4] = c["get_len"]
        X[i, idx7 + 5] = c["ttfb"] or 0.0
        X[i, idx7 + 6] = 1.0  # protocol placeholder

        # Label extraction from merged_df
        # Note: 'start_time_epoch' must be set externally for alignment
        idx = find_interval_idx(t_i)
        # Buffer warning: 1 if BufferHealth <= 20, else 0
        Y_bw[i] = 1 if buffer_health[idx] <= 20.0 else 0
        # Video state: from precomputed state_labels
        Y_vs[i] = state_labels[idx]
        # Resolution: check merged_df's PlaybackQuality one-hot (columns 5..13)
        # We assume merged_df column 5 + q_idx indicates resolution
        pq = merged_df.iloc[idx, 5+1:5+7].astype(int).values  # 144p..1080p
        if pq.sum() == 1:
            Y_res[i] = int(np.argmax(pq))
        else:
            Y_res[i] = -1

    return X, Y_bw, Y_vs, Y_res

# =============================================================================
# 5. MAIN PIPELINE: DATA COLLECTION, FEATURE EXTRACTION, MODEL TRAINING
# =============================================================================

def get_txt_files(directory_path):
    """
    Returns a list of relative paths for all .txt files in the specified directory.

    Args:
        directory_path (str): Path to the directory to search.

    Returns:
        List[str]: Relative file paths (from the current working directory) 
                   of all .txt files directly inside directory_path.
    """
    txt_paths = []
    try:
        for fname in os.listdir(directory_path):
            full_path = os.path.join(directory_path, fname)
            if os.path.isfile(full_path) and fname.lower().endswith(".txt"):
                # Convert to a path relative to the current working directory
                rel_path = os.path.relpath(full_path)
                txt_paths.append(rel_path)
        return txt_paths

    except FileNotFoundError:
        # Directory doesn't exist
        return []
    except PermissionError:
        # No permission to list this directory
        return []

    

def get_PCAP_files(directory_path):
    """
    Returns a list of relative paths for all .txt files in the specified directory.

    Args:
        directory_path (str): Path to the directory to search.

    Returns:
        List[str]: Relative file paths (from the current working directory) 
                   of all .txt files directly inside directory_path.
    """
    txt_paths = []
    try:
        for fname in os.listdir(directory_path):
            full_path = os.path.join(directory_path, fname)
            if os.path.isfile(full_path) and fname.lower().endswith(".pcap"):
                # Convert to a path relative to the current working directory
                rel_path = os.path.relpath(full_path)
                txt_paths.append(rel_path)
        return txt_paths

    except FileNotFoundError:
        # Directory doesn't exist
        return []
    except PermissionError:
        # No permission to list this directory
        return []

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
    stream_name_txt = stream_name
    
    merge_df = parse_merged_txt(stream_name_txt)
    #print playback info, playback qulity fully
    
    # create playback info df
    playback_info_df = pd.DataFrame(merge_df["Playback Info"].tolist(), columns=["Playback Event", "Epoch Time", "Start Time", "Playback Progress","Video Length", "Playback Quality", "Buffer Health", "Buffer Progress", "Buffer Valid"])
    #merge_df["Playback Info"]
    return playback_info_df

# ...existing code...

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



def process_group(group_name):
    """
    Process one Requet group (e.g., "groupA") and return:
      - X_chunks: concatenated features for all chunks in that group
      - Y_bw_all, Y_vs_all, Y_res_all: corresponding label arrays
      - clip_ids: list of clip identifiers aligned with chunk indices
    """
    group_dir = os.path.join(DATASET_DIR, group_name)
    
    group_dir_txt = group_dir + "/MERGED_FILES"
    group_dir_pcap = group_dir + "/PCAP_FILES"
    # print(group_dir_txt)
    txt_files = sorted(get_txt_files(group_dir_txt))
    pcap_files = sorted(get_PCAP_files(group_dir_pcap))
    print(f"[INFO] Processing {len(txt_files)} txt files and {len(pcap_files)} pcap files in {group_name}...")
    # print(f"  txt files: {txt_files[:5]} ...")
    # print(f"  pcap files: {pcap_files[:5]} ...")
    # print()
    X_list, bw_list, vs_list, res_list, clip_list = [], [], [], [], []
    # Global start_time for alignment (set per experiment)
    global start_time_epoch

    i = 0
    all_chunks = []
    for txt_path, pcap_path in zip(txt_files, pcap_files):
        # print("preparing for ", txt_path, pcap_path)
        #print how many files are yet to be processed
        print(f"[INFO] Processing {txt_path} and {pcap_path} ...")
        print("[INFO] Remaining files: ", len(txt_files) - i)
        i += 1
        clip_id = os.path.splitext(os.path.basename(txt_path))[0]
        # 1. Parse merged.txt
        merged_df = parse_merged_txt(txt_path)
        # Assume column 0 = Relative Time (ms), so start_time_epoch = first timestamp in seconds
        
        first_rel_ms = float(merged_df.iloc[0, 0])
        start_time_epoch = first_rel_ms 

        # 2. Parse PCAP
        pkt_list = load_pcap_packets(pcap_path)
        # Determine client IP: take the src from the first Network Info in merged_df
        # We assume merged_df column 6 holds [IP_Src, IP_Dst, ...] for flow 1
        # netinfo1 = merged_df.iloc[0, 6]
        client_ip_1 = merged_df["Network Info 1"][0][0]
        client_ip_2 = merged_df["Network Info 2"][0][0]
        client_ip_3 = merged_df["Network Info 3"][0][0]

        if client_ip_1 == client_ip_2 and client_ip_1 == client_ip_3:
            client_ip = client_ip_1
        elif client_ip_1 == client_ip_2:
            client_ip = client_ip_1
        elif client_ip_1 == client_ip_3:
            client_ip = client_ip_1
        elif client_ip_2 == client_ip_3:
            client_ip = client_ip_2
        else:
            # If all three are different, we cannot determine a single client IP
            print(f"[WARN] Multiple client IPs detected for {pcap_path}: {client_ip_1}, {client_ip_2}, {client_ip_3}. Using first one.")
            #end the program here
            raise ValueError(f"Multiple client IPs detected for {pcap_path}: {client_ip_1}, {client_ip_2}, {client_ip_3}.")
        

        if not client_ip:
            print(f"[WARN] Could not infer client IP for {pcap_path}. Skipping.")
            continue

        uplink, downlink = group_packets_by_flow(pkt_list, client_ip)

        resolution = get_resolution_from_playback_info(txt_path)
        print(f"Resolution for {txt_path}: {resolution}")

        # 3. Chunk detection per flow
        
        all_chunks.append(getChunks(pkt_list, client_ip,uplink, downlink, resolution))


    return all_chunks
      

def main():
    # 1. Clone dataset if needed
    clone_requet_dataset()

    # 2. Process Group A
    print("[INFO] Processing groupA ...")
    all_chunks = process_group("groupA")

    # print("Total number of streams in groupA:", len(all_chunks))

    # 2.5. Extract features and labels from chunks
    print("[INFO] Extracting features and labels from chunks...")


    # 3. Train & CV on groupA
    print("[INFO] Training & evaluating on groupA (4-fold CV)...")
    
if __name__ == "__main__":
    main()