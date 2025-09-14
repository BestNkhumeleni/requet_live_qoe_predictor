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
from concurrent.futures import ProcessPoolExecutor, as_completed
from collections import defaultdict
import pickle
import numpy as np
import pandas as pd

# Scapy for PCAP parsing
from scapy.all import rdpcap, IP, TCP, UDP

# scikit-learn for model training
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import KFold

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from collections import Counter

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

 
# from scapy.all import rdpcap, IP, TCP
# from collections import defaultdict

def getChunks(pcap_path, client_ip, resolution,
                     get_thresh=300, down_thresh=0, min_chunk_size=0):
    """
    Parses a pcap and emits chunks with features:
      [ start_ts,
        chunk_duration,
        ttfb,
        slack_time,
        download_time,
        chunk_size,
        audio(0)/video(1),
        resolution ]
    using the *exact* same logic as the live version:
     - payload lengths = full packet length (len(pkt))
     - GET triggers only when uplink > get_thresh
     - first-downlink only when > down_thresh
     - reset *all* buffers on each boundary
    """
    # load packets
    pkts = rdpcap(pcap_path)

    # state
    stream_start_ts     = None
    start_time_epoch    = None
    slacktime           = 0
    chunk_size          = 0
    ttfb                = 0.0
    we_got_first_uplink = False
    first_downlink      = False

    # per-flow payload‐length buffers
    uplink   = defaultdict(list)
    downlink = defaultdict(list)

    chunks = []

    def sum_bytes(lst):
        return sum(lst)

    for pkt in pkts:
        # only TCP/IPv4
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        ts    = pkt.time
        ip    = pkt[IP]
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        # <-- full packet length, not just payload
        plen  = len(bytes(pkt))  

        # initialize on first packet
        if stream_start_ts is None:
            stream_start_ts  = ts
            start_time_epoch = ts
            slacktime        = ts

        rel_ts   = ts - stream_start_ts
        flow_key = (ip.src, ip.dst, sport, dport)

        # —— CLIENT → SERVER (uplink GET)
        if ip.src == client_ip and dport == 443:
            uplink[flow_key].append(plen)
            upl_size = sum_bytes(uplink[flow_key])

            # only trigger when you accumulate > get_thresh
            if not we_got_first_uplink and upl_size > get_thresh:
                # compute features
                ts0           = start_time_epoch
                duration      = ts - ts0
                slack         = ts - slacktime
                download_time = duration - slack - ttfb

                raw = [
                    rel_ts,                               # [0] chunk start
                    duration,                          # [1] chunk duration
                    ttfb,                              # [2] TTFB
                    slack,                             # [3] slack time
                    download_time,                     # [4] download time
                    chunk_size,                        # [5] downlink bytes
                    0 if upl_size < min_chunk_size else 1  # [6] audio(0)/video(1)
                ]

                # only record if we actually saw enough downlink data
                if chunk_size >= min_chunk_size:
                    chunks.append(raw + [resolution])

                # ── FULL RESET ──
                chunk_size          = upl_size
                start_time_epoch    = ts
                slacktime           = ts
                ttfb                = 0.0
                we_got_first_uplink = True
                first_downlink      = False

                # clear *every* flow buffer so next GET re-accumulates from zero
                uplink.clear()
                downlink.clear()

        # —— SERVER → CLIENT (downlink response)
        elif ip.dst == client_ip and sport == 443:
            # allow next GET to trigger
            we_got_first_uplink = False

            downlink[flow_key].append(plen)
            down_size = sum_bytes(downlink[flow_key])

            # only the first downlink > down_thresh sets ttfb & chunk_size
            if not first_downlink and down_size > down_thresh:
                chunk_size      += down_size
                ttfb             = ts - start_time_epoch
                first_downlink   = True

            # update slack marker
            slacktime = ts

    return chunks


def process_experiment(txt_path, pcap_path):
    """
    Process one txt/pcap pair and return its chunks list and the resolution.
    """
    clip_id = os.path.splitext(os.path.basename(txt_path))[0]

    # 1. parse merge
    merged_df = parse_merged_txt(txt_path)
    first_rel_ms = float(merged_df.iloc[0, 0])
    global start_time_epoch
    start_time_epoch = first_rel_ms

    # 2. pcap
    pkt_list = load_pcap_packets(pcap_path)
    ips = [
        merged_df["Network Info 1"][0][0],
        merged_df["Network Info 2"][0][0],
        merged_df["Network Info 3"][0][0],
    ]
    # majority vote for client IP
    client_ip = max(set(ips), key=ips.count)
    if ips.count(client_ip) == 1:
        raise ValueError(f"Ambiguous client IPs {ips} for {pcap_path}")

    # uplink, downlink = group_packets_by_flow(pkt_list, client_ip)

    # 3. get “predicted” (i.e. playback‐info) resolution
    resolution = get_resolution_from_playback_info(txt_path)

    # 4. chunk detection
    chunks = getChunks(pcap_path, client_ip,resolution)
    return chunks, resolution


def process_group(group_name, max_workers=None):
    """
    Process all txt/pcap pairs under DATASET_DIR/group_name in parallel.
    Prints per‐job status, remaining count, and resolution.
    Returns a flat list of all chunks.
    """
    group_dir = os.path.join(DATASET_DIR, group_name)
    txt_dir   = os.path.join(group_dir, "MERGED_FILES")
    pcap_dir  = os.path.join(group_dir, "PCAP_FILES")

    txt_files  = sorted(get_txt_files(txt_dir))
    pcap_files = sorted(get_PCAP_files(pcap_dir))
    pairs1      = list(zip(txt_files, pcap_files))
    i = 0
    for txt,pcap in pairs1:
        resolution = get_resolution_from_playback_info(txt)
        if not (resolution == "720p"or resolution == "1080p"):
            txt_files.remove(txt)
            pcap_files.remove(pcap)
            i+=1
            print(f"removed file whos resolution was {resolution} file #{i}")

    pairs = list(zip(txt_files, pcap_files))
    print(f"[INFO] Submitting {len(pairs)} jobs for {group_name}…")
    max_workers = max_workers or os.cpu_count()

    all_chunks  = []
    total_jobs  = len(pairs)
    done_count  = 0

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_experiment, txt, pcap): (txt, pcap)
            for txt, pcap in pairs
        }

        for fut in as_completed(futures):
            done_count += 1
            remaining = total_jobs - done_count
            txt_path, pcap_path = futures[fut]

            try:
                chunks, resolution = fut.result()
                all_chunks.extend(chunks)
                save_all_chunks(all_chunks)
                print(f"[OK]    {os.path.basename(txt_path)} → {len(chunks)} chunks, Predicted resolution: {resolution}")
            except Exception as e:
                print(f"[ERROR] {os.path.basename(txt_path)} failed: {e}")

            print(f"[INFO] Jobs remaining: {remaining}")

    return all_chunks


def save_all_chunks(all_chunks, filepath='all_chunks_1080.pkl'):
    """
    Saves the nested all_chunks list to disk without altering its structure.

    Parameters:
    - all_chunks: list of streams; each stream is a list of chunks (as defined)
    - filepath: path to the output pickle file (default 'all_chunks.pkl')
    """
    with open(filepath, 'wb') as f:
        pickle.dump(all_chunks, f)
    # print(f"Saved all_chunks structure to {filepath}")

def load_all_chunks(filepath='all_chunks.pkl'):
    """
    Loads the nested all_chunks list from disk.

    Parameters:
    - filepath: path to the input pickle file

    Returns:
    - all_chunks: the nested list structure loaded from disk
    """
    with open(filepath, 'rb') as f:
        all_chunks = pickle.load(f)
    return all_chunks

# Example usage:
# save_all_chunks(all_chunks, 'my_chunks.pkl')
# restored_chunks = load_all_chunks('my_chunks.pkl')


def main():
    # 1. Clone dataset if needed
    clone_requet_dataset()

    # 2. Process Group A
    print("[INFO] Processing groupA ...")
    all_chunks = process_group("A")
    save_all_chunks(all_chunks)


if __name__ == "__main__":
    main()