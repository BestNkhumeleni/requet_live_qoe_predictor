from scapy.all import PcapReader, IP, TCP
import pickle
import os
import pandas as pd
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

DATASET_DIR = "RequetDataSet"

def save_all_chunks(all_chunks, filepath='all_chunks.pkl'):
    with open(filepath, 'wb') as f:
        pickle.dump(all_chunks, f)

def parse_to_2d(bracketed_strings):
    out = []
    for s in bracketed_strings:
        s = s.strip()
        content = s[1:-1] if (s.startswith('[') and s.endswith(']')) else s
        row = []
        for p in content.split(','):
            p = p.strip()
            row.append(int(p) if p.isdigit() else p)
        out.append(row)
    return out

def parse_merged_txt(filename):
    grid = []
    with open(filename, "r") as file:
        for line in file:
            if line == "\n":
                continue
            parts = line.strip()
            db1 = parts.find("[["); db2 = parts.find("]]")
            first_part = parts[1:db1-2].strip()
            second_part = parts[db1 + 1:db2+1]
            last_part = parts[db2 + 5:-2]

            first_part = first_part.split(", ")
            second_part = parse_to_2d(second_part.split(", "))

            tp1 = last_part[last_part.find("[") + 1:last_part.find("]")]
            tp2 = last_part[last_part.find("],")+2:last_part.find(",[")].split(",")
            tp3 = last_part[last_part.find(",[")+2: last_part.rfind("],")]
            tp4 = last_part[last_part.find(tp3)+len(tp3)+2:].split(",")

            final_part = []
            final_part.append(tp1.split(", "))
            final_part += tp2
            final_part.append(tp3.split(", "))
            final_part += tp4

            row = []
            row += first_part
            row += second_part
            row.append(final_part)
            grid.append(row)

    columns = [
        "Relative Time", "Packets Sent", "Packets Received", "Bytes Sent", "Bytes Received",
        *[f"Network Info {i}" for i in range(1, 27)],
        "Playback Info"
    ]
    return pd.DataFrame(grid, columns=columns)

def get_playback_info(stream_name):
    merge_df = parse_merged_txt(stream_name)
    if merge_df is None or merge_df.empty:
        return pd.DataFrame()
    return pd.DataFrame(
        merge_df["Playback Info"].tolist(),
        columns=["Playback Event", "Epoch Time", "Start Time", "Playback Progress",
                 "Video Length", "Playback Quality", "Buffer Health", "Buffer Progress", "Buffer Valid"]
    )

def get_resolution_from_playback_info(stream_name):
    QUALITY_LABELS = ["unlabelled","144p","240p","360p","480p","720p","1080p","1440p","2160p"]
    playback_df = get_playback_info(stream_name)
    if playback_df.empty:
        return "unlabelled"
    counts = [0]*9
    for row in playback_df["Playback Quality"]:
        for i in range(len(row)):
            if row[i] == "1":
                counts[i] += 1
    return QUALITY_LABELS[counts.index(max(counts))]

def get_txt_files(directory_path):
    p = Path(directory_path)
    return sorted(str(f) for f in p.iterdir() if f.is_file() and f.suffix.lower()==".txt")

def get_PCAP_files(directory_path):
    p = Path(directory_path)
    return sorted(str(f) for f in p.iterdir() if f.is_file() and f.suffix.lower()==".pcap")

# ---------- FAST, STREAMING CHUNKER (parallellized per file) ----------

def process_pcap_file(pcap_path: str, resolution: str):
    """
    Single-pass scanner that finalizes a chunk when current packet is uplink (dport 443)
    and previous packet was downlink (sport 443). Includes the current packet in the chunk,
    then starts the next chunk AFTER it (matches your original behavior).
    Returns a list of 7-element feature rows (chunk features + resolution label at index -1).
    """
    CH_HTTPS = 443
    chunks = []

    # Running accumulators for the CURRENT chunk
    p_count = 0
    upl_count = 0
    down_count = 0
    upl_bytes = 0
    down_bytes = 0
    jitter_sum = 0.0
    first_time = None
    prev_time = None
    prev_was_downlink = False  # used to detect boundary with current uplink
    first_down = False
    first_down_time = None

    def finalize_chunk():
        nonlocal p_count, upl_count, down_count, upl_bytes, down_bytes, jitter_sum, first_time, prev_time, prev_was_downlink, first_down, first_down_time
        if down_bytes > 0 and down_count > 1 and p_count > 0 and first_time is not None and prev_time is not None:
            duration = (prev_time - first_time)
            # Avoid div by zero; keep same units as your code
            avg_gap_ms = (duration / p_count) * 1000 if p_count else 0.0
            jitter_ms = (jitter_sum / p_count) * 1000 if p_count else 0.0
            bitrate_kbps = (down_bytes*8) / (duration + 1e-6) / 1000 if duration > 0 else 0.0

            # chunk layout = [p, downl_size, total_size, duration_ms, avg_gap_ms, jitter_ms, bitrate_kbps, resolution]
            row = [0]*8
            row[0] = p_count
            row[1] = down_bytes
            row[2] = upl_bytes + down_bytes
            row[3] = duration * 1000.0
            row[4] = avg_gap_ms
            row[5] = jitter_ms
            row[6] = bitrate_kbps
            row[7] = resolution
            print(f"[DEBUG] Chunk finalized: {row}")
            chunks.append(row)

        # reset accumulators for the NEXT chunk
        p_count = 0
        upl_count = 0
        down_count = 0
        upl_bytes = 0
        down_bytes = 0
        jitter_sum = 0.0
        first_time = None
        prev_time = None
        prev_was_downlink = False
        first_down = False

    try:
        with PcapReader(pcap_path) as pr:
            for pkt in pr:
                # Only consider IPv4/TCP packets with port 443 either side
                if IP in pkt and TCP in pkt:
                    tcp = pkt[TCP]
                    t = float(pkt.time)

                    # initialize times
                    if first_time is None:
                        first_time = t
                        prev_time = t
                    else:
                        # accumulate inter-arrival for jitter
                        jitter_sum += (t - prev_time)
                        prev_time = t

                    # packet counters
                    p_count += 1

                    is_uplink = (tcp.dport == CH_HTTPS)
                    is_downlink = (tcp.sport == CH_HTTPS)

                    if is_downlink and first_down is False:
                        first_down = True


                    # sizes: use TCP payload length to match your original logic
                    pay_len = len(tcp.payload) if tcp.payload else 0
                    if is_uplink:
                        upl_count += 1
                        upl_bytes += pay_len
                    elif is_downlink:
                        down_count += 1
                        down_bytes += pay_len

                    # boundary condition: previous packet was downlink, current is uplink
                    # -> close current chunk INCLUDING current packet, then start new chunk
                    if is_uplink and prev_was_downlink:
                        # current packet is already included in accumulators
                        finalize_chunk()
                        # after finalize, the next chunk starts AFTER current packet
                        # so do NOT seed the next chunk with this packet
                        continue

                    prev_was_downlink = is_downlink

        # finalize tail chunk if any
        finalize_chunk()
    except Exception as e:
        # if a file is malformed, return what we have (or empty)
        # you can also log `e` if desired
        pass

    return chunks

if __name__ == "__main__":
    group_dir = os.path.join(DATASET_DIR, "A")
    txt_dir   = os.path.join(group_dir, "MERGED_FILES")
    pcap_dir  = os.path.join(group_dir, "PCAP_FILES")

    txt_files  = get_txt_files(txt_dir)
    pcap_files = get_PCAP_files(pcap_dir)

    # Filter to only 720p / 1080p pairs (preserving order)
    filtered_pairs = []
    for txt, pcap in zip(txt_files, pcap_files):
        if not (os.path.exists(txt) and os.path.exists(pcap)):
            print(f"[ERROR] Missing file(s) for pair: {txt} and {pcap}")
            continue
        resolution = get_resolution_from_playback_info(txt)
        if resolution not in ("720p", "1080p"):
            filtered_pairs.append((pcap, resolution))
        else:
            print(f"[INFO] Skipping {txt} / {pcap}: resolution {resolution}")

    total = len(filtered_pairs)
    print(f"[INFO] Submitting {total} jobs for 'A'…")

    # Parallel across files (processes for true parallelism with scapy)
    all_chunks = []
    with ProcessPoolExecutor(max_workers=os.cpu_count() or 2) as ex:
        futures = {ex.submit(process_pcap_file, pcap, res): (pcap, res) for pcap, res in filtered_pairs}
        done_count = 0
        for fut in as_completed(futures):
            pcap, res = futures[fut]
            try:
                file_chunks = fut.result()
                all_chunks.extend(file_chunks)
            except Exception as e:
                print(f"[WARN] {pcap} failed: {e}")
            done_count += 1
            print(f"[INFO] Progress: {done_count}/{total} files")

    # One write at the end (faster & atomic)
    save_all_chunks(all_chunks, filepath='all_chunks_not_720_1080.pkl')
    print(f"[DONE] Saved {len(all_chunks)} chunks to all_chunks_720_1080.pkl")
