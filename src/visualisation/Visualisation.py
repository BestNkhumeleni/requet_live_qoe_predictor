


def print_chunk_summary(first_pkt, last_pkt,jitter, uplink_size, downlink_size, total_packets):
        #takes the first pkt (an uplink) and the last pkt also an uplink
        total_size = uplink_size + downlink_size
        if total_packets > 0:
            print("\nChunk Summary")
            print("Total packets: ", total_packets)
            # print("Uplink packets: ", uplink_packets)
            # print("Uplink size: ", uplink_size)
            # print("Downlink packets: ", downlink_packets)
            print("Downlink size: ", downlink_size)
            print("Total size: ", total_size)
            print("Chunk duration: ", (last_pkt.time - first_pkt.time)*1000, "ms")
            # print("average time between packets: ", ((last_pkt.time - first_pkt.time)/total_packets)*1000, "ms")
            print("Inter-packet spacing (jitter) average: ", (jitter/total_packets)*1000, "ms/pkt")
            print("bitrate: ", (downlink_size*8)/((last_pkt.time - first_pkt.time)+0.000001)/1000, "Kbps")
            #duration of chunk

            print("-" * 20)
