from scapy.all import rdpcap, IP, TCP, UDP

def process_chunks(pkt_list):
    p = 0
    upl = 0
    upl_size = 0
    downl = 0
    downl_size = 0
    for pkt in pkt_list:
        p+=1
    #if tcp port == 443 
    #up packets have dport 443
    #down packets have sport 443
    #coutnt all up and down packets and their sizes
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
            if pkt[TCP].dport == 443:
                upl+=1
                upl_size+=len(pkt[TCP].payload)
            elif pkt[TCP].sport == 443:
                downl+=1
                downl_size+=len(pkt[TCP].payload)
    if downl_size>0 and downl>1:        
        print()
        print("Total packets: ",p)
        print("Uplink packets: ",upl)
        print("Uplink size: ",upl_size)
        print("Downlink packets: ",downl)
        print("Downlink size: ",downl_size)
        print("Total size: ",upl_size+downl_size)

def find_next_chunk(pkt_list):
    #find the next uplink packet after a downlink packet
    start_index = 0
    for i in range(len(pkt_list)):
        curent_pkt = pkt_list[i]
        last_pkt = pkt_list[i-1]
        if curent_pkt.haslayer(IP) and curent_pkt.haslayer(TCP) and (curent_pkt[TCP].dport == 443):
            if last_pkt.haslayer(IP) and last_pkt.haslayer(TCP) and (last_pkt[TCP].sport == 443):
                chunk = pkt_list[start_index:i+1]
                
                process_chunks(chunk)
                start_index = i+1

pkt_list = rdpcap("Chunk_detection.pcap")
find_next_chunk(pkt_list)