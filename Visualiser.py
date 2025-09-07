import matplotlib.pyplot as plt
import numpy as np

class Visualiser:

  def __init__(self, video_start_time):
    self.video_start_time = video_start_time
    self.setup_plots()

  def setup_plots(self):
    fig, ax = plt.subplots(2, 2, figsize=(12, 12))

    self.packet_plot = ax[0,0]
    self.chunk_size_plot = ax[1,0]
    self.average_timing_plot = ax[0,1]
    self.last_plot = ax[1,1]

    self.packet_plot.set_title('Packet Size over Time')
    self.packet_plot.set_xlabel('Time (s)')
    self.packet_plot.set_ylabel('Packet Size (bytes)')

    self.chunk_size_plot.set_title('Chunk Size Visualization')
    self.chunk_size_plot.set_xlabel('Chunk Attributes')
    
    plt.ion()  # Turn on interactive mode
    plt.show()
  
  def add_packet(self,pkt):
    #get relative time stamp 
    rel_time = pkt.time - self.video_start_time   
    size = len(pkt)
    #add a dot to the packet size over time plot
    self.packet_plot.scatter(rel_time, size, color='blue', s=10)
    plt.pause(0.01)  # Pause to update the plot
    plt.draw()

  def create_visuals(self, first_pkt, last_pkt,jitter, uplink_size, downlink_size, total_packets):
    total_size = uplink_size + downlink_size
    duration = (last_pkt.time - first_pkt.time)*1000  # in ms
    bitrate = (downlink_size*8)/((last_pkt.time - first_pkt.time)+0.000001)/1000  # in Kbps
    jitter_avg = (jitter/total_packets)*1000  # in ms/pkt
    #create individual bar for downlink size, duration, bitrate, jitter_avg
    labels = ['Downlink Size (bytes)', 'Duration (ms)', 'Bitrate (Kbps)', 'Avg Jitter (ms/pkt)']
    values = [downlink_size, duration, bitrate, jitter_avg]
    colors = ['blue', 'orange', 'green', 'red']

    bars = plt.bar(labels, values, color=colors)
    plt.title('Chunk Summary Visualization')
    plt.ylabel('Values')
    plt.ylim(0, max(values) * 1.2) 