import matplotlib.pyplot as plt
import numpy as np

class Visualiser:
  bitrate_category = "Bitrate"
  jitter_category = "Jitter"
  first_packet_time = 0
  def __init__(self, first_packet_time):
    self.first_packet_time = self.first_packet_time if self.first_packet_time != 0 else first_packet_time
    self.setup_plots()

  def setup_plots(self):
    fig, ax = plt.subplots(2, 2, figsize=(12, 12))

    self.packet_plot = ax[0,0]
    self.chunk_size_plot = ax[1,0]
    self.average_bitrate_plot = ax[0,1]
    self.average_jitter_plot = ax[1,1]

    self.packet_plot.set_title('Packet Size over Time')
    self.packet_plot.set_xlabel('Time (s)')
    self.packet_plot.set_ylabel('Packet Size (bytes)')

    self.chunk_size_plot.set_title('Chunk Size Visualization')
    self.chunk_size_plot.set_xlabel('time')

    self.average_bitrate_plot.set_title('Average Bitrate per Chunk')
    self.average_bitrate_plot.set_xlabel('Time (s)')
    self.average_bitrate_plot.set_ylabel('Data Rate(Kbps)')

    self.average_jitter_plot.set_title('Average Jitter per packet in Chunk')
    self.average_jitter_plot.set_xlabel('Time (s)')
    self.average_jitter_plot.set_ylabel('Data Rate(sec/packet)')
    
    plt.ion()  # Turn on interactive mode
    plt.show()
  
  def add_packet(self,pkt):
    #get relative time stamp 
    rel_time = pkt.time - self.first_packet_time   
    size = len(pkt)
    #add a dot to the packet size over time plot
    self.packet_plot.scatter(rel_time, size, color='blue', s=10)
    plt.pause(0.01)  # Pause to update the plot
    plt.draw()

  def create_visuals(self, first_pkt, last_pkt,jitter, uplink_size, downlink_size, total_packets):
    #create histogram of total size and downlink size
    bar_centre = (last_pkt.time - first_pkt.time)/2 + (first_pkt.time - self.first_packet_time)

    #plotting end of chunk dotted line
    self.plotChunkEnd(last_pkt.time - self.first_packet_time)

    duration = (last_pkt.time - first_pkt.time)  # in s
    
    bitrate = (downlink_size*8)/((last_pkt.time - first_pkt.time)+0.000001)  # in Kbps
    bitrate = bitrate/1000000  # convert to Mbps

    self.average_bitrate_plot.scatter(bar_centre, bitrate,s = 10)
    jitter_avg = (jitter/total_packets/1000)  # in ms/pkt
    self.average_jitter_plot.scatter(bar_centre, jitter_avg, s=10)


    rel_time = last_pkt.time - self.first_packet_time
    total_size = uplink_size + downlink_size
    self.chunk_size_plot.bar(bar_centre, total_size, color='blue', label='Total Size',width=duration)
    self.chunk_size_plot.bar(bar_centre, downlink_size, color='orange', label='Downlink Size', width=duration)
    # self.chunk_size_plot.legend()
    plt.pause(0.01)  # Pause to update the plot
    plt.draw()
  
  def plotChunkEnd(self,time):
    self.average_bitrate_plot.axvline(x=time, linestyle='dashed', color="gray")
    self.packet_plot.axvline(x=time, linestyle='dashed', color="gray")
    self.average_jitter_plot.axvline(x=time, linestyle='dashed', color="gray")
