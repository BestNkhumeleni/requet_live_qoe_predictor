Cruide steps on how to get set up

step 1:

Run "requet_end_to_end.py"
What this does is that it clones the repo with all the data and derives input features from that data and saves those input features into a pkl files to be read into an ML trainer.

pacp_tester.py is an offline version of the feature extractor, primarily for testing purposes and to ensure that input features being derived from the pcap files are being derived the same way as for live data capture

live_tester.py is the live version of pacp_tester, this however, uses a trained model and the derived input features from live data capture to predict the resolution of the video being streamed, this is the metric we use to test qoe 

Chunk_detection is also for testing purposes and can safely be ignored
