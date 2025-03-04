# Final Project - Communication Networks  

## **Project Overview**  
This project analyzes network traffic characteristics and their impact on network performance, security, and user privacy.  
The project is divided into three main parts:  

### **Part 1: Open-ended Questions**  
Answering theoretical questions on topics such as flow control, routing, MPTCP, packet loss, and performance analysis in network and transport layers.  

### **Part 2: Research Paper Analysis**  
Reviewing scientific papers on encrypted traffic classification and comparing different network traffic features.  

### **Part 3: Practical Traffic Analysis**  
1. **Capturing network traffic using Wireshark** for various applications:  
   - Web Browsing: Chrome, Edge  
   - Streaming Services: YouTube, Spotify  
   - Video Conferencing: Zoom  

2. **Comparing network traffic characteristics**:  
   - IP, TCP, and TLS header fields  
   - Packet sizes and inter-arrival times  
   - Flow volume and number of packets  

3. **Identifying traffic patterns from an attacker's perspective**:  
   - Analyzing whether an attacker can identify applications even with encrypted traffic  
   - Comparing attack scenarios with full vs. limited knowledge of packet metadata  

---

# How to Run the Project  

## 1. Install Dependencies  
Install the following libraries in PyCharm:  
- `pandas`  
- `matplotlib`  
- `seaborn`  

## 2. In order to run this file - `traffic_analyzer.py`  
 You need to follow these steps:  
1. Capture in Wireshark 5 different records while keeping all other apps closed to reduce noise, and name the records as follows:  

 - Capture traffic using Spotify and save it as `spotify.pcapng`.  

 - Make a record while using Chrome and save it as `chrome.pcapng`.  

 - Make a record while using YouTube and save it as `youtube.pcapng`.  

 - Make a record while using Zoom and save it as `zoom.pcapng`.  

 - Make a record while using Microsoft Edge and save it as `microsoft_edge.pcapng`.  

2. Make sure all records include these columns. If not, add them:  
"No.", "Time", "Source IP", "Destination IP", "Protocol", "Length", "Info", "Delta-time", "Time to Live", "Calculated Window Size", "TLS Version", "TLS Handshake Type", "TLS Cipher Suite", "TCP Sequence Number", "TCP Acknowledgment Number", "TCP Flags", "Source Port", "Destination Port".  

3. Export each `.pcapng` file to a `.csv` file and keep the same name as in the recording.  

4. Add the `.csv` files to the `finalAssNetworking` directory and then run the `traffic_analyzer.py` file using PyCharm.  

---

## 3. In order to run this file - `attack_analyzer.py`  
 You need to follow these steps:  

1. Capture new traffic on whatever app you want and save it as `chrome_spotify_attacker.pcapng`.  
   *(We used this name for our testing, so name your recording the same.)*  

2. Following the explanation above, make sure your recording has the exact same columns as mentioned for running the previous file.  

3. Export the `.pcapng` file to a `.csv` file and keep the same name as in the recording.  

4. Add the `.csv` file to the `finalAssNetworking` directory.  

5. Before running `attack_analyzer.py`, make sure all five previously created `.csv` files and the newly created file are in the same directory (`finalAssNetworking`).  

6. Run `attack_analyzer.py` using PyCharm.  

7. After executing `attack_analyzer.py`, four graphs will appear inside a new folder named `results`, which will be created at runtime.  
