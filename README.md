# Network Traffic Detector

A simple network traffic detector.

## Key Features
- **Shows TCP SYN traffic in blue**: The traffic initiated by the running host.
- **Shows TCP ACK traffic in green**: The traffic coming in response to the running host's initiation.
- **Highlights potential dangerous traffic in red**: This may not necessarily be dangerous and could be from the host itself or the host's router. However, it's still worth keeping an eye on.
- **Unresolved network addresses**: If the network address cannot be resolved, the code will display the output in red.
- **Enhanced forensic investigation**: The code can be further enhanced with deep packet analysis for more detailed forensic investigation.

## Technologies Used
- Ruby
- WEBrick
- PacketGen
- Resolv
- Socket

## Installation Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/guneybilen/network_traffic_detector.git
2. cd network_traffic_detector
3. bundler install
4. rvmsudo ruby host_traffic_detector.rb

