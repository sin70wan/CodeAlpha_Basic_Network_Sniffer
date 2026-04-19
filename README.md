# Basic Network Packet Sniffer

## CodeAlpha Cybersecurity Internship - Task 1

### Description
A Python-based network packet sniffer that captures and analyzes live network traffic using Scapy.

### Features
- Captures TCP, UDP, and ICMP packets
- Displays source/destination IP addresses
- Shows port numbers and TCP flags
- Extracts payload data

### Requirements
- Python 3.x
- Scapy: `pip install scapy`
- Npcap (Windows) or libpcap (Linux)

### Usage
```bash
# Run as Administrator
python network_sniffer.py
# Choose 2 (specific number)
# Enter 20 (packets to capture)
# Press Enter for default interface
