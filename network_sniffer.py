#!/usr/bin/env python3
"""
Basic Network Packet Sniffer
CodeAlpha Cybersecurity Internship - Task 1
Captures and analyzes network traffic packets
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime

# Counter for packets
packet_count = 0

def analyze_packet(packet):
    """Analyze and display packet information"""
    global packet_count
    packet_count += 1
    
    print("\n" + "="*70)
    print(f"[PACKET #{packet_count}] Time: {datetime.datetime.now()}")
    print("="*70)
    
    # Check if packet has IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        
        # Determine protocol type
        if protocol == 6:
            print("Protocol: TCP (Transmission Control Protocol)")
            if TCP in packet:
                tcp = packet[TCP]
                print(f"Source Port: {tcp.sport}")
                print(f"Destination Port: {tcp.dport}")
                print(f"Flags: {tcp.flags}")
                
        elif protocol == 17:
            print("Protocol: UDP (User Datagram Protocol)")
            if UDP in packet:
                udp = packet[UDP]
                print(f"Source Port: {udp.sport}")
                print(f"Destination Port: {udp.dport}")
                
        elif protocol == 1:
            print("Protocol: ICMP (Internet Control Message Protocol)")
            if ICMP in packet:
                icmp = packet[ICMP]
                print(f"ICMP Type: {icmp.type}")
                print(f"ICMP Code: {icmp.code}")
        else:
            print(f"Protocol: Other (Protocol Number: {protocol})")
        
        # Show raw payload data if available
        if Raw in packet:
            raw_data = packet[Raw].load
            print(f"\nPayload Data (first 100 bytes): {raw_data[:100]}")
            print(f"Payload Length: {len(raw_data)} bytes")
            
    else:
        print("Non-IP Packet (e.g., ARP)")

def start_sniffing(interface=None, packet_limit=50):
    """
    Start capturing network packets
    
    Args:
        interface: Network interface to sniff (None = auto-detect)
        packet_limit: Number of packets to capture (0 = unlimited)
    """
    print("\n" + "="*70)
    print("🔍 BASIC NETWORK SNIFFER - CodeAlpha")
    print("="*70)
    print(f"Starting packet capture...")
    print(f"Packet limit: {packet_limit if packet_limit > 0 else 'Unlimited'}")
    print(f"Interface: {interface if interface else 'Default'}")
    print("\n⚠️  Press Ctrl+C to stop capturing")
    print("="*70)
    
    try:
        # Start sniffing
        sniff(iface=interface, 
              prn=analyze_packet, 
              count=packet_limit if packet_limit > 0 else None,
              store=False)
              
    except KeyboardInterrupt:
        print("\n" + "="*70)
        print(f"✅ Capture stopped. Total packets captured: {packet_count}")
        print("="*70)
    except PermissionError:
        print("\n❌ ERROR: Permission denied!")
        print("Run this script with administrator/root privileges:")
        print("  Windows: Run terminal as Administrator")
        print("  Linux/Mac: sudo python3 network_sniffer.py")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")

def main():
    """Main function - handles user input and starts sniffer"""
    print("\n" + "="*70)
    print("📡 BASIC NETWORK PACKET SNIFFER")
    print("CodeAlpha Cybersecurity Internship - Task 1")
    print("="*70)
    
    # Get user preferences
    print("\nOptions:")
    print("1. Capture unlimited packets (Ctrl+C to stop)")
    print("2. Capture specific number of packets")
    
    choice = input("\nEnter your choice (1 or 2): ").strip()
    
    if choice == "2":
        try:
            packet_limit = int(input("Enter number of packets to capture: "))
            if packet_limit <= 0:
                packet_limit = 50
                print(f"Using default: {packet_limit} packets")
        except ValueError:
            packet_limit = 50
            print(f"Invalid input. Using default: {packet_limit} packets")
    else:
        packet_limit = 0  # Unlimited
    
    # Ask for specific interface (optional)
    interface = input("\nEnter network interface name (press Enter for default): ").strip()
    if not interface:
        interface = None
    
    # Start sniffing
    start_sniffing(interface, packet_limit)

if __name__ == "__main__":
    main()