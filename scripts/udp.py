import scapy.all as scapy


# Test Case 2: Simple UDP Packet (Random Application Data)
packet2 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.UDP(dport=12345) / scapy.Raw(load="Hello via UDP")
scapy.send(packet2)

# # Test Case 3: UDP Packet without Payload
# packet3 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.UDP(dport=5000)
# scapy.send(packet3)

# # Test Case 4: Large UDP Packet
# packet4 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.UDP(dport=4000) / scapy.Raw(load="A" * 1400)
# scapy.send(packet4)

# # Test Case 5: UDP Packet to Closed Port (simulate ICMP Port Unreachable)
# packet5 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.UDP(dport=9999) / scapy.Raw(load="Check closed port")
# scapy.send(packet5)
