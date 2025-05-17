import scapy.all as scapy

# Test Case 1: Normal HTTP GET request
packet1 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80) / scapy.Raw(load="GET /index.html HTTP/1.1")
scapy.send(packet1)

# # Test Case 2: Normal ICMP Echo Request (Ping)
# packet2 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.ICMP()
# scapy.send(packet2)

# # Test Case 3: Normal DNS Query
# packet3 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.UDP(dport=53) / scapy.Raw(load="www.example.com")
# scapy.send(packet3)

# # Test Case 4: Normal TCP packet (no payload)
# packet4 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80)
# scapy.send(packet4)
