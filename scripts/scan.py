import scapy.all as scapy

# # Test Case 1: NULL Scan (no flags set)
# packet1 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80, flags=0)
# scapy.send(packet1)

# Test Case 2: FIN Scan (only FIN flag set)
# packet2 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80, flags="F")
# scapy.send(packet2)

# # Test Case 3: Xmas Scan (FIN, PSH, URG flags set)
packet3 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80, flags="FPU")
scapy.send(packet3)

# # Test Case 4: TCP SYN Scan (only SYN flag set)
# packet4 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80, flags="S")
# scapy.send(packet4)
