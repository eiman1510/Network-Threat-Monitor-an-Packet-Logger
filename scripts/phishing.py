import scapy.all as scapy

# Test Case 1
packet1 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80) / scapy.Raw(load="http://suspicioussite.xyz/login")
scapy.send(packet1)


# # Test Case 2
# packet2 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80) / scapy.Raw(load="http://192.168.1.100/login")
# scapy.send(packet2)

# # Test Case 3
# packet3 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80) / scapy.Raw(load="http://malicioussite.com/download.exe")
# scapy.send(packet3)

# # Test Case 4
# packet4 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80) / scapy.Raw(load="http://fraudulent-site.com/reset-password")
# scapy.send(packet4)
