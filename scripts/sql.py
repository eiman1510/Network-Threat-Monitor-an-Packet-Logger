import scapy.all as scapy

# # Test Case 1: SQL Injection with a simple comment
# packet1 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80) / scapy.Raw(load="'; --")
# scapy.send(packet1)

# # Test Case 2: SQL Injection with a UNION SELECT query
packet2 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80) / scapy.Raw(load="UNION SELECT username, password FROM users")
scapy.send(packet2)

# # Test Case 3: SQL Injection with 'OR' condition
# packet3 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80) / scapy.Raw(load="OR 1=1")
# scapy.send(packet3)

# # # Test Case 4: SQL Injection using 'OR' combined with 'DROP'
# packet4 = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(dport=80) / scapy.Raw(load="OR 1=1; DROP TABLE users;")
# scapy.send(packet4)
