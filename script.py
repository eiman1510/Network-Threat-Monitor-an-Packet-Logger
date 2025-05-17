import scapy.all as scapy
import re
import time
from collections import Counter
import os
import platform
import sys
import threading
import queue

# === Setup ===
os.makedirs("logs", exist_ok=True)
LOG_FILE = "logs/network_traffic.log"
scan_counts = Counter()
ddos_counts = Counter()

# Global variables for attack simulation detection
active_attack_mode = None
log_queue = queue.Queue()
should_stop = threading.Event()

# === Patterns ===
PHISHING_PATTERNS = [
    r"(?:https?://)?(?:www\.)?(?!example\.com)[a-z0-9-]+\.(?:tk|ml|ga|cf|gq)",
    r"(?:https?://)?.*\.(?:\d{1,3}\.){3}\d{1,3}",
    r"(?:https?://)?.*(login|verify|update).*",
    r"(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z]{2,}){1,2}/.*(login|account|bank|payment).*",
    r"(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z]{2,}){1,2}/.*\?(?:user|email|pass).*",
    r"(\.zip|\.exe|\.scr)\b",
    r"(?:https?://)(?:www\.)?[a-z0-9-]+(?:\.[a-z]{2,}){1,2}/.*(reset|recover|support).*",
    r"(?:https?://)?(?:www\.)?(?!example\.com)[a-z0-9-]+\.(?:cn|ru|in|xyz|co|co\.uk)",
    r"(?:https?://)?(?:www\.)?[a-z0-9-]+\.(?:com|org|net)/.*(admin|config|system).*",
]

SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\bOR\b.+\b=\b",
    r"UNION(\s+ALL)?(\s+SELECT)",
    r"SELECT.+FROM",
    r"INSERT(\s+INTO)?\s",
    r"UPDATE\s.+\sSET\s",
    r"DELETE\s+FROM",
    r"DROP\s+TABLE",
    r"EXEC(\s|\+)+(s|x)p\w+",
    r"OR\s+1=1",
    r"' OR '1'='1",
    r"admin' --",
]
# === Logging Helper ===
def log_packet(log_type, details, attack_type=None):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {log_type}: {details}\n"
    
    # Add to queue for processing
    log_queue.put((log_entry, log_type, attack_type))

# Thread to handle logging
def log_processor():
    while not should_stop.is_set() or not log_queue.empty():
        try:
            log_entry, log_type, attack_type = log_queue.get(timeout=1)
            
            # Filter logs based on active attack mode
            if active_attack_mode is None or attack_type is None or active_attack_mode == attack_type:
                print(log_entry.strip())
                with open(LOG_FILE, "a") as log:
                    log.write(log_entry)
            
            log_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Error in log processor: {e}")

# === Scan Detection ===
def detect_scan_type(packet):
    flags = packet[scapy.TCP].flags
    if flags == "SA":
        return "TCP CONNECT SCAN"
    elif flags == 0:
        return "NULL SCAN"
    elif flags == "FPU":
        return "XMAS SCAN"
    elif flags == "F":
        return "FIN SCAN"
    return None

# === Main Packet Handler ===
def packet_callback(packet):

      
    if not packet.haslayer(scapy.IP):
        return

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst

    # Ignore local/broadcast packets to reduce junk
    if (src_ip.startswith("127.") or dst_ip.startswith("127.") or 
        src_ip.startswith("224.") or dst_ip.startswith("224.")):
        return

    is_attack = False
    attack_type = None
    payload = ""

    if packet.haslayer(scapy.Raw):
        try:
            payload = packet[scapy.Raw].load.decode("utf-8", errors="ignore")
            payload = ''.join(c for c in payload if c.isprintable())
        except Exception:
            payload = ""

    # === Phishing Detection ===
    if payload and any(re.search(pattern, payload, re.IGNORECASE) for pattern in PHISHING_PATTERNS):
        log_packet("PHISHING ATTEMPT", f"{src_ip} -> {dst_ip} | Payload: {payload}", "phishing")
        is_attack = True
        attack_type = "phishing"
        return

    # === SQL Injection Detection ===
    elif payload and any(re.search(pattern, payload, re.IGNORECASE) for pattern in SQLI_PATTERNS):
        log_packet("SQL INJECTION ATTEMPT", f"{src_ip} -> {dst_ip} | Payload: {payload}", "sql")
        is_attack = True
        attack_type = "sql"
        return

    # === Port Scan Detection (TCP) ===
    elif packet.haslayer(scapy.TCP):
        scan_type = detect_scan_type(packet)
        if scan_type:
            log_packet(f"{scan_type}", f"{src_ip} -> {dst_ip}", "scan")
            is_attack = True
            attack_type = "scan"
            return

    # === UDP Scan Detection ===
    elif packet.haslayer(scapy.UDP):
        scan_counts[(src_ip, dst_ip)] += 1
        if scan_counts[(src_ip, dst_ip)] >= 10:
            log_packet("UDP SCAN DETECTED", f"{src_ip} -> {dst_ip}", "udp")
            scan_counts[(src_ip, dst_ip)] = 0
            is_attack = True
            attack_type = "udp"
            return
    # === DDoS Detection (basic threshold) ===
    ddos_counts[dst_ip] += 1
    if ddos_counts[dst_ip] > 200:
        log_packet("DDoS ATTACK DETECTED", f"Target: {dst_ip} (Over 200 packets)", "ddos")
        ddos_counts[dst_ip] = 0
        is_attack = True
        attack_type = "ddos"
        return

    # === Normal Packets ===
    if not is_attack:
        summary = f"{src_ip} -> {dst_ip}"
        if packet.haslayer(scapy.TCP):
            summary += f" | TCP dport={packet[scapy.TCP].dport}"
            attack_type = "tcp"
        elif packet.haslayer(scapy.UDP):
            summary += f" | UDP dport={packet[scapy.UDP].dport}"
            attack_type = "udp"
        elif packet.haslayer(scapy.ICMP):
            summary += " | ICMP"
            attack_type = None
        
        # Log normal packets but tag with the protocol type
        log_packet("NORMAL PACKET", summary, attack_type)
        return

def set_attack_mode(mode=None):
    global active_attack_mode
    active_attack_mode = mode
    print(f"[*] Attack mode set to: {mode if mode else 'ALL'}")

def clear_logs():
    with open(LOG_FILE, "w") as log:
        log.write("")
    print("[*] Logs cleared.")

def main():
    # Create a log processor thread
    log_thread = threading.Thread(target=log_processor, daemon=True)
    log_thread.start()
    
    # Interface Selection
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: python script.py [--attack=TYPE] [--iface=INTERFACE]")
        print("  --attack=TYPE: Filter for specific attack (phishing, sql, scan, tcp, udp, ddos)")
        print("  --iface=INTERFACE: Specify network interface")
        sys.exit(0)
    
    attack_filter = None
    iface = None
    
    for arg in sys.argv[1:]:
        if arg.startswith("--attack="):
            attack_filter = arg.split("=")[1]
        elif arg.startswith("--iface="):
            iface = arg.split("=")[1]
    
    if attack_filter:
        set_attack_mode(attack_filter)
    
    # if not iface:
    #     if platform.system() == "Windows":
    #         iface = [i for i in scapy.get_if_list() if "NPF_Loopback" not in i][0]
    #     else:
    #         iface = "eth0"  # Default for Linux
    iface="eth0"
    
    print(f"[*] Starting packet monitoring on {iface}...")
    print(f"[*] Logging to: {LOG_FILE}")
    print("[*] Press Ctrl+C to stop")
    
    try:
        scapy.sniff(
            iface=iface,
            filter="tcp or udp",
            prn=packet_callback,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
    finally:
        should_stop.set()
        log_thread.join(timeout=2)
        print("[*] Packet capture stopped.")

if __name__ == "__main__":
    main()