from scapy.all import *
from scapy import *
from scapy.layers.dot11 import Dot11Auth, Dot11Deauth, Dot11Beacon
interface = IFACES.dev_from_index(18)
print(interface)
import sqlite3
from datetime import datetime

# Initialize SQLite database for logging attacks
conn = sqlite3.connect('intrusion_log.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS attacks 
             (id INTEGER PRIMARY KEY, ip TEXT, attack_type TEXT, timestamp TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS blacklistedips 
             (id INTEGER PRIMARY KEY, ip TEXT)''')
conn.commit()

# Define common OS fingerprinting rules based on TTL and Window Size
os_fingerprints = [
    {"os": "Linux", "ttl": 64, "window_size": 5840},
    {"os": "Windows", "ttl": 128, "window_size": 65535},
    {"os": "MacOS", "ttl": 64, "window_size": 65535},
    {"os": "FreeBSD", "ttl": 64, "window_size": 65535},
    {"os": "Solaris", "ttl": 255, "window_size": 8760}
]

# Function to identify OS based on TTL and Window Size
def identify_os(ttl, window_size):
    for fingerprint in os_fingerprints:
        if fingerprint["ttl"] == ttl and fingerprint["window_size"] == window_size:
            return fingerprint["os"]
    return "Unknown"


active_devices =set()
def log_attack(ip, attack_type):
    """Logs an attack event to the SQLite database."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with conn:
        conn.execute("INSERT INTO attacks (ip, attack_type, timestamp) VALUES (?, ?, ?)", (ip, attack_type, timestamp))
    print(f"Logged {attack_type} attack from {ip} at {timestamp}")

# Research Paper: https://www.researchgate.net/publication/343472668_Practically_Detecting_WiFi_Deauthentication_Attack_80211_Deauth_Packets_using_Python_and_Scapy
# Detects deauthentication frames
def detect_deauth(packet):
    if packet.haslayer(Dot11Deauth):
        # Log the source address of the deauth packet
        attacker_ip = packet.addr2
        log_attack(attacker_ip, "Deauthentication Attack")

# Detects "evil twin" attacks by monitoring for repeated SSID beacon frames with the same SSID from different MAC addresses
evil_twin_cache = {}

def detect_evil_twin(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet.info.decode()
        bssid = packet.addr2
        if ssid in evil_twin_cache:
            if bssid != evil_twin_cache[ssid]:
                log_attack(bssid, "Evil Twin Attack")
        else:
            evil_twin_cache[ssid] = bssid

# Detects brute force attacks by counting repeated authentication requests
auth_cache = {}
def detect_bruteforce(packet):
    if packet.haslayer(Dot11Auth):
        attacker_ip = packet.addr2
        if attacker_ip in auth_cache:
            auth_cache[attacker_ip] += 1
            if auth_cache[attacker_ip] > 10:  # Threshold for brute force attempts
                log_attack(attacker_ip, "Brute Force Attack")
                auth_cache[attacker_ip] = 0  # Reset counter after detection
        else:
            auth_cache[attacker_ip] = 1

# Sniff packets and apply attack detection
def packet_handler(packet:packet):
    # print(packet)
    # print(packet, dir(packet))
    if IP in packet and packet[IP].src[:3] in ("192", "172", "10."):
        active_devices.add(packet[IP].src)
    with open("active_devices.txt", "w") as f:
        print(active_devices)
        f.writelines(list(active_devices))
    detect_deauth(packet)
    detect_evil_twin(packet)
    detect_bruteforce(packet)

print("Starting WiFi intrusion detection...")
# Run the sniffer on the monitor interface
try:
    sniff(iface=interface, prn=packet_handler, store=0)  # Replace 'wlan0mon' with your WiFi interface in monitor mode
except KeyboardInterrupt:
    print("Stopping WiFi intrusion detection...")
    conn.close()
