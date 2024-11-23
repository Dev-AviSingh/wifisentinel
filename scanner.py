from scapy.all import *
from scapy import *
from scapy.layers.dot11 import Dot11Auth, Dot11Deauth, Dot11Beacon
import json
from time import sleep
# interface = IFACES.dev_from_index(18)
# print(interface)
interface = "wlan0"
import sqlite3
from datetime import datetime
from typing import TypedDict, Literal
from threading import Thread

# Determine the local subnet
try:
    LOCAL_SUBNET = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
    LOCAL_SUBNET = LOCAL_SUBNET[:LOCAL_SUBNET.rfind(".")] + ".0/24"
except Exception as e:
    print(str(e))
    LOCAL_SUBNET = "192.168.1.1/24"
# LOCAL_SUBNET = "192.168.0.1/24"
print(LOCAL_SUBNET)

# For the scapy sniffer and threads.
stop = False

class ActiveDevice(TypedDict):
    ip:str
    os:Literal["Linux", "Windows", "MacOS", "FreeBSD", "Solaris", "Unknown", "Router"]
    lastActive:str
    mac:str
    blacklisted:bool = False


# Initialize SQLite database for logging attacks
conn = sqlite3.connect('intrusion_log.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS attacks 
             (id INTEGER PRIMARY KEY, ip TEXT, attack_type TEXT, timestamp TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS blacklistedips 
             (id INTEGER PRIMARY KEY, ip TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS known_devices 
             (id INTEGER PRIMARY KEY, mac TEXT, os TEXT, last_active TEXT, blacklisted INTEGER)''')

conn.commit()

# Define common OS fingerprinting rules based on TTL and Window Size
os_fingerprints = [
    {"os": "Linux", "ttl": 64, "window_size": 5840},
    {"os": "Windows", "ttl": 128, "window_size": 65535},
    {"os": "MacOS", "ttl": 64, "window_size": 65535},
    {"os": "FreeBSD", "ttl": 64, "window_size": 65535},
    {"os": "Solaris", "ttl": 255, "window_size": 8760}
]

active_devices:dict[str, ActiveDevice] = {}


# Function to predict OS based on TTL
def predict_os(ttl):
    if ttl >= 64 and ttl <= 70:
        return "Linux/Unix"
    elif ttl >= 120 and ttl <= 130:
        return "Windows"
    elif ttl >= 240:
        return "Networking Device (e.g., Router)"
    else:
        return "Unknown OS"

# Function to scan and predict OS
def scan_network(ip):
    # Create ARP request
    arp_req_frame = ARP(pdst=ip)
    broadcast_ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    # Send ARP request and get responses
    answered_list = srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]

    result = active_devices.copy()
    for i in range(len(answered_list)):
        client_ip = answered_list[i][1].psrc
        client_mac = answered_list[i][1].hwsrc

        # Use ICMP to determine TTL (and indirectly predict OS)
        ip_pkt = IP(dst=client_ip)
        icmp_pkt = ICMP()
        response = sr1(ip_pkt / icmp_pkt, timeout=1, verbose=False)
        if response:
            ttl = response.ttl
            os_prediction = predict_os(ttl)
        else:
            ttl = "N/A"
            os_prediction = "Unknown (No ICMP response)"

        # Append details to the result
        client_dict = {
            "ip": client_ip,
            "mac": client_mac,
            "ttl": ttl,
            "os": os_prediction,
            "lastActive":datetime.now().strftime("%H:%M:%S"),
            "blacklisted":0
        }
        # print(client_dict)
        result[client_ip] = client_dict

    return result


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
        attacker_mac = packet.addr2
        log_attack(attacker_mac, "Deauthentication Attack")

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
def detect_bruteforce(packet:packet):
    if packet.haslayer(Dot11Auth):
        attacker_mac = packet.addr2
        if attacker_mac in auth_cache:
            auth_cache[attacker_mac] += 1
            if auth_cache[attacker_mac] > 10:  # Threshold for brute force attempts
                log_attack(attacker_mac, "Brute Force Attack")
                auth_cache[attacker_mac] = 0  # Reset counter after detection
        else:
            auth_cache[attacker_mac] = 1



def update_known_devices(active_devices: dict[str, ActiveDevice]):
    """
    Update the known_devices SQLite table with the current active devices.
    """
    for ip, device in active_devices.items():
        # Check if the device is already in the database
        with conn:
            c = conn.cursor()
            c.execute("SELECT id, blacklisted FROM known_devices WHERE mac = ?", (device["mac"],))
            row = c.fetchone()

            if row:
                # Update the last_active timestamp if the device is already known
                device_id, blacklisted = row
                c.execute(
                    "UPDATE known_devices SET last_active = ? WHERE id = ?",
                    (device["lastActive"], device_id)
                )
            else:
                # Insert the new device into the database
                c.execute(
                    "INSERT INTO known_devices (mac, os, last_active, blacklisted) VALUES (?, ?, ?, ?)",
                    (device["mac"], device["os"], device["lastActive"], int(device.get("blacklisted", False)))
                )
            conn.commit()

def local_scanner(interval:int):

    while not stop:
        active_devices = scan_network(LOCAL_SUBNET)
        while True:
            try:
                update_known_devices(active_devices)
                break
            except sqlite3.OperationalError:
                continue
        # print(len(active_devices.keys()))
        with open("active_devices.json", "w") as f:
            json.dump(active_devices, f)
        # print(active_devices)
        sleep(interval)

# Sniff packets and apply attack detection
def packet_handler(packet:packet):
    # with open("active_devices.txt", "w") as f:
    #     print(active_devices)
    #     f.writelines(list(active_devices))
    
    if IP in packet:
        ip = packet[IP].src
        if ip[:7] == LOCAL_SUBNET[:7]:
            if ip in active_devices:
                active_devices[ip]["lastActive"] = datetime.now().strftime("%H:%M:%S")
            else:
                active_devices[ip] = ActiveDevice(ip = ip, os = predict_os(packet[IP].ttl),  mac=packet[Ether].src,lastActive=datetime.now().strftime("%H:%M:%S"),  blacklisted=False)

    # print(active_devices.keys())

    detect_deauth(packet)
    detect_evil_twin(packet)
    detect_bruteforce(packet)


if __name__ == "__main__":
    print("Starting WiFi intrusion detection...")
    
    t = Thread(target = local_scanner, args = (0, ))
    t.start()    
    try:
        sniff(iface=interface, prn=packet_handler, store=0, stop_filter = lambda _: stop)
    except KeyboardInterrupt:
        stop = True
        print("Stopping WiFi intrusion detection...")
        conn.close()
        t.join()
    
