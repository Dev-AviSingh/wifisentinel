import time
from pywifi import PyWiFi, const, Profile

def scan_bssids():
    wifi = PyWiFi()
    interfaces = wifi.interfaces()
    print(interfaces)
    iface = interfaces[0]  # Select the first wireless interface
    iface.scan()  # Start scanning
    time.sleep(5)  # Give it a couple of seconds to gather results

    # Get scan results
    scan_results = iface.scan_results()

    bssids = set()
    print("BSSIDs of nearby networks:")

    for network in scan_results:
        print(network)
        bssid = network.bssid
        if bssid not in bssids:
            bssids.add(bssid)
            print(f"BSSID: {bssid}")

# Run the scan function
scan_bssids()
