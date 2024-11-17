from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
from datetime import datetime
from scapy.all import ARP, Ether, srp

app = Flask(__name__)

DATABASE = 'intrusion_log.db'
blacklist = set()  # In-memory blacklist of device IPs or MACs

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Route to show the single page with all features
@app.route('/')
def dashboard():
    return render_template("index.html")

# Network scanning function
def scan_network():
    target_ip = "192.168.1.1/24"  # Replace with your subnet
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []

    for sent, received in result:
        device = {'ip': received.psrc, 'mac': received.hwsrc}
        if device['ip'] not in blacklist and device['mac'] not in blacklist:
            devices.append(device)
        else:
            blacklist.add(device['ip'])

    return devices 

# Route to add a device to the blacklist
@app.route('/blacklist', methods=['POST', 'GET'])
def blacklist_route():
    if request.method == "GET":
        return jsonify(blacklist)

    device_ip = request.form.get('device_ip')
    device_mac = request.form.get('device_mac')
    
    if device_ip:
        blacklist.add(device_ip)
    if device_mac:
        blacklist.add(device_mac)
    
    return redirect(url_for('dashboard'))

@app.route("/list_attacks", methods = ["GET"])
def list_attacks():
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM attacks ORDER BY timestamp DESC').fetchall()
    conn.close()

    return jsonify(logs)

@app.route("/devices")
def get_devices():
    return jsonify(scan_network())

if __name__ == '__main__':
    app.run(debug=True)
