from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
from datetime import datetime
from scapy.all import ARP, Ether, srp
import json
import os
import pexpect
import re
import tkinter as tk
from PIL import Image, ImageTk
import qrcode
app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
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


# Route to add a device to the blacklist
@app.route('/blacklist', methods=['POST', 'GET'])
def blacklist_route():
    if request.method == "GET":
        black_devices = []
        with get_db_connection() as conn:
            for data in conn.execute("SELECT mac, os,last_active FROM known_devices WHERE blacklisted=1").fetchall():
                black_devices.append({
                        "mac":data[0],
                        "os": data[1],
                        "lastActive":data[2]
                    })
                 
        print(black_devices)
        return jsonify({"blacklisted_devices":list(black_devices)})

    device_mac = request.form.get('device_mac')
    
    if device_mac:
        blacklist.add(device_mac)
        conn = get_db_connection()
        conn.execute("UPDATE known_devices SET blacklisted = 1 WHERE mac = ?;", (device_mac, ))
        conn.commit()

    return f"Blacklisted : {device_mac}"

@app.route("/list_attacks", methods = ["GET"])
def list_attacks():

    # offset = request.args.get("offset", default=0)

    conn = get_db_connection()
    logs = [{"timestamp":x[3], "description":x[2], "source":x[1]} for x in conn.execute(f'SELECT * FROM attacks ORDER BY timestamp DESC').fetchall()]
    conn.close()


    return jsonify(logs)

@app.route("/devices")
def get_devices():
    devices= ""
    with open("active_devices.json", "r") as f:
        devices = json.load(f)
    return devices


if __name__ == '__main__':
    url_pattern = re.compile(r"(https?://[a-zA-Z0-9.-]+\.serveo\.net)")
    url = None
    while True:
        print("waiting for serveo to get online.")
        with open("serveooutput.txt", "r") as f:
            
            match = url_pattern.search(f.read())
            if match:
                url = match.group(1)
                break
    print(url)
    qr = qrcode.make(url)
    qr.show()
    with get_db_connection() as conn:
        black_devices = [x['mac'] for x in conn.execute("SELECT * FROM known_devices WHERE blacklisted=1").fetchall()]
        blacklist = set(black_devices)
    app.run(host = "0.0.0.0", port = 80, debug=True)
