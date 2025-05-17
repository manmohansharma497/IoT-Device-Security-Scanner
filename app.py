from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from scanner import (
    discover_devices,
    scan_ports,
    check_default_credentials,
    fetch_cve_data,
    fetch_shodan_data,
    generate_report,
    get_vendor_name,
    send_email,
)
from database import init_db, save_scan, get_scans, get_device_details
import threading
import time
import json

app = Flask(__name__)
socketio = SocketIO(app)
init_db()


# Background scanning thread
def background_scanner():
    while True:
        try:
            network = "172.16.52.0/24"
            devices = discover_devices(network)
            for device in devices:
                try:
                    vendor_name = get_vendor_name(device["mac"])
                    open_ports = scan_ports(device["ip"])
                    credentials = check_default_credentials(device["ip"])
                    cve_data = fetch_cve_data(vendor_name)
                    shodan_data = fetch_shodan_data(device["ip"])

                    report = generate_report(
                        device=device,
                        open_ports=open_ports,
                        credentials=credentials,
                        cve_data=cve_data,
                        shodan_data=shodan_data,
                        vendor_name=vendor_name,
                    )

                    save_scan(report)
                    socketio.emit("new_scan", report)

                except Exception as e:
                    print(f"Error processing device {device['ip']}: {str(e)}")
                    continue

            time.sleep(3600)

        except Exception as e:
            print(f"Scanner error: {str(e)}")
            time.sleep(60)


# Start background thread
scanner_thread = threading.Thread(target=background_scanner)
scanner_thread.daemon = True
scanner_thread.start()


# API Endpoints
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scans")
def get_all_scans():
    scans = get_scans()
    return jsonify(scans)


@app.route("/api/vulnerability-stats")
def get_vulnerability_stats():
    scans = get_scans()
    stats = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    for scan in scans:
        cve_data = scan[7]
        if cve_data:
            try:
                cve_json = json.loads(cve_data)
                if (
                    cve_json
                    and "result" in cve_json
                    and "CVE_Items" in cve_json["result"]
                ):
                    for item in cve_json["result"]["CVE_Items"]:
                        severity = (
                            item.get("impact", {})
                            .get("baseMetricV2", {})
                            .get("severity", "LOW")
                        )
                        if severity == "CRITICAL":
                            stats["critical"] += 1
                        elif severity == "HIGH":
                            stats["high"] += 1
                        elif severity == "MEDIUM":
                            stats["medium"] += 1
                        else:
                            stats["low"] += 1
            except:
                continue

    return jsonify(stats)


@app.route("/api/port-stats")
def get_port_stats():
    scans = get_scans()
    ports = {"http": 0, "ssh": 0, "telnet": 0, "other": 0}

    for scan in scans:
        open_ports = scan[5]
        if open_ports:
            try:
                ports_list = json.loads(open_ports)
                for port in ports_list:
                    if port["port"] == 80:
                        ports["http"] += 1
                    elif port["port"] == 22:
                        ports["ssh"] += 1
                    elif port["port"] == 23:
                        ports["telnet"] += 1
                    else:
                        ports["other"] += 1
            except:
                continue

    return jsonify([ports["http"], ports["ssh"], ports["telnet"], ports["other"]])


@app.route("/api/device-details")
def get_device_details_api():
    ip_address = request.args.get("ip")
    if not ip_address:
        return jsonify({"error": "IP address required"}), 400

    device = get_device_details(ip_address)
    return jsonify(device) if device else (jsonify({"error": "Device not found"}), 404)


# In app.py - Add a new endpoint
@app.route("/api/device-full-details")
def get_device_full_details():
    ip_address = request.args.get("ip")
    if not ip_address:
        return jsonify({"error": "IP address required"}), 400

    device = get_device_details(ip_address)
    if not device:
        return jsonify({"error": "Device not found"}), 404

    # Enhanced details logic
    details = {
        "basic_info": {
            "ip": device["ip_address"],
            "mac": device["mac_address"],
            "vendor": device["vendor_name"],
            "last_seen": device["timestamp"],
        },
        "network_info": {
            "open_ports": device.get("open_ports", []),
            "services": list(
                set(port["service"] for port in device.get("open_ports", []))
            ),
        },
        "security_info": {
            "vulnerabilities": len(
                device.get("cve_data", {}).get("result", {}).get("CVE_Items", [])
            ),
            "default_creds": bool(device.get("default_credentials", [])),
            "risk_score": calculate_risk_score(device),
        },
    }

    return jsonify(details)


def calculate_risk_score(device):
    """Calculate a simple risk score based on various factors"""
    score = 0

    # Points for open ports
    risky_ports = {22: 1, 23: 3, 80: 1, 443: 1, 21: 2, 3389: 2}
    for port in device.get("open_ports", []):
        score += risky_ports.get(port["port"], 0)

    # Points for vulnerabilities
    vuln_count = len(device.get("cve_data", {}).get("result", {}).get("CVE_Items", []))
    score += min(vuln_count * 2, 10)  # Max 10 points for vulnerabilities

    # Points for default credentials
    if device.get("default_credentials"):
        score += 5

    return min(score, 20)  # Cap at 20


if __name__ == "__main__":
    socketio.run(app, debug=True)
