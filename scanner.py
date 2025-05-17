import nmap
import scapy.all as scapy
import requests
import smtplib
import json
from email.mime.text import MIMEText
from datetime import datetime
from typing import List, Dict, Optional, Any

# Configuration
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
MAC_LOOKUP_API_URL = "https://api.macvendors.com/"
SHODAN_API_URL = "https://api.shodan.io/shodan/host/"
SHODAN_API_KEY = "Your Shodan API"  # Replace with your actual key
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("user", "user"),
    ("root", "root"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "123456"),
]
EMAIL_CONFIG = {
    "sender": "your_email@example.com",
    "password": "your_email_password",
    "receiver": "receiver_email@example.com",
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
}


def discover_devices(network: str) -> List[Dict[str, str]]:
    """Discover devices on the network using ARP scanning."""
    print(f"[*] Scanning network {network} for IoT devices...")
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return [
        {"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list
    ]


def get_vendor_name(mac_address: str) -> str:
    """Get vendor name from MAC address using API lookup."""
    try:
        response = requests.get(f"{MAC_LOOKUP_API_URL}{mac_address}", timeout=5)
        return response.text.strip() if response.status_code == 200 else "Unknown"
    except Exception as e:
        print(f"[!] Error fetching vendor name: {e}")
        return "Unknown"


def scan_ports(ip):
    print(f"[*] Scanning ports for {ip}...")
    nm = nmap.PortScanner()

    try:
        # Scan with timeout and error handling
        nm.scan(hosts=ip, arguments="-p 1-1024 -sV --host-timeout 30s")

        # Check if host was scanned successfully
        if ip not in nm.all_hosts():
            print(f"[!] Host {ip} scan failed or host was down")
            return []

        # Get open ports
        open_ports = []
        for proto in nm[ip].all_protocols():
            ports = nm[ip][proto].keys()
            for port in ports:
                if nm[ip][proto][port]["state"] == "open":
                    open_ports.append(
                        {
                            "port": port,
                            "service": nm[ip][proto][port]["name"],
                            "version": nm[ip][proto][port]["version"],
                            "protocol": proto,
                        }
                    )
        return open_ports

    except nmap.PortScannerError as e:
        print(f"[!] Nmap scan error for {ip}: {str(e)}")
        return []
    except Exception as e:
        print(f"[!] Unexpected error scanning {ip}: {str(e)}")
        return []


def check_default_credentials(ip: str) -> List[Dict[str, str]]:
    """Check for default credentials on IoT devices."""
    print(f"[*] Checking default credentials for {ip}...")
    # This is a simulation - in a real implementation you would attempt actual logins
    return [{"username": "admin", "password": "admin"}]  # Simulated vulnerable device


def fetch_cve_data(vendor_name: str) -> Optional[Dict]:
    """Fetch CVE data for a vendor from NVD database."""
    print(f"[*] Fetching CVE data for {vendor_name}...")
    try:
        response = requests.get(f"{CVE_API_URL}?keyword={vendor_name}", timeout=10)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"[!] Error fetching CVE data: {e}")
        return None


def fetch_shodan_data(ip: str) -> Optional[Dict]:
    """Fetch device information from Shodan."""
    print(f"[*] Fetching Shodan data for {ip}...")
    try:
        response = requests.get(
            f"{SHODAN_API_URL}{ip}?key={SHODAN_API_KEY}", timeout=10
        )
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"[!] Error fetching Shodan data: {e}")
        return None


def send_email(subject: str, body: str) -> bool:
    """Send email alert about vulnerabilities."""
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_CONFIG["sender"]
        msg["To"] = EMAIL_CONFIG["receiver"]

        with smtplib.SMTP(
            EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]
        ) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["sender"], EMAIL_CONFIG["password"])
            server.sendmail(
                EMAIL_CONFIG["sender"], EMAIL_CONFIG["receiver"], msg.as_string()
            )
        print("[*] Email sent successfully.")
        return True
    except Exception as e:
        print(f"[!] Error sending email: {e}")
        return False


def generate_report(
    device: Dict[str, str],
    open_ports: List[Dict[str, Any]],
    credentials: List[Dict[str, str]],
    cve_data: Optional[Dict],
    shodan_data: Optional[Dict],
    vendor_name: str,
) -> Dict[str, Any]:
    """Generate a comprehensive security report for a device."""
    return {
        "device_name": (
            shodan_data.get("product", "IoT Device") if shodan_data else "IoT Device"
        ),
        "ip_address": device["ip"],
        "mac_address": device["mac"],
        "vendor_name": vendor_name,
        "open_ports": open_ports,
        "default_credentials": credentials,
        "cve_data": cve_data,
        "shodan_data": shodan_data,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
