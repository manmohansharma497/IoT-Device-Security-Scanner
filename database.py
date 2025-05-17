import sqlite3
import json
from typing import Dict, Any, List, Tuple, Optional


def init_db() -> None:
    """Initialize the SQLite database."""
    conn = sqlite3.connect("iot_scans.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT,
            ip_address TEXT,
            mac_address TEXT,
            vendor_name TEXT,
            open_ports TEXT,
            default_credentials TEXT,
            cve_data TEXT,
            shodan_data TEXT,
            timestamp TEXT
        )
    """
    )
    conn.commit()
    conn.close()


def save_scan(report: Dict[str, Any]) -> None:
    """Save a scan report to the database."""
    conn = sqlite3.connect("iot_scans.db")
    cursor = conn.cursor()

    # Ensure all JSON fields are properly serialized
    open_ports = json.dumps(report["open_ports"]) if report.get("open_ports") else None
    default_credentials = (
        json.dumps(report["default_credentials"])
        if report.get("default_credentials")
        else None
    )
    cve_data = json.dumps(report["cve_data"]) if report.get("cve_data") else None
    shodan_data = (
        json.dumps(report["shodan_data"]) if report.get("shodan_data") else None
    )

    cursor.execute(
        """
        INSERT INTO scans (
            device_name, ip_address, mac_address, vendor_name,
            open_ports, default_credentials, cve_data, shodan_data, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            report.get("device_name"),
            report.get("ip_address"),
            report.get("mac_address"),
            report.get("vendor_name"),
            open_ports,
            default_credentials,
            cve_data,
            shodan_data,
            report.get("timestamp"),
        ),
    )
    conn.commit()
    conn.close()


def get_scans():
    try:
        conn = sqlite3.connect("iot_scans.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
        scans = cursor.fetchall()
        conn.close()

        if not scans:
            print("[DEBUG] No scans found in database")
        return scans

    except sqlite3.Error as e:
        print(f"[ERROR] Database error: {e}")
        return []


def get_device_details(ip_address: str) -> Optional[Dict[str, Any]]:
    """Get detailed information for a specific device."""
    conn = sqlite3.connect("iot_scans.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE ip_address = ?", (ip_address,))
    scan = cursor.fetchone()
    conn.close()

    if not scan:
        return None

    try:
        open_ports = json.loads(scan[5]) if scan[5] and scan[5] != "None" else []
    except json.JSONDecodeError:
        print(f"Warning: Invalid open_ports JSON for {ip_address}: {scan[5]}")
        open_ports = []

    try:
        default_credentials = (
            json.loads(scan[6]) if scan[6] and scan[6] != "None" else []
        )
    except json.JSONDecodeError:
        print(f"Warning: Invalid credentials JSON for {ip_address}: {scan[6]}")
        default_credentials = []

    try:
        cve_data = json.loads(scan[7]) if scan[7] and scan[7] != "None" else None
    except json.JSONDecodeError:
        print(f"Warning: Invalid CVE data JSON for {ip_address}: {scan[7]}")
        cve_data = None

    try:
        shodan_data = json.loads(scan[8]) if scan[8] and scan[8] != "None" else None
    except json.JSONDecodeError:
        print(f"Warning: Invalid Shodan data JSON for {ip_address}: {scan[8]}")
        shodan_data = None

    return {
        "id": scan[0],
        "device_name": scan[1],
        "ip_address": scan[2],
        "mac_address": scan[3],
        "vendor_name": scan[4],
        "open_ports": open_ports,
        "default_credentials": default_credentials,
        "cve_data": cve_data,
        "shodan_data": shodan_data,
        "timestamp": scan[9],
    }


# In database.py
def fix_corrupted_data():
    conn = sqlite3.connect("iot_scans.db")
    cursor = conn.cursor()

    # Update all rows with invalid JSON
    cursor.execute(
        "SELECT id, open_ports, default_credentials, cve_data, shodan_data FROM scans"
    )
    for row in cursor.fetchall():
        id_, open_ports, credentials, cve_data, shodan_data = row

        # Fix each field if needed
        new_values = {}
        for field in ["open_ports", "default_credentials", "cve_data", "shodan_data"]:
            value = locals()[field]
            if value and value != "None":
                try:
                    json.loads(value)
                except json.JSONDecodeError:
                    new_values[field] = None  # Or appropriate default

        if new_values:
            cursor.execute(
                f"""
                UPDATE scans SET
                open_ports = ?,
                default_credentials = ?,
                cve_data = ?,
                shodan_data = ?
                WHERE id = ?
            """,
                (
                    new_values.get("open_ports", open_ports),
                    new_values.get("default_credentials", credentials),
                    new_values.get("cve_data", cve_data),
                    new_values.get("shodan_data", shodan_data),
                    id_,
                ),
            )

    conn.commit()
    conn.close()
