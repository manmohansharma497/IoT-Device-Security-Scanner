import sqlite3
import json


def migrate():
    # Connect to old database
    old_conn = sqlite3.connect("iot_scans.db")
    old_cursor = old_conn.cursor()

    # Create new database structure
    new_conn = sqlite3.connect("iot_scans_new.db")
    new_cursor = new_conn.cursor()

    # Create new tables
    new_cursor.execute(
        """
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            mac_address TEXT UNIQUE,
            vendor_name TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    """
    )

    new_cursor.execute(
        """
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            open_ports TEXT,
            default_credentials TEXT,
            cve_data TEXT,
            shodan_data TEXT,
            timestamp TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )
    """
    )

    # Get all old scans
    old_cursor.execute("SELECT * FROM scans ORDER BY timestamp")
    old_scans = old_cursor.fetchall()

    # Migrate data
    device_map = {}  # ip -> device_id

    for scan in old_scans:
        ip = scan[2]
        mac = scan[3]

        # Check if device exists
        new_cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (ip,))
        device = new_cursor.fetchone()

        if not device:
            # Insert new device
            new_cursor.execute(
                "INSERT INTO devices (ip_address, mac_address, vendor_name, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                (ip, mac, scan[4], scan[9], scan[9]),
            )
            device_id = new_cursor.lastrowid
        else:
            device_id = device[0]

        # Insert scan
        new_cursor.execute(
            "INSERT INTO scans (device_id, open_ports, default_credentials, cve_data, shodan_data, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (device_id, scan[5], scan[6], scan[7], scan[8], scan[9]),
        )

    new_conn.commit()
    new_conn.close()
    old_conn.close()

    print("Migration completed successfully. New database saved as iot_scans_new.db")


if __name__ == "__main__":
    migrate()
