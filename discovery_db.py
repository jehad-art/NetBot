import sqlite3
import json
from datetime import datetime

DB_NAME = "discovery.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                hostname TEXT,
                mac TEXT,
                device_type TEXT,
                status TEXT,
                protocols TEXT,
                last_seen TEXT,
                credentials TEXT
            )
        """)
        conn.commit()


def upsert_device(ip, open_ports, hostname=None, mac=None):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO devices (ip, hostname, mac, device_type, status, protocols, last_seen, credentials)
            VALUES (?, ?, ?, 'unknown', 'discovered', ?, ?, NULL)
            ON CONFLICT(ip) DO UPDATE SET
                hostname=excluded.hostname,
                mac=excluded.mac,
                protocols=excluded.protocols,
                last_seen=excluded.last_seen
        """,
        (
            ip,
            hostname,
            mac,
            json.dumps(open_ports),
            datetime.utcnow().isoformat()
        ))
        conn.commit()

def is_known_device(ip):
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT 1 FROM devices WHERE ip = ? AND credentials IS NOT NULL",
            (ip,)
        )
        return cursor.fetchone() is not None

def get_all_devices():
    with get_connection() as conn:
        cursor = conn.execute("SELECT * FROM devices")
        return [dict(row) for row in cursor.fetchall()]


def get_devices_by_status(status):
    with get_connection() as conn:
        cursor = conn.execute("SELECT * FROM devices WHERE status = ?", (status,))
        return [dict(row) for row in cursor.fetchall()]

def get_unprovisioned_devices():
    with get_connection() as conn:
        cursor = conn.execute("SELECT * FROM devices WHERE credentials IS NULL")
        return [dict(row) for row in cursor.fetchall()]


if __name__ == "__main__":
    init_db()
    devices = get_all_devices()
    print(json.dumps(devices, indent=2))