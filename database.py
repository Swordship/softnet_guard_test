"""
SoftNet-Guard - Database Module
Module 2: Data Storage Layer
Handles all SQLite operations for device and traffic data.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = "softnet_guard.db"


def get_connection():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allows dict-like access
    return conn


def initialize_database():
    """Create all required tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    # Table: Discovered devices
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT NOT NULL,
            mac_address TEXT,
            hostname    TEXT,
            vendor      TEXT,
            status      TEXT DEFAULT 'active',
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            UNIQUE(ip_address)
        )
    """)

    # Table: Traffic statistics per device
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address      TEXT NOT NULL,
            timestamp       TEXT NOT NULL,
            bytes_sent      INTEGER DEFAULT 0,
            bytes_received  INTEGER DEFAULT 0,
            packet_count    INTEGER DEFAULT 0,
            protocol        TEXT,
            destination_ip  TEXT
        )
    """)

    # Table: Security alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            alert_type  TEXT NOT NULL,
            severity    TEXT NOT NULL,
            source_ip   TEXT,
            description TEXT,
            resolved    INTEGER DEFAULT 0
        )
    """)

    # Table: DNS queries captured
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_queries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            source_ip   TEXT,
            domain      TEXT NOT NULL,
            query_type  TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Database initialized successfully.")


def upsert_device(ip, mac=None, hostname=None, vendor=None):
    """Insert a new device or update last_seen if already exists."""
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO devices (ip_address, mac_address, hostname, vendor, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
            mac_address = COALESCE(excluded.mac_address, mac_address),
            hostname    = COALESCE(excluded.hostname, hostname),
            vendor      = COALESCE(excluded.vendor, vendor),
            last_seen   = excluded.last_seen,
            status      = 'active'
    """, (ip, mac, hostname, vendor, now, now))

    conn.commit()
    conn.close()


def get_all_devices():
    """Fetch all devices from the database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def log_traffic(ip, bytes_sent, bytes_received, packet_count, protocol=None, dest_ip=None):
    """Log a traffic record for a device."""
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO traffic_stats
        (ip_address, timestamp, bytes_sent, bytes_received, packet_count, protocol, destination_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (ip, now, bytes_sent, bytes_received, packet_count, protocol, dest_ip))
    conn.commit()
    conn.close()


def create_alert(alert_type, severity, source_ip, description):
    """Create a new security alert."""
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO alerts (timestamp, alert_type, severity, source_ip, description)
        VALUES (?, ?, ?, ?, ?)
    """, (now, alert_type, severity, source_ip, description))
    conn.commit()
    conn.close()


def get_alerts(limit=50):
    """Fetch recent alerts."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_traffic_summary():
    """Get total traffic grouped by device."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip_address,
               SUM(bytes_sent)     AS total_sent,
               SUM(bytes_received) AS total_received,
               SUM(packet_count)   AS total_packets,
               COUNT(*)            AS record_count,
               MAX(timestamp)      AS last_activity
        FROM traffic_stats
        GROUP BY ip_address
        ORDER BY total_packets DESC
    """)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def log_dns(source_ip, domain, query_type="A"):
    """Log a DNS query."""
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO dns_queries (timestamp, source_ip, domain, query_type)
        VALUES (?, ?, ?, ?)
    """, (now, source_ip, domain, query_type))
    conn.commit()
    conn.close()


def get_stats():
    """Get overall summary statistics for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM devices")
    total_devices = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM devices WHERE status = 'active'")
    active_devices = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM alerts WHERE resolved = 0")
    open_alerts = cursor.fetchone()["total"]

    cursor.execute("SELECT SUM(packet_count) AS total FROM traffic_stats")
    row = cursor.fetchone()
    total_packets = row["total"] if row["total"] else 0

    conn.close()
    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "open_alerts": open_alerts,
        "total_packets": total_packets
    }
