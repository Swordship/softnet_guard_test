"""
SoftNet-Guard - Feature Extractor
Module 3: Builds the 13-feature traffic vector per device
per time window from the traffic_stats table in SQLite.

Features extracted:
  1.  packet_count          - total packets in window
  2.  bytes_sent            - total bytes sent
  3.  bytes_received        - total bytes received
  4.  bytes_total           - sent + received
  5.  bytes_per_packet      - average packet size
  6.  send_receive_ratio    - bytes_sent / (bytes_total + 1)
  7.  protocol_diversity    - Shannon entropy of protocol mix
  8.  unique_destinations   - number of distinct destination IPs
  9.  dns_query_count       - DNS queries in this window
  10. http_ratio            - HTTP packets / total
  11. https_ratio           - HTTPS packets / total
  12. dns_ratio             - DNS packets / total
  13. is_high_port          - fraction of traffic on port > 1024
"""

import sqlite3
import math
from collections import defaultdict, Counter
from datetime import datetime, timedelta

DB_PATH = "softnet_guard.db"

FEATURE_NAMES = [
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "bytes_total",
    "bytes_per_packet",
    "send_receive_ratio",
    "protocol_diversity",
    "unique_destinations",
    "dns_query_count",
    "http_ratio",
    "https_ratio",
    "dns_ratio",
    "is_high_port",
]


def shannon_entropy(counts: list) -> float:
    """
    Calculate Shannon entropy for protocol diversity.
    Higher entropy = more mixed protocols = potentially suspicious.
    Formula: H = -sum(p_i * log2(p_i))
    """
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features_for_device(ip: str, window_minutes: int = 5):
    """
    Extract 13 features for a single device from the last
    `window_minutes` of traffic data in the database.

    Returns a dict with feature names as keys, or None if no data.
    """
    conn   = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    since = (datetime.now() - timedelta(minutes=window_minutes)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Pull all traffic records for this device in the window
    cursor.execute("""
        SELECT bytes_sent, bytes_received, packet_count,
               protocol, destination_ip, timestamp
        FROM traffic_stats
        WHERE ip_address = ?
          AND timestamp >= ?
    """, (ip, since))
    rows = cursor.fetchall()

    # Pull DNS query count for this device
    cursor.execute("""
        SELECT COUNT(*) AS cnt FROM dns_queries
        WHERE source_ip = ? AND timestamp >= ?
    """, (ip, since))
    dns_row = cursor.fetchone()
    dns_count = dns_row["cnt"] if dns_row else 0

    conn.close()

    if not rows:
        return None

    # Aggregate
    total_packets   = sum(r["packet_count"]   for r in rows)
    total_sent      = sum(r["bytes_sent"]      for r in rows)
    total_received  = sum(r["bytes_received"]  for r in rows)
    total_bytes     = total_sent + total_received

    protocol_counts = Counter(
        r["protocol"] for r in rows if r["protocol"]
    )
    unique_dests = len(set(
        r["destination_ip"] for r in rows if r["destination_ip"]
    ))

    # Per-packet bytes
    bytes_per_pkt = total_bytes / total_packets if total_packets > 0 else 0

    # Send/receive ratio (0=only receiving, 1=only sending)
    send_ratio = total_sent / (total_bytes + 1)

    # Protocol diversity via Shannon entropy
    proto_diversity = shannon_entropy(list(protocol_counts.values()))

    # Protocol-specific ratios
    http_ratio  = protocol_counts.get("HTTP",  0) / (total_packets + 1)
    https_ratio = protocol_counts.get("HTTPS", 0) / (total_packets + 1)
    dns_ratio   = protocol_counts.get("DNS",   0) / (total_packets + 1)

    # High port heuristic: >1024 often means ephemeral/suspicious
    # We use dns_count as a proxy here since we don't store port in traffic_stats
    is_high_port = 1.0 if dns_count > 50 else 0.0

    return {
        "ip":                  ip,
        "window_minutes":      window_minutes,
        "packet_count":        total_packets,
        "bytes_sent":          total_sent,
        "bytes_received":      total_received,
        "bytes_total":         total_bytes,
        "bytes_per_packet":    round(bytes_per_pkt, 2),
        "send_receive_ratio":  round(send_ratio, 4),
        "protocol_diversity":  proto_diversity,
        "unique_destinations": unique_dests,
        "dns_query_count":     dns_count,
        "http_ratio":          round(http_ratio, 4),
        "https_ratio":         round(https_ratio, 4),
        "dns_ratio":           round(dns_ratio, 4),
        "is_high_port":        is_high_port,
    }


def extract_all_devices(window_minutes: int = 5) -> list:
    """
    Extract features for every known device in the last window.
    Returns list of feature dicts (only devices with data).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ips = [r["ip_address"] for r in
           conn.execute("SELECT DISTINCT ip_address FROM devices").fetchall()]
    conn.close()

    results = []
    for ip in ips:
        feat = extract_features_for_device(ip, window_minutes)
        if feat:
            results.append(feat)
    return results


def to_vector(feature_dict: dict) -> list:
    """
    Convert feature dict to a plain numeric list (for sklearn).
    Order must match FEATURE_NAMES.
    """
    return [feature_dict[f] for f in FEATURE_NAMES]


if __name__ == "__main__":
    from database import initialize_database
    initialize_database()

    print("Extracting features for all devices (last 60 min)...\n")
    features = extract_all_devices(window_minutes=60)

    if not features:
        print("No traffic data yet. Run the capture first.")
    else:
        for f in features:
            print(f"Device: {f['ip']}")
            for name in FEATURE_NAMES:
                print(f"  {name:25s}: {f[name]}")
            print()