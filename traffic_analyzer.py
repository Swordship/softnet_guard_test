"""
SoftNet-Guard - Real Traffic Analyzer (Npcap-powered)
Module 2: Live Packet Capture

Captures REAL network traffic using Scapy + Npcap.
No simulation. Every packet is genuine.

Requirements:
  - Npcap installed: https://npcap.com/
  - Run VS Code / terminal as Administrator
"""

import time
import threading
from collections import defaultdict
from datetime import datetime
from database import log_traffic, log_dns, create_alert, get_all_devices

# ── In-memory buffer ──────────────────────────
class TrafficBuffer:
    def __init__(self):
        self._lock = threading.Lock()
        self.stats = defaultdict(lambda: {
            "bytes_sent": 0, "bytes_received": 0,
            "packet_count": 0,
            "protocols": defaultdict(int),
            "destinations": set()
        })
        self.packet_total = 0

    def record(self, src, dst, size, proto):
        with self._lock:
            self.stats[src]["bytes_sent"]    += size
            self.stats[src]["packet_count"]  += 1
            self.stats[src]["protocols"][proto] += 1
            self.stats[src]["destinations"].add(dst)
            self.stats[dst]["bytes_received"] += size
            self.packet_total += 1

    def flush(self):
        with self._lock:
            snap = dict(self.stats)
            self.stats.clear()
            return snap

BUFFER = TrafficBuffer()
_stop_event = threading.Event()

# ── Protocol detection ────────────────────────
def detect_protocol(pkt) -> str:
    try:
        from scapy.all import TCP, UDP, ICMP, DNS
        if pkt.haslayer(DNS):   return "DNS"
        if pkt.haslayer(TCP):
            p = {pkt[TCP].dport, pkt[TCP].sport}
            if 443 in p: return "HTTPS"
            if 80  in p: return "HTTP"
            if 22  in p: return "SSH"
            if 25  in p or 587 in p: return "SMTP"
            if 53  in p: return "DNS"
            return "TCP"
        if pkt.haslayer(UDP):
            p = {pkt[UDP].dport, pkt[UDP].sport}
            if 53  in p or 5353 in p: return "DNS"
            if 67  in p or 68   in p: return "DHCP"
            if 123 in p:              return "NTP"
            return "UDP"
        if pkt.haslayer(ICMP):  return "ICMP"
    except Exception:
        pass
    return "OTHER"

# ── Packet handler ────────────────────────────
_dns_seen = set()

def on_packet(pkt):
    try:
        from scapy.all import IP, DNS, DNSQR
        if not pkt.haslayer(IP):
            return
        src   = pkt[IP].src
        dst   = pkt[IP].dst
        size  = len(pkt)
        proto = detect_protocol(pkt)
        BUFFER.record(src, dst, size, proto)

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            raw    = pkt[DNSQR].qname
            domain = raw.decode("utf-8", errors="ignore").rstrip(".")
            key    = (src, domain)
            if domain and key not in _dns_seen:
                _dns_seen.add(key)
                log_dns(source_ip=src, domain=domain, query_type="A")
                print(f"  [DNS] {src:15s} -> {domain}")
    except Exception:
        pass

# ── Flush worker ──────────────────────────────
BANDWIDTH_ALERT_MB = 30

def flush_worker(interval=30):
    while not _stop_event.is_set():
        time.sleep(interval)
        snap  = BUFFER.flush()
        count = 0
        for ip, data in snap.items():
            if data["packet_count"] == 0:
                continue
            top_proto = max(data["protocols"], key=data["protocols"].get) \
                        if data["protocols"] else "UNKNOWN"
            log_traffic(
                ip             = ip,
                bytes_sent     = data["bytes_sent"],
                bytes_received = data["bytes_received"],
                packet_count   = data["packet_count"],
                protocol       = top_proto,
                dest_ip        = next(iter(data["destinations"]), None)
            )
            count += 1
            total_mb = (data["bytes_sent"] + data["bytes_received"]) / (1024*1024)
            if total_mb > BANDWIDTH_ALERT_MB:
                msg = f"High bandwidth: {ip} used {total_mb:.1f} MB in {interval}s"
                print(f"  [ALERT] {msg}")
                create_alert("HIGH_BANDWIDTH", "High", ip, msg)
        if count:
            print(f"  [DB] Flushed {count} IP(s), total captured: {BUFFER.packet_total}")

# ── Interface selector ────────────────────────
def pick_interface():
    try:
        from scapy.all import conf
        print(f"\n[Npcap] Using interface: {conf.iface}\n")
        return None
    except Exception:
        return None

# ── Main capture ──────────────────────────────
def start_capture(duration=None):
    """
    Start REAL live packet capture using Npcap.

    Before running:
      1. Install Npcap: https://npcap.com/
         (tick 'WinPcap API-compatible mode')
      2. Run VS Code as Administrator
      3. python traffic_analyzer.py
    """
    try:
        from scapy.all import sniff
    except ImportError:
        print("[ERROR] Scapy not installed. Run: pip install scapy")
        return

    iface = pick_interface()
    _stop_event.clear()
    t = threading.Thread(target=flush_worker, args=(30,), daemon=True)
    t.start()

    print("\n" + "="*55)
    print("  SoftNet-Guard | LIVE Packet Capture (Npcap)")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duration: {'Until Ctrl+C' if not duration else str(duration)+'s'}")
    print("="*55)
    print("  DNS queries will appear here in real-time...\n")

    try:
        sniff(prn=on_packet, store=False, timeout=duration, iface=iface)
    except KeyboardInterrupt:
        print("\n[Capture] Stopped.")
    except PermissionError:
        print("\n[ERROR] Permission denied - run VS Code as Administrator")
    except OSError as e:
        if "npcap" in str(e).lower() or "winpcap" in str(e).lower() or "No such" in str(e):
            print("\n[ERROR] Npcap not found.")
            print("  1. Download: https://npcap.com/")
            print("  2. Install with 'WinPcap API-compatible mode' ticked")
            print("  3. Restart VS Code as Administrator")
        else:
            print(f"\n[ERROR] {e}")
    except Exception as e:
        print(f"\n[Capture] Error: {e}")
    finally:
        _stop_event.set()
        snap = BUFFER.flush()
        saved = 0
        for ip, data in snap.items():
            if data["packet_count"] > 0:
                top = max(data["protocols"], key=data["protocols"].get) \
                      if data["protocols"] else "UNKNOWN"
                log_traffic(ip, data["bytes_sent"], data["bytes_received"],
                            data["packet_count"], top)
                saved += 1
        if saved:
            print(f"[DB] Final flush: {saved} IP(s) saved.")
        print(f"[Capture] Total packets: {BUFFER.packet_total}")


if __name__ == "__main__":
    from database import initialize_database
    initialize_database()
    start_capture()
