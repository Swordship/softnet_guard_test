"""
SoftNet-Guard - Device Scanner
Module 2: Data Collection & Processing
Discovers all devices on the local network using:
  1. ARP table parsing  (works on Windows without Npcap)
  2. Scapy ARP scan    (requires Npcap on Windows - more accurate)
  3. Socket-based ping sweep as fallback
"""

import subprocess
import socket
import threading
import re
import time
import ipaddress
from datetime import datetime
from database import upsert_device, create_alert, get_all_devices

# ──────────────────────────────────────────────
# MAC Vendor lookup (offline, top vendors only)
# ──────────────────────────────────────────────
MAC_VENDOR_TABLE = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1a:a0": "Dell",
    "00:1b:21": "Intel",
    "b4:2e:99": "Apple",
    "3c:22:fb": "Apple",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "00:e0:4c": "Realtek",
    "18:31:bf": "Amazon",
    "fc:65:de": "TP-Link",
    "50:c7:bf": "TP-Link",
    "c8:3a:35": "Tenda",
    "74:da:38": "Edimax",
    "00:1f:3f": "Samsung",
    "a4:c3:f0": "Samsung",
}


def get_vendor(mac: str) -> str:
    """Identify device vendor from MAC address prefix."""
    if not mac:
        return "Unknown"
    prefix = mac[:8].lower().replace("-", ":")
    for key, vendor in MAC_VENDOR_TABLE.items():
        if prefix.startswith(key.lower()):
            return vendor
    return "Unknown"


def is_real_device(ip: str, mac: str) -> bool:
    """
    Return True only for real unicast devices.
    Filters out:
      - Multicast IPs     : 224.0.0.0 – 239.255.255.255
      - Broadcast IP      : 255.255.255.255
      - Loopback          : 127.x.x.x
      - Link-local        : 169.254.x.x
      - Multicast MACs    : start with 01:00:5E or 33:33
      - Broadcast MAC     : FF:FF:FF:FF:FF:FF
    """
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_multicast:       return False
        if ip_obj.is_loopback:        return False
        if ip_obj.is_link_local:      return False
        if ip_obj.is_unspecified:     return False
        if str(ip_obj) == "255.255.255.255": return False
    except ValueError:
        return False

    if mac:
        mac_up = mac.upper().replace("-", ":")
        if mac_up.startswith("01:00:5E"): return False   # IPv4 multicast MAC
        if mac_up.startswith("33:33"):    return False   # IPv6 multicast MAC
        if mac_up == "FF:FF:FF:FF:FF:FF": return False   # Broadcast

    return True


def get_hostname(ip: str) -> str:
    """Reverse DNS lookup to get hostname."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return ""


def get_local_ip() -> str:
    """Get this machine's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_network_prefix(local_ip: str) -> str:
    """Derive the /24 network from the local IP (e.g. 192.168.1.0/24)."""
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


# ──────────────────────────────────────────────
# Method 1: Parse Windows ARP table
# ──────────────────────────────────────────────
def scan_arp_table() -> list:
    """
    Parse the Windows ARP cache to get IP → MAC mappings.
    Fast and works without any extra drivers.
    """
    devices = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10
        )
        # Regex: match lines like "  192.168.1.10   aa-bb-cc-dd-ee-ff   dynamic"
        pattern = re.compile(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})\s+(\w+)"
        )
        for line in result.stdout.splitlines():
            match = pattern.search(line)
            if match:
                ip  = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                entry_type = match.group(3)
                # Skip broadcast/multicast
                if mac in ("FF:FF:FF:FF:FF:FF", "01:00:5E", "33:33"):
                    continue
                if entry_type.lower() in ("dynamic", "static"):
                    devices.append({"ip": ip, "mac": mac})
        print(f"[ARP Table] Found {len(devices)} entries in ARP cache.")
    except Exception as e:
        print(f"[ARP Table] Error: {e}")
    return devices


# ──────────────────────────────────────────────
# Method 2: Scapy ARP Scan (needs Npcap)
# ──────────────────────────────────────────────
def scan_with_scapy(network: str) -> list:
    """
    Send ARP broadcast packets to every host in the subnet.
    Much more thorough than reading the ARP cache.
    Requires Npcap on Windows: https://npcap.com/
    """
    devices = []
    try:
        from scapy.all import ARP, Ether, srp
        print(f"[Scapy] Sending ARP scan to {network} ...")
        arp_request = ARP(pdst=network)
        broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet      = broadcast / arp_request
        answered, _ = srp(packet, timeout=3, verbose=False)
        for sent, received in answered:
            devices.append({
                "ip":  received.psrc,
                "mac": received.hwsrc.upper()
            })
        print(f"[Scapy] Found {len(devices)} live hosts.")
    except ImportError:
        print("[Scapy] Scapy not available, skipping.")
    except Exception as e:
        print(f"[Scapy] Error (Npcap may not be installed): {e}")
    return devices


# ──────────────────────────────────────────────
# Method 3: Ping sweep fallback
# ──────────────────────────────────────────────
def ping_host(ip: str, results: list):
    """Ping a single IP and add it to results if alive."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "500", ip],
            capture_output=True, text=True, timeout=2
        )
        if "TTL=" in result.stdout or "ttl=" in result.stdout:
            results.append({"ip": ip, "mac": None})
    except Exception:
        pass


def ping_sweep(network: str) -> list:
    """
    Send ICMP pings to all hosts in /24 using multithreading.
    Fallback method when Scapy/Npcap is unavailable.
    """
    print(f"[Ping Sweep] Scanning {network} ...")
    live_hosts = []
    threads = []
    net = ipaddress.IPv4Network(network, strict=False)

    for host in net.hosts():
        t = threading.Thread(target=ping_host, args=(str(host), live_hosts))
        threads.append(t)
        t.start()
        # Batch threads to avoid overwhelming the system
        if len(threads) >= 50:
            for th in threads:
                th.join()
            threads = []

    for th in threads:
        th.join()

    print(f"[Ping Sweep] Found {len(live_hosts)} live hosts.")
    return live_hosts


# ──────────────────────────────────────────────
# Main Scanner Function
# ──────────────────────────────────────────────
def run_device_scan(use_scapy=True) -> list:
    """
    Run a full device discovery scan using all available methods.
    Results are deduplicated and saved to the database.

    Args:
        use_scapy: Try Scapy ARP scan first (needs Npcap on Windows)

    Returns:
        List of discovered device dicts
    """
    print("\n" + "="*50)
    print("  SoftNet-Guard | Module 2 - Device Scanner")
    print(f"  Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50)

    local_ip = get_local_ip()
    network  = get_network_prefix(local_ip)
    print(f"[Info] Local IP : {local_ip}")
    print(f"[Info] Network  : {network}")

    # Collect devices from all methods
    all_found = {}

    # Method 1: ARP table (always works on Windows)
    for d in scan_arp_table():
        all_found[d["ip"]] = d

    # Method 2: Scapy active scan (if requested)
    if use_scapy:
        for d in scan_with_scapy(network):
            if d["ip"] not in all_found:
                all_found[d["ip"]] = d
            elif d.get("mac") and not all_found[d["ip"]].get("mac"):
                all_found[d["ip"]]["mac"] = d["mac"]
    else:
        # Fallback: ping sweep
        for d in ping_sweep(network):
            if d["ip"] not in all_found:
                all_found[d["ip"]] = d

    # Remove the monitoring machine itself
    all_found.pop(local_ip, None)

    # Filter: keep only real unicast devices (remove multicast/broadcast)
    real_devices = {
        ip: info for ip, info in all_found.items()
        if is_real_device(ip, info.get("mac"))
    }
    skipped = len(all_found) - len(real_devices)
    if skipped:
        print(f"[Filter] Removed {skipped} multicast/broadcast address(es) - not real devices.")

    print(f"\n[Scanner] Real devices found: {len(real_devices)}")
    print("-" * 50)

    # Enrich with hostname & vendor, save to DB
    final_devices = []
    for ip, info in real_devices.items():
        mac      = info.get("mac")
        hostname = get_hostname(ip)
        vendor   = get_vendor(mac) if mac else "Unknown"

        print(f"  [OK] {ip:18s} | MAC: {mac or 'N/A':20s} | {hostname or 'No hostname':30s} | {vendor}")

        upsert_device(ip=ip, mac=mac, hostname=hostname, vendor=vendor)

        final_devices.append({
            "ip": ip, "mac": mac,
            "hostname": hostname, "vendor": vendor
        })

    print("-" * 50)
    print(f"[DB] {len(final_devices)} real device(s) saved to database.\n")
    return final_devices


# ──────────────────────────────────────────────
# Continuous Monitoring Mode
# ──────────────────────────────────────────────
def monitor_continuously(interval_seconds=60, use_scapy=True):
    """
    Run device scans repeatedly to detect new/departing devices.
    Raises an alert when a new unknown device joins the network.
    """
    print(f"[Monitor] Starting continuous scan every {interval_seconds}s. Press Ctrl+C to stop.")
    known_ips = set(d["ip_address"] for d in get_all_devices())

    while True:
        try:
            discovered = run_device_scan(use_scapy=use_scapy)
            current_ips = set(d["ip"] for d in discovered)

            # Detect new devices
            new_devices = current_ips - known_ips
            for ip in new_devices:
                print(f"[ALERT] New device joined: {ip}")
                create_alert(
                    alert_type="NEW_DEVICE",
                    severity="Medium",
                    source_ip=ip,
                    description=f"Unknown device with IP {ip} joined the network."
                )

            known_ips = current_ips | known_ips
            print(f"[Monitor] Next scan in {interval_seconds} seconds...")
            time.sleep(interval_seconds)

        except KeyboardInterrupt:
            print("\n[Monitor] Stopped by user.")
            break


if __name__ == "__main__":
    from database import initialize_database
    initialize_database()
    run_device_scan(use_scapy=True)
