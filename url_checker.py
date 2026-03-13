"""
SoftNet-Guard - Malicious URL Detector
Module 2: Google Safe Browsing API Integration

Checks any URL against Google's database of:
  - Phishing sites
  - Malware distribution
  - Unwanted software
  - Social engineering

Setup:
  1. Go to: https://developers.google.com/safe-browsing/v4/get-started
  2. Create a project → Enable Safe Browsing API → Get API key
  3. Paste your key below where it says YOUR_API_KEY_HERE
     OR set environment variable: SAFE_BROWSING_KEY=your_key
"""

import os
import requests
import json
from datetime import datetime
from database import initialize_database, log_dns, create_alert

# ── Put your API key here ─────────────────────
API_KEY = os.environ.get("SAFE_BROWSING_KEY", "AIzaSyA7A7NVthufoldoJw2e453Sz7KoaWNFjGs")

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    f"?key={API_KEY}"
)

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",      # phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION"
]

# ── Check a single URL ────────────────────────
def check_url(url: str) -> dict:
    """
    Check one URL against Google Safe Browsing API.

    Returns:
        {
          "url": str,
          "safe": bool,
          "threats": list of threat type strings,
          "checked_at": str
        }
    """
    if API_KEY == "YOUR_API_KEY_HERE":
        return {
            "url": url, "safe": None,
            "threats": [],
            "error": "API key not set. See url_checker.py for setup.",
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    payload = {
        "client": {
            "clientId":      "softnet-guard",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes":      THREAT_TYPES,
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}]
        }
    }

    try:
        resp = requests.post(
            SAFE_BROWSING_URL,
            json    = payload,
            timeout = 5
        )
        resp.raise_for_status()
        data    = resp.json()
        matches = data.get("matches", [])

        if matches:
            threats = list({m["threatType"] for m in matches})
            severity = "Critical" if "MALWARE" in threats else "High"
            msg = f"Malicious URL detected: {url} | Threats: {', '.join(threats)}"
            create_alert("MALICIOUS_URL", severity, "DNS Monitor", msg)
            print(f"  [BLOCKED] {url}")
            print(f"            Threats: {', '.join(threats)}")
            return {
                "url":        url,
                "safe":       False,
                "threats":    threats,
                "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        else:
            return {
                "url":        url,
                "safe":       True,
                "threats":    [],
                "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    except requests.exceptions.ConnectionError:
        return {"url": url, "safe": None, "threats": [],
                "error": "No internet connection", "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    except requests.exceptions.HTTPError as e:
        return {"url": url, "safe": None, "threats": [],
                "error": f"API error: {e}", "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    except Exception as e:
        return {"url": url, "safe": None, "threats": [],
                "error": str(e), "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}


# ── Check multiple URLs at once ───────────────
def check_urls_bulk(urls: list) -> list:
    """
    Check multiple URLs in a single API call (more efficient).
    Returns list of result dicts.
    """
    if API_KEY == "YOUR_API_KEY_HERE":
        print("[URL Checker] API key not set. See url_checker.py line 20.")
        return [{"url": u, "safe": None, "threats": [], "error": "No API key"} for u in urls]

    payload = {
        "client": {"clientId": "softnet-guard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes":      THREAT_TYPES,
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": u} for u in urls]
        }
    }

    try:
        resp = requests.post(SAFE_BROWSING_URL, json=payload, timeout=8)
        resp.raise_for_status()
        data    = resp.json()
        matches = data.get("matches", [])
        bad_urls = {m["threat"]["url"]: m["threatType"] for m in matches}

        results = []
        for url in urls:
            if url in bad_urls:
                threat = bad_urls[url]
                severity = "Critical" if threat == "MALWARE" else "High"
                create_alert("MALICIOUS_URL", severity, "DNS Monitor",
                             f"Malicious URL: {url} | {threat}")
                results.append({"url": url, "safe": False,
                                 "threats": [threat],
                                 "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            else:
                results.append({"url": url, "safe": True, "threats": [],
                                 "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        return results

    except Exception as e:
        return [{"url": u, "safe": None, "threats": [], "error": str(e)} for u in urls]


# ── DNS-based auto checker ────────────────────
def monitor_dns_and_check(interval=60):
    """
    Periodically fetch recent DNS queries from DB
    and check each domain against Safe Browsing API.
    Run this in a background thread.
    """
    import sqlite3
    import time
    print(f"[URL Monitor] Starting DNS-based URL checking every {interval}s")

    while True:
        try:
            conn = sqlite3.connect("softnet_guard.db")
            conn.row_factory = sqlite3.Row
            # Get domains queried in the last `interval` seconds
            rows = conn.execute("""
                SELECT DISTINCT domain FROM dns_queries
                WHERE datetime(timestamp) >= datetime('now', ?)
            """, (f"-{interval} seconds",)).fetchall()
            conn.close()

            domains = [r["domain"] for r in rows if r["domain"]]
            if domains:
                urls = [f"http://{d}" for d in domains]
                print(f"[URL Monitor] Checking {len(urls)} domain(s)...")
                results = check_urls_bulk(urls)
                blocked = [r for r in results if r.get("safe") == False]
                if blocked:
                    print(f"[URL Monitor] BLOCKED {len(blocked)} malicious domain(s)!")
                    for r in blocked:
                        print(f"  !! {r['url']} — {r['threats']}")
                else:
                    print(f"[URL Monitor] All {len(urls)} domain(s) clean.")
            else:
                print("[URL Monitor] No new DNS queries to check.")

        except Exception as e:
            print(f"[URL Monitor] Error: {e}")

        time.sleep(interval)


# ── Test known bad URLs (for demo) ────────────
DEMO_URLS = [
    "http://testsafebrowsing.appspot.com/s/malware.html",   # Google's own test URL
    "http://testsafebrowsing.appspot.com/s/phishing.html",  # Google's own test URL
    "https://google.com",
    "https://github.com",
]

def run_demo_check():
    """Check a mix of safe and known-malicious test URLs (Google's own test pages)."""
    print("\n" + "="*55)
    print("  SoftNet-Guard | URL Safety Checker")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*55)

    if API_KEY == "YOUR_API_KEY_HERE":
        print("""
[SETUP REQUIRED] Get your free Google Safe Browsing API key:

  Step 1: Go to https://console.cloud.google.com/
  Step 2: Create a new project (name it anything)
  Step 3: Go to APIs & Services -> Library
  Step 4: Search "Safe Browsing" -> Enable it
  Step 5: Go to APIs & Services -> Credentials
  Step 6: Create Credentials -> API Key -> Copy it
  Step 7: Open url_checker.py line 20, replace:
            YOUR_API_KEY_HERE
          with your actual key.
  Step 8: Run again: python url_checker.py
""")
        return

    print(f"\nChecking {len(DEMO_URLS)} URLs...\n")
    for url in DEMO_URLS:
        result = check_url(url)
        if result.get("error"):
            status = f"ERROR: {result['error']}"
            icon   = "?"
        elif result["safe"]:
            status = "SAFE"
            icon   = "OK"
        else:
            status = f"DANGEROUS - {', '.join(result['threats'])}"
            icon   = "!!"
        print(f"  [{icon:2s}] {url}")
        print(f"       Status: {status}\n")

    print("="*55)
    print("Check the dashboard Alerts section for any blocked URLs.")


if __name__ == "__main__":
    initialize_database()
    run_demo_check()
