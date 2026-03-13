"""
SoftNet-Guard - Main Runner

python main.py                  → Dashboard + scan
python main.py --scan           → Device scan only
python main.py --capture        → Live Npcap capture (needs Npcap + Admin)
python main.py --train          → Train ML models on datasets
python main.py --detect         → Run anomaly detection loop
python main.py --check-url      → Test URL checker
"""

import sys
import threading
from database import initialize_database


def main():
    initialize_database()
    args = sys.argv[1:]

    if "--scan" in args:
        from device_scanner import run_device_scan
        devices = run_device_scan(use_scapy=("--scapy" in args))
        print(f"\nScan complete. {len(devices)} real device(s) found.")
        return

    if "--capture" in args:
        from traffic_analyzer import start_capture
        start_capture()
        return

    if "--train" in args:
        from anomaly_detector import train_model
        from phishing_detector import train_phishing_model
        print("=== Training Isolation Forest (TON-IoT + UNSW-NB15) ===")
        train_model(ton_iot_path="train_test_network.csv", unsw_path="UNSW_NB15_training-set.csv")
        print("\n=== Training Phishing Detector (PhiUSIIL) ===")
        train_phishing_model(xlsx_path="PhiUSIIL_Phishing_URL_Dataset.csv")
        print("\nAll models trained and saved.")
        return

    if "--detect" in args:
        from anomaly_detector import run_continuously
        run_continuously(interval_seconds=30, window_minutes=60)
        return

    if "--check-url" in args:
        from url_checker import run_demo_check
        run_demo_check()
        return

    # ── Default: full system ──
    print("""
+----------------------------------------------+
|      SoftNet-Guard -- Starting Up            |
|  Module 2: Data Collection  (Active)         |
|  Module 3: ML Anomaly Detection (Active)     |
+----------------------------------------------+
    """)

    # Background: device scan
    from device_scanner import run_device_scan
    threading.Thread(target=run_device_scan,
                     kwargs={"use_scapy": False}, daemon=True).start()

    # Background: anomaly detection loop
    from anomaly_detector import run_continuously
    threading.Thread(
        target=run_continuously,
        kwargs={"interval_seconds": 60, "window_minutes": 60},
        daemon=True
    ).start()

    print("  Dashboard    -> http://127.0.0.1:5000")
    print("  URL Checker  -> http://127.0.0.1:5000/url-checker")
    print("  ML Scores    -> http://127.0.0.1:5000/api/ml-scores")
    print("  Press Ctrl+C to stop\n")

    from app import app
    app.run(debug=False, host="0.0.0.0", port=5000)


if __name__ == "__main__":
    main()