"""
SoftNet-Guard - Web Dashboard
Flask app with API endpoints for all modules.
"""

from flask import Flask, render_template, jsonify, request
from database import (
    initialize_database, get_all_devices,
    get_alerts, get_traffic_summary, get_stats
)
import threading
from device_scanner import run_device_scan
from url_checker import check_url, check_urls_bulk
from anomaly_detector import get_latest_scores
from phishing_detector import predict_url, load_phishing_model

# Load phishing model once at startup
_phishing_model = None
def get_phishing_model():
    global _phishing_model
    if _phishing_model is None:
        _phishing_model = load_phishing_model()
    return _phishing_model

app = Flask(__name__)

@app.route("/")
def dashboard():
    stats   = get_stats()
    devices = get_all_devices()
    alerts  = get_alerts(limit=10)
    traffic = get_traffic_summary()
    return render_template("dashboard.html",
        stats=stats, devices=devices,
        alerts=alerts, traffic=traffic)

@app.route("/api/devices")
def api_devices():
    return jsonify(get_all_devices())

@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_alerts())

@app.route("/api/traffic")
def api_traffic():
    return jsonify(get_traffic_summary())

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())

@app.route("/api/scan", methods=["POST"])
def api_scan():
    devices = run_device_scan(use_scapy=False)
    return jsonify({"scanned": len(devices), "devices": devices})

@app.route("/api/check-url", methods=["POST"])
def api_check_url():
    """Check a URL against Google Safe Browsing API."""
    data = request.get_json()
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if not url.startswith("http"):
        url = "http://" + url
    result = check_url(url)
    return jsonify(result)

@app.route("/api/ml-scores")
def api_ml_scores():
    """Return Isolation Forest anomaly scores for all active devices."""
    scores = get_latest_scores()
    return jsonify(scores)

@app.route("/api/check-url-ml", methods=["POST"])
def api_check_url_ml():
    """ML-based phishing URL check using PhiUSIIL-trained Random Forest."""
    data = request.get_json()
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = predict_url(url, get_phishing_model())
    return jsonify(result)

@app.route("/url-checker")
def url_checker_page():
    return render_template("url_checker.html")

if __name__ == "__main__":
    initialize_database()
    t = threading.Thread(target=run_device_scan,
                         kwargs={"use_scapy": False}, daemon=True)
    t.start()
    print("\n  Dashboard  → http://127.0.0.1:5000")
    print("  URL Checker→ http://127.0.0.1:5000/url-checker\n")
    app.run(debug=False, host="0.0.0.0", port=5000)