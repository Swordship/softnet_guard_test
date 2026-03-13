"""
SoftNet-Guard - Anomaly Detector
Module 3: Isolation Forest ML Model

Pre-trains on real attack datasets (TON-IoT + UNSW-NB15),
then scores live traffic vectors from your network.

Anomaly score -> 0.0 = normal, 1.0 = highly anomalous

Anomaly types classified:
  - BANDWIDTH_ANOMALY   : bytes_total or bytes_per_packet spike
  - CONNECTION_ANOMALY  : too many unique destinations
  - PROTOCOL_ANOMALY    : unusual protocol diversity
  - DNS_ANOMALY         : abnormal DNS query volume
  - TEMPORAL_ANOMALY    : general anomaly not matching above
"""

import os
import csv
import pickle
import time
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

from feature_extractor import extract_all_devices, to_vector, FEATURE_NAMES
from database import create_alert

MODEL_PATH  = "isolation_forest.pkl"
SCALER_PATH = "scaler.pkl"

ANOMALY_THRESHOLD  = 0.6
BANDWIDTH_SPIKE_MB = 50
DEST_SPIKE         = 20
DNS_SPIKE          = 100
PDI_SPIKE          = 2.5


def load_ton_iot(path):
    normal_rows = []
    try:
        with open(path, encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if str(row.get("label", "1")).strip() != "0":
                    continue
                try:
                    src_bytes = float(row.get("src_bytes", 0) or 0)
                    dst_bytes = float(row.get("dst_bytes", 0) or 0)
                    src_pkts  = float(row.get("src_pkts",  1) or 1)
                    dst_pkts  = float(row.get("dst_pkts",  0) or 0)
                    proto     = row.get("proto", "tcp").lower()
                    dns_q     = 1 if row.get("dns_query", "-") not in ("-", "") else 0
                    total_pkts  = src_pkts + dst_pkts
                    total_bytes = src_bytes + dst_bytes
                    http_r  = 1.0 if proto == "http" else 0.0
                    https_r = 1.0 if proto == "ssl"  else 0.0
                    dns_r   = 1.0 if proto == "dns"  else 0.0
                    normal_rows.append([
                        total_pkts, src_bytes, dst_bytes, total_bytes,
                        total_bytes / (total_pkts + 1),
                        src_bytes / (total_bytes + 1),
                        0.0, 1, dns_q, http_r, https_r, dns_r, 0.0
                    ])
                except (ValueError, ZeroDivisionError):
                    continue
        print(f"[Dataset] TON-IoT: loaded {len(normal_rows)} normal rows.")
    except FileNotFoundError:
        print(f"[Dataset] TON-IoT not found at '{path}', skipping.")
    return np.array(normal_rows) if normal_rows else np.empty((0, 13))


def load_unsw_nb15(path):
    """
    Loads normal traffic rows from UNSW-NB15 training set.
    Supports both:
      - UNSW_NB15_training-set.csv  (has headers: id, dur, proto, ... label)
      - UNSW-NB15_1.csv             (no headers, label at index 48)
    """
    normal_rows = []
    try:
        with open(path, encoding="utf-8-sig") as f:
            first_line = f.readline().strip()
            f.seek(0)

            # Detect if file has a proper header row
            has_named_header = "label" in first_line.lower() or "proto" in first_line.lower()

            reader = csv.DictReader(f) if has_named_header else None

            if has_named_header:
                # Named columns version (UNSW_NB15_training-set.csv)
                for row in reader:
                    try:
                        label = int(float(row.get("label", 1) or 1))
                        if label != 0:
                            continue
                        sbytes = float(row.get("sbytes", 0) or 0)
                        dbytes = float(row.get("dbytes", 0) or 0)
                        spkts  = float(row.get("spkts",  1) or 1)
                        dpkts  = float(row.get("dpkts",  0) or 0)
                        smean  = float(row.get("smean",  0) or 0)
                        dmean  = float(row.get("dmean",  0) or 0)
                        service = str(row.get("service", "") or "").lower().strip()

                        total_pkts  = spkts + dpkts
                        total_bytes = sbytes + dbytes
                        http_r  = 1.0 if service == "http"  else 0.0
                        https_r = 1.0 if service in ("ssl", "https") else 0.0
                        dns_r   = 1.0 if service == "dns"   else 0.0

                        normal_rows.append([
                            total_pkts, sbytes, dbytes, total_bytes,
                            (smean + dmean) / 2,
                            sbytes / (total_bytes + 1),
                            0.0, 1, 1 if dns_r else 0,
                            http_r, https_r, dns_r, 0.0
                        ])
                    except (ValueError, TypeError):
                        continue
            else:
                # Raw index version (UNSW-NB15_1.csv - no header)
                raw_reader = csv.reader(f)
                for row in raw_reader:
                    try:
                        if len(row) < 49:
                            continue
                        label = int(float(row[48] or 0))
                        if label != 0:
                            continue
                        sbytes  = float(row[7]  or 0)
                        dbytes  = float(row[8]  or 0)
                        spkts   = float(row[16] or 1)
                        dpkts   = float(row[17] or 0)
                        smsz    = float(row[22] or 0)
                        dmsz    = float(row[23] or 0)
                        service = str(row[13] or "").lower().strip()
                        total_pkts  = spkts + dpkts
                        total_bytes = sbytes + dbytes
                        http_r  = 1.0 if service == "http" else 0.0
                        https_r = 1.0 if service in ("ssl", "https") else 0.0
                        dns_r   = 1.0 if service == "dns" else 0.0
                        normal_rows.append([
                            total_pkts, sbytes, dbytes, total_bytes,
                            (smsz + dmsz) / 2,
                            sbytes / (total_bytes + 1),
                            0.0, 1, 1 if dns_r else 0,
                            http_r, https_r, dns_r, 0.0
                        ])
                    except (ValueError, IndexError):
                        continue

        print(f"[Dataset] UNSW-NB15: loaded {len(normal_rows)} normal rows.")
    except FileNotFoundError:
        print(f"[Dataset] UNSW-NB15 not found at '{path}', skipping.")
    return np.array(normal_rows) if normal_rows else np.empty((0, 13))


def train_model(
    ton_iot_path="train_test_network.csv",
    unsw_path="UNSW_NB15_training-set.csv",
    n_estimators=100,
    contamination=0.05,
):
    print("\n[Model] Loading training datasets...")
    ton  = load_ton_iot(ton_iot_path)
    unsw = load_unsw_nb15(unsw_path)

    parts = [x for x in [ton, unsw] if x.shape[0] > 0]
    if not parts:
        print("[Model] No dataset rows found. Training on synthetic baseline.")
        rng = np.random.default_rng(42)
        X = rng.uniform(
            low  = [10,  1000,  1000,   2000,  500, 0.3, 0.0, 1,  0, 0.0, 0.5, 0.0, 0.0],
            high = [500, 50000, 50000, 100000, 1500, 0.7, 1.5, 5, 10, 0.1, 0.9, 0.1, 0.0],
            size = (200, 13)
        )
    else:
        X = np.vstack(parts)

    print(f"[Model] Total training rows: {X.shape[0]}")
    scaler   = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    print(f"[Model] Training Isolation Forest (n_estimators={n_estimators}, contamination={contamination})...")
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    with open(MODEL_PATH,  "wb") as f: pickle.dump(model,  f)
    with open(SCALER_PATH, "wb") as f: pickle.dump(scaler, f)
    print(f"[Model] Saved -> {MODEL_PATH}, {SCALER_PATH}")
    return model, scaler


def load_model():
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        with open(MODEL_PATH,  "rb") as f: model  = pickle.load(f)
        with open(SCALER_PATH, "rb") as f: scaler = pickle.load(f)
        print("[Model] Loaded existing model from disk.")
        return model, scaler
    else:
        print("[Model] No saved model found. Training now...")
        return train_model()


def score_vector(vector, model, scaler):
    X        = np.array(vector).reshape(1, -1)
    X_scaled = scaler.transform(X)
    raw      = model.decision_function(X_scaled)[0]
    score    = max(0.0, min(1.0, 0.5 - raw))
    return round(score, 4)


def classify_anomaly(features):
    total_mb = features["bytes_total"] / (1024 * 1024)
    if total_mb > BANDWIDTH_SPIKE_MB:
        return "BANDWIDTH_ANOMALY"
    if features["unique_destinations"] > DEST_SPIKE:
        return "CONNECTION_ANOMALY"
    if features["protocol_diversity"] > PDI_SPIKE:
        return "PROTOCOL_ANOMALY"
    if features["dns_query_count"] > DNS_SPIKE:
        return "DNS_ANOMALY"
    return "TEMPORAL_ANOMALY"


def severity_from_score(score):
    if score >= 0.85: return "Critical"
    if score >= 0.75: return "High"
    if score >= 0.65: return "Medium"
    return "Low"


def run_detection_cycle(model, scaler, window_minutes=5):
    features_list = extract_all_devices(window_minutes=window_minutes)
    if not features_list:
        print(f"[Detector] No traffic data in last {window_minutes} min.")
        return

    print(f"\n[Detector] Scoring {len(features_list)} device(s)...")
    print(f"  {'IP':18s} {'Score':>7s}  {'Status':10s}  {'Type'}")
    print("  " + "-" * 60)

    for feat in features_list:
        vec   = to_vector(feat)
        score = score_vector(vec, model, scaler)
        ip    = feat["ip"]
        if score >= ANOMALY_THRESHOLD:
            atype    = classify_anomaly(feat)
            severity = severity_from_score(score)
            desc = (
                f"Anomaly detected on {ip} | "
                f"Score: {score:.3f} | "
                f"Packets: {feat['packet_count']} | "
                f"Data: {feat['bytes_total'] / (1024*1024):.2f} MB | "
                f"Proto Diversity: {feat['protocol_diversity']}"
            )
            create_alert(atype, severity, ip, desc)
            status = f"[ALERT] {severity}"
        else:
            atype  = "Normal"
            status = "OK"
        print(f"  {ip:18s} {score:>7.3f}  {status:10s}  {atype}")


def run_continuously(interval_seconds=60, window_minutes=5,
                     ton_path="ton-iot.csv", unsw_path="UNSW-NB15_1.csv"):
    print("\n" + "=" * 55)
    print("  SoftNet-Guard | Module 3 - Anomaly Detector")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Interval: every {interval_seconds}s")
    print(f"  Window  : last {window_minutes} min of traffic")
    print("=" * 55)
    model, scaler = load_model()
    while True:
        try:
            run_detection_cycle(model, scaler, window_minutes)
            print(f"[Detector] Next check in {interval_seconds}s...")
            time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print("\n[Detector] Stopped.")
            break
        except Exception as e:
            print(f"[Detector] Error: {e}")
            time.sleep(interval_seconds)


def get_latest_scores():
    try:
        model, scaler = load_model()
        features_list = extract_all_devices(window_minutes=30)
        results = []
        for feat in features_list:
            score  = score_vector(to_vector(feat), model, scaler)
            status = "anomaly" if score >= ANOMALY_THRESHOLD else "normal"
            results.append({
                "ip":     feat["ip"],
                "score":  score,
                "status": status,
                "type":   classify_anomaly(feat) if status == "anomaly" else "Normal"
            })
        return results
    except Exception as e:
        return [{"error": str(e)}]


if __name__ == "__main__":
    from database import initialize_database
    initialize_database()
    import sys
    if "--train" in sys.argv:
        train_model()
    else:
        run_continuously(interval_seconds=30, window_minutes=60)