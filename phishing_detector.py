"""
SoftNet-Guard - ML Phishing URL Detector
Module 3: Random Forest trained on PhiUSIIL dataset

Scores any URL using 8 extractable features.
Works OFFLINE - no API key needed.
Complements Google Safe Browsing API.
"""

import os
import re
import csv
import pickle
import numpy as np
from urllib.parse import urlparse

MODEL_PATH = "phishing_model.pkl"

PHISH_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "HasObfuscation",
    "IsHTTPS",
    "NoOfSpecialChars",
    "NoOfDegitsInURL",
]


def extract_url_features(url):
    try:
        parsed       = urlparse(url if "://" in url else "http://" + url)
        domain       = parsed.netloc or parsed.path.split("/")[0]
        clean_domain = re.sub(r"^www\.", "", domain)
        sub_count    = max(0, clean_domain.count(".") - 1)
        is_ip        = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean_domain) else 0
        has_obfusc   = 1 if re.search(r"%[0-9a-fA-F]{2}|@|0x", url) else 0
        special_chars= len(re.findall(r"[^a-zA-Z0-9/:.\-_~?=&]", url))
        digit_count  = len(re.findall(r"\d", url))
        return {
            "URLLength":        len(url),
            "DomainLength":     len(clean_domain),
            "IsDomainIP":       is_ip,
            "NoOfSubDomain":    sub_count,
            "HasObfuscation":   has_obfusc,
            "IsHTTPS":          1 if parsed.scheme == "https" else 0,
            "NoOfSpecialChars": special_chars,
            "NoOfDegitsInURL":  digit_count,
        }
    except Exception:
        return {f: 0 for f in PHISH_FEATURES}


def to_vector(feat):
    return [feat[f] for f in PHISH_FEATURES]


def train_phishing_model(xlsx_path="PhiUSIIL_Phishing_URL_Dataset.csv"):
    """
    Train Random Forest on PhiUSIIL dataset.
    Supports .csv files (reads with csv module).
    Label: 1 = phishing, 0 = legitimate
    """
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report

        print(f"[Phishing Model] Loading dataset: {xlsx_path}")

        X, y = [], []

        with open(xlsx_path, encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    label = int(float(row.get("label", 0) or 0))
                    feat  = [
                        float(row.get("URLLength",            0) or 0),
                        float(row.get("DomainLength",         0) or 0),
                        float(row.get("IsDomainIP",           0) or 0),
                        float(row.get("NoOfSubDomain",        0) or 0),
                        float(row.get("HasObfuscation",       0) or 0),
                        float(row.get("IsHTTPS",              0) or 0),
                        float(row.get("NoOfOtherSpecialCharsInURL", 0) or 0),
                        float(row.get("NoOfDegitsInURL",      0) or 0),
                    ]
                    X.append(feat)
                    y.append(label)
                except (ValueError, TypeError):
                    continue

        X = np.array(X)
        y = np.array(y)

        print(f"[Phishing Model] Rows: {len(X)} | Phishing: {sum(y==1)} | Legit: {sum(y==0)}")

        if len(X) < 10:
            print("[Phishing Model] Not enough rows to train. Skipping.")
            return None

        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        clf.fit(X_tr, y_tr)

        y_pred = clf.predict(X_te)
        print("[Phishing Model] Evaluation on test set:")
        print(classification_report(y_te, y_pred,
              target_names=["Legit", "Phishing"], zero_division=0))

        with open(MODEL_PATH, "wb") as f:
            pickle.dump(clf, f)
        print(f"[Phishing Model] Saved -> {MODEL_PATH}")
        return clf

    except FileNotFoundError:
        print(f"[Phishing Model] Dataset not found: {xlsx_path}")
        return None
    except Exception as e:
        print(f"[Phishing Model] Error: {e}")
        return None


def load_phishing_model(xlsx_path="PhiUSIIL_Phishing_URL_Dataset.csv"):
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            clf = pickle.load(f)
        print("[Phishing Model] Loaded from disk.")
        return clf
    else:
        print("[Phishing Model] Training fresh model...")
        return train_phishing_model(xlsx_path)


def predict_url(url, model=None):
    if model is None:
        model = load_phishing_model()
    if model is None:
        return {
            "url": url, "ml_phishing": None,
            "confidence": 0.0, "features": {},
            "risk_level": "Unknown", "error": "Model not available"
        }
    feat  = extract_url_features(url)
    vec   = np.array(to_vector(feat)).reshape(1, -1)
    pred  = model.predict(vec)[0]
    proba = model.predict_proba(vec)[0]
    conf  = float(max(proba))
    if pred == 1 and conf >= 0.8:
        risk = "High"
    elif pred == 1:
        risk = "Medium"
    else:
        risk = "Low"
    return {
        "url":         url,
        "ml_phishing": bool(pred == 1),
        "confidence":  round(conf, 3),
        "features":    feat,
        "risk_level":  risk
    }


if __name__ == "__main__":
    from database import initialize_database
    initialize_database()
    import sys
    if "--train" in sys.argv:
        train_phishing_model()
    else:
        test_urls = [
            "https://google.com",
            "http://192.168.1.1/login",
            "http://paypa1-secure-login.xyz/verify?id=12345%20abc",
            "https://github.com/monish/softnet-guard",
            "http://free-prize-winner.tk/claim?user=admin@gmail.com",
        ]
        model = load_phishing_model()
        print("\n[Phishing Detector] URL Analysis:\n")
        for url in test_urls:
            r    = predict_url(url, model)
            icon = "PHISHING" if r["ml_phishing"] else "SAFE   "
            print(f"  [{icon}] ({r['confidence']:.0%} conf) {url}")