"""
SoftNet-Guard: Fixed Model Evaluation Script
Run from your softnet_guard folder:
    python evaluate_models.py
"""

import pickle
import pandas as pd
import numpy as np
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, confusion_matrix)
import warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("  SoftNet-Guard Model Evaluation")
print("=" * 60)

# ── Load models ──────────────────────────────────────────────
with open('isolation_forest.pkl', 'rb') as f:
    iso_forest = pickle.load(f)
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)
with open('phishing_model.pkl', 'rb') as f:
    phishing_model = pickle.load(f)

print("[OK] Models loaded\n")

# ── Helper functions ─────────────────────────────────────────
def if_predict(X_scaled):
    raw = iso_forest.predict(X_scaled)
    return np.where(raw == -1, 1, 0)

def pad_features(X, n):
    X = X.copy()
    if X.shape[1] > n:
        X = X.iloc[:, :n]
    while X.shape[1] < n:
        X[f'pad_{X.shape[1]}'] = 0
    return X

def print_metrics(name, y_true, y_pred):
    acc  = accuracy_score(y_true, y_pred) * 100
    prec = precision_score(y_true, y_pred, zero_division=0) * 100
    rec  = recall_score(y_true, y_pred, zero_division=0) * 100
    f1   = f1_score(y_true, y_pred, zero_division=0) * 100
    cm   = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr  = (fp / (fp + tn) * 100) if (fp + tn) > 0 else 0

    print(f"\n{'─'*55}")
    print(f"  Dataset  : {name}")
    print(f"{'─'*55}")
    print(f"  Accuracy            : {acc:.1f}%")
    print(f"  Precision           : {prec:.1f}%")
    print(f"  Recall (TPR)        : {rec:.1f}%")
    print(f"  F1-Score            : {f1:.1f}%")
    print(f"  False Positive Rate : {fpr:.1f}%")
    print(f"\n  Confusion Matrix:")
    print(f"                    Predicted")
    print(f"                 Normal   Attack")
    print(f"  Actual Normal  {tn:7d}  {fp:7d}")
    print(f"  Actual Attack  {fn:7d}  {tp:7d}")
    print(f"\n  Samples  : {len(y_true):,}")
    print(f"  Normal   : {int((np.array(y_true)==0).sum()):,}")
    print(f"  Attack   : {int((np.array(y_true)==1).sum()):,}")

# ════════════════════════════════════════════════════════════
# DATASET 1 — UNSW-NB15
# No header row in this file — read with header=None
# Label is the very last column
# ════════════════════════════════════════════════════════════
print("[1/3] Evaluating Isolation Forest on UNSW-NB15...")

try:
    df_unsw = pd.read_csv('UNSW_NB15_training-set.csv', nrows=50000)
    print(f"  Loaded {len(df_unsw):,} rows, {df_unsw.shape[1]} columns")

    y_unsw = pd.to_numeric(df_unsw.iloc[:, -1], errors='coerce').fillna(0)
    y_unsw = (y_unsw != 0).astype(int).values

    X_unsw = df_unsw.iloc[:, :-1].apply(pd.to_numeric, errors='coerce').fillna(0)
    X_unsw = pad_features(X_unsw, scaler.n_features_in_)

    X_unsw_scaled = scaler.transform(X_unsw)
    y_pred_unsw = if_predict(X_unsw_scaled)

    print_metrics("UNSW-NB15", y_unsw, y_pred_unsw)

except Exception as e:
    print(f"  [ERROR] {e}")

# ════════════════════════════════════════════════════════════
# DATASET 2 — TON-IoT
# Label column: 'label' (0=normal, 1=attack)
# ════════════════════════════════════════════════════════════
print("\n[2/3] Evaluating Isolation Forest on TON-IoT...")

try:
    df_ton = pd.read_csv('train_test_network.csv', nrows=100000)
    print(f"  Loaded {len(df_ton):,} rows")

    y_ton = pd.to_numeric(df_ton['label'], errors='coerce').fillna(0)
    y_ton = (y_ton != 0).astype(int).values

    drop_cols = [c for c in ['label', 'type'] if c in df_ton.columns]
    X_ton = df_ton.drop(columns=drop_cols)
    X_ton = X_ton.select_dtypes(include=[np.number]).fillna(0)
    X_ton = pad_features(X_ton, scaler.n_features_in_)

    X_ton_scaled = scaler.transform(X_ton)
    y_pred_ton = if_predict(X_ton_scaled)

    print_metrics("TON-IoT", y_ton, y_pred_ton)

except Exception as e:
    print(f"  [ERROR] {e}")

# ════════════════════════════════════════════════════════════
# DATASET 3 — PhiUSIIL Phishing URL
# Label column: 'label'
# 8 exact features the phishing model was trained on
# ════════════════════════════════════════════════════════════
print("\n[3/3] Evaluating Random Forest on PhiUSIIL...")

try:
    df_phi = pd.read_csv('PhiUSIIL_Phishing_URL_Dataset.csv', nrows=50000)
    print(f"  Loaded {len(df_phi):,} rows")

    y_phi = pd.to_numeric(df_phi['label'], errors='coerce').fillna(0)
    y_phi = (y_phi != 0).astype(int).values

    # Exact 8 features (NoOfDegitsInURL is the typo spelling in the dataset)
    phishing_features = [
        'URLLength',
        'DomainLength',
        'IsDomainIP',
        'NoOfSubDomain',
        'HasObfuscation',
        'IsHTTPS',
        'NoOfOtherSpecialCharsInURL',
        'NoOfDegitsInURL'
    ]

    missing = [f for f in phishing_features if f not in df_phi.columns]
    if missing:
        print(f"  [WARN] Missing features: {missing}")
        print(f"  Falling back to first {phishing_model.n_features_in_} numeric cols")
        X_phi = df_phi.drop(columns=['label'])
        X_phi = X_phi.select_dtypes(include=[np.number]).fillna(0)
        X_phi = pad_features(X_phi, phishing_model.n_features_in_)
    else:
        X_phi = df_phi[phishing_features].fillna(0)
        print(f"  [OK] All 8 features found")

    y_pred_phi = phishing_model.predict(X_phi)
    print_metrics("PhiUSIIL Phishing URL", y_phi, y_pred_phi)

except Exception as e:
    print(f"  [ERROR] {e}")

print("\n" + "=" * 60)
print("  Done. Copy these numbers into your PPT slides.")
print("=" * 60)