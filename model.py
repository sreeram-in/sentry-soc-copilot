"""
model.py -- trains XGBoost (attack classifier) + Isolation Forest (anomaly detector)
on CICIDS CSVs found anywhere under data/.
If no dataset is found, the model stays disabled instead of training on random numbers.

Dataset fingerprinting: the saved model is only reused if the files under data/ (same
paths, sizes, and modified-times) match what produced it. Add/remove/replace a CSV and
the next startup retrains automatically instead of silently reusing a stale model.pkl.
"""
import hashlib
import os
import pickle

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    from sklearn.ensemble import GradientBoostingClassifier
    HAS_XGB = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_PATH = os.path.join(DATA_DIR, "model.pkl")

MAX_ROWS_PER_FILE = 150000   # cap per class-group per CSV so training stays fast
MIN_CLASS_SAMPLES = 50       # classes rarer than this are dropped

DIRECT_FEATURES = [
    "dur", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd", "totlen_bwd",
    "flow_iat_mean", "flow_iat_std", "fwd_iat_mean", "fwd_iat_std",
    "bwd_iat_mean", "bwd_iat_std", "syn_cnt", "ack_cnt", "psh_cnt", "rst_cnt",
    "down_up_ratio", "pkt_size_avg", "pkt_size_std",
]
FEATURE_COLS = DIRECT_FEATURES + ["flow_bytes_s", "flow_pkts_s", "syn_ratio", "rst_ratio"]

COLUMN_ALIASES = {
    "dur":           ["flow duration", "duration", "dur"],
    "tot_fwd_pkts":  ["total fwd packets", "tot fwd pkts", "total fwd pkts"],
    "tot_bwd_pkts":  ["total backward packets", "tot bwd pkts", "total bwd pkts"],
    "totlen_fwd":    ["total length of fwd packets", "totlen fwd pkts", "totlen fwd"],
    "totlen_bwd":    ["total length of bwd packets", "totlen bwd pkts", "totlen bwd"],
    "flow_iat_mean": ["flow iat mean"],
    "flow_iat_std":  ["flow iat std"],
    "fwd_iat_mean":  ["fwd iat mean"],
    "fwd_iat_std":   ["fwd iat std"],
    "bwd_iat_mean":  ["bwd iat mean"],
    "bwd_iat_std":   ["bwd iat std"],
    "syn_cnt":       ["syn flag count", "syn flag cnt"],
    "ack_cnt":       ["ack flag count", "ack flag cnt"],
    "psh_cnt":       ["psh flag count", "psh flag cnt"],
    "rst_cnt":       ["rst flag count", "rst flag cnt"],
    "down_up_ratio": ["down/up ratio"],
    "pkt_size_avg":  ["average packet size", "pkt size avg", "packet length mean", "pkt len mean"],
    "pkt_size_std":  ["packet length std", "pkt len std"],
    "label":         ["label"],
}
OPTIONAL = {"down_up_ratio", "pkt_size_avg", "pkt_size_std"}
MICROSECOND_FIELDS = {"dur", "flow_iat_mean", "flow_iat_std", "fwd_iat_mean",
                      "fwd_iat_std", "bwd_iat_mean", "bwd_iat_std"}

# Order matters: first match wins.
LABEL_RULES = [
    ("benign", "Normal"),
    ("ddos", "DDoS"),
    ("dos", "DoS"),
    ("portscan", "PortScan"),
    ("port scan", "PortScan"),
    ("web", "WebAttack"),
    ("sql", "WebAttack"),
    ("patator", "BruteForce"),
    ("brute", "BruteForce"),
    ("bot", "Bot"),
    ("infil", "Infiltration"),
]


def _map_label(raw):
    s = str(raw).strip().lower()
    for sub, bucket in LABEL_RULES:
        if sub in s:
            return bucket
    return "Other"


def _find_col(df, aliases):
    for a in aliases:
        if a in df.columns:
            return a
    return None


def _load_one_csv(path):
    try:
        df = pd.read_csv(path, low_memory=False)
    except Exception as e:
        print(f"    couldn't read ({e})")
        return None
    df.columns = [str(c).strip().lower() for c in df.columns]

    cols = {}
    for feat in DIRECT_FEATURES + ["label"]:
        c = _find_col(df, COLUMN_ALIASES[feat])
        if c is None:
            if feat in OPTIONAL:
                continue
            print(f"    missing column for '{feat}' -- skipping {os.path.basename(path)}")
            return None
        cols[feat] = c

    out = pd.DataFrame()
    for feat in DIRECT_FEATURES:
        if feat in cols:
            vals = pd.to_numeric(df[cols[feat]], errors="coerce")
            out[feat] = vals / 1e6 if feat in MICROSECOND_FIELDS else vals
        else:
            out[feat] = 0.0

    out["dur"] = out["dur"].clip(lower=0.001)
    pk = out["tot_fwd_pkts"] + out["tot_bwd_pkts"]
    by = out["totlen_fwd"] + out["totlen_bwd"]
    out["flow_bytes_s"] = by / out["dur"]
    out["flow_pkts_s"] = pk / out["dur"]
    pk = pk.clip(lower=1)
    out["syn_ratio"] = out["syn_cnt"] / pk
    out["rst_ratio"] = out["rst_cnt"] / pk
    out["Label"] = df[cols["label"]].map(_map_label)

    out = out.replace([np.inf, -np.inf], np.nan).dropna()

    normal = out[out["Label"] == "Normal"]
    attack = out[out["Label"] != "Normal"]
    if len(normal) > MAX_ROWS_PER_FILE:
        normal = normal.sample(MAX_ROWS_PER_FILE, random_state=42)
    if len(attack) > MAX_ROWS_PER_FILE:
        attack = attack.sample(MAX_ROWS_PER_FILE, random_state=42)
    return pd.concat([normal, attack], ignore_index=True)


def _scan_csvs():
    """Every usable CSV under data/, excluding our own live-capture log."""
    if not os.path.isdir(DATA_DIR):
        return []
    csvs = []
    for root, _, files in os.walk(DATA_DIR):
        for f in files:
            if f.lower().endswith(".csv") and f.lower() != "live_captured.csv":
                csvs.append(os.path.join(root, f))
    csvs.sort()
    return csvs


def _fingerprint(csvs):
    """Hash of (path, size, mtime) for every CSV -- changes whenever data/ changes."""
    h = hashlib.sha256()
    for p in csvs:
        try:
            st = os.stat(p)
            h.update(f"{p}|{st.st_size}|{int(st.st_mtime)}\n".encode())
        except OSError:
            h.update(f"{p}|missing\n".encode())
    return h.hexdigest()


def load_real_datasets(csvs=None):
    if csvs is None:
        csvs = _scan_csvs()
    print(f"[model.py] Found {len(csvs)} CSV file(s) under data/")
    frames = []
    for p in csvs:
        print(f"  Loading: {p}")
        d = _load_one_csv(p)
        if d is not None and len(d) > 0:
            print(f"    -> {len(d):,} usable rows")
            frames.append(d)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


class SOCModel:
    def __init__(self):
        self.classifier = None
        self.iso_forest = None
        self.iso_threshold = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.eval_metrics = {}
        self.ready = False
        self.backend_name = "XGBoost" if HAS_XGB else "GradientBoosting"
        self.load_or_train()

    def load_or_train(self):
        csvs = _scan_csvs()
        fingerprint = _fingerprint(csvs)

        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    s = pickle.load(f)
                if s.get("dataset_fingerprint") == fingerprint:
                    self.classifier = s["classifier"]
                    self.iso_forest = s["iso_forest"]
                    self.iso_threshold = s["iso_threshold"]
                    self.scaler = s["scaler"]
                    self.label_encoder = s["label_encoder"]
                    self.eval_metrics = s["eval_metrics"]
                    self.backend_name = s.get("backend_name", self.backend_name)
                    self.ready = True
                    print("[+] Saved model loaded (data/ unchanged since it was trained).")
                    return
                print("[*] data/ contents changed since the saved model was trained -- retraining...")
            except Exception as e:
                print(f"[-] Could not load saved model ({e}). Retraining...")

        if not csvs:
            print("[!] No usable CICIDS CSVs in data/. Detection is DISABLED until you add them.")
            self.backend_name = "No model (add dataset)"
            return

        df = load_real_datasets(csvs)
        if df.empty:
            print("[!] CSVs were found in data/ but none produced usable rows "
                  "(column names didn't match CICIDS2017/2018 aliases). Detection is DISABLED.")
            self.backend_name = "No model (bad dataset)"
            return
        self._train(df, fingerprint)

    def _train(self, df, fingerprint):
        counts = df["Label"].value_counts()
        keep = counts[counts >= MIN_CLASS_SAMPLES].index
        df = df[df["Label"].isin(keep)]
        print("[model.py] Class counts:\n", df["Label"].value_counts().to_string())

        X = df[FEATURE_COLS].values
        y = self.label_encoder.fit_transform(df["Label"].values)
        Xs = self.scaler.fit_transform(X)

        Xtr, Xte, ytr, yte = train_test_split(
            Xs, y, test_size=0.2, random_state=42,
            stratify=y if len(np.unique(y)) > 1 else None)

        if HAS_XGB:
            self.classifier = xgb.XGBClassifier(
                n_estimators=100, max_depth=6, learning_rate=0.1,
                random_state=42, eval_metric="mlogloss", n_jobs=-1)
        else:
            self.classifier = GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)
        self.classifier.fit(Xtr, ytr)

        classes = list(self.label_encoder.classes_)
        if "Normal" in classes:
            Xn = Xtr[ytr == classes.index("Normal")]
        else:
            Xn = Xtr
        if len(Xn) > 100000:
            Xn = Xn[np.random.RandomState(42).choice(len(Xn), 100000, replace=False)]
        self.iso_forest = IsolationForest(n_estimators=100, random_state=42, n_jobs=-1)
        self.iso_forest.fit(Xn)
        self.iso_threshold = float(np.percentile(self.iso_forest.score_samples(Xn), 0.1))

        ypred = self.classifier.predict(Xte)
        labels_idx = list(range(len(classes)))
        self.eval_metrics = {
            "accuracy": round(float(accuracy_score(yte, ypred)) * 100, 2),
            "train_size": len(Xtr),
            "test_size": len(Xte),
            "labels": classes,
            "report": classification_report(
                yte, ypred, labels=labels_idx, target_names=classes,
                output_dict=True, zero_division=0),
            "confusion": confusion_matrix(yte, ypred, labels=labels_idx).tolist(),
        }

        os.makedirs(DATA_DIR, exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump({
                "classifier": self.classifier, "iso_forest": self.iso_forest,
                "iso_threshold": self.iso_threshold, "scaler": self.scaler,
                "label_encoder": self.label_encoder, "eval_metrics": self.eval_metrics,
                "backend_name": self.backend_name,
                "dataset_fingerprint": fingerprint,
            }, f)
        self.ready = True
        print(f"[+] Model trained ({self.eval_metrics['accuracy']}% test accuracy) and saved.")

    def predict(self, feature_dict):
        if not self.ready:
            return {"label": "Normal", "confidence": 0.0, "is_attack": False,
                    "is_anomaly": False, "anomaly_score": 0.0, "top_features": []}

        vec = [float(feature_dict.get(n, 0.0)) for n in FEATURE_COLS]
        Xs = self.scaler.transform(np.array([vec]))

        probas = self.classifier.predict_proba(Xs)[0]
        idx = int(np.argmax(probas))
        label = str(self.label_encoder.inverse_transform([idx])[0])

        score = float(self.iso_forest.score_samples(Xs)[0])

        imp = getattr(self.classifier, "feature_importances_", np.ones(len(FEATURE_COLS)))
        contrib = np.abs(Xs[0]) * imp
        top = np.argsort(contrib)[::-1][:3]
        top_features = [{"feature": FEATURE_COLS[i], "impact": round(float(contrib[i]), 3)}
                        for i in top]

        return {
            "label": label,
            "confidence": round(float(probas[idx]) * 100.0, 1),
            "is_attack": label != "Normal",
            "is_anomaly": bool(score < self.iso_threshold),
            "anomaly_score": round(score, 3),
            "top_features": top_features,
        }

    def get_eval_metrics(self):
        return self.eval_metrics