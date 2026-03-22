#!/usr/bin/env python3
"""
Distributed EMBER-style Malware Classifier Training
Adapts https://github.com/elastic/ember for OpenỌ̀ṣọ́ọ̀sì mesh.
Trains on: local MalwareData.csv + mesh samples from SQLite.
Exports model for Rust inference. Run periodically for continuous learning.
"""
import os
import sys
import json
import sqlite3
import argparse
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
MODEL_DIR = PROJECT_ROOT / "models" / "malware"
DATA_DIR = PROJECT_ROOT / "malware"
DB_PATH = Path(os.environ.get("OSOOSI_DB_PATH", str(PROJECT_ROOT / "osoosi.db")))

# Default: use legacy 54-feature format (compatible with existing pe_features)
# Set EMBER_FEATURES=1 to use EMBER (requires: pip install ember)
USE_EMBER = os.environ.get("EMBER_FEATURES", "").lower() in ("1", "true", "yes")


def load_mesh_samples(limit: int = 10000) -> tuple[list, list]:
    """Load malware samples from mesh (SQLite malware_samples table)."""
    X, y = [], []
    if not DB_PATH.exists():
        return X, y
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cur = conn.execute(
            "SELECT features_json, label FROM malware_samples ORDER BY received_at DESC LIMIT ?",
            (limit,),
        )
        for row in cur:
            try:
                features = json.loads(row[0])
                if isinstance(features, list) and len(features) >= 54:
                    X.append(features[:54])  # truncate to legacy 54 if needed
                    y.append(int(row[1]))
            except (json.JSONDecodeError, TypeError):
                continue
        conn.close()
    except Exception as e:
        print(f"Warning: Could not load mesh samples: {e}")
    return X, y


def load_malware_data_csv() -> tuple[list, list]:
    """Load from MalwareData.csv (legacy format)."""
    csv_path = DATA_DIR / "MalwareData.csv"
    if not csv_path.exists():
        return [], []
    import pandas as pd
    df = pd.read_csv(csv_path, sep="|", low_memory=True)
    if "legitimate" not in df.columns:
        return [], []
    y = df["legitimate"].values
    df = df.drop(columns=["Name", "md5", "legitimate"], errors="ignore")
    X = df.values.tolist()
    return X, y.tolist()


def train_sklearn(X, y, feature_names: list) -> tuple:
    """Train RF/LR, return (model, scaler)."""
    import numpy as np
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, f1_score

    X = np.array(X, dtype=np.float64)
    y = np.array(y)
    # Handle NaN
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)
    rf_acc = accuracy_score(y_test, rf.predict(X_test_scaled))
    rf_f1 = f1_score(y_test, rf.predict(X_test_scaled))

    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train)
    lr_acc = accuracy_score(y_test, lr.predict(X_test_scaled))
    lr_f1 = f1_score(y_test, lr.predict(X_test_scaled))

    if rf_acc >= lr_acc:
        return rf, scaler, "random_forest"
    return lr, scaler, "logistic_regression"


def export_for_rust(model, scaler, feature_names: list, model_type: str, path: Path):
    """Export model as JSON for Rust MalwareModel."""
    data = {
        "model_type": model_type,
        "feature_names": feature_names,
        "scaler_mean": scaler.mean_.tolist(),
        "scaler_scale": scaler.scale_.tolist(),
    }
    if model_type == "logistic_regression":
        data["intercept"] = float(model.intercept_[0])
        data["coefficients"] = model.coef_[0].tolist()
    else:
        trees = []
        for est in model.estimators_:
            t = est.tree_
            trees.append({
                "feature": t.feature.tolist(),
                "threshold": [float(x) for x in t.threshold],
                "children_left": t.children_left.tolist(),
                "children_right": t.children_right.tolist(),
                "value": [[float(v[0][0]), float(v[0][1]) if v[0].shape[0] > 1 else 0.0] for v in t.value],
            })
        data["trees"] = trees
        data["n_estimators"] = len(model.estimators_)
    with open(path, "w") as f:
        json.dump(data, f)
    print(f"Exported {model_type} to {path}")


def main():
    parser = argparse.ArgumentParser(description="Train distributed EMBER-style malware classifier")
    parser.add_argument("--mesh-limit", type=int, default=10000, help="Max mesh samples to load")
    parser.add_argument("--output", type=str, default=str(MODEL_DIR / "malware_model.json"))
    args = parser.parse_args()

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # Load data
    X_mesh, y_mesh = load_mesh_samples(args.mesh_limit)
    X_csv, y_csv = load_malware_data_csv()

    X = X_mesh + X_csv
    y = y_mesh + y_csv

    if len(X) < 10:
        print("Insufficient samples. Need at least 10. Add mesh samples or MalwareData.csv.")
        sys.exit(1)

    # Feature names (legacy 54)
    feature_names = [
        "Machine", "SizeOfOptionalHeader", "Characteristics",
        "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode",
        "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint",
        "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment", "FileAlignment",
        "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion",
        "MajorSubsystemVersion", "MinorSubsystemVersion",
        "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics",
        "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit",
        "LoaderFlags", "NumberOfRvaAndSizes",
        "SectionsNb", "SectionsMeanEntropy", "SectionsMinEntropy", "SectionsMaxEntropy",
        "SectionsMeanRawsize", "SectionsMinRawsize", "SectionMaxRawsize",
        "SectionsMeanVirtualsize", "SectionsMinVirtualsize", "SectionMaxVirtualsize",
        "ImportsNbDLL", "ImportsNb", "ImportsNbOrdinal", "ExportNb",
        "ResourcesNb", "ResourcesMeanEntropy", "ResourcesMinEntropy", "ResourcesMaxEntropy",
        "ResourcesMeanSize", "ResourcesMinSize", "ResourcesMaxSize",
        "LoadConfigurationSize", "VersionInformationSize",
        "TimeDateStamp", "ExportSize", "ImportSize",
    ]
    # Pad/truncate features to 54
    X_padded = []
    for row in X:
        if len(row) < 54:
            row = list(row) + [0.0] * (54 - len(row))
        else:
            row = row[:54]
        X_padded.append(row)
    X = X_padded

    print(f"Training on {len(X)} samples ({len(X_mesh)} from mesh, {len(X_csv)} from CSV)")
    model, scaler, model_type = train_sklearn(X, y, feature_names)
    export_for_rust(model, scaler, feature_names, model_type, Path(args.output))

    summary = {
        "mesh_samples": len(X_mesh),
        "csv_samples": len(X_csv),
        "total": len(X),
        "model_type": model_type,
    }
    with open(MODEL_DIR / "training_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Training complete. Summary: {summary}")


if __name__ == "__main__":
    main()
