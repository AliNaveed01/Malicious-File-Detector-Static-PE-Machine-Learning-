import json
import joblib
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

# Try XGBoost if available
try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("[WARN] XGBoost not installed. Skipping XGBoost model.")


def get_project_root() -> Path:
    # models/train_models.py -> models/ -> project root
    return Path(__file__).resolve().parents[1]


def load_features() -> pd.DataFrame:
    root = get_project_root()
    path = root / "data" / "processed" / "pe_features.csv"

    if not path.exists():
        raise FileNotFoundError(f"Feature file not found: {path}")

    print(f"[INFO] Loading features from: {path}")
    df = pd.read_csv(path)

    # Drop non-ML columns
    drop_cols = ["hash", "source", "malice"]
    df = df.drop(columns=drop_cols, errors="ignore")

    return df


def split_data(df: pd.DataFrame):
    X = df.drop("label", axis=1)
    y = df["label"]

    feature_columns = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    return X_train, X_test, y_train, y_test, feature_columns


def scale_features(X_train, X_test):
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    return scaler, X_train_scaled, X_test_scaled


def train_random_forest(X_train, y_train):
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        random_state=42,
        n_jobs=1  # avoid multiprocessing warnings
    )
    rf.fit(X_train, y_train)
    return rf


def train_logistic_regression(X_train_scaled, y_train):
    lr = LogisticRegression(
        max_iter=500,
        n_jobs=1  # avoid multiprocessing warnings
    )
    lr.fit(X_train_scaled, y_train)
    return lr


def train_xgboost(X_train, y_train):
    model = XGBClassifier(
        n_estimators=300,
        learning_rate=0.1,
        max_depth=8,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="logloss",
        n_jobs=1
    )
    model.fit(X_train, y_train)
    return model


def evaluate(model, X_test, y_test, model_name):
    preds = model.predict(X_test)

    print(f"\n===== {model_name} Evaluation =====")
    print("Accuracy:  ", accuracy_score(y_test, preds))
    print("Precision: ", precision_score(y_test, preds))
    print("Recall:    ", recall_score(y_test, preds))
    print("F1 Score:  ", f1_score(y_test, preds))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, preds))

    print("\nClassification Report:")
    print(classification_report(y_test, preds))

    return f1_score(y_test, preds)


def save_artifacts(model, scaler, feature_columns, model_name, use_scaler):
    root = get_project_root()
    models_dir = root / "models"
    models_dir.mkdir(exist_ok=True)

    joblib.dump(model, models_dir / "best_model.pkl")
    joblib.dump(scaler, models_dir / "scaler.pkl")

    with open(models_dir / "feature_columns.json", "w") as f:
        json.dump(feature_columns, f, indent=4)

    meta = {
        "model_name": model_name,
        "use_scaler": use_scaler,
    }
    with open(models_dir / "model_meta.json", "w") as f:
        json.dump(meta, f, indent=4)

    print(f"\n[INFO] Saved model, scaler, and metadata in: {models_dir}")


def main():
    df = load_features()

    X_train, X_test, y_train, y_test, feature_columns = split_data(df)
    scaler, X_train_scaled, X_test_scaled = scale_features(X_train, X_test)

    results = {}

    # Random Forest (unscaled)
    rf = train_random_forest(X_train, y_train)
    results["RandomForest"] = evaluate(rf, X_test, y_test, "Random Forest")

    # Logistic Regression (scaled)
    lr = train_logistic_regression(X_train_scaled, y_train)
    results["LogisticRegression"] = evaluate(
        lr, X_test_scaled, y_test, "Logistic Regression"
    )

    # XGBoost (optional, unscaled)
    if HAS_XGBOOST:
        xgb = train_xgboost(X_train, y_train)
        results["XGBoost"] = evaluate(xgb, X_test, y_test, "XGBoost")

    # Choose best model by F1 score
    best_name = max(results, key=results.get)
    print("\n[INFO] Best model =", best_name)

    if best_name == "RandomForest":
        best_model = rf
        use_scaler = False  # RF was trained on unscaled features
    elif best_name == "LogisticRegression":
        best_model = lr
        use_scaler = True   # LR was trained on scaled features
    else:
        best_model = xgb
        use_scaler = False  # XGB here uses unscaled features

    save_artifacts(best_model, scaler, feature_columns, best_name, use_scaler)


if __name__ == "__main__":
    main()
