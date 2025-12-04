import sys
from pathlib import Path

import pandas as pd

# ---------- CONFIG ----------
MALICE_THRESHOLD = 0.4  # > 0.4 => malicious, <= 0.4 => benign


def get_project_root() -> Path:
    """
    Returns the project root directory assuming this file is at:
    <root>/data/dataset_overview.py
    """
    # dataset_overview.py -> data/ -> project root
    return Path(__file__).resolve().parents[1]


def load_labels(dataset_root: Path) -> pd.DataFrame:
    """
    Load benign and malware label CSVs from the DikeDataset/labels folder
    and return a single DataFrame with a 'label' column.

    label: 0 = benign, 1 = malicious (based on MALICE_THRESHOLD)
    """
    labels_dir = dataset_root / "labels"
    benign_csv = labels_dir / "benign.csv"
    malware_csv = labels_dir / "malware.csv"

    if not benign_csv.exists() or not malware_csv.exists():
        raise FileNotFoundError(
            f"Could not find benign.csv or malware.csv in {labels_dir}"
        )

    print(f"[INFO] Loading labels from: {labels_dir}")

    benign_df = pd.read_csv(benign_csv)
    benign_df["source"] = "benign"

    malware_df = pd.read_csv(malware_csv)
    malware_df["source"] = "malware"

    df = pd.concat([benign_df, malware_df], ignore_index=True)

    # Basic sanity check
    required_cols = {"hash", "malice", "type"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in labels: {missing}")

    # Create binary label based on malice score
    df["label"] = (df["malice"] > MALICE_THRESHOLD).astype(int)

    return df


def summarize_labels(df: pd.DataFrame) -> None:
    """Print a basic summary of the labels and malice distribution."""
    print("\n=== Dataset Overview ===")
    print(f"Total samples: {len(df)}")

    print("\nBy source (benign/malware folders):")
    print(df["source"].value_counts())

    print("\nBy file type (e.g. PE / OLE):")
    if "type" in df.columns:
        print(df["type"].value_counts())
    else:
        print("No 'type' column found in labels.")

    print(f"\nMalice threshold for binary label: {MALICE_THRESHOLD}")
    print("Label meaning: 0 = benign (<= threshold), 1 = malicious (> threshold)")

    print("\nLabel distribution (0/1):")
    print(df["label"].value_counts())

    print("\nMalice statistics:")
    print(df["malice"].describe())

    print("\nMalice distribution buckets:")
    buckets = pd.cut(df["malice"], bins=[0, 0.2, 0.4, 0.6, 0.8, 1.0])
    print(buckets.value_counts().sort_index())


def main():
    project_root = get_project_root()
    dataset_root = project_root / "data" / "raw" / "DikeDataset"

    print(f"[INFO] Project root: {project_root}")
    print(f"[INFO] Using dataset at: {dataset_root}")

    if not dataset_root.exists():
        print(f"[ERROR] DikeDataset folder not found at: {dataset_root}")
        sys.exit(1)

    df = load_labels(dataset_root)
    summarize_labels(df)


if __name__ == "__main__":
    main()
