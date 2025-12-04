import sys
from pathlib import Path
import pandas as pd
from sklearn.utils import resample

# ------------------ CONFIG ------------------
MALICE_THRESHOLD = 0.4       # > threshold = malicious
IMBALANCE_RATIO_LIMIT = 3.0  # If one class is 3x bigger → undersample
# ------------------------------------------------


def get_project_root() -> Path:
    """Returns the project root directory."""
    return Path(__file__).resolve().parents[2]


def load_and_merge_labels(dataset_root: Path) -> pd.DataFrame:
    """Load labels from benign.csv and malware.csv and merge."""
    labels_dir = dataset_root / "labels"

    benign_csv = labels_dir / "benign.csv"
    malware_csv = labels_dir / "malware.csv"

    if not benign_csv.exists() or not malware_csv.exists():
        raise FileNotFoundError("benign.csv or malware.csv not found in labels folder")

    benign_df = pd.read_csv(benign_csv)
    benign_df["source"] = "benign"

    malware_df = pd.read_csv(malware_csv)
    malware_df["source"] = "malware"

    df = pd.concat([benign_df, malware_df], ignore_index=True)
    return df


def clean_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Filter only PE files and assign binary labels based on malice."""
    print("[INFO] Filtering to type == 0 (PE files only)...")

    df = df[df["type"] == 0].copy()
    print(f"[INFO] Remaining samples after PE filter: {len(df)}")

    print(f"[INFO] Applying malice threshold: {MALICE_THRESHOLD}")
    df["label"] = (df["malice"] > MALICE_THRESHOLD).astype(int)

    print(df["label"].value_counts())
    return df


def balance_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Undersample malware if needed."""
    counts = df["label"].value_counts()
    benign_count = counts.get(0, 0)
    malware_count = counts.get(1, 0)

    print(f"[INFO] Before balancing: benign={benign_count}, malware={malware_count}")

    # Compute imbalance ratio
    if benign_count == 0:
        print("[WARNING] No benign samples found. Cannot balance dataset.")
        return df

    imbalance_ratio = malware_count / benign_count
    print(f"[INFO] Imbalance ratio = {imbalance_ratio:.2f}")

    # If imbalance severe → undersample malware
    if imbalance_ratio > IMBALANCE_RATIO_LIMIT:
        print("[INFO] Dataset is skewed → applying undersampling on malware")

        df_benign = df[df["label"] == 0]
        df_malware = df[df["label"] == 1]

        df_malware_down = resample(
            df_malware,
            replace=False,
            n_samples=len(df_benign)*2,  # match benign count
            random_state=42
        )

        df_balanced = pd.concat([df_benign, df_malware_down], ignore_index=True)
        print(f"[INFO] After balancing: {df_balanced['label'].value_counts()}")
        return df_balanced

    print("[INFO] Dataset not skewed enough → no balancing needed")
    return df


def save_outputs(clean_df: pd.DataFrame, balanced_df: pd.DataFrame, out_dir: Path):
    out_dir.mkdir(exist_ok=True, parents=True)

    clean_path = out_dir / "labels_cleaned.csv"
    balanced_path = out_dir / "labels_balanced.csv"

    clean_df.to_csv(clean_path, index=False)
    balanced_df.to_csv(balanced_path, index=False)

    print(f"[INFO] Saved cleaned labels to: {clean_path}")
    print(f"[INFO] Saved balanced labels to: {balanced_path}")


def main():
    project_root = get_project_root()
    dataset_root = project_root / "malicious_file_detector" / "data" / "raw" / "DikeDataset"
    output_dir = project_root / "malicious_file_detector" / "data" / "processed"

    print(f"[INFO] Project root: {project_root}")

    if not dataset_root.exists():
        print(f"[ERROR] Dataset not found at: {dataset_root}")
        sys.exit(1)

    print("[INFO] Loading labels...")
    df_labels = load_and_merge_labels(dataset_root)

    print("[INFO] Cleaning labels...")
    cleaned_df = clean_labels(df_labels)

    print("[INFO] Checking balance & undersampling...")
    balanced_df = balance_dataset(cleaned_df)

    print("[INFO] Saving...")
    save_outputs(cleaned_df, balanced_df, output_dir)

    print("[INFO] Label preprocessing complete!")


if __name__ == "__main__":
    main()
