import math
import os
import sys
from pathlib import Path
import re
from typing import Optional, Dict, Any, List

import pefile
import numpy as np
import pandas as pd

# ------------------ CONFIG ------------------
MALICE_THRESHOLD = 0.6  # (for reference only here)
LABELS_FILE = "labels_balanced.csv"
OUTPUT_FEATURES_FILE = "pe_features.csv"

SUSPICIOUS_SECTION_NAMES = {
    b".upx", b"upx0", b"upx1", b"aspack", b"mpress", b".textbss"
}

IMPORTANT_DLLS = [
    "kernel32.dll",
    "user32.dll",
    "advapi32.dll",
    "ws2_32.dll",
    "wininet.dll",
    "ntdll.dll",
    "shell32.dll",
    "msvcrt.dll",
    "crypt32.dll",
]
# ------------------------------------------------


def get_project_root() -> Path:
    """
    Returns the project root directory assuming this file is at:
    <root>/data/extract_pe_features.py
    """
    return Path(__file__).resolve().parents[1]


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of given bytes."""
    if not data:
        return 0.0

    byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = byte_counts / len(data)
    probs = probs[probs > 0]
    return float(-(probs * np.log2(probs)).sum())


def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    """
    Extract printable ASCII strings of at least min_len characters.
    """
    pattern = rb"[ -~]{%d,}" % min_len  # printable ASCII range
    return [s.decode("ascii", errors="ignore") for s in re.findall(pattern, data)]


def find_sample_file(dataset_root: Path, file_hash: str) -> Optional[Path]:
    """
    Try to find the sample file in benign or malware folders using hash.
    Tries filenames: <hash>, <hash>.exe, <hash>.bin
    """
    files_root = dataset_root / "files"

    candidates = [
        files_root / "benign" / file_hash,
        files_root / "malware" / file_hash,
        files_root / "benign" / f"{file_hash}.exe",
        files_root / "malware" / f"{file_hash}.exe",
        files_root / "benign" / f"{file_hash}.bin",
        files_root / "malware" / f"{file_hash}.bin",
    ]

    for c in candidates:
        if c.exists():
            return c

    return None


def extract_pe_features(file_path: Path) -> Dict[str, Any]:
    """
    Extract static PE features from a single file.
    Returns a dict of feature_name -> value.
    Raises an exception if parsing fails.
    """
    features: Dict[str, Any] = {}

    # Read raw bytes
    data = file_path.read_bytes()
    file_size = len(data)
    file_entropy = shannon_entropy(data)

    features["file_size"] = file_size
    features["file_entropy"] = file_entropy

    # Strings features
    strings = extract_strings(data, min_len=4)
    num_strings = len(strings)
    lengths = [len(s) for s in strings] if strings else []

    features["num_strings"] = num_strings
    features["avg_string_len"] = float(np.mean(lengths)) if lengths else 0.0
    features["max_string_len"] = int(np.max(lengths)) if lengths else 0

    # Simple pattern-based string stats
    url_pattern = re.compile(r"https?://", re.IGNORECASE)
    reg_pattern = re.compile(r"HKEY_[A-Z_]+", re.IGNORECASE)
    path_pattern = re.compile(r"[A-Za-z]:\\", re.IGNORECASE)
    ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

    num_urls = num_registry = num_filepaths = num_ips = 0

    for s in strings:
        if url_pattern.search(s):
            num_urls += 1
        if reg_pattern.search(s):
            num_registry += 1
        if path_pattern.search(s):
            num_filepaths += 1
        if ip_pattern.search(s):
            num_ips += 1

    features["num_urls"] = num_urls
    features["num_registry_strings"] = num_registry
    features["num_filepath_strings"] = num_filepaths
    features["num_ip_strings"] = num_ips

    # PE-level features
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ]
    )

    # Header features
    features["machine"] = getattr(pe.FILE_HEADER, "Machine", 0)
    features["number_of_sections"] = getattr(pe.FILE_HEADER, "NumberOfSections", 0)
    features["characteristics"] = getattr(pe.FILE_HEADER, "Characteristics", 0)

    optional = pe.OPTIONAL_HEADER
    features["size_of_code"] = getattr(optional, "SizeOfCode", 0)
    features["size_of_image"] = getattr(optional, "SizeOfImage", 0)
    features["subsystem"] = getattr(optional, "Subsystem", 0)
    features["dll_characteristics"] = getattr(optional, "DllCharacteristics", 0)

    # Section features
    section_entropies = []
    num_exec_sections = 0
    num_write_sections = 0
    num_suspicious_sections = 0

    for section in pe.sections:
        sec_data = section.get_data()
        e = shannon_entropy(sec_data)
        section_entropies.append(e)

        name = section.Name.rstrip(b"\x00").lower()
        if name in SUSPICIOUS_SECTION_NAMES:
            num_suspicious_sections += 1

        characteristics = section.Characteristics
        # IMAGE_SCN_MEM_EXECUTE = 0x20000000, WRITE = 0x80000000
        if characteristics & 0x20000000:
            num_exec_sections += 1
        if characteristics & 0x80000000:
            num_write_sections += 1

    if section_entropies:
        features["mean_section_entropy"] = float(np.mean(section_entropies))
        features["max_section_entropy"] = float(np.max(section_entropies))
        features["std_section_entropy"] = float(np.std(section_entropies))
    else:
        features["mean_section_entropy"] = 0.0
        features["max_section_entropy"] = 0.0
        features["std_section_entropy"] = 0.0

    features["num_exec_sections"] = num_exec_sections
    features["num_write_sections"] = num_write_sections
    features["num_suspicious_sections"] = num_suspicious_sections

    # Import table features
    num_imported_dlls = 0
    num_imported_functions = 0
    dll_flags = {f"imports_{dll.split('.')[0].lower()}": 0 for dll in IMPORTANT_DLLS}

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        num_imported_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore").lower()
            num_imported_functions += len(entry.imports)

            for dll in IMPORTANT_DLLS:
                if dll_name == dll.lower():
                    key = f"imports_{dll.split('.')[0].lower()}"
                    dll_flags[key] = 1

    features["num_imported_dlls"] = num_imported_dlls
    features["num_imported_functions"] = num_imported_functions
    features.update(dll_flags)

    return features


def main():
    project_root = get_project_root()
    dataset_root = project_root / "data" / "raw" / "DikeDataset"
    processed_dir = project_root / "data" / "processed"

    print(f"[INFO] Project root: {project_root}")
    print(f"[INFO] Dataset root: {dataset_root}")

    if not dataset_root.exists():
        print(f"[ERROR] DikeDataset not found at: {dataset_root}")
        sys.exit(1)

    labels_path = processed_dir / LABELS_FILE
    if not labels_path.exists():
        print(f"[ERROR] Labels file not found: {labels_path}")
        sys.exit(1)

    print(f"[INFO] Loading labels from: {labels_path}")
    labels_df = pd.read_csv(labels_path)

    required_cols = {"hash", "label", "malice", "source"}
    missing = required_cols - set(labels_df.columns)
    if missing:
        print(f"[ERROR] Labels file missing required columns: {missing}")
        sys.exit(1)

    features_list: List[Dict[str, Any]] = []
    missing_files = 0
    failed_parses = 0

    total = len(labels_df)
    print(f"[INFO] Extracting features for {total} samples...")

    for idx, row in labels_df.iterrows():
        file_hash = row["hash"]
        label = int(row["label"])
        malice = float(row["malice"])
        source = row.get("source", "")

        sample_path = find_sample_file(dataset_root, file_hash)
        if sample_path is None:
            missing_files += 1
            if missing_files <= 10:
                print(f"[WARN] File not found for hash {file_hash}")
            continue

        try:
            feats = extract_pe_features(sample_path)
            feats["hash"] = file_hash
            feats["label"] = label
            feats["malice"] = malice
            feats["source"] = source
            features_list.append(feats)
        except Exception as e:
            failed_parses += 1
            if failed_parses <= 10:
                print(f"[WARN] Failed to parse {sample_path.name}: {e}")
            continue

        if (idx + 1) % 100 == 0 or idx == total - 1:
            print(f"[INFO] Processed {idx + 1}/{total} samples...")

    print(f"[INFO] Finished extraction.")
    print(f"[INFO] Missing files: {missing_files}")
    print(f"[INFO] Failed PE parses: {failed_parses}")
    print(f"[INFO] Successfully extracted: {len(features_list)}")

    if not features_list:
        print("[ERROR] No features extracted. Aborting.")
        sys.exit(1)

    features_df = pd.DataFrame(features_list)
    processed_dir.mkdir(parents=True, exist_ok=True)
    out_path = processed_dir / OUTPUT_FEATURES_FILE
    features_df.to_csv(out_path, index=False)

    print(f"[INFO] Saved features to: {out_path}")


if __name__ == "__main__":
    main()
