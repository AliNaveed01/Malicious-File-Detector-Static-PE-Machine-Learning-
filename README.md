# 🛡️ Malicious File Detector (Static PE + Machine Learning)

A complete end-to-end malware detection system that uses **static analysis of Windows PE files**, extracts meaningful features, trains ML models (RandomForest, Logistic Regression, XGBoost), and provides a final **Streamlit-based web application** for real-time malware detection.

This solution is based on the **DikeDataset** (open-source malware dataset), and implements all steps mentioned in the project proposal:
✓ dataset processing
✓ feature extraction
✓ machine learning
✓ real-time prediction
✓ user-friendly frontend

---

# 📁 Project Structure

```
malicious_file_detector/
│
├── app.py                          # Streamlit web app
│
├── data/
│   ├── __init__.py
│   ├── dataset_overview.py         # Exploratory analysis of raw CSV labels
│   ├── extract_pe_features.py      # Static PE feature extractor
│   ├── prepare_labels.py           # Label cleaning + balancing + thresholding
│   │
│   ├── raw/
│   │   └── DikeDataset/            # Downloaded dataset (not included in repo)
│   │       ├── files/              # Contains PE files (benign + malware)
│   │       ├── labels/             # benign.csv + malware.csv
│   │       └── others/             # Additional metadata from dataset
│   │
│   └── processed/
│       ├── labels_cleaned.csv      # PE-only filtered labels
│       ├── labels_balanced.csv     # After undersampling malware
│       └── pe_features.csv         # Extracted training features
│
├── models/
│   ├── best_model.pkl              # Saved ML model (LogisticRegression)
│   ├── scaler.pkl                  # StandardScaler used during training
│   ├── feature_columns.json        # List of training feature names
│   └── model_meta.json             # Metadata (model name, scaler usage)
│
├── scripts/                        # (optional) Additional utilities
│
├── README.md                       # <-- YOU ARE HERE
└── requirements.txt                # For venv installation
```

---

# 📦 Dataset: DikeDataset (PE Malware)

We use the open-source **DikeDataset**, part of a large malware corpus containing Windows PE files.

### 🔗 Download Link

[https://github.com/DikeDataset/DikeDataset](https://github.com/DikeDataset/DikeDataset)

This repository contains:

```
DikeDataset/
├── files/
│   ├── benign/
│   └── malware/
├── labels/
│   ├── benign.csv
│   └── malware.csv
└── others/
```

### 📌 Important Notes

* The dataset is **large** (multiple GB), so it is **NOT** included in this GitHub repository.
* You must manually download it and place it here:

```
malicious_file_detector/data/raw/DikeDataset/
```

---

# 🧹 Step 1 — Label Preprocessing

We take the raw metadata from:

* `benign.csv`
* `malware.csv`

and perform:

### ✔ Merge CSVs

Combine benign and malware metadata.

### ✔ Filter only PE files

`type == 0` (PE executables).
OLE, DOC, XLS malware is excluded.

### ✔ Convert VirusTotal malice score → binary label

Threshold used:

```
malice > 0.6 → MALICIOUS
malice ≤ 0.6 → BENIGN
```

### ✔ Handle imbalance

After thresholding, classes were:

* **8970 malicious**
* **982 benign**

We apply **undersampling** of the malicious set:

```
Final balanced dataset: 982 benign + 982 malicious
```

### 📝 Output files

```
data/processed/labels_cleaned.csv
data/processed/labels_balanced.csv
```

Generate them using:

```bash
python3 data/prepare_labels.py
```

---

# 🧪 Step 2 — Static PE Feature Extraction

We implemented full Windows PE static analysis in:

```
data/extract_pe_features.py
```

### Features extracted:

#### 📌 1. File-level

* file size
* Shannon entropy
* number of printable strings
* URL count
* Registry string count
* File path count
* IP address count

#### 📌 2. PE Header Features

* Machine
* NumberOfSections
* Characteristics
* SizeOfCode
* SizeOfImage
* Subsystem
* DllCharacteristics

#### 📌 3. Section-based Features

* mean/max/std entropy
* number of executable sections
* number of writable sections
* number of suspicious sections (`.upx`, `aspack`, etc.)

#### 📌 4. Import Table

* number of imported DLLs
* number of functions imported
* per-DLL import flags for:

  * kernel32.dll
  * user32.dll
  * advapi32.dll
  * ws2_32.dll
  * wininet.dll
  * ntdll.dll
  * shell32.dll
  * crypt32.dll

### ✨ Example Feature Output (snippet)

```json
{
  "file_size": 105984,
  "file_entropy": 6.77,
  "num_strings": 410,
  "avg_string_len": 8.3,
  "num_urls": 2,
  "num_exec_sections": 4,
  "num_write_sections": 1,
  "number_of_sections": 7,
  "num_imported_dlls": 6,
  "imports_kernel32": 1,
  "imports_advapi32": 1,
  ...
}
```

### Generate feature dataset:

```bash
python3 data/extract_pe_features.py
```

### Output:

```
data/processed/pe_features.csv
```

---

# 🤖 Step 3 — Machine Learning Training

Training script:

```
models/train_models.py
```

### Models Used (per proposal)

* **RandomForestClassifier**
* **LogisticRegression**
* **XGBoost** (optional, skipped on your environment)

### Important:

We **removed `malice`** from training features because real-time predictions cannot use VirusTotal scores.

### Train/Test split:

```
80% train
20% test
Stratified to preserve balance
```

### 🚀 Final Model Performance (after fixing malice leakage)

#### Random Forest

```
Accuracy: 0.986
Precision: 0.994
Recall: 0.984
F1-score: 0.989
```

#### Logistic Regression (Winner)

```
Accuracy: 0.993
Precision: 0.992
Recall: 0.997
F1-score: 0.994
```

### Saved Artifacts:

```
models/
├── best_model.pkl
├── scaler.pkl
├── feature_columns.json
└── model_meta.json
```

Run training:

```bash
python3 models/train_models.py
```

---

# 🌐 Step 4 — Streamlit Web Application

Main web app:

```
app.py
```

### Features:

✔ Upload any PE file (`.exe`, `.dll`)
✔ Extracts static features
✔ Applies trained ML model
✔ Displays:

* Prediction: **BENIGN or MALICIOUS**
* Probability score
* Feature summary table
* Full raw feature JSON


### Run the app:

```bash
streamlit run app.py
```

Then open:

```
http://localhost:8501
```

Upload any PE file and get an instant classification.

---

# 🧠 System Workflow Diagram

```
               ┌──────────────┐
               │   DikeDataset│
               │ (raw labels +│
               │    PE files) │
               └───────┬──────┘
                       │
                prepare_labels.py
                       │
                       ▼
       labels_balanced.csv (1964 samples)
                       │
               extract_pe_features.py
                       │
                       ▼
            pe_features.csv (feature table)
                       │
               train_models.py
                       │
                       ▼
       best_model.pkl + scaler + metadata
                       │
                       ▼
                    app.py
         (real-time PE file classification)
```


# 📝 Requirements (for venv-based users)

If someone prefers using a Python virtual environment instead of pipx:

```
pip install -r requirements.txt
streamlit run app.py
```

Example `requirements.txt`:

```
streamlit
pandas
numpy
scikit-learn
pefile
joblib
```

---

# 📌 Final Notes

* This project **does not depend on dynamic analysis** or sandboxing.
* Entire detection is based on **static PE metadata & section analysis**.
* Features and training pipeline are explainable and reproducible.
* The Streamlit UI makes the model accessible to non-technical users.