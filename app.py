import json
import tempfile
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from data.extract_pe_features import extract_pe_features  # reuse our extractor


# ---------- PATHS ----------
PROJECT_ROOT = Path(__file__).resolve().parent
MODELS_DIR = PROJECT_ROOT / "models"


@st.cache_resource
def load_artifacts():
    """Load trained model, scaler, feature list, and metadata."""
    model_path = MODELS_DIR / "best_model.pkl"
    scaler_path = MODELS_DIR / "scaler.pkl"
    feat_path = MODELS_DIR / "feature_columns.json"
    meta_path = MODELS_DIR / "model_meta.json"

    if not model_path.exists():
        st.error(f"Model file not found: {model_path}")
        st.stop()
    if not scaler_path.exists():
        st.error(f"Scaler file not found: {scaler_path}")
        st.stop()
    if not feat_path.exists():
        st.error(f"Feature columns file not found: {feat_path}")
        st.stop()
    if not meta_path.exists():
        st.error(f"Model metadata file not found: {meta_path}")
        st.stop()

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    feature_columns = json.loads(feat_path.read_text())
    meta = json.loads(meta_path.read_text())

    return model, scaler, feature_columns, meta


def build_feature_vector(file_path: Path, feature_columns):
    """Extract PE features from a file and align them with training columns."""
    raw_feats = extract_pe_features(file_path)

    df = pd.DataFrame([raw_feats])
    df = df.reindex(columns=feature_columns, fill_value=0)

    return df, raw_feats


def predict_file(file_path: Path):
    """Run end-to-end prediction on a file."""
    model, scaler, feature_columns, meta = load_artifacts()
    use_scaler = meta.get("use_scaler", False)

    X_df, raw_feats = build_feature_vector(file_path, feature_columns)

    if use_scaler:
        X_input = scaler.transform(X_df)
    else:
        X_input = X_df.values

    pred = model.predict(X_input)[0]

    prob_malicious = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X_input)[0]
        prob_malicious = float(proba[1])  # label 1 = malicious

    return int(pred), prob_malicious, raw_feats


# ---------- STREAMLIT UI ----------
st.set_page_config(page_title="Malicious PE Detector", layout="wide")

st.title("🔍 Malicious File Detector (Static PE + ML)")
st.write(
    "Upload a **Windows PE executable** (e.g., `.exe`, `.dll`) and the model will "
    "analyze its static features and predict whether it is **benign** or **malicious**.\n\n"
    "This uses the model you trained on the DikeDataset with static PE features."
)

uploaded_file = st.file_uploader(
    "Upload a file to analyze",
    type=None,
    help="PE files (EXE/DLL) are supported. Other file types may fail to parse."
)

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = Path(tmp.name)

    st.info(f"File saved to temporary path: `{tmp_path}`")

    try:
        with st.spinner("Extracting static features and running model..."):
            pred_label, prob_mal, raw_feats = predict_file(tmp_path)

        label_text = "MALICIOUS" if pred_label == 1 else "BENIGN"
        if prob_mal is not None:
            conf_text = f"{prob_mal * 100:.2f}%"
        else:
            conf_text = "N/A"

        if pred_label == 1:
            st.error(f"⚠️ Prediction: **{label_text}** (probability malicious: {conf_text})")
        else:
            st.success(f"✅ Prediction: **{label_text}** (probability malicious: {conf_text})")

        # Show key features
        st.subheader("Key Extracted Features")
        key_fields = [
            "file_size",
            "file_entropy",
            "num_strings",
            "avg_string_len",
            "num_urls",
            "num_registry_strings",
            "num_filepath_strings",
            "num_ip_strings",
            "number_of_sections",
            "mean_section_entropy",
            "max_section_entropy",
            "num_exec_sections",
            "num_write_sections",
            "num_imported_dlls",
            "num_imported_functions",
        ]

        rows = []
        for k in key_fields:
            if k in raw_feats:
                rows.append({"Feature": k, "Value": raw_feats[k]})

        if rows:
            feat_df = pd.DataFrame(rows)
            st.table(feat_df)
        else:
            st.write("No key features available to display.")

        with st.expander("Show all extracted features (raw JSON)"):
            st.json(raw_feats)

    except Exception as e:
        st.error(f"Failed to analyze file: {e}")
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
else:
    st.info("👆 Upload a file above to start analysis.")
