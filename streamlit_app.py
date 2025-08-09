import streamlit as st
from dotenv import load_dotenv
import os
import pandas as pd
import uuid
import glob
import base64

from llm_config import get_llm_config
from llm_utils import call_llm, clear_cache_file
from data_loader import read_threats, read_requirements
from threat_processor import process_threats
from file_paths import get_rmp_fallback_description, get_requirement_format_description

load_dotenv()
st.set_page_config(page_title="Threat Mapper", layout="wide")

# ✅ Auto-delete old uploaded files when app starts
def clean_old_uploaded_files():
    for file in glob.glob("uploaded_*.xlsx"):
        try:
            os.remove(file)
        except Exception as e:
            st.warning(f"⚠️ Couldn't delete old file: {file} ({e})")

clean_old_uploaded_files()

# ✅ Background image setup (kept, but disabled by default)
def set_background(image_path):
    with open(image_path, "rb") as img_file:
        encoded = base64.b64encode(img_file.read()).decode()
    st.markdown(
        f"""
        <style>
        .stApp {{
            background-image: url("data:image/png;base64,{encoded}");
            background-size: cover;
            background-repeat: no-repeat;
            background-attachment: fixed;
            background-position: center;
        }}
        .stApp::before {{
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(255, 255, 255, 0.9);
            z-index: -1;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

# set_background("cyber_banner.png")
st.title("🔐 Prototype: Threat-to-Requirement Mapping Tool")

# --- Upload UI
st.subheader("📁 Upload Files")
col1, col2 = st.columns(2)
with col1:
    req_file = st.file_uploader("📘 Upload Requirements Excel", type=["xlsx"])
with col2:
    threat_file = st.file_uploader("💀 Upload Threats Excel", type=["xlsx"])

# --- Column validation expectations
REQUIRED_REQ_COLUMNS = {"Requirement ID", "Description"}           # "Assets Allocated to" is optional but recommended
REQUIRED_THREAT_COLUMNS = {"Id", "Title", "Category", "Interaction", "Description"}

# Read files (raw) for early column checks
req_df = None
threat_df = None

if req_file:
    try:
        req_df = pd.read_excel(req_file)
        req_df.columns = [str(c).strip() for c in req_df.columns]
        missing_req = REQUIRED_REQ_COLUMNS - set(req_df.columns)
        if missing_req:
            st.error("❌ The uploaded Requirements file is missing required columns:\n\n"
                     + "\n".join(f"- {col}" for col in missing_req)
                     + "\n\n✅ Expected at minimum:\n"
                     + "\n".join(f"- {col}" for col in REQUIRED_REQ_COLUMNS)
                     + "\n\nℹ️ Optional (recommended):\n- Assets Allocated to")
            st.stop()
    except Exception as e:
        st.error(f"❌ Failed to read Requirements file: {e}")
        st.stop()

if threat_file:
    try:
        threat_df = pd.read_excel(threat_file)
        threat_df.columns = [str(c).strip() for c in threat_df.columns]
        missing_threat = REQUIRED_THREAT_COLUMNS - set(threat_df.columns)
        if missing_threat:
            st.error("❌ The uploaded Threats file is missing required columns:\n\n"
                     + "\n".join(f"- {col}" for col in missing_threat)
                     + "\n\n✅ Expected columns:\n"
                     + "\n".join(f"- {col}" for col in REQUIRED_THREAT_COLUMNS))
            st.stop()
    except Exception as e:
        st.error(f"❌ Failed to read Threats file: {e}")
        st.stop()

# Reset file pointers for re-reads downstream
if req_file:
    req_file.seek(0)
if threat_file:
    threat_file.seek(0)

# --- Advanced Configuration
with st.expander("⚙️ Advanced Configuration", expanded=False):
    # Mode selector
    mode = st.selectbox(
        "Mode",
        ["Embedding-only (Strict STRIDE)", "LLM (⚠️ May be blocked on corporate network)"],
        help="Embedding-only runs fully offline at runtime. LLM mode may be blocked by your network."
    )

    # LLM provider details (only visible when LLM selected)
    if mode.startswith("LLM"):
        model_provider = st.selectbox("Choose LLM Provider", ["openai", "mistral", "groq"])
        user_key = st.text_input(f"{model_provider.capitalize()} API Key (Optional, overrides .env)", type="password")
    else:
        model_provider = None
        user_key = None

    # Common options
    chunk_size = st.number_input("📦 Chunk size (1–10)", min_value=1, max_value=10, value=5)
    enable_cache = st.checkbox("💾 Enable caching", value=True)
    clear_cache = st.checkbox("🧹 Clear cache before run", value=False)
    print_tokens = st.checkbox("🔢 Print token count (LLM only)", value=True)
    print_logs = st.checkbox("📜 Print LLM responses (LLM only)", value=False)

    # NEW: Known assets input (comma-separated)
    asset_list_input = st.text_input(
        "Known Asset List (comma-separated)",
        value="",
        placeholder="e.g., vCenter Server, Switch, Firewall, NTP, OS Linux, OS Windows, Workstation",
        help="If your Requirements sheet does NOT contain 'Assets Allocated to', provide known assets here to enable asset-based filtering."
    )
    asset_list = [a.strip() for a in asset_list_input.split(",") if a.strip()]

# Set env for LLM mode (if chosen)
if model_provider:
    env_key_map = {"openai": "OPENAI_API_KEY", "mistral": "OPENROUTER_API_KEY", "groq": "GROQ_API_KEY"}
    os.environ["LLM_PROVIDER"] = model_provider
    if user_key:
        os.environ[env_key_map[model_provider]] = user_key

# Helper: quick check if req_df has an assets column
def has_assets_col(df: pd.DataFrame) -> bool:
    lc = {str(c).strip().lower() for c in df.columns}
    return ("assets allocated to" in lc) or ("assets" in lc) or ("allocated assets" in lc) or ("asset" in lc)

# Proactive guidance if user forgot assets entirely
if req_df is not None and not has_assets_col(req_df) and len(asset_list) == 0:
    st.info(
        "ℹ️ Asset-based filtering is disabled: your Requirements file does not include 'Assets Allocated to' "
        "and the 'Known Asset List' is empty. The tool will match across ALL requirements for each threat."
    )

# --- Main runner
def run_matching(req_path, threat_path, chunk_size, print_tokens, print_logs, asset_list):
    # For the embedding path we’ll read DataFrames directly
    threats_df = pd.read_excel(threat_path)
    requirements_df = pd.read_excel(req_path)

    rmp_context = get_rmp_fallback_description()
    req_structure_hint = get_requirement_format_description()

    if mode.startswith("Embedding"):
        from embedding_only_processor import process_threats_embedding
        return process_threats_embedding(
            threats_df=threats_df,
            requirements_df=requirements_df,
            asset_list=asset_list,   # <= pass UI-provided list (may be empty)
            threshold=st.session_state.get("threshold", 0.7),
            alpha=st.session_state.get("alpha", 0.8),
            strict_direct_only=st.session_state.get("strict_direct_only", True),
            show_indirect=st.session_state.get("show_indirect", False),
        )

    # Fallback: LLM path (unchanged)
    return process_threats(
        threats_df,
        read_requirements(req_path),
        "",  # system_summary not used
        rmp_context,
        req_structure_hint,
        chunk_size=chunk_size,
        print_tokens=print_tokens,
        print_logs=print_logs,
        asset_list=asset_list,  # still pass; LLM path may use it
    )

# --- Embedding-only specific controls
if 'alpha' not in st.session_state:
    st.session_state.alpha = 0.80
if 'threshold' not in st.session_state:
    st.session_state.threshold = 0.70
if 'strict_direct_only' not in st.session_state:
    st.session_state.strict_direct_only = True
if 'show_indirect' not in st.session_state:
    st.session_state.show_indirect = False

if mode.startswith("Embedding"):
    st.subheader("🧠 Embedding-only Controls")
    c1, c2 = st.columns(2)
    with c1:
        st.session_state.threshold = st.slider("Similarity Threshold", 0.0, 1.0, st.session_state.threshold, 0.05,
                                               help="Cosine similarity cutoff. Higher = stricter.")
    with c2:
        st.session_state.alpha = st.slider("Category Weight α", 0.0, 1.0, st.session_state.alpha, 0.05,
                                           help="Weight for STRIDE canonical match vs. threat text. Higher = stricter.")
    c3, c4 = st.columns(2)
    with c3:
        st.session_state.strict_direct_only = st.checkbox("Direct-only (strict anchors)", value=st.session_state.strict_direct_only)
    with c4:
        st.session_state.show_indirect = st.checkbox("Allow indirect matches if no direct found", value=st.session_state.show_indirect)

# --- Run button
if st.button("🚀 Run Matching", type="primary", use_container_width=True):
    if not (req_file and threat_file):
        st.warning("Please upload both Requirements and Threats files.")
    else:
        with st.spinner("🔄 Processing threats and requirements... please wait"):
            result_df = run_matching(
                req_file.name,
                threat_file.name,
                chunk_size,
                print_tokens,
                print_logs,
                asset_list,
            )

        st.success("✅ Processing complete!")
        st.dataframe(result_df, use_container_width=True)

        # Download
        csv_name = f"mapped_requirements_{uuid.uuid4().hex[:8]}.csv"
        st.download_button(
            "⬇️ Download CSV",
            data=result_df.to_csv(index=False).encode("utf-8"),
            file_name=csv_name,
            mime="text/csv",
            use_container_width=True
        )
