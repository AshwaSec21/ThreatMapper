import os
import glob
import uuid
import base64
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from llm_config import get_llm_config
from llm_utils import call_llm, clear_cache_file
from file_paths import get_rmp_fallback_description, get_requirement_format_description
from threat_processor import process_threats  # LLM path (unchanged)

load_dotenv()
st.set_page_config(page_title="Threat Mapper", layout="wide")

# ---------- Utilities ----------
def clean_old_uploaded_files():
    for file in glob.glob("uploaded_*.xlsx"):
        try:
            os.remove(file)
        except Exception as e:
            st.warning(f"⚠️ Couldn't delete old file: {file} ({e})")

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

def _has_assets_col(df: pd.DataFrame) -> bool:
    if df is None:
        return False
    lc = {str(c).strip().lower() for c in df.columns}
    return ("assets allocated to" in lc) or ("assets" in lc) or ("allocated assets" in lc) or ("asset" in lc)

clean_old_uploaded_files()
# set_background("cyber_banner.png")

st.title("🔐 Prototype: Threat-to-Requirement Mapping Tool")

# ---------- Uploads ----------
st.subheader("📁 Upload Files")
c1, c2 = st.columns(2)
with c1:
    req_file = st.file_uploader("📘 Upload Requirements Excel", type=["xlsx"])
with c2:
    threat_file = st.file_uploader("💀 Upload Threats Excel", type=["xlsx"])

REQUIRED_REQ_COLUMNS = {"Requirement ID", "Description"}  # Assets column optional but recommended
REQUIRED_THREAT_COLUMNS = {"Id", "Title", "Category", "Interaction", "Description"}

req_df = None
threat_df = None

# Validate Requirements
if req_file:
    try:
        req_df = pd.read_excel(req_file)
        req_df.columns = [str(c).strip() for c in req_df.columns]
        missing_req = REQUIRED_REQ_COLUMNS - set(req_df.columns)
        if missing_req:
            st.error(
                "❌ The uploaded Requirements file is missing required columns:\n\n"
                + "\n".join(f"- {col}" for col in missing_req)
                + "\n\n✅ Expected at minimum:\n"
                + "\n".join(f"- {col}" for col in REQUIRED_REQ_COLUMNS)
                + "\n\nℹ️ Optional (recommended):\n- Assets Allocated to"
            )
            st.stop()
    except Exception as e:
        st.error(f"❌ Failed to read Requirements file: {e}")
        st.stop()

# Validate Threats
if threat_file:
    try:
        threat_df = pd.read_excel(threat_file)
        threat_df.columns = [str(c).strip() for c in threat_df.columns]
        missing_threat = REQUIRED_THREAT_COLUMNS - set(threat_df.columns)
        if missing_threat:
            st.error(
                "❌ The uploaded Threats file is missing required columns:\n\n"
                + "\n".join(f"- {col}" for col in missing_threat)
                + "\n\n✅ Expected columns:\n"
                + "\n".join(f"- {col}" for col in REQUIRED_THREAT_COLUMNS)
            )
            st.stop()
    except Exception as e:
        st.error(f"❌ Failed to read Threats file: {e}")
        st.stop()

# Reset pointers
if req_file:
    req_file.seek(0)
if threat_file:
    threat_file.seek(0)

# ---------- Advanced Configuration ----------
with st.expander("⚙️ Advanced Configuration", expanded=False):
    mode = st.selectbox(
        "Mode",
        ["Embedding-only (Strict STRIDE)", "LLM (⚠️ May be blocked on corporate network)"],
        help="Embedding-only runs fully offline at runtime. LLM mode may be blocked by your network."
    )

    if mode.startswith("LLM"):
        model_provider = st.selectbox("Choose LLM Provider", ["openai", "mistral", "groq"])
        user_key = st.text_input(f"{model_provider.capitalize()} API Key (Optional, overrides .env)", type="password")
    else:
        model_provider = None
        user_key = None

    chunk_size = st.number_input("📦 Chunk size (1–10)", min_value=1, max_value=10, value=5)
    enable_cache = st.checkbox("💾 Enable caching", value=True)
    clear_cache = st.checkbox("🧹 Clear cache before run", value=False)
    print_tokens = st.checkbox("🔢 Print token count (LLM only)", value=True)
    print_logs = st.checkbox("📜 Print LLM responses (LLM only)", value=False)

    # MANDATORY if Requirements has no assets column
    asset_list_input = st.text_input(
        "Known Asset List (comma-separated)",
        value="",
        placeholder="e.g., vCenter Server, Switch, Firewall, NTP, OS Linux, OS Windows, Workstation",
        help="REQUIRED if your Requirements sheet does NOT contain an 'Assets Allocated to' column."
    )
    asset_list = [a.strip() for a in asset_list_input.split(",") if a.strip()]

# set env for LLM
if model_provider:
    env_key_map = {"openai": "OPENAI_API_KEY", "mistral": "OPENROUTER_API_KEY", "groq": "GROQ_API_KEY"}
    os.environ["LLM_PROVIDER"] = model_provider
    if user_key:
        os.environ[env_key_map[model_provider]] = user_key

# Helpful guidance
if req_df is not None and not _has_assets_col(req_df) and len(asset_list) == 0:
    st.warning(
        "⚠️ Your Requirements file does not include an **'Assets Allocated to'** column.\n\n"
        "Please enter a **Known Asset List** above (comma-separated) to enable asset-based matching."
    )

# Embedding-only controls
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
    cA, cB = st.columns(2)
    with cA:
        st.session_state.threshold = st.slider("Similarity Threshold", 0.0, 1.0, st.session_state.threshold, 0.05,
                                               help="Cosine similarity cutoff. Higher = stricter.")
    with cB:
        st.session_state.alpha = st.slider("Category Weight α", 0.0, 1.0, st.session_state.alpha, 0.05,
                                           help="Weight for STRIDE canonical match vs. threat text. Higher = stricter.")
    cC, cD = st.columns(2)
    with cC:
        st.session_state.strict_direct_only = st.checkbox("Direct-only (strict anchors)", value=st.session_state.strict_direct_only)
    with cD:
        st.session_state.show_indirect = st.checkbox("Allow indirect matches if no direct found", value=st.session_state.show_indirect)

# ---------- Runner helpers ----------
def run_matching_embedding(threats_df: pd.DataFrame, requirements_df: pd.DataFrame, asset_list):
    from embedding_only_processor import process_threats_embedding
    return process_threats_embedding(
        threats_df=threats_df,
        requirements_df=requirements_df,
        asset_list=asset_list,
        threshold=st.session_state.threshold,
        alpha=st.session_state.alpha,
        strict_direct_only=st.session_state.strict_direct_only,
        show_indirect=st.session_state.show_indirect,
    )

def run_matching_llm(threats_path, requirements_path, chunk_size, print_tokens, print_logs, asset_list):
    # LLM path preserved as-is (if you use it)
    rmp_context = get_rmp_fallback_description()
    req_structure_hint = get_requirement_format_description()
    threats_df = pd.read_excel(threats_path)
    return process_threats(
        threats_df,
        requirements_path,
        "",  # system_summary not used
        rmp_context,
        req_structure_hint,
        chunk_size=chunk_size,
        print_tokens=print_tokens,
        print_logs=print_logs,
        asset_list=asset_list,
    )

# ---------- Run button ----------
if st.button("🚀 Run Matching", type="primary", use_container_width=True):
    if not (req_df is not None and threat_df is not None):
        st.warning("Please upload both Requirements and Threats files.")
        st.stop()

    # ENFORCE: if req sheet lacks assets col, user must provide Known Asset List
    if not _has_assets_col(req_df) and len(asset_list) == 0:
        st.error(
            "Cannot run: either add an **'Assets Allocated to'** column to the Requirements file "
            "or enter a **Known Asset List** in the configuration."
        )
        st.stop()

    with st.spinner("🔄 Processing threats and requirements... please wait"):
        if mode.startswith("Embedding"):
            result_df = run_matching_embedding(threat_df, req_df, asset_list)
        else:
            result_df = run_matching_llm(threat_file.name, req_file.name, chunk_size, print_tokens, print_logs, asset_list)

    st.success("✅ Processing complete!")
    st.dataframe(result_df, use_container_width=True)

    csv_name = f"mapped_requirements_{uuid.uuid4().hex[:8]}.csv"
    st.download_button(
        "⬇️ Download CSV",
        data=result_df.to_csv(index=False).encode("utf-8"),
        file_name=csv_name,
        mime="text/csv",
        use_container_width=True
    )
