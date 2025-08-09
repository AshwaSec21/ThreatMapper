import streamlit as st
from dotenv import load_dotenv
import os
import pandas as pd
import uuid
import glob
import base64

from llm_config import get_llm_config  # kept for LLM mode
from llm_utils import call_llm, clear_cache_file  # kept for LLM mode
from data_loader import read_threats, read_requirements
from threat_processor import process_threats  # LLM path
from file_paths import get_rmp_fallback_description, get_requirement_format_description

# =========================
# App setup
# =========================
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

# ✅ Background image setup (optional)
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
st.title("🔐 Protype: Threat-to-Requirement Mapping Tool")

# =========================
# Upload UI
# =========================
st.subheader("📁 Upload Files")
col1, col2 = st.columns(2)
with col1:
    req_file = st.file_uploader("📘 Upload Requirements Excel", type=["xlsx"])
with col2:
    threat_file = st.file_uploader("💀 Upload Threats Excel", type=["xlsx"])

# =========================
# Column validation
# =========================
required_req_columns = {"Requirement ID", "Description", "Assets Allocated to"}
required_threat_columns = {"Id", "Title", "Category", "Interaction", "Description"}

# Requirements Validation
if req_file:
    try:
        req_df_preview = pd.read_excel(req_file)
        missing_req = required_req_columns - set(req_df_preview.columns)
        if missing_req:
            st.error(
                "❌ The uploaded Requirements file is missing the following required columns:\n\n"
                + "\n".join(f"- {col}" for col in missing_req)
                + "\n\n✅ Expected columns:\n"
                + "\n".join(f"- {col}" for col in required_req_columns)
            )
            st.stop()
    except Exception as e:
        st.error(f"❌ Failed to read Requirements file: {e}")
        st.stop()

# Threats Validation
if threat_file:
    try:
        threat_df_preview = pd.read_excel(threat_file)
        missing_threat = required_threat_columns - set(threat_df_preview.columns)
        if missing_threat:
            st.error(
                "❌ The uploaded Threats file is missing the following required columns:\n\n"
                + "\n".join(f"- {col}" for col in missing_threat)
                + "\n\n✅ Expected columns:\n"
                + "\n".join(f"- {col}" for col in required_threat_columns)
            )
            st.stop()
    except Exception as e:
        st.error(f"❌ Failed to read Threats file: {e}")
        st.stop()

# Reset pointers after validation, so we can read again later
if req_file:
    req_file.seek(0)
if threat_file:
    threat_file.seek(0)

# =========================
# Advanced Configuration
# =========================
with st.expander("⚙️ Advanced Configuration", expanded=False):
    model_provider = st.selectbox("Choose LLM Provider", ["openai", "mistral", "groq"])
    user_key = st.text_input(f"{model_provider.capitalize()} API Key (Optional, overrides .env)", type="password")

    chunk_size = st.number_input("📦 Chunk size (1–10)", min_value=1, max_value=10, value=5)
    enable_cache = st.checkbox("💾 Enable caching", value=True)
    clear_cache = st.checkbox("🧹 Clear cache before run", value=False)
    print_tokens = st.checkbox("🔢 Print token count", value=True)
    print_logs = st.checkbox("📜 Print LLM responses", value=False)
    asset_list = st.text_area(
        "🧱 Known assets (comma-separated)",
        value="vCenter, Server, Switch, Firewall, NTP, OS ESXi, Workstation, BR Solution",
    )

env_key_map = {
    "openai": "OPENAI_API_KEY",
    "mistral": "OPENROUTER_API_KEY",
    "groq": "GROQ_API_KEY",
}
os.environ["LLM_PROVIDER"] = model_provider
if user_key:
    os.environ[env_key_map[model_provider]] = user_key

# =========================
# Matching Mode (with LLM warning)
# =========================
st.subheader("🧠 Matching Mode")
mode = st.radio(
    "Choose matching mode",
    [
        "LLM (⚠️ May be blocked by organization network/firewall)",
        "Embedding-only (Strict STRIDE)"
    ],
    index=1,  # keep Embedding-only as default; set to 0 if you want LLM default
    horizontal=True,
)

# Show a clear warning if LLM is selected
if mode.startswith("LLM"):
    st.warning(
        "⚠️ LLM mode requires outbound API access to external AI providers. "
        "Your organization’s network/firewall may block these requests, so this mode might not work."
    )

# Defaults so variables always exist
threshold = None
alpha = None
strict_direct_only = None
show_indirect = None

if mode.startswith("Embedding"):
    st.markdown(
        "**Embedding-only Strict Mode**: marks a threat as mitigated only when the "
        "requirement text explicitly contains category-native controls "
        "(e.g., Tampering → digital signatures/checksums)."
    )
    threshold = st.slider("Similarity Threshold (cosine)", 0.40, 0.95, 0.70, 0.01)
    alpha = st.slider("Category Weight α (higher = stronger category focus)", 0.0, 1.0, 0.80, 0.05)
    strict_direct_only = st.checkbox("Direct-only (explicit category-native controls only)", value=True)
    show_indirect = st.checkbox("Allow Indirect (supportive) matches if no Direct found", value=False)

# =========================
# Main runner
# =========================
def run_matching(req_path, threat_path, chunk_size, print_tokens, print_logs, asset_list):
    threats_df = pd.read_excel(threat_path)
    requirements_df = pd.read_excel(req_path)  # <-- ensure DataFrame-like

    rmp_context = get_rmp_fallback_description()
    req_structure_hint = get_requirement_format_description()

    # Embedding-only branch (no LLMs)
    if mode.startswith("Embedding"):
        from embedding_only_processor import process_threats_embedding
        return process_threats_embedding(
            threats_df=threats_df,
            requirements_df=requirements_df,  # pass as DataFrame/list-of-dicts
            asset_list=[a.strip() for a in asset_list.split(",") if a.strip()],
            threshold=threshold,
            alpha=alpha,
            strict_direct_only=strict_direct_only,
            show_indirect=show_indirect,
        )

    # LLM branch (original behavior)
    return process_threats(
        threats_df,
        requirements_df,
        "",  # system_summary not used
        rmp_context,
        req_structure_hint,
        chunk_size=chunk_size,
        print_tokens=print_tokens,
        print_logs=print_logs,
        asset_list=[a.strip() for a in asset_list.split(",") if a.strip()],
    )

# =========================
# Action button
# =========================
st.markdown("---")
if st.button("🚀 Run Matching", type="primary", use_container_width=True):
    if not req_file or not threat_file:
        st.error("Please upload both **Requirements** and **Threats** files.")
        st.stop()

    # Save uploads to temp paths (so loaders can read them)
    req_name = f"uploaded_requirements_{uuid.uuid4().hex}.xlsx"
    thr_name = f"uploaded_threats_{uuid.uuid4().hex}.xlsx"
    with open(req_name, "wb") as f:
        f.write(req_file.getbuffer())
    with open(thr_name, "wb") as f:
        f.write(threat_file.getbuffer())

    try:
        result_df = run_matching(
            req_name,
            thr_name,
            chunk_size,
            print_tokens,
            print_logs,
            asset_list,
        )
    finally:
        # Cleanup temp files
        try:
            os.remove(req_name)
            os.remove(thr_name)
        except Exception as e:
            st.warning(f"⚠️ Failed to clean up uploaded files: {e}")

    st.success("✅ Matching completed!")
    if isinstance(result_df, pd.DataFrame) and not result_df.empty:
        st.dataframe(result_df, use_container_width=True)
        st.download_button(
            "💾 Download Results",
            result_df.to_csv(index=False).encode(),
            "matched_results.csv",
            "text/csv",
            use_container_width=True,
        )
    else:
        st.info("No matches found based on the selected mode and thresholds.")
