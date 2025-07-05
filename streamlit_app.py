import streamlit as st
from dotenv import load_dotenv
import os
import pandas as pd
import uuid

from llm_config import get_llm_config
from llm_utils import call_llm, clear_cache_file

# Project-specific imports
from data_loader import read_threats, read_requirements
from threat_processor import process_threats
from file_paths import get_rmp_fallback_description, get_requirement_format_description

load_dotenv()

st.set_page_config(page_title="Threat Mapper", layout="wide")
st.title("🔐 Protype: Threat-to-Requirement Mapping Tool")

# --- File uploads (side by side) ---
st.subheader("📁 Upload Files")
col1, col2 = st.columns(2)
with col1:
    req_file = st.file_uploader("📘 Upload Requirements Excel", type=["xlsx"])
with col2:
    threat_file = st.file_uploader("💀 Upload Threats Excel", type=["xlsx"])

# --- Advanced config in a collapsible expander ---
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
        value="vCenter, Server, Switch, Firewall, NTP, OS ESXi, Workstation, BR Solution"
    )

# --- Apply LLM provider config ---
env_key_map = {
    "openai": "OPENAI_API_KEY",
    "mistral": "OPENROUTER_API_KEY",
    "groq": "GROQ_API_KEY"
}
os.environ["LLM_PROVIDER"] = model_provider
if user_key:
    os.environ[env_key_map[model_provider]] = user_key

# --- Main logic ---
def run_matching(req_path, threat_path, chunk_size, print_tokens, print_logs, asset_list):
    threats_df = read_threats(threat_path)
    requirements = read_requirements(req_path)
    rmp_context = get_rmp_fallback_description()
    req_structure_hint = get_requirement_format_description()

    return process_threats(
        threats_df,
        requirements,
        "",  # system_summary not used
        rmp_context,
        req_structure_hint,
        chunk_size=chunk_size,
        print_tokens=print_tokens,
        print_logs=print_logs,
        asset_list=[a.strip() for a in asset_list.split(",") if a.strip()]
    )

# --- Execution ---
if st.button("🚀 Run Matching") and req_file and threat_file:
    st.write("🔍 Processing...")

    if clear_cache:
        clear_cache_file()
        st.info("✅ Cache cleared.")

    # Save uploaded files
    req_path = f"uploaded_{uuid.uuid4().hex}_requirements.xlsx"
    threat_path = f"uploaded_{uuid.uuid4().hex}_threats.xlsx"
    with open(req_path, "wb") as f:
        f.write(req_file.read())
    with open(threat_path, "wb") as f:
        f.write(threat_file.read())

    # Run
    result_df = run_matching(req_path, threat_path, chunk_size, print_tokens, print_logs, asset_list)

    # Cleanup
    try:
        os.remove(req_path)
        os.remove(threat_path)
    except Exception as e:
        st.warning(f"⚠️ Failed to clean up uploaded files: {e}")

    st.success("✅ Matching completed!")
    st.dataframe(result_df)
    st.download_button("💾 Download Results", result_df.to_csv(index=False).encode(), "matched_results.csv", "text/csv")
