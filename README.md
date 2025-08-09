# ThreatMapper

ThreatMapper is a **Streamlit-based cybersecurity tool** that maps threats (from the Microsoft Threat Modeling Tool) to existing cybersecurity requirements using:
- **Asset-based filtering**
- **Rule-based STRIDE matching**
- **Semantic similarity via sentence-transformers embeddings**
- **(Optional) LLM-based reasoning for more accurate mappings**

The tool can run entirely **offline** using a locally downloaded embedding model.

---

## Features
- **Asset filtering**: Match requirements only to threats targeting the same assets.
- **Strict STRIDE rules**: Direct / Indirect / No match classification.
- **Semantic search**: Uses `all-MiniLM-L6-v2` embeddings for fuzzy matching.
- **Streamlit UI**: Upload threat and requirement files, configure settings, and export results.
- **Offline mode**: Works without internet if the model is downloaded locally.

---

## Project Structure
```
.
├── embedding_only_processor.py   # Offline embedding-based matching
├── llm_matcher.py                 # LLM-based matching logic
├── llm_threat_mapper.py           # Common helper functions (e.g., asset extraction)
├── streamlit_app.py               # Streamlit user interface
├── strict_stride_rules.py         # STRIDE matching rules
├── threat_processor.py            # Orchestrates the processing pipeline
├── requirements.txt               # Python dependencies
└── models/                        # Local embedding models (optional, for offline)
```

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/ThreatMapper.git
cd ThreatMapper
```

### 2. Create a virtual environment (recommended)
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. (Optional) Download model for offline mode
```bash
python -c "from sentence_transformers import SentenceTransformer; m = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2'); m.save('models/all-MiniLM-L6-v2')"
```

---

## Usage

### 1. Run Streamlit App
```bash
streamlit run streamlit_app.py
```

### 2. In the browser UI:
- Upload:
  - **Threats File**: Export from Microsoft Threat Modeling Tool (Excel format)
  - **Requirements File**: Cybersecurity requirements (Excel format)
- Configure:
  - Model type (LLM or embedding-only)
  - Chunk size (for large files)
  - Asset list
  - Similarity threshold
- Click **Run Mapping** to see results
- Export the results to CSV

---

## Requirements File Format
Your requirements file **must** contain these columns:
- `Requirement ID`
- `Description`
- `Assets Allocated to` *(optional but improves accuracy)*

---

## Threats File Format
Threat file should be exported from **Microsoft Threat Modeling Tool** with:
- `Id`
- `Title`
- `Description`
- `Interaction`
- `Category` *(STRIDE type)*

---

## Running in Offline Mode
1. Download the embedding model as shown in the **Installation** section.
2. Keep it in `models/all-MiniLM-L6-v2`.
3. The app will automatically load it without internet access.

---

## License
MIT License — free to use and modify.

---

## Author
Developed by **Ashwath Kumar** — AI-assisted threat-to-requirement mapping tool for cybersecurity compliance.
