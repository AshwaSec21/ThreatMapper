import os
import re
import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer, util

from strict_stride_rules import STRICT_RULES
from llm_threat_mapper import get_threat_assets

# Offline-only model load from local folder
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

LOCAL_MODEL_PATH = os.path.join("models", "all-MiniLM-L6-v2")
if not os.path.isdir(LOCAL_MODEL_PATH):
    raise RuntimeError(
        f"SentenceTransformer model not found at '{LOCAL_MODEL_PATH}'.\n"
        f"Place the downloaded model folder there and try again."
    )
model = SentenceTransformer(LOCAL_MODEL_PATH)

def _embed(texts):
    return model.encode(texts, convert_to_tensor=True, normalize_embeddings=True)

def _find_hits(text, patterns):
    found = []
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            found.append(m.group(0))
    return found

def _classify_direct(text, category):
    rule = STRICT_RULES.get((category or "").strip(), {})
    must = rule.get("must_any", [])
    forb = rule.get("forbid_any", [])
    must_hits = _find_hits(text, must) if must else []
    forb_hits = _find_hits(text, forb) if forb else []

    if must and not must_hits:
        return ("None", [], [f"No direct anchor for {category}"])
    if forb and forb_hits and not must_hits:
        return ("Indirect", [], [f"Forbidden-only terms: {', '.join(forb_hits)}"])
    if must_hits:
        return ("Direct", must_hits, [])
    return ("None", [], [])

def _to_dataframe(obj):
    if isinstance(obj, pd.DataFrame):
        return obj
    if isinstance(obj, list) and (len(obj) == 0 or isinstance(obj[0], dict)):
        return pd.DataFrame(obj)
    raise TypeError(f"requirements_df must be a pandas DataFrame or list[dict], got {type(obj)}")

def _clean_header(s: str) -> str:
    s = str(s).replace("\u00a0", " ").strip()
    s = re.sub(r"\s+", " ", s)
    return s

def _normalize_req_columns(df: pd.DataFrame) -> pd.DataFrame:
    if not isinstance(df, pd.DataFrame):
        return df
    df.columns = [_clean_header(c) for c in df.columns]
    current = {c.lower(): c for c in df.columns}
    alias_map = {
        "requirement id": "Requirement ID",
        "req id": "Requirement ID",
        "requirement_id": "Requirement ID",
        "requirementid": "Requirement ID",
        "id": "Requirement ID",
        "description": "Description",
        "details": "Description",
        "requirement description": "Description",
        "desc": "Description",
        "assets allocated to": "Assets Allocated to",
        "assets": "Assets Allocated to",
        "asset": "Assets Allocated to",
        "allocated assets": "Assets Allocated to",
    }
    rename_map = {}
    for low, orig in current.items():
        if low in alias_map:
            rename_map[orig] = alias_map[low]
    if rename_map:
        df = df.rename(columns=rename_map)
    return df

def _validate_requirements_df(df: pd.DataFrame):
    if not isinstance(df, pd.DataFrame):
        raise TypeError(f"requirements_df must be a pandas DataFrame, got {type(df)}")
    required_columns = {"Requirement ID", "Description"}
    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(
            f"requirements_df missing required columns: {missing}. "
            f"Available: {list(df.columns)}"
        )

def _build_req_embs(df: pd.DataFrame):
    _validate_requirements_df(df)
    texts = (df["Requirement ID"].astype(str) + " :: " + df["Description"].astype(str)).tolist()
    return _embed(texts)

def _filter_requirements_by_assets_df(df: pd.DataFrame, threat_assets):
    if not isinstance(df, pd.DataFrame) or not threat_assets:
        return df
    col_map = {c.lower(): c for c in df.columns}
    assets_col = None
    for key in ("assets allocated to", "assets", "asset", "allocated assets"):
        if key in col_map:
            assets_col = col_map[key]
            break
    if assets_col is None:
        return df
    aset = [a.strip().lower() for a in threat_assets if a and isinstance(a, str)]
    if not aset:
        return df
    def _match(cell):
        if pd.isna(cell):
            return False
        txt = str(cell).lower()
        return any(a in txt for a in aset)
    return df[df[assets_col].apply(_match)]

def _rank_by_stride(df: pd.DataFrame, threat_row, threshold=0.70, alpha=0.80):
    _validate_requirements_df(df)
    category = (threat_row.get("Category") or "").strip()
    title = threat_row.get("Title", "")
    desc = threat_row.get("Description", "")
    ttext = f"{title}. {desc}".strip()

    must_any = STRICT_RULES.get(category, {}).get("must_any", [])
    canonical = [re.sub(r"\\b|\\(|\\)|\\?|\\+|\\*|\\[|\\]|\\||\\^|\\$|-", " ", p) for p in must_any]
    canonical = [re.sub(r"\s+", " ", c).strip() for c in canonical if c]

    if len(df) == 0:
        return df.assign(SimilarityScore=pd.Series(dtype=float), MatchBasis=pd.Series(dtype=str))

    req_embs = _build_req_embs(df)

    if canonical:
        can_embs = _embed(canonical)
        sim_can = util.cos_sim(req_embs, can_embs).cpu().numpy()
        max_can = sim_can.max(axis=1)
    else:
        max_can = np.zeros((len(df),), dtype=np.float32)

    if ttext:
        thr_emb = _embed([ttext])[0]
        sim_thr = util.cos_sim(req_embs, thr_emb).cpu().numpy().reshape(-1)
    else:
        sim_thr = np.zeros((len(df),), dtype=np.float32)

    score = alpha * max_can + (1 - alpha) * sim_thr if ttext else max_can

    out = df.copy()
    out["SimilarityScore"] = np.round(score, 3)
    out["MatchBasis"] = np.where(max_can >= sim_thr, "CategoryCanonical", "ThreatContext")
    out = out[out["SimilarityScore"] >= threshold]
    out = out.sort_values("SimilarityScore", ascending=False)
    return out

def _req_has_assets_col(df: pd.DataFrame) -> bool:
    lc = {c.lower() for c in df.columns}
    return ("assets allocated to" in lc) or ("assets" in lc) or ("allocated assets" in lc) or ("asset" in lc)

# ---------------- Main pipeline ----------------
def process_threats_embedding(
    threats_df: pd.DataFrame,
    requirements_df,
    asset_list=None,
    threshold: float = 0.70,
    alpha: float = 0.80,
    strict_direct_only: bool = True,
    show_indirect: bool = False,
) -> pd.DataFrame:
    """
    Enforced policy:
      - If Requirements sheet lacks 'Assets Allocated to', user MUST provide Known Asset List (asset_list).
      - No default asset list is used.
      - Asset detection per threat uses Interaction → Description fallback.
    """
    requirements_df = _to_dataframe(requirements_df)
    requirements_df = _normalize_req_columns(requirements_df)
    _validate_requirements_df(requirements_df)

    has_req_assets = _req_has_assets_col(requirements_df)
    assets_catalog = asset_list or []

    if not has_req_assets and len(assets_catalog) == 0:
        rows = []
        for _, threat in threats_df.iterrows():
            rows.append({
                "Threat ID": threat.get("Id"),
                "Threat Title": threat.get("Title"),
                "Category": threat.get("Category"),
                "Threat Interaction": threat.get("Interaction", ""),
                "Threat Description": threat.get("Description", ""),
                "Mitigation Verdict": "No mapping (asset catalog not provided)",
                "Matched Requirement ID": "",
                "Matched Requirement Description": "",
                "Similarity Score": "",
                "Evidence": "",
                "Reason": "Requirements sheet lacks 'Assets Allocated to' and no Known Asset List was provided"
            })
        return pd.DataFrame(rows)

    rows = []
    for _, threat in threats_df.iterrows():
        threat_assets = get_threat_assets(
            threat.get("Interaction", ""),
            assets_catalog,
            description=threat.get("Description", "")
        )

        if len(threat_assets) > 0 and has_req_assets:
            filtered = _filter_requirements_by_assets_df(requirements_df, threat_assets)
        else:
            filtered = requirements_df

        verdict_records = []
        for _, r in filtered.iterrows():
            text = f"{r.get('Requirement ID','')} :: {r.get('Description','')}"
            verdict, evidence, reason = _classify_direct(text, (threat.get('Category') or '').strip())
            verdict_records.append((r['Requirement ID'], verdict, evidence, reason))

        filtered = filtered.copy()
        vmap = {rid: (v, e, reason) for (rid, v, e, reason) in verdict_records}
        filtered["Verdict"] = filtered["Requirement ID"].map(lambda x: vmap.get(x, ("None", [], []))[0])
        filtered["Evidence"] = filtered["Requirement ID"].map(lambda x: ", ".join(vmap.get(x, ("None", [], []))[1]))
        filtered["Reason"] = filtered["Requirement ID"].map(lambda x: "; ".join(vmap.get(x, ("None", [], []))[2]))

        direct_df = filtered[filtered["Verdict"] == "Direct"]
        if len(direct_df) > 0:
            ranked = _rank_by_stride(direct_df, threat, threshold=0.0, alpha=alpha)
        else:
            ranked = pd.DataFrame(columns=filtered.columns.tolist() + ["SimilarityScore", "MatchBasis"])

        if len(ranked) == 0 and show_indirect:
            indirect_df = filtered[filtered["Verdict"] == "Indirect"]
            ranked = _rank_by_stride(indirect_df, threat, threshold=threshold, alpha=alpha)

        if len(ranked) == 0:
            reason_txt = "No requirement contained mandatory direct anchors"
            if len(assets_catalog) > 0 and len(threat_assets) == 0:
                reason_txt = "No asset found in Interaction/Description"
            rows.append({
                "Threat ID": threat.get("Id"),
                "Threat Title": threat.get("Title"),
                "Category": threat.get("Category"),
                "Threat Interaction": threat.get("Interaction", ""),
                "Threat Description": threat.get("Description", ""),
                "Mitigation Verdict": "No direct mitigation found",
                "Matched Requirement ID": "",
                "Matched Requirement Description": "",
                "Similarity Score": "",
                "Evidence": "",
                "Reason": reason_txt,
            })
        else:
            for _, rr in ranked.iterrows():
                rows.append({
                    "Threat ID": threat.get("Id"),
                    "Threat Title": threat.get("Title"),
                    "Category": threat.get("Category"),
                    "Threat Interaction": threat.get("Interaction", ""),
                    "Threat Description": threat.get("Description", ""),
                    "Mitigation Verdict": rr.get("Verdict", "Direct"),
                    "Matched Requirement ID": rr.get("Requirement ID", ""),
                    "Matched Requirement Description": rr.get("Description", ""),
                    "Similarity Score": rr.get("SimilarityScore", ""),
                    "Evidence": rr.get("Evidence", ""),
                    "Reason": rr.get("Reason", ""),
                })

    return pd.DataFrame(rows)
