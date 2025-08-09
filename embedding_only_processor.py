import os
import re
import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer, util

from strict_stride_rules import STRICT_RULES
from llm_threat_mapper import get_threat_assets  # updated to also scan Description

# ================================
# Force fully offline local model
# ================================
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

LOCAL_MODEL_PATH = os.path.join("models", "all-MiniLM-L6-v2")

if not os.path.isdir(LOCAL_MODEL_PATH):
    raise RuntimeError(
        f"SentenceTransformer model not found at '{LOCAL_MODEL_PATH}'.\n"
        f"Place the downloaded model folder there (commit to Git) and try again.\n"
        f"Tip (run at home):\n"
        f'  python -c "from sentence_transformers import SentenceTransformer; '
        f"m=SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2'); "
        f'm.save(r\'{LOCAL_MODEL_PATH}\')"'
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
    """Accept DataFrame or list[dict]; raise otherwise."""
    if isinstance(obj, pd.DataFrame):
        return obj
    if isinstance(obj, list) and (len(obj) == 0 or isinstance(obj[0], dict)):
        return pd.DataFrame(obj)
    raise TypeError(f"requirements_df must be a pandas DataFrame or list[dict], got {type(obj)}")

def _clean_header(s: str) -> str:
    # remove NBSPs, trim, collapse spaces
    s = str(s).replace("\u00a0", " ").strip()
    s = re.sub(r"\s+", " ", s)
    return s

def _normalize_req_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Map common variants to canonical names EXACTLY:
      - 'Requirement ID'
      - 'Description'
      - 'Assets Allocated to'
    """
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
    """
    Filter DataFrame rows where 'Assets Allocated to' (or similar) contains any threat asset (case-insensitive).
    If the sheet has no assets column, return df unchanged.
    """
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
    """
    Rank df by blended similarity:
      score = alpha * max(category_canonical_similarity) + (1 - alpha) * threat_similarity
    Only rows with score >= threshold are returned.
    """
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
        sim_can = util.cos_sim(req_embs, can_embs).cpu().numpy()  # (N, K)
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

def process_threats_embedding(
    threats_df: pd.DataFrame,
    requirements_df,  # accept DataFrame or list[dict]
    asset_list=None,
    threshold: float = 0.70,
    alpha: float = 0.80,
    strict_direct_only: bool = True,
    show_indirect: bool = False,
) -> pd.DataFrame:
    """
    LLM-free pipeline:
      0) Detect assets from Interaction; fallback to Description if needed
      1) If assets not detected BUT asset scoping is expected -> emit a short reason and skip misleading matches
      2) Otherwise, asset filter (on DataFrame) where possible
      3) Rule-based Direct/Indirect/None using STRICT_RULES
      4) Rank Directs (and optionally Indirects) by embeddings
    """
    # Normalize → DataFrame → normalize headers → validate
    requirements_df = _to_dataframe(requirements_df)
    requirements_df = _normalize_req_columns(requirements_df)
    _validate_requirements_df(requirements_df)

    rows = []
    for _, threat in threats_df.iterrows():
        # 0) Detect assets (Interaction → Description fallback)
        threat_assets = get_threat_assets(
            threat.get("Interaction", ""),
            asset_list or [],
            description=threat.get("Description", "")
        )

        # Determine if we *expect* assets to scope: either we have a UI asset list, or reqs have an assets column
        expect_asset_scope = (asset_list and len(asset_list) > 0) or _req_has_assets_col(requirements_df)

        # 1) If we expect asset scoping but couldn't detect any assets → emit reason and continue
        if expect_asset_scope and len(threat_assets) == 0:
            rows.append({
                "Threat ID": threat.get("Id"),
                "Threat Title": threat.get("Title"),
                "Category": threat.get("Category"),
                "Threat Interaction": threat.get("Interaction", ""),
                "Threat Description": threat.get("Description", ""),
                "Mitigation Verdict": "No mapping (asset not detected)",
                "Matched Requirement ID": "",
                "Matched Requirement Description": "",
                "Similarity Score": "",
                "Evidence": "",
                "Reason": "No asset found in Interaction/Description",
            })
            continue  # do not try to match blindly (prevents misleading results)

        # 2) Asset filter where possible
        filtered = _filter_requirements_by_assets_df(requirements_df, threat_assets) if threat_assets else requirements_df
        filtered = _normalize_req_columns(filtered)

        # 3) Rule classify (Direct/Indirect/None)
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

        # 4) Ranking
        direct_df = filtered[filtered["Verdict"] == "Direct"]
        if len(direct_df) > 0:
            ranked = _rank_by_stride(direct_df, threat, threshold=0.0, alpha=alpha)  # keep all directs; score only for sort
        else:
            ranked = pd.DataFrame(columns=filtered.columns.tolist() + ["SimilarityScore", "MatchBasis"])

        if len(ranked) == 0 and show_indirect:
            indirect_df = filtered[filtered["Verdict"] == "Indirect"]
            ranked = _rank_by_stride(indirect_df, threat, threshold=threshold, alpha=alpha)

        if len(ranked) == 0:
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
                "Reason": "No requirement contained mandatory direct anchors"
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
