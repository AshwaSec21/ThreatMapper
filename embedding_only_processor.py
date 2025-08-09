
import numpy as np
import pandas as pd
import os
import re
from sentence_transformers import SentenceTransformer, util
from strict_stride_rules import STRICT_RULES
from llm_threat_mapper import get_threat_assets, filter_requirements_by_assets

MODEL_CANDIDATES = [
    "models/all-MiniLM-L6-v2",   # preferred local path
    "all-MiniLM-L6-v2",          # fallback to hub (if allowed)
]

def _load_model():
    for path in MODEL_CANDIDATES:
        try:
            return SentenceTransformer(path)
        except Exception:
            continue
    # last resort
    return SentenceTransformer("all-MiniLM-L6-v2")

_EMB = _load_model()

def _embed(texts):
    return _EMB.encode(texts, convert_to_tensor=True, normalize_embeddings=True)

def _find_hits(text, patterns):
    found = []
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            found.append(m.group(0))
    return found

def _classify_direct(text, category):
    rule = STRICT_RULES.get(category, {})
    must = rule.get("must_any", [])
    forb = rule.get("forbid_any", [])
    must_hits = _find_hits(text, must) if must else []
    forb_hits = _find_hits(text, forb) if forb else []

    if must and not must_hits:
        return ("None", [], ["No direct anchor for "+category])
    if forb and forb_hits and not must_hits:
        return ("Indirect", [], [f"Forbidden-only terms: {', '.join(forb_hits)}"])
    if must_hits:
        return ("Direct", must_hits, [])
    return ("None", [], [])

def _build_req_embs(df):
    texts = (df["Requirement ID"].astype(str) + " :: " + df["Description"].astype(str)).tolist()
    return _embed(texts)

def _rank_by_stride(df, req_embs, threat_row, threshold=0.70, alpha=0.80):
    # Canonical phrases come from strict rule 'must_any' stripped to plain hints
    category = (threat_row.get("Category") or "").strip()
    title = threat_row.get("Title",""); desc = threat_row.get("Description","")
    ttext = f"{title}. {desc}".strip()

    # derive canonical phrases by cleaning regex to words
    must_any = STRICT_RULES.get(category, {}).get("must_any", [])
    canonical = [re.sub(r"\\b|\\(|\\)|\\?|\\+|\\*|\\[|\\]|\\||\\^|\\$|-", " ", p) for p in must_any]
    canonical = [re.sub(r"\s+", " ", c).strip() for c in canonical if c]

    can_embs = _embed(canonical) if canonical else None
    thr_emb = _embed([ttext])[0] if ttext else None

    if len(df)==0:
        return df.assign(SimilarityScore=pd.Series(dtype=float), MatchBasis=pd.Series(dtype=str))

    # sim to canonical (max)
    if can_embs is not None and len(canonical)>0:
        sim_can = util.cos_sim(_build_req_embs(df), can_embs).cpu().numpy()
        max_can = sim_can.max(axis=1)
    else:
        max_can = np.zeros((len(df),), dtype=np.float32)

    # sim to threat
    if ttext:
        sim_thr = util.cos_sim(_build_req_embs(df), thr_emb).cpu().numpy().reshape(-1)
    else:
        sim_thr = np.zeros((len(df),), dtype=np.float32)

    score = alpha * max_can + (1 - alpha) * sim_thr if ttext else max_can

    out = df.copy()
    out["SimilarityScore"] = np.round(score, 3)
    out["MatchBasis"] = np.where(max_can >= sim_thr, "CategoryCanonical", "ThreatContext")
    out = out[out["SimilarityScore"] >= threshold]
    out = out.sort_values("SimilarityScore", ascending=False)
    return out

def process_threats_embedding(
    threats_df,
    requirements_df,
    asset_list=None,
    threshold=0.70,
    alpha=0.80,
    strict_direct_only=True,
    show_indirect=False,
):
    rows = []
    # Pre-embed all requirements once for speed (full set)
    all_req_embs = _build_req_embs(requirements_df)

    for _, threat in threats_df.iterrows():
        # Asset filter
        threat_assets = get_threat_assets(threat.get("Interaction", ""), asset_list)
        filtered = filter_requirements_by_assets(requirements_df, threat_assets) if asset_list else requirements_df

        # Classify each requirement as Direct/Indirect/None by rules
        verdicts = []
        for _, r in filtered.iterrows():
            text = f"{r.get('Requirement ID','')} :: {r.get('Description','')}"
            verdict, evidence, reason = _classify_direct(text, (threat.get('Category') or '').strip())
            verdicts.append((r['Requirement ID'], verdict, evidence, reason))

        filtered = filtered.copy()
        vmap = {rid:(v,e,reason) for (rid,v,e,reason) in verdicts}
        filtered["Verdict"] = filtered["Requirement ID"].map(lambda x: vmap.get(x,("None",[],[]))[0])
        filtered["Evidence"] = filtered["Requirement ID"].map(lambda x: ", ".join(vmap.get(x,("None",[],[]))[1]))
        filtered["Reason"] = filtered["Requirement ID"].map(lambda x: "; ".join(vmap.get(x,("None",[],[]))[2]))

        # If strict_direct_only, keep only Direct
        direct_df = filtered[filtered["Verdict"]=="Direct"]
        # Rank directs (optionally) via embeddings; if none, possibly show indirect (if toggle)
        if len(direct_df) > 0:
            ranked = _rank_by_stride(direct_df, None, threat, threshold=0.0, alpha=alpha)
        else:
            ranked = pd.DataFrame(columns=filtered.columns.tolist()+["SimilarityScore","MatchBasis"])

        if len(ranked)==0 and show_indirect:
            # Consider indirects with similarity threshold
            indirect_df = filtered[filtered["Verdict"]=="Indirect"]
            ranked = _rank_by_stride(indirect_df, None, threat, threshold=threshold, alpha=alpha)

        # If still none, record empty baseline row
        if len(ranked)==0:
            rows.append({
                "Threat ID": threat.get("Id"),
                "Threat Title": threat.get("Title"),
                "Category": threat.get("Category"),
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
                    "Mitigation Verdict": rr.get("Verdict","Direct"),
                    "Matched Requirement ID": rr.get("Requirement ID",""),
                    "Matched Requirement Description": rr.get("Description",""),
                    "Similarity Score": rr.get("SimilarityScore",""),
                    "Evidence": rr.get("Evidence",""),
                    "Reason": rr.get("Reason",""),
                })

    return pd.DataFrame(rows)
