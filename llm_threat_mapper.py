import re

# ---------- helpers ----------
def _normalize(s):
    return (s or "").strip().lower()

def _split_before_colon(text):
    if not text:
        return "", ""
    parts = text.split(":", 1)
    if len(parts) == 2:
        return parts[0].strip(), text
    return "", text

def _match_assets_in_text(text, asset_list):
    if not text or not asset_list:
        return []
    txt = _normalize(text)
    hits = []
    for a in asset_list:
        if not a:
            continue
        if _normalize(a) in txt:
            hits.append(a)
    seen = set()
    out = []
    for a in hits:
        if a not in seen:
            out.append(a)
            seen.add(a)
    return out

# ---------- main API ----------
def get_threat_assets(interaction, asset_list, description=None):
    """
    Extract involved assets:
      1) Try 'prefix before colon' from Interaction: e.g., 'Firewall to NTP: text'
      2) If none, scan full Interaction for known assets
      3) If none, scan Description
    """
    assets = []

    left, _ = _split_before_colon(interaction or "")
    if left:
        candidates = re.split(r"\bto\b|,|;|/|\\|\|", left, flags=re.IGNORECASE)
        for c in candidates:
            cand = c.strip()
            if cand:
                for a in asset_list or []:
                    if _normalize(a) == _normalize(cand) or _normalize(a) in _normalize(cand):
                        assets.append(a)

    if not assets:
        assets = _match_assets_in_text(interaction, asset_list)

    if not assets and description:
        assets = _match_assets_in_text(description, asset_list)

    seen = set()
    uniq = []
    for a in assets:
        if a not in seen:
            uniq.append(a)
            seen.add(a)
    return uniq
def filter_requirements_by_assets(requirements, threat_assets):
    """
    Return only requirements that reference one or more of the threat-involved assets.
    Comparison is case-insensitive.
    """
    filtered = []
    threat_assets_lower = [a.lower() for a in threat_assets]

    for req in requirements:
        allocated_assets = [a.strip().lower() for a in re.split(r'[,|\n]+', req["assets"])]
        if any(asset in allocated_assets for asset in threat_assets_lower):
            filtered.append(req)

    return filtered

# ---------- (LLM path) prompt generator ----------
def generate_llm_prompt(threat, filtered_requirements, rmp_context, req_structure_hint, asset_list=None):
    import yaml
    threat_assets = get_threat_assets(
        threat.get("Interaction", ""),
        asset_list or [],
        description=threat.get("Description", "")
    )
    asset_hint = ", ".join(threat_assets) if threat_assets else "N/A"

    threat_yaml = yaml.dump({
        "ID": threat.get("Id"),
        "Title": threat.get("Title"),
        "Category": threat.get("Category"),
        "Interaction": threat.get("Interaction"),
        "Description": threat.get("Description"),
    }, default_flow_style=False)

    candidate_reqs_yaml = yaml.dump([
        {"ID": r["id"], "Text": r["text"]}
        for r in filtered_requirements
    ], default_flow_style=False)

    instructions = f"""
You are given two YAML blocks: one called `Threat`, and one called `CandidateRequirements`.

Your job is to:
- ONLY include requirements that **explicitly and functionally** mitigate the described threat.
- Consider that all CandidateRequirements are already **filtered by asset relevance**: they are allocated to these assets → {asset_hint}
- Match requirements **based on semantic alignment** with the threat **Category** (e.g., Elevation Of Privilege, Information Disclosure, etc.)
- Explain how the requirement mitigates the threat **in function**, not just keyword overlap.

Output format MUST be in JSON. The JSON should be an object with a single key "mitigations", whose value is a list of objects. Each object in this list MUST have the following keys:
- "requirement": (string) — a single requirement ID such as "[AVP_PCyA_2099]"
- "justification": (string) — an explanation of how this requirement mitigates the given threat.

If, and only if, NO requirements are found that effectively mitigate the given threat, the "mitigations" list SHOULD be empty.

Requirement Metadata Notes:
{rmp_context}

Requirement Format Hint:
{req_structure_hint}
Very important instructions:
- Reply ONLY with a valid JSON object matching exactly:
{{"mitigations":[{{"requirement":"[requirement_id]","justification":"..."}}]}}
If no match: {{"mitigations":[]}}
""".strip()

    prompt = f"""{instructions}

Threat:
{threat_yaml}

CandidateRequirements:
{candidate_reqs_yaml}
"""
    return prompt.strip()
