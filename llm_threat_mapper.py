import re
from sentence_transformers import SentenceTransformer, util

# Load embedding model once
model = SentenceTransformer("all-MiniLM-L6-v2")

def generate_llm_prompt(threat, filtered_requirements, rmp_context, req_structure_hint, asset_list=None):
    import yaml
    from llm_threat_mapper import get_threat_assets

    threat_assets = get_threat_assets(threat.get("Interaction", ""), asset_list)
    asset_hint = ", ".join(threat_assets)

    threat_yaml = yaml.dump({
        "ID": threat["Id"],
        "Title": threat["Title"],
        "Category": threat["Category"],
        "Interaction": threat["Interaction"],
        "Description": threat["Description"]
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

If, and only if, NO requirements are found that effectively mitigate the given threat, the "mitigations" list SHOULD be empty. DO NOT return "None", "Not Applicable", or similar strings within the list items if no mitigations are found. Instead, return an empty list.

Example expected JSON structure for mitigations found:
{{
  "mitigations": [
    {{
      "requirement": "[AVP_PCyA_2099]",
      "justification": "TLS client authentication ensures only authorized entities (like Switch) are allowed to interact with vCenter."
    }},
    {{
      "requirement": "[AVP_PCyA_2527]",
      "justification": "RBAC restricts access based on predefined roles, limiting what impersonated users can do."
    }}
  ]
}}

Example expected JSON structure when NO mitigations are found:
{{
  "mitigations": []
}}

Requirement Metadata Notes:
{rmp_context}

Requirement Format Hint:
{req_structure_hint}
Very important instructions:
- Your entire response MUST ONLY be a valid JSON block that strictly follows the structure below.
- DO NOT explain your reasoning outside the JSON.
- DO NOT write any introduction, summary, or commentary before or after the JSON.
- DO NOT format the JSON as Markdown (no triple backticks).
- Just respond with raw JSON.

The required JSON structure is:

{{
  "mitigations": [
    {{
      "requirement": "[requirement_id]",
      "justification": "Short but precise justification."
    }}
  ]
}}

If no requirement matches, return:

{{
  "mitigations": []
}}

"""

    prompt = f"""{instructions.strip()}

Threat:
{threat_yaml}

CandidateRequirements:
{candidate_reqs_yaml}
"""
    return prompt.strip()
 

def get_threat_assets(interaction: str, asset_list=None) -> list:
    """
    Extract asset names from interaction like 'AssetA to AssetB: description'.
    Ignores everything after ':' and filters against known assets (case-insensitive).
    """
    if asset_list is None:
        asset_list = {
            "vCenter Server", "Switch", "Firewall", "NTP", "OS ESXi", "Harvester",
            "Exported CSP", "OS Linux", "OS Windows", "vCenter", "Workstation",
            "Exported Projects", "BR Solution", "AVP Application Suite"
        }

    # Remove description part after the colon (if any)
    interaction = interaction.split(":", 1)[0].strip()

    # Extract tokens around 'to' (with any amount of surrounding whitespace)
    match = re.split(r"\s+to\s+", interaction, maxsplit=1, flags=re.IGNORECASE)

    normalized_assets = {a.lower(): a for a in asset_list}  # keep original casing

    found_assets = []
    for token in match:
        token_clean = token.strip().lower()
        if token_clean in normalized_assets:
            found_assets.append(normalized_assets[token_clean])

    return found_assets

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

def is_requirement_relevant_to_threat(threat_category, req_text):
    """
    Use semantic similarity to determine if the requirement aligns with the STRIDE category.
    """
    canonical_mitigation = {
        "elevation of privilege": "requirement must enforce privilege separation and authorization",
        "spoofing": "requirement must authenticate and verify identity",
        "information disclosure": "requirement must ensure confidentiality through encryption or access control",
        "tampering": "requirement must preserve data integrity and resist tampering",
        "repudiation": "requirement must support audit logging and traceability",
        "denial of service": "requirement must protect availability and throttle excessive input"
    }

    reference = canonical_mitigation.get(threat_category.lower())
    if not reference:
        return False

    sim_score = util.cos_sim(model.encode(reference), model.encode(req_text))[0][0].item()
    return sim_score > 0.6
