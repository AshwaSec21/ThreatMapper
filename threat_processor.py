import pandas as pd
from llm_matcher import match_threat_to_requirements
from llm_threat_mapper import get_threat_assets, filter_requirements_by_assets

def process_threats(
    threats_df,
    requirements,
    system_summary,
    rmp_context,
    req_structure_hint,
    chunk_size=5,
    print_tokens=False,
    print_logs=False,
    asset_list=None
) -> pd.DataFrame:
    """
    For each threat:
    - Identify assets from the Interaction field
    - Filter applicable requirements based on those assets
    - Use LLM to suggest mitigations with justification
    """
    enriched_rows = []

    for _, row in threats_df.iterrows():
        threat = row.to_dict()
        interaction = threat.get("Interaction", "")
        threat_assets = get_threat_assets(interaction, asset_list=asset_list or [])

        if print_logs:
            print(f"🔍 threat_assets: {threat_assets}")

        # Step 1: Filter requirements by assets
        relevant_reqs = filter_requirements_by_assets(requirements, threat_assets)

        # Step 2: Get mitigations with justification
        mitigations = match_threat_to_requirements(
            threat=threat,
            filtered_requirements=relevant_reqs,
            rmp_context=rmp_context,
            req_structure_hint=req_structure_hint,
            chunk_size=chunk_size,
            print_tokens=print_tokens,
            print_logs=print_logs
        )

        if mitigations:
            threat["Mitigating Requirements"] = "; ".join(m["requirement"] for m in mitigations)
            threat["Justification"] = "\n\n".join(
                f"{m['requirement']}: {m['justification']}" for m in mitigations
            )
        else:
            threat["Mitigating Requirements"] = "None"
            threat["Justification"] = "No applicable requirements identified by LLM."

        enriched_rows.append(threat)

    return pd.DataFrame(enriched_rows)
