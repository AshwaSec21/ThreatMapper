import json
from llm_utils import call_llm
from llm_threat_mapper import (
    generate_llm_prompt,
    get_threat_assets,
    filter_requirements_by_assets,
    is_requirement_relevant_to_threat,
)

# New: Import tokenizer from Hugging Face
from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("google/flan-t5-base")

def count_tokens(text):
    return len(tokenizer.encode(text))

def chunk_list(items, chunk_size):
    """Yield successive chunks from a list."""
    for i in range(0, len(items), chunk_size):
        yield items[i:i + chunk_size]

def match_threat_to_requirements(
        threat,
        filtered_requirements,
        rmp_context,
        req_structure_hint,
        chunk_size=5,
        print_tokens=False,
        print_logs=False,
        asset_list=None):
    """
    Given a threat, find matching requirements using asset filtering + LLM.
    Parses structured JSON output to collect both requirement IDs and justifications.
    """

    threat_assets = get_threat_assets(threat.get("Interaction", ""), asset_list)
    mitigations = []

    for chunk in chunk_list(filtered_requirements, chunk_size):
        prompt = generate_llm_prompt(threat, chunk, rmp_context, req_structure_hint, asset_list=asset_list)
        token_count = count_tokens(prompt)

        if print_tokens:
            print(f"🔢 $$$$$$$$$$$Token count for chunk:$$$$$$$$$$$$$$$$$$ {token_count}")

        llm_response = call_llm(prompt)

        if print_logs:
            print(f"🔍 Raw LLM response:\n{llm_response}\n#############End LLM Response################")

        try:
            parsed = json.loads(llm_response)
            for entry in parsed.get("mitigations", []):
                req_id = entry.get("requirement", "").strip()
                justification = entry.get("justification", "").strip()
                if req_id:
                    mitigations.append({"requirement": req_id, "justification": justification})
        except Exception as e:
            print(f"❌ JSON parsing failed: {e}")

    return mitigations  # List of dicts with requirement + justification
