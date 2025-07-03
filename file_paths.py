def get_threat_file():
    return "Threats_18_Jun_2025.xlsx"

def get_requirements_file():
    return "A-0000357719-PCyA-AVP-vD.xlsx"

def get_output_file():
    return "threats_with_requirements.xlsx"

def get_rmp_file():
    # Optional – return None for now
    return None
def get_rmp_fallback_description():
    return (
        "The requirements are structured with unique IDs like [AVP_PCyA_1234], followed by a "
        "natural-language description. Requirements often include attributes like #Allocation "
        "to indicate which system component they are related to. They typically end with a "
        "marker like [BeginBookAVP_PCyA_1234]."
    )

def get_requirement_format_description():
    return """
Each requirement entry includes:
- 'Requirement ID': a unique ID 
- 'Description': the actual requirement text
- 'Assets Allocated to': a list of system components (e.g., Harvester, vCenter, VSAN...this can be different for different systems) to which the requirement applies

🟡 Note: Asset names in 'Assets Allocated to' may not exactly match the asset names mentioned in the threat description.
Examples:
- A requirement might list "Switch" while the threat refers to "SwitchStack"
- A requirement might list "ESXi" or "Harvester", while the threat talks about "Hypervisor"
- A requirement might list "VSAN", while the threat talks about virtual storage

🔍 Treat these as relevant if they refer to conceptually similar or related components, even if the naming differs.

✅ When identifying matching requirements:
1. Prioritize semantic alignment between the threat description and the requirement text
2. Give special consideration to overlap or close match between affected assets and allocated assets, even if exact terms differ
"""
