
def main():
    print("🚀 Starting the tool...Please wait, importing packages takes time", flush=True)
    from data_loader import read_threats, read_requirements
    from system_summary import get_system_summary
    # from rmp_loader import extract_rmp_context
    from threat_processor import process_threats
    from result_writer import save_updated_threats
    from file_paths import (
        get_threat_file,
        get_requirements_file,
        get_output_file,
        get_rmp_file,
        get_rmp_fallback_description,
        get_requirement_format_description,
    )

    threat_file = get_threat_file()
    requirements_file = get_requirements_file()
    rmp_file = get_rmp_file()
    output_file = get_output_file()

    # Load threats and requirements
    threats_df = read_threats(threat_file)
    requirements = read_requirements(requirements_file)

    # Load system and RMP context
    system_summary = get_system_summary()
    print("📘 Loading system context (RMP or fallback)...")
    rmp_context = get_rmp_fallback_description()

    req_structure_hint = get_requirement_format_description()

    print("🔹 Matching threats to requirements via LLM...")
    processed_df = process_threats(
        threats_df, requirements, system_summary, rmp_context, req_structure_hint
    )

    # Write result
    save_updated_threats(processed_df, output_file)

if __name__ == "__main__":
    main()
