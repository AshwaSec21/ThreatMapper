import os

def get_rmp_file() -> str | None:
    """
    Returns the path to the RMP file, or None if not used.
    """
    return None  # Update this path if you wish to include RMP later

def get_rmp_fallback_description() -> str:
    """
    Returns a fallback RMP description to help the LLM understand the context
    in the absence of an RMP file.
    """
    return (
        "The requirements are derived from internal and external standards and are organized "
        "in a structured Excel sheet. Each requirement contains a unique ID, a detailed description, "
        "and a list of system assets to which the requirement is allocated. This allocation helps map "
        "requirements to threats which are also asset-specific."
    )
