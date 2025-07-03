import pandas as pd

def read_threats(file_path: str) -> pd.DataFrame:
    """Loads the threats Excel file."""
    return pd.read_excel(file_path)

def read_requirements(file_path: str) -> list[dict]:
    """Loads the requirements Excel file and converts them to a list of dictionaries."""
    df = pd.read_excel(file_path)
    requirements = []
    for _, row in df.iterrows():
        requirements.append({
            "id": row["Requirement ID"],
            "text": row["Description"],
            "assets": row["Assets Allocated to"]
        })
    return requirements
