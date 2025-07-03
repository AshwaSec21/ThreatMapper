import pandas as pd

def save_updated_threats(threats_df: pd.DataFrame, output_path: str):
    """
    Save the updated threats DataFrame with matched requirements to an Excel file.

    Args:
        threats_df: DataFrame containing threats and 'Requirement Covered' column.
        output_path: Path to save the output Excel file.
    """
    threats_df.to_excel(output_path, index=False)
    print(f"✅ Results saved to: {output_path}")
