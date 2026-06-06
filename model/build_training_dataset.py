"""
ZYGANT Tier 1 Dataset Preparation
EPSS + KEV + Cleaned NVD Merge

Purpose:
This script downloads the latest EPSS and CISA KEV data, cleans them in memory,
merges them with your already-cleaned NVD dataset, and saves only one final
merged dataset.

This version does NOT save raw EPSS, raw KEV, cleaned EPSS, or cleaned KEV files.
It only saves the final merged dataset for Tier 1 model training.

Before running:
1. Replace the placeholder paths in the CONFIG section.
2. Make sure your cleaned NVD file already exists locally.
3. Install required packages if needed:

   pip install pandas requests
"""

import gzip
import io
from pathlib import Path

import pandas as pd
import requests


# ============================================================
# CONFIG - REPLACE THESE PATHS
# ============================================================

# Path to your already-cleaned NVD dataset.
CLEANED_NVD_PATH = Path("Datasets/nvd_2022-2024_cleaned.csv")

# Path where the final merged Tier 1 dataset should be saved.
FINAL_MERGED_OUTPUT_PATH = Path("Datasets/nvd_epss_kev_merged.csv")


# ============================================================
# DATA SOURCE URLS
# ============================================================

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ============================================================
# EPSS DOWNLOAD AND CLEANING
# ============================================================

def pull_epss() -> pd.DataFrame:
    """
    Download the latest EPSS dataset and clean it in memory.

    Output columns:
    - cve_id
    - epss_score
    - epss_percentile
    """

    print("Downloading latest EPSS dataset...")

    response = requests.get(EPSS_URL, timeout=60)
    response.raise_for_status()

    # EPSS is downloaded as a compressed .csv.gz file.
    decompressed = gzip.decompress(response.content).decode("utf-8")
    lines = decompressed.splitlines()

    # EPSS may contain comment lines before the actual CSV header.
    header_index = next(i for i, line in enumerate(lines) if line.startswith("cve,"))
    csv_text = "\n".join(lines[header_index:])

    epss_df = pd.read_csv(io.StringIO(csv_text))

    # Rename columns to match the CVE ID format used in the ZYGANT dataset.
    epss_df = epss_df.rename(columns={
        "cve": "cve_id",
        "epss": "epss_score",
        "percentile": "epss_percentile"
    })

    # Keep only the columns needed for Tier 1 training.
    epss_df = epss_df[["cve_id", "epss_score", "epss_percentile"]]

    # Normalize CVE IDs so they merge correctly with NVD.
    epss_df["cve_id"] = epss_df["cve_id"].astype(str).str.strip().str.upper()

    # Convert scores to numeric values.
    epss_df["epss_score"] = pd.to_numeric(epss_df["epss_score"], errors="coerce")
    epss_df["epss_percentile"] = pd.to_numeric(epss_df["epss_percentile"], errors="coerce")

    # Remove duplicate CVE IDs if any exist.
    epss_df = epss_df.drop_duplicates(subset="cve_id")

    print(f"EPSS loaded and cleaned: {len(epss_df):,} CVEs")

    return epss_df


# ============================================================
# KEV DOWNLOAD AND CLEANING
# ============================================================

def pull_kev() -> pd.DataFrame:
    """
    Download the latest CISA KEV catalog and clean it in memory.

    Output columns:
    - cve_id

    KEV is later converted into a binary feature:
    - is_kev = 1 if the CVE appears in KEV
    - is_kev = 0 if it does not
    """

    print("Downloading latest CISA KEV catalog...")

    response = requests.get(KEV_URL, timeout=60)
    response.raise_for_status()

    kev_json = response.json()
    vulnerabilities = kev_json.get("vulnerabilities", [])

    kev_df = pd.DataFrame(vulnerabilities)

    if kev_df.empty:
        raise ValueError("KEV catalog downloaded, but no vulnerabilities were found.")

    # Rename cveID to cve_id to match NVD and EPSS.
    kev_df = kev_df.rename(columns={"cveID": "cve_id"})

    # Keep only the CVE ID for the Tier 1 merge.
    kev_df = kev_df[["cve_id"]]

    # Normalize CVE IDs so they merge correctly with NVD.
    kev_df["cve_id"] = kev_df["cve_id"].astype(str).str.strip().str.upper()

    # Remove duplicate CVE IDs if any exist.
    kev_df = kev_df.drop_duplicates(subset="cve_id")

    print(f"KEV loaded and cleaned: {len(kev_df):,} exploited CVEs")

    return kev_df


# ============================================================
# LOAD CLEANED NVD DATASET
# ============================================================

def load_cleaned_nvd() -> pd.DataFrame:
    """
    Load your already-cleaned NVD dataset.

    Expected:
    - The file should already be cleaned.
    - The file should contain a CVE ID column named cve_id.
    """

    print("Loading cleaned NVD dataset...")

    nvd_df = pd.read_csv(CLEANED_NVD_PATH)

    # Standardize column names.
    nvd_df.columns = nvd_df.columns.str.strip().str.lower()

    if "cve_id" not in nvd_df.columns:
        raise ValueError("Your cleaned NVD dataset must contain a column named 'cve_id'.")

    # Normalize CVE IDs so they merge correctly with EPSS and KEV.
    nvd_df["cve_id"] = nvd_df["cve_id"].astype(str).str.strip().str.upper()

    print(f"NVD loaded: {len(nvd_df):,} rows")

    return nvd_df


# ============================================================
# MERGE DATASETS
# ============================================================

def merge_datasets(nvd_df: pd.DataFrame, epss_df: pd.DataFrame, kev_df: pd.DataFrame) -> pd.DataFrame:
    """
    Merge NVD, EPSS, and KEV using cve_id.

    Merge logic:
    1. Keep all NVD records.
    2. Add EPSS score where a CVE match exists.
    3. Add KEV flag where a CVE match exists.
    """

    print("Merging NVD with EPSS...")

    merged_df = nvd_df.merge(
        epss_df,
        on="cve_id",
        how="left",
        indicator="epss_merge"
    )

    epss_matches = (merged_df["epss_merge"] == "both").sum()
    epss_missing = (merged_df["epss_merge"] == "left_only").sum()

    print(f"EPSS matches found: {epss_matches:,}")
    print(f"NVD records without EPSS match: {epss_missing:,}")

    print("Merging with KEV...")

    # Create a KEV flag before merging.
    kev_flags = kev_df.copy()
    kev_flags["is_kev"] = 1

    merged_df = merged_df.merge(
        kev_flags,
        on="cve_id",
        how="left",
        indicator="kev_merge"
    )

    kev_matches = (merged_df["kev_merge"] == "both").sum()

    # If CVE was found in KEV, is_kev = 1.
    # Otherwise, is_kev = 0.
    merged_df["is_kev"] = merged_df["is_kev"].fillna(0).astype(int)

    print(f"KEV matches found: {kev_matches:,}")

    # Remove merge tracking columns after reporting results.
    merged_df = merged_df.drop(columns=["epss_merge", "kev_merge"])

    # Fill missing EPSS scores with 0.
    # This means the CVE did not have a matching EPSS score in the latest EPSS dataset.
    merged_df["epss_score"] = merged_df["epss_score"].fillna(0)
    merged_df["epss_percentile"] = merged_df["epss_percentile"].fillna(0)

    print("Final merged dataset shape:", merged_df.shape)
    print("Duplicate rows:", merged_df.duplicated().sum())
    print("Duplicate CVE IDs:", merged_df.duplicated(subset="cve_id").sum())

    return merged_df


# ============================================================
# SAVE FINAL DATASET ONLY
# ============================================================

def save_final_dataset(merged_df: pd.DataFrame) -> None:
    """
    Save only the final merged dataset.

    This keeps the project folder clean for now.
    Raw and intermediate EPSS/KEV files are not saved in this version.
    """

    FINAL_MERGED_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    merged_df.to_csv(FINAL_MERGED_OUTPUT_PATH, index=False)

    print(f"Final merged Tier 1 dataset saved to: {FINAL_MERGED_OUTPUT_PATH}")


# ============================================================
# MAIN PROGRAM
# ============================================================

def main() -> None:
    """
    Run the full Tier 1 dataset preparation workflow.

    Final output:
    - One merged CSV file containing NVD + EPSS + KEV fields.
    """

    epss_df = pull_epss()
    kev_df = pull_kev()
    nvd_df = load_cleaned_nvd()

    merged_df = merge_datasets(nvd_df, epss_df, kev_df)

    save_final_dataset(merged_df)

    print("ZYGANT Tier 1 dataset preparation completed successfully.")


if __name__ == "__main__":
    main()
