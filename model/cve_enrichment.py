"""
ZYGANT - CVE Enrichment Workflow

Purpose:
This script enriches uploaded vulnerability data before it is sent to the
ZYGANT prioritization model.

This is different from model training.

Training workflow:
- Uses historical NVD + EPSS + KEV data.
- Trains the Tier 1 machine learning model.

Enrichment/scoring workflow:
- Starts with CVE IDs from a scanner, dashboard, spreadsheet, or uploaded file.
- Fetches the required NVD, EPSS, and KEV information for those CVEs.
- Creates a model-ready enriched dataset.
- Saves only the final enriched file.

Expected input:
- A CSV or Excel file containing at least one CVE ID column.
- Example columns: Asset ID, CVE ID

Expected output:
- One enriched CSV file containing:
  - Uploaded asset/vulnerability fields
  - NVD/CVSS fields required by the model
  - EPSS score and percentile
  - KEV status as is_kev

Before running:
1. Replace INPUT_VULNERABILITY_FILE with your uploaded dataset path.
2. Replace OUTPUT_ENRICHED_FILE with your desired output path.
3. Make sure required packages are installed:

   pip install pandas requests openpyxl
"""

import gzip
import io
import time
from pathlib import Path

import pandas as pd
import requests


# ============================================================
# CONFIG
# ============================================================

# Path to the uploaded vulnerability file.
# This file should contain CVE IDs from a scanner, dashboard, or spreadsheet.
# Example:
# INPUT_VULNERABILITY_FILE = Path("Datasets/Vulnerabilities Dataset.xlsx")
INPUT_VULNERABILITY_FILE = Path("Datasets/Vulnerabilities Dataset.xlsx")

# Path where the final enriched dataset should be saved.
# This is the file that can later be passed into the Tier 1 + Tier 2 scoring workflow.
# Example:
# OUTPUT_ENRICHED_FILE = Path("Datasets/sera_enriched_vulnerabilities.csv")
OUTPUT_ENRICHED_FILE = Path("Datasets/sera_enriched_vulnerabilities.csv")

# Name of the CVE ID column in the uploaded file.
# Change this if your file uses a different column name.
# Examples: "CVE ID", "cve_id", "CVE"
CVE_COLUMN_NAME = "CVE ID"

# Optional NVD API key.
# Leave as None if you do not have one.
# If you later get an API key, place it here as a string or load it from an environment variable.
NVD_API_KEY = None

# NVD API endpoint used to fetch CVE details.
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# EPSS current scores file.
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# CISA KEV catalog.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ============================================================
# INPUT FILE LOADING
# ============================================================

def load_uploaded_vulnerabilities(file_path: Path) -> pd.DataFrame:
    """
    Load the uploaded vulnerability file.

    The file can be:
    - .csv
    - .xlsx
    - .xls

    The goal is to keep the original uploaded data so fields such as
    Asset ID can be preserved for Tier 3 contextual scoring later.
    """

    # Stop early if the file path does not exist.
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")

    # Read Excel files using pandas.
    if file_path.suffix.lower() in [".xlsx", ".xls"]:
        df = pd.read_excel(file_path)

    # Read CSV files using pandas.
    elif file_path.suffix.lower() == ".csv":
        df = pd.read_csv(file_path)

    # Stop if the file type is not supported.
    else:
        raise ValueError("Unsupported file type. Please use .csv, .xlsx, or .xls.")

    # Standardize column spacing while keeping the original names readable.
    df.columns = df.columns.astype(str).str.strip()

    # Check that the expected CVE column exists.
    if CVE_COLUMN_NAME not in df.columns:
        raise ValueError(
            f"Column '{CVE_COLUMN_NAME}' not found. "
            f"Available columns: {list(df.columns)}"
        )

    # Normalize CVE IDs so they match NVD, EPSS, and KEV formats.
    df[CVE_COLUMN_NAME] = df[CVE_COLUMN_NAME].astype(str).str.strip().str.upper()

    # Rename the CVE column to cve_id for consistent merging.
    df = df.rename(columns={CVE_COLUMN_NAME: "cve_id"})

    # Remove rows where CVE ID is missing or invalid-looking.
    df = df[df["cve_id"].str.startswith("CVE-")].copy()

    print(f"Uploaded vulnerability records loaded: {len(df):,}")

    return df


# ============================================================
# CVE EXTRACTION
# ============================================================

def extract_unique_cves(uploaded_df: pd.DataFrame) -> list:
    """
    Extract unique CVE IDs from the uploaded vulnerability file.

    This avoids calling NVD multiple times for the same CVE.
    """

    # Get unique CVE IDs and sort them for consistent output.
    cve_ids = sorted(uploaded_df["cve_id"].dropna().unique().tolist())

    print(f"Unique CVEs found: {len(cve_ids):,}")

    return cve_ids


# ============================================================
# NVD FETCHING AND PARSING
# ============================================================

def get_cvss_metrics_from_nvd_item(cve_item: dict) -> dict:
    """
    Extract CVSS fields from one NVD CVE item.

    NVD may contain CVSS v3.1, v3.0, or v2.
    For this project, CVSS v3.1 is preferred when available.
    If v3.1 is not available, the script tries v3.0.
    """

    # Get the metrics section safely.
    metrics = cve_item.get("cve", {}).get("metrics", {})

    # Prefer CVSS v3.1 because it is commonly used in modern NVD records.
    cvss_entries = metrics.get("cvssMetricV31", [])

    # Fall back to CVSS v3.0 if v3.1 is not available.
    if not cvss_entries:
        cvss_entries = metrics.get("cvssMetricV30", [])

    # If no CVSS v3 data exists, return empty/default values.
    if not cvss_entries:
        return {
            "cvss_base_score": None,
            "baseseverity": None,
            "attackvector": None,
            "attackcomplexity": None,
            "privilegesrequired": None,
            "userinteraction": None,
            "scope": None,
            "confidentialityimpact": None,
            "integrityimpact": None,
            "availabilityimpact": None,
        }

    # Use the first CVSS record returned by NVD.
    cvss_data = cvss_entries[0].get("cvssData", {})

    # Extract only the model-required CVSS fields.
    return {
        "cvss_base_score": cvss_data.get("baseScore"),
        "baseseverity": cvss_data.get("baseSeverity"),
        "attackvector": cvss_data.get("attackVector"),
        "attackcomplexity": cvss_data.get("attackComplexity"),
        "privilegesrequired": cvss_data.get("privilegesRequired"),
        "userinteraction": cvss_data.get("userInteraction"),
        "scope": cvss_data.get("scope"),
        "confidentialityimpact": cvss_data.get("confidentialityImpact"),
        "integrityimpact": cvss_data.get("integrityImpact"),
        "availabilityimpact": cvss_data.get("availabilityImpact"),
    }


def fetch_single_cve_from_nvd(cve_id: str) -> dict:
    """
    Fetch one CVE record from the NVD API.

    This function returns a dictionary containing the NVD/CVSS fields needed
    by the Tier 1 model.
    """

    # Build request headers.
    headers = {}

    # Add API key only if one is configured.
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # Query NVD by CVE ID.
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=headers,
        timeout=60
    )

    # Raise an error if NVD returns a failed response.
    response.raise_for_status()

    # Convert response JSON into a Python dictionary.
    data = response.json()

    # NVD returns CVE records inside the vulnerabilities list.
    vulnerabilities = data.get("vulnerabilities", [])

    # If NVD does not return a matching CVE, keep the CVE ID but leave fields blank.
    if not vulnerabilities:
        return {"cve_id": cve_id}

    # Use the first matching NVD item.
    cve_item = vulnerabilities[0]

    # Start with CVE ID.
    parsed = {"cve_id": cve_id}

    # Add published and last modified dates if available.
    parsed["published"] = cve_item.get("cve", {}).get("published")
    parsed["lastmodified"] = cve_item.get("cve", {}).get("lastModified")

    # Add CVSS fields required by the Tier 1 model.
    parsed.update(get_cvss_metrics_from_nvd_item(cve_item))

    return parsed


def fetch_nvd_for_cves(cve_ids: list) -> pd.DataFrame:
    """
    Fetch NVD/CVSS information for each uploaded CVE.

    This currently calls NVD once per CVE.
    That is simple and clear for testing.

    Later, if needed, this can be optimized with caching, batching,
    API key usage, or SQLite storage.
    """

    print("Fetching NVD data for uploaded CVEs...")

    records = []

    # Use a slower delay when no API key is configured.
    # This helps avoid hitting NVD rate limits.
    request_delay = 0.6 if NVD_API_KEY else 6.0

    for index, cve_id in enumerate(cve_ids, start=1):
        try:
            print(f"[{index}/{len(cve_ids)}] Fetching {cve_id}")
            record = fetch_single_cve_from_nvd(cve_id)
            records.append(record)

        except Exception as error:
            # Keep the CVE in the output even if the API call fails.
            print(f"Warning: Failed to fetch {cve_id}: {error}")
            records.append({"cve_id": cve_id})

        # Delay between requests to respect NVD rate limits.
        time.sleep(request_delay)

    nvd_df = pd.DataFrame(records)

    # Normalize CVE IDs before merging.
    nvd_df["cve_id"] = nvd_df["cve_id"].astype(str).str.strip().str.upper()

    print(f"NVD records prepared: {len(nvd_df):,}")

    return nvd_df


# ============================================================
# EPSS DOWNLOAD AND CLEANING
# ============================================================

def pull_epss() -> pd.DataFrame:
    """
    Download the latest EPSS dataset and clean it in memory.

    This does not save raw EPSS data locally.
    Only the final enriched dataset is saved at the end.
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

    # Read EPSS into a dataframe.
    epss_df = pd.read_csv(io.StringIO(csv_text))

    # Rename columns to match ZYGANT merge logic.
    epss_df = epss_df.rename(columns={
        "cve": "cve_id",
        "epss": "epss_score",
        "percentile": "epss_percentile"
    })

    # Keep only the fields needed for prioritization.
    epss_df = epss_df[["cve_id", "epss_score", "epss_percentile"]]

    # Normalize CVE IDs.
    epss_df["cve_id"] = epss_df["cve_id"].astype(str).str.strip().str.upper()

    # Convert score fields into numeric values.
    epss_df["epss_score"] = pd.to_numeric(epss_df["epss_score"], errors="coerce")
    epss_df["epss_percentile"] = pd.to_numeric(epss_df["epss_percentile"], errors="coerce")

    # Remove duplicate CVE IDs if any exist.
    epss_df = epss_df.drop_duplicates(subset="cve_id")

    print(f"EPSS records prepared: {len(epss_df):,}")

    return epss_df


# ============================================================
# KEV DOWNLOAD AND CLEANING
# ============================================================

def pull_kev() -> pd.DataFrame:
    """
    Download the latest CISA KEV catalog and clean it in memory.

    This creates a simple KEV flag:
    - is_kev = 1 if CVE exists in KEV
    - is_kev = 0 if CVE does not exist in KEV
    """

    print("Downloading latest CISA KEV catalog...")

    response = requests.get(KEV_URL, timeout=60)
    response.raise_for_status()

    # Convert KEV JSON response into a dictionary.
    kev_json = response.json()

    # KEV vulnerabilities are stored in the vulnerabilities list.
    vulnerabilities = kev_json.get("vulnerabilities", [])

    # Convert KEV list into a dataframe.
    kev_df = pd.DataFrame(vulnerabilities)

    # Stop if the KEV catalog unexpectedly returns empty data.
    if kev_df.empty:
        raise ValueError("KEV catalog downloaded, but no vulnerabilities were found.")

    # Rename cveID to cve_id so it can merge with uploaded and NVD data.
    kev_df = kev_df.rename(columns={"cveID": "cve_id"})

    # Keep only CVE ID because the model only needs a KEV flag for now.
    kev_df = kev_df[["cve_id"]]

    # Normalize CVE IDs.
    kev_df["cve_id"] = kev_df["cve_id"].astype(str).str.strip().str.upper()

    # Remove duplicates if any exist.
    kev_df = kev_df.drop_duplicates(subset="cve_id")

    # Create binary KEV flag.
    kev_df["is_kev"] = 1

    print(f"KEV records prepared: {len(kev_df):,}")

    return kev_df


# ============================================================
# MERGE ENRICHED DATA
# ============================================================

def merge_enrichment_data(
    uploaded_df: pd.DataFrame,
    nvd_df: pd.DataFrame,
    epss_df: pd.DataFrame,
    kev_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Merge uploaded vulnerability data with NVD, EPSS, and KEV.

    Merge logic:
    1. Keep all uploaded vulnerability records.
    2. Add NVD/CVSS fields where CVE matches.
    3. Add EPSS score and percentile where CVE matches.
    4. Add KEV flag where CVE matches.
    """

    print("Merging uploaded CVEs with NVD data...")

    # Keep all uploaded rows so no scanner/dashboard findings are lost.
    enriched_df = uploaded_df.merge(
        nvd_df,
        on="cve_id",
        how="left"
    )

    print("Merging enriched CVEs with EPSS data...")

    # Add EPSS score and percentile.
    enriched_df = enriched_df.merge(
        epss_df,
        on="cve_id",
        how="left"
    )

    print("Merging enriched CVEs with KEV data...")

    # Add KEV flag.
    enriched_df = enriched_df.merge(
        kev_df,
        on="cve_id",
        how="left"
    )

    # If a CVE is not found in KEV, mark it as 0.
    enriched_df["is_kev"] = enriched_df["is_kev"].fillna(0).astype(int)

    # If a CVE does not have EPSS data, fill with 0.
    enriched_df["epss_score"] = enriched_df["epss_score"].fillna(0)
    enriched_df["epss_percentile"] = enriched_df["epss_percentile"].fillna(0)

    print("Final enriched dataset shape:", enriched_df.shape)
    print("Unique CVEs in enriched dataset:", enriched_df["cve_id"].nunique())

    return enriched_df


# ============================================================
# SAVE OUTPUT
# ============================================================

def save_enriched_dataset(enriched_df: pd.DataFrame, output_path: Path) -> None:
    """
    Save the final enriched dataset.

    This is the only file saved by this enrichment workflow.
    """

    # Create output folder if it does not already exist.
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save final enriched dataset.
    enriched_df.to_csv(output_path, index=False)

    print("Saved enriched CVE dataset to:", output_path)


# ============================================================
# MAIN WORKFLOW
# ============================================================

def main() -> None:
    """
    Run the complete CVE enrichment workflow.

    Final output:
    - One enriched CSV file ready for Tier 1 + Tier 2 scoring.
    """

    # Load uploaded vulnerability file.
    uploaded_df = load_uploaded_vulnerabilities(INPUT_VULNERABILITY_FILE)

    # Extract unique CVEs to avoid duplicate NVD API requests.
    cve_ids = extract_unique_cves(uploaded_df)

    # Fetch NVD fields for uploaded CVEs.
    nvd_df = fetch_nvd_for_cves(cve_ids)

    # Download latest EPSS data in memory.
    epss_df = pull_epss()

    # Download latest KEV data in memory.
    kev_df = pull_kev()

    # Merge uploaded data with NVD, EPSS, and KEV.
    enriched_df = merge_enrichment_data(uploaded_df, nvd_df, epss_df, kev_df)

    # Save only the final enriched dataset.
    save_enriched_dataset(enriched_df, OUTPUT_ENRICHED_FILE)

    print("ZYGANT CVE enrichment completed successfully.")


if __name__ == "__main__":
    main()
