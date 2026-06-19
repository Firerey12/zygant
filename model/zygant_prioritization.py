"""
ZYGANT - End-to-End Vulnerability Prioritization Workflow

Purpose:
This script runs the local ZYGANT prioritization workflow.

Current local workflow:
1. Load uploaded vulnerability dataset.
2. Run CVE enrichment using cve_enrichment.py.
3. Save enriched vulnerability dataset locally.
4. Load saved Tier 1 model artifact.
5. Predict Tier 1 ML exploitation-likelihood score.
6. Apply Tier 2 KEV boost.
7. Save prioritized vulnerability results as a CSV.

Important:
- This script does NOT train the model.
- The Tier 1 model must already be trained and saved as a joblib artifact.
- The uploaded vulnerability file can be a CSV or Excel file.
- The enriched file is saved locally for testing and review.
- The final prioritized output is saved locally for dashboard/testing use.

Expected local files:
- cve_enrichment.py
- Model/tier1_lightgbm_regressor.joblib
- Datasets/Vulnerabilities Dataset.xlsx

Before running:
1. Make sure cve_enrichment.py is in the same folder as this file.
2. Make sure your trained Tier 1 model artifact exists.
3. Update the paths in the CONFIG section if needed.
4. Run: python zygant_prioritization.py
"""

from pathlib import Path

import joblib
import pandas as pd

# Import your CVE enrichment functions.
# This keeps enrichment separate and avoids duplicating code.
import cve_enrichment


# ============================================================
# CONFIG - LOCAL FILE PATHS
# ============================================================

# Input:
# This is the raw vulnerability file uploaded by the user or exported from the scanner/dashboard.
# It should contain at least Asset ID and CVE ID.
UPLOADED_VULNERABILITY_FILE = Path("Datasets/Vulnerabilities Dataset.xlsx")

# Output:
# This is the enriched dataset created after joining uploaded CVEs with NVD, EPSS, and KEV.
ENRICHED_DATASET_PATH = Path("Datasets/sera_enriched_vulnerabilities.csv")

# Input:
# This is the trained Tier 1 model artifact created by tier1_ml_model.py.
MODEL_ARTIFACT_PATH = Path("Model/tier1_lightgbm_regressor.joblib")

# Output:
# This is the final prioritized vulnerability queue.
PRIORITIZED_OUTPUT_PATH = Path("Datasets/zygant_prioritized_vulnerabilities.csv")

# Name of the CVE column in the uploaded file.
# Change this if your uploaded file uses a different column name.
CVE_COLUMN_NAME = "CVE ID"

# Tier 2 maximum KEV boost.
# This is applied proportionally, not as a direct flat +20%.
MAX_KEV_BOOST = 0.20


# ============================================================
# COLUMN NORMALIZATION
# ============================================================

def normalize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardize column names so files from different sources are easier to process.

    Examples:
    - Asset ID becomes asset_id
    - CVE ID becomes cve_id
    - CVSS Base Score becomes cvss_base_score
    """

    df = df.copy()

    df.columns = (
        df.columns.astype(str)
        .str.strip()
        .str.lower()
        .str.replace(" ", "_", regex=False)
        .str.replace("-", "_", regex=False)
        .str.replace("(", "", regex=False)
        .str.replace(")", "", regex=False)
    )

    return df


# ============================================================
# STEP 1 - RUN CVE ENRICHMENT
# ============================================================

def run_cve_enrichment() -> pd.DataFrame:
    """
    Run the CVE enrichment workflow using functions from cve_enrichment.py.

    This step:
    1. Loads the uploaded vulnerability file.
    2. Extracts unique CVE IDs.
    3. Fetches NVD/CVSS data.
    4. Downloads EPSS data.
    5. Downloads KEV data.
    6. Merges everything by CVE ID.
    7. Saves the enriched CSV locally.
    """

    print("\n=== Step 1: Running CVE enrichment ===")

    # Update cve_enrichment configuration using this file's local paths.
    cve_enrichment.INPUT_VULNERABILITY_FILE = UPLOADED_VULNERABILITY_FILE
    cve_enrichment.OUTPUT_ENRICHED_FILE = ENRICHED_DATASET_PATH
    cve_enrichment.CVE_COLUMN_NAME = CVE_COLUMN_NAME

    # Load uploaded vulnerability data.
    uploaded_df = cve_enrichment.load_uploaded_vulnerabilities(
        cve_enrichment.INPUT_VULNERABILITY_FILE
    )

    # Extract unique CVEs to avoid duplicate NVD API requests.
    cve_ids = cve_enrichment.extract_unique_cves(uploaded_df)

    # Fetch NVD data for uploaded CVEs.
    nvd_df = cve_enrichment.fetch_nvd_for_cves(cve_ids)

    # Download EPSS data in memory.
    epss_df = cve_enrichment.pull_epss()

    # Download KEV data in memory.
    kev_df = cve_enrichment.pull_kev()

    # Merge uploaded data with NVD, EPSS, and KEV.
    enriched_df = cve_enrichment.merge_enrichment_data(
        uploaded_df=uploaded_df,
        nvd_df=nvd_df,
        epss_df=epss_df,
        kev_df=kev_df
    )

    # Save enriched dataset locally.
    cve_enrichment.save_enriched_dataset(enriched_df, ENRICHED_DATASET_PATH)

    print("CVE enrichment completed.")

    return enriched_df


# ============================================================
# STEP 2 - LOAD TRAINED MODEL ARTIFACT
# ============================================================

def load_model_artifact(path: Path) -> dict:
    """
    Load the saved Tier 1 model artifact.

    Expected artifact keys:
    - model
    - feature_columns
    - categorical_columns
    - numeric_columns
    - trained_at
    - notes
    """

    print("\n=== Step 2: Loading Tier 1 model artifact ===")

    # Stop if the model artifact does not exist.
    if not path.exists():
        raise FileNotFoundError(
            f"Model artifact not found: {path}. "
            "Run tier1_ml_model.py first to train and save the Tier 1 artifact."
        )

    # Load the artifact from disk.
    artifact = joblib.load(path)

    # Required fields needed for scoring.
    required_keys = [
        "model",
        "feature_columns",
        "categorical_columns",
        "numeric_columns"
    ]

    # Validate artifact structure before scoring.
    for key in required_keys:
        if key not in artifact:
            raise ValueError(f"Model artifact is missing required key: {key}")

    print("Loaded model artifact:", path)

    return artifact


# ============================================================
# STEP 3 - PREPARE FEATURES FOR MODEL SCORING
# ============================================================

def prepare_features_for_scoring(df: pd.DataFrame, artifact: dict) -> pd.DataFrame:
    """
    Prepare enriched vulnerability data using the exact feature schema from training.

    Why this matters:
    - The model must receive the same feature columns it saw during training.
    - Asset fields such as asset_id should NOT enter the Tier 1 ML model.
    - Asset fields are preserved only for reporting and future Tier 3 context.
    """

    # Read saved training schema from the artifact.
    feature_columns = artifact["feature_columns"]
    categorical_cols = artifact["categorical_columns"]
    numeric_cols = artifact["numeric_columns"]

    # Work on a copy of the enriched data.
    X_new = df.copy()

    # Create any missing training feature columns.
    for col in feature_columns:
        if col not in X_new.columns:
            if col in categorical_cols:
                X_new[col] = "UNKNOWN"
            else:
                X_new[col] = 0

    # Keep only columns used during Tier 1 training.
    X_new = X_new[feature_columns]

    # Clean categorical feature columns.
    for col in categorical_cols:
        if col in X_new.columns:
            X_new[col] = X_new[col].astype(str).fillna("UNKNOWN")

    # Clean numeric feature columns.
    for col in numeric_cols:
        if col in X_new.columns:
            X_new[col] = pd.to_numeric(X_new[col], errors="coerce").fillna(0)

    return X_new


# ============================================================
# STEP 4 - APPLY TIER 1 ML SCORING
# ============================================================

def apply_tier1_scoring(df: pd.DataFrame, artifact: dict) -> pd.DataFrame:
    """
    Predict Tier 1 ML score using the trained LightGBM model.

    Tier 1 score meaning:
    - Predicted exploitation-likelihood score.
    - Based on NVD/CVSS-style vulnerability features.
    - KEV is not used as a model feature because it belongs to Tier 2.
    """

    print("\n=== Step 3: Applying Tier 1 ML scoring ===")

    df = df.copy()

    # Normalize column names after enrichment.
    df = normalize_column_names(df)

    # Validate required CVE column.
    if "cve_id" not in df.columns:
        raise ValueError("Enriched dataset must contain a cve_id column.")

    # Normalize CVE IDs.
    df["cve_id"] = df["cve_id"].astype(str).str.strip().str.upper()

    # Ensure KEV column exists for Tier 2.
    if "is_kev" not in df.columns:
        df["is_kev"] = 0

    # Clean KEV column.
    df["is_kev"] = pd.to_numeric(df["is_kev"], errors="coerce").fillna(0).astype(int)

    # Prepare only the model features saved in the artifact.
    X_new = prepare_features_for_scoring(df, artifact)

    print("Rows to prioritize:", len(df))
    print("Model features used:", X_new.shape[1])

    # Load the trained model pipeline.
    model = artifact["model"]

    # Predict Tier 1 ML score.
    df["tier1_ml_score"] = model.predict(X_new)

    # Keep score between 0 and 1.
    df["tier1_ml_score"] = df["tier1_ml_score"].clip(lower=0, upper=1)

    return df


# ============================================================
# STEP 5 - APPLY TIER 2 KEV BOOST
# ============================================================

def apply_kev_boost(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply Tier 2 KEV boost after Tier 1 scoring.

    Formula:
    kev_boost = is_kev * MAX_KEV_BOOST * (1 - tier1_ml_score)

    Why this is used:
    - KEV means the CVE is known to be exploited.
    - The boost increases priority without making every KEV automatically Critical.
    - High Tier 1 scores receive smaller boosts because they are already high.
    """

    print("\n=== Step 4: Applying Tier 2 KEV boost ===")

    df = df.copy()

    # Stop if Tier 1 score is missing.
    if "tier1_ml_score" not in df.columns:
        raise ValueError("tier1_ml_score must exist before applying KEV boost.")

    # Clean KEV flag.
    df["is_kev"] = pd.to_numeric(df["is_kev"], errors="coerce").fillna(0).astype(int)

    # Calculate proportional KEV boost.
    df["kev_boost"] = df["is_kev"] * MAX_KEV_BOOST * (1 - df["tier1_ml_score"])

    # Add boost to Tier 1 score and keep it in the 0 to 1 range.
    df["final_score"] = (df["tier1_ml_score"] + df["kev_boost"]).clip(lower=0, upper=1)

    return df


# ============================================================
# STEP 6 - APPLY TIER 3 CONTEXTUAL AWARENESS
# ============================================================

def map_label_score(value, score_map: dict, default: float = 0.0) -> float:
    """
    Convert a contextual label into a numeric score between 0 and 1.

    This keeps Tier 3 rule-based, explainable, and easy to tune later.
    """

    if pd.isna(value):
        return default

    normalized_value = str(value).strip().lower()

    return score_map.get(normalized_value, default)


def score_compliance(value) -> float:
    """
    Score compliance impact.

    If multiple compliance labels exist, the highest score is used because one
    strong regulatory requirement is enough to increase business risk.
    """

    if pd.isna(value):
        return 0.0

    value_text = str(value).strip().lower()

    # These labels match the SERA dataset values:
    # "GDPR, PCI-DSS, PII", "GDPR", "GDPR, PII", and "None".
    compliance_scores = {
        "none": 0.00,
        "pii": 0.65,
        "gdpr": 0.80,
        "pci-dss": 1.00,
        "pci_dss": 1.00,
        "pci": 1.00
    }

    matched_scores = [
        score
        for label, score in compliance_scores.items()
        if label in value_text
    ]

    return max(matched_scores) if matched_scores else 0.0


def calculate_context_score(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate Tier 3 contextual score.

    Only the selected contextual factors are used:
    - Business Criticality
    - Operational Disruption
    - Business Impact
    - Data Classification
    - Privilege Level
    - Network Exposure
    - Host Exposure
    - Compliance
    - Blast Radius

    The weighted score stays between 0 and 1 because every factor is normalized
    and the weights add up to 1.00.
    """

    print("\n=== Step 5: Calculating Tier 3 contextual score ===")

    df = df.copy()

    # Business criticality has the highest weight because it shows how essential the asset is to the organization.
    business_criticality_map = {
        "low": 0.25,
        "medium": 0.50,
        "high": 0.75,
        "critical": 1.00
    }

    # Business impact is highly weighted because it measures the damage if the asset is compromised.
    business_impact_map = {
        "low": 0.25,
        "medium": 0.50,
        "high": 0.75,
        "critical": 1.00
    }

    # Operational disruption is important because severe disruption can stop business services.
    operational_disruption_map = {
        "negligible": 0.10,
        "minor": 0.35,
        "significant": 0.75,
        "severe": 1.00
    }

    # Data classification is important because restricted/confidential data increases breach impact.
    data_classification_map = {
        "internal": 0.35,
        "confidential": 0.75,
        "restricted": 1.00
    }

    # Privilege level matters because privileged systems can increase attacker movement and control.
    privilege_level_map = {
        "standard": 0.30,
        "elevated": 0.70,
        "privileged": 1.00
    }

    # Network exposure matters because externally reachable assets are easier for attackers to target.
    network_exposure_map = {
        "isolated": 0.10,
        "internal": 0.40,
        "dmz": 0.75,
        "external": 1.00
    }

    # Host exposure matters because highly exposed hosts increase the chance of spread or access.
    host_exposure_map = {
        "low": 0.25,
        "medium": 0.60,
        "high": 1.00
    }

    # Blast radius matters because core infrastructure issues can affect many systems at once.
    blast_radius_map = {
        "standalone": 0.25,
        "shared": 0.60,
        "core infrastructure": 1.00
    }

    # Convert the selected contextual labels into numeric scores.
    df["business_criticality_score"] = df.get("business_criticality", pd.Series(index=df.index)).apply(
        lambda x: map_label_score(x, business_criticality_map)
    )

    df["business_impact_score"] = df.get("business_impact", pd.Series(index=df.index)).apply(
        lambda x: map_label_score(x, business_impact_map)
    )

    df["operational_disruption_score"] = df.get("operational_disruption", pd.Series(index=df.index)).apply(
        lambda x: map_label_score(x, operational_disruption_map)
    )

    df["data_classification_score"] = df.get("data_classification", pd.Series(index=df.index)).apply(
        lambda x: map_label_score(x, data_classification_map)
    )

    df["privilege_level_score"] = df.get("privilege_level", pd.Series(index=df.index)).apply(
        lambda x: map_label_score(x, privilege_level_map)
    )

    df["network_exposure_score"] = df.get("network_exposure", pd.Series(index=df.index)).apply(
        lambda x: map_label_score(x, network_exposure_map)
    )

    df["host_exposure_score"] = df.get("host_exposure", pd.Series(index=df.index)).apply(
        lambda x: map_label_score(x, host_exposure_map)
    )

    df["blast_radius_score"] = df.get("blast_radius", pd.Series(index=df.index)).apply(
        lambda x: map_label_score(x, blast_radius_map)
    )

    df["compliance_score"] = df.get("compliance", pd.Series(index=df.index)).apply(score_compliance)

    # Weighted contextual score.
    # Business criticality and business impact lead the score because they best represent business risk.
    df["context_score"] = (
        df["business_criticality_score"] * 0.22 +
        df["business_impact_score"] * 0.18 +
        df["operational_disruption_score"] * 0.14 +
        df["data_classification_score"] * 0.13 +
        df["network_exposure_score"] * 0.11 +
        df["privilege_level_score"] * 0.09 +
        df["blast_radius_score"] * 0.06 +
        df["host_exposure_score"] * 0.04 +
        df["compliance_score"] * 0.03
    ).clip(lower=0, upper=1)

    return df


def apply_contextual_boost(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply Tier 3 contextual boost after Tier 2 scoring.

    Formula:
    context_boost = context_score * MAX_CONTEXT_BOOST * (1 - tier2_score)

    This uses remaining score capacity so Tier 3 improves prioritization without
    making every vulnerability Critical.
    """

    print("\n=== Step 6: Applying Tier 3 contextual boost ===")

    df = df.copy()

    if "tier2_score" not in df.columns:
        raise ValueError("tier2_score must exist before applying Tier 3 context boost.")

    # Calculate business/context score from selected SERA contextual factors.
    df = calculate_context_score(df)

    # Controlled context boost prevents score inflation while still allowing business context to influence priority.
    df["context_boost"] = df["context_score"] * MAX_CONTEXT_BOOST * (1 - df["tier2_score"])

    # Final ZYGANT score combines Tier 1 exploitability, Tier 2 KEV intelligence, and Tier 3 business context.
    df["final_score"] = (df["tier2_score"] + df["context_boost"]).clip(lower=0, upper=1)

    return df


# ============================================================
# STEP 7 - PRIORITY LABELS
# ============================================================

def map_priority(score: float) -> str:
    """
    Convert numeric final score into a readable priority label.

    These thresholds can be tuned after testing.
    """

    if score >= 0.90:
        return "Critical"
    if score >= 0.70:
        return "High"
    if score >= 0.40:
        return "Medium"
    return "Low"


# ============================================================
# STEP 8 - SAVE FINAL PRIORITIZED OUTPUT
# ============================================================

def save_prioritized_results(df: pd.DataFrame, output_path: Path) -> pd.DataFrame:
    """
    Save the final prioritized vulnerability queue.

    Asset columns are preserved if available.
    This makes the output usable for local review and dashboard integration later.
    """

    print("\n=== Step 7: Saving prioritized results ===")

    df = df.copy()

    # Add readable priority label.
    df["priority"] = df["final_score"].apply(map_priority)

    # Sort by highest final score first.
    df = df.sort_values("final_score", ascending=False).reset_index(drop=True)

    # Add rank after sorting.
    df["rank"] = df.index + 1

    # Keep useful output columns if they exist.
    output_columns = [
        "rank",
        "asset_id",
        "cve_id",
        "cvss_base_score",
        "epss_percentile",
        "is_kev",
        "tier1_ml_score",
        "kev_boost",
        "tier2_score",
        "context_score",
        "context_boost",
        "final_score",
        "priority"
    ]

    # Keep only columns that exist in the dataframe.
    existing_columns = [col for col in output_columns if col in df.columns]

    # Create output folder if needed.
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save prioritized output.
    df[existing_columns].to_csv(output_path, index=False)

    print("Saved prioritized queue to:", output_path)

    # Print quick review statistics.
    print("\nPriority distribution:")
    print(df["priority"].value_counts())

    print("\nKEV distribution:")
    print(df["is_kev"].value_counts())

    print("\nAverage score breakdown:")
    print("Tier 1 average:", round(df["tier1_ml_score"].mean(), 4))
    print("Tier 2 average:", round(df["tier2_score"].mean(), 4))
    print("Context average:", round(df["context_score"].mean(), 4))
    print("Final average:", round(df["final_score"].mean(), 4))

    return df[existing_columns]


# ============================================================
# MAIN END-TO-END PRIORITIZATION WORKFLOW
# ============================================================

def run_zygant_prioritization() -> pd.DataFrame:
    """
    Run the full local ZYGANT prioritization workflow.

    Complete workflow:
    1. Enrich uploaded vulnerability file.
    2. Save enriched CSV locally.
    3. Load trained Tier 1 model artifact.
    4. Predict Tier 1 score.
    5. Apply Tier 2 KEV boost.
    6. Apply Tier 3 contextual awareness boost.
    7. Save prioritized CSV locally.
    """

    print("Starting ZYGANT local prioritization workflow...")

    # Step 1: Run enrichment and save enriched CSV.
    enriched_df = run_cve_enrichment()

    # Step 2: Load trained Tier 1 artifact.
    artifact = load_model_artifact(MODEL_ARTIFACT_PATH)

    # Step 3: Apply Tier 1 ML scoring.
    scored_df = apply_tier1_scoring(enriched_df, artifact)

    # Step 4: Apply Tier 2 KEV boost.
    scored_df = apply_kev_boost(scored_df)

    # Step 5: Apply Tier 3 contextual awareness.
    scored_df = apply_contextual_boost(scored_df)

    # Step 6: Save prioritized output.
    output_df = save_prioritized_results(scored_df, PRIORITIZED_OUTPUT_PATH)

    print("\nZYGANT prioritization completed successfully.")
    print("No model training was performed in this workflow.")

    return output_df


# ============================================================
# SCRIPT ENTRY POINT
# ============================================================

if __name__ == "__main__":
    run_zygant_prioritization()
