"""
ZYGANT - Tier 1 ML Model

ZYGANT is an AI-powered vulnerability prioritization engine that helps
organizations rank cybersecurity vulnerabilities based on real-world risk.

This file contains ONLY the Tier 1 machine learning implementation.

Tier 1 purpose:
- Train a LightGBM Regressor.
- Predict EPSS percentile using NVD/CVSS vulnerability features.
- Produce a machine-learning exploitation-likelihood score.

Why EPSS percentile is the target:
- EPSS percentile shows how a CVE ranks compared to other vulnerabilities
  in terms of exploitation likelihood.
- Predicting EPSS percentile gives ZYGANT a Tier 1 ML score.

Important ZYGANT logic:
- EPSS percentile is the target, so it is not used as an input feature.
- EPSS score is removed because it is closely related to EPSS percentile.
- is_kev is removed because KEV belongs to Tier 2, not Tier 1.
- Tier 2 will later apply a KEV boost after the ML score is generated.
- Tier 3 will later add organizational context such as asset criticality and business risk.

Current output:
- Trains and evaluates the Tier 1 model.
"""

import pandas as pd
import joblib
from datetime import datetime
from pathlib import Path
from lightgbm import LGBMRegressor

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


# ============================================================
# CONFIG
# ============================================================

# Input dataset created from cleaned NVD + latest EPSS + latest KEV merge.
INPUT_DATASET_PATH = Path("Datasets/nvd_epss_kev_merged.csv")

MODEL_OUTPUT_PATH = Path("Model/tier1_lightgbm_regressor.joblib")


# ============================================================
# DATA LOADING
# ============================================================

def load_dataset(path: Path) -> pd.DataFrame:
    """
    Load the merged Tier 1 dataset.

    Expected input:
    - A CSV file containing cleaned NVD data merged with EPSS and KEV.
    - The file must contain cve_id.
    - The file must contain epss_percentile because that is the Tier 1 target.
    """

    # Read the merged dataset into a pandas dataframe.
    df = pd.read_csv(path)

    # Standardize column names to avoid errors caused by spaces or capitalization.
    df.columns = df.columns.str.strip().str.lower()

    # cve_id is required because it uniquely identifies each vulnerability.
    if "cve_id" not in df.columns:
        raise ValueError("The dataset must contain a 'cve_id' column.")

    # epss_percentile is required because Tier 1 predicts this value.
    if "epss_percentile" not in df.columns:
        raise ValueError("The dataset must contain an 'epss_percentile' column.")

    # Standardize CVE IDs so the format stays consistent across ZYGANT.
    df["cve_id"] = df["cve_id"].astype(str).str.strip().str.upper()

    # Convert target column to numeric values.
    df["epss_percentile"] = pd.to_numeric(df["epss_percentile"], errors="coerce")

    # Replace missing EPSS percentile values with 0.
    df["epss_percentile"] = df["epss_percentile"].fillna(0)

    return df


# ============================================================
# FEATURE SELECTION
# ============================================================

def build_feature_matrix(df: pd.DataFrame):
    """
    Separate the model inputs from the target.

    X = features used by the model.
    y = target value the model learns to predict.

    Tier 1 target:
    - y = epss_percentile

    Leakage prevention:
    - epss_percentile is removed from X because it is the answer.
    - epss_score is removed because it is directly related to the answer.
    - is_kev is removed because KEV is handled later in Tier 2.
    """

    # The model learns to predict EPSS percentile.
    y = df["epss_percentile"]

    # These columns should not be used as Tier 1 model input features.
    columns_to_drop = [
        "cve_id",              # Identifier, not a predictive feature.
        "description",         # Text is not modeled in this simple Tier 1 version.
        "published",           # Raw date column is not used directly.
        "lastmodified",        # Raw date column is not used directly.
        "epss_score",          # Removed because it is closely related to epss_percentile.
        "epss_percentile",     # Removed because it is the target.
        "is_kev"               # Removed because KEV belongs to Tier 2 boost logic.
    ]

    # Create X by dropping non-feature and leakage-risk columns.
    X = df.drop(columns=[col for col in columns_to_drop if col in df.columns])

    # These are categorical NVD/CVSS fields that need one-hot encoding.
    categorical_cols = [
        col for col in [
            "baseseverity",
            "attackvector",
            "attackcomplexity",
            "privilegesrequired",
            "userinteraction",
            "scope",
            "confidentialityimpact",
            "integrityimpact",
            "availabilityimpact"
        ]
        if col in X.columns
    ]

    # Any remaining columns are treated as numeric.
    numeric_cols = [col for col in X.columns if col not in categorical_cols]

    return X, y, categorical_cols, numeric_cols


# ============================================================
# MODEL PIPELINE
# ============================================================

def build_model_pipeline(categorical_cols, numeric_cols) -> Pipeline:
    """
    Build the LightGBM regression pipeline.

    The pipeline keeps preprocessing and model training together.

    It handles:
    - Missing numeric values.
    - Missing categorical values.
    - One-hot encoding for categorical fields.
    - LightGBM regression training.
    """

    # Fill missing numeric values with 0.
    numeric_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="constant", fill_value=0))
    ])

    # Fill missing categorical values with UNKNOWN and encode categories as numeric columns.
    categorical_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="constant", fill_value="UNKNOWN")),
        ("onehot", OneHotEncoder(handle_unknown="ignore"))
    ])

    # Apply numeric preprocessing to numeric columns and categorical preprocessing to categorical columns.
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_cols),
            ("cat", categorical_transformer, categorical_cols)
        ]
    )

    # LightGBM Regressor is used because Tier 1 predicts a continuous score, not a class label.
    model = LGBMRegressor(
        random_state=42,
        n_estimators=300,
        learning_rate=0.05
    )

    # Combine preprocessing and model training into one pipeline.
    pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("regressor", model)
    ])

    return pipeline


# ============================================================
# MODEL EVALUATION
# ============================================================

def evaluate_model(y_test, y_pred) -> None:
    """
    Evaluate the Tier 1 regression model.

    These metrics show how close the predicted EPSS percentile is
    to the actual EPSS percentile.
    """

    # MAE shows the average absolute difference between actual and predicted EPSS percentile.
    mae = mean_absolute_error(y_test, y_pred)

    # MSE gives stronger penalty to larger prediction errors.
    mse = mean_squared_error(y_test, y_pred)

    # RMSE is easier to understand because it is on the same 0 to 1 scale as EPSS percentile.
    rmse = mse ** 0.5

    # R2 shows how much of the target variation the model explains.
    r2 = r2_score(y_test, y_pred)

    print("\nTier 1 LightGBM Regressor Evaluation")

    # Lower MAE means the model is closer to the actual EPSS percentile on average.
    print("MAE:", mae)

    # Lower MSE means the model makes fewer large prediction errors.
    print("MSE:", mse)

    # Lower RMSE means better prediction accuracy on the EPSS percentile scale.
    print("RMSE:", rmse)

    # R2 closer to 1.0 means the model explains more of the EPSS percentile variation.
    print("R2 Score:", r2)


# ============================================================
# TRAINING WORKFLOW
# ============================================================

def train_tier1_model() -> None:
    """
    Train and evaluate the Tier 1 ML model.

    Workflow:
    1. Load merged NVD + EPSS + KEV dataset.
    2. Use EPSS percentile as the target.
    3. Remove EPSS and KEV leakage columns from features.
    4. Train a LightGBM Regressor.
    5. Evaluate prediction quality.
    """

    # Load the merged dataset.
    df = load_dataset(INPUT_DATASET_PATH)

    # Create X features and y target.
    X, y, categorical_cols, numeric_cols = build_feature_matrix(df)

    # Show dataset shape so we know how much data is being used.
    print("Dataset rows:", len(df))
    print("Number of model features before encoding:", X.shape[1])

    # Split data into training and testing sets.
    # The test set is used to evaluate the model on unseen records.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42
    )

    # Build the preprocessing + LightGBM regression pipeline.
    pipeline = build_model_pipeline(categorical_cols, numeric_cols)

    # Train the Tier 1 model.
    pipeline.fit(X_train, y_train)

    # Predict EPSS percentile for the test set.
    y_pred = pipeline.predict(X_test)

    # Keep predictions inside the valid EPSS percentile range of 0 to 1.
    y_pred = pd.Series(y_pred).clip(lower=0, upper=1)

    # Evaluate how well the model predicted EPSS percentile.
    evaluate_model(y_test, y_pred)

    # Create the Model folder if it does not exist.
    MODEL_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    # Save all important Tier 1 artifacts together.
    artifact = {
        "model": pipeline,
        "feature_columns": list(X.columns),
        "categorical_columns": categorical_cols,
        "numeric_columns": numeric_cols,
        "trained_at": datetime.now().isoformat(),
        "notes": "Tier 1 LightGBM model trained to predict EPSS percentile using historical NVD + EPSS + KEV data."
    }
    
    # Save the artifact so Tier 2 and Tier 3 can load it later.
    joblib.dump(artifact, MODEL_OUTPUT_PATH)
    
    print("\nTier 1 model training completed successfully.")
    print("Tier 1 model artifact saved to:", MODEL_OUTPUT_PATH)


# ============================================================
# SCRIPT ENTRY POINT
# ============================================================

if __name__ == "__main__":
    train_tier1_model()
