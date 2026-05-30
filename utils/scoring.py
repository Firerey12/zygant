import pandas as pd
from joblib import load

model = load("../model/lightgbm_pipeline.joblib")

def map_priority(score):
    if score >= 0.85:
        return "Critical"
    elif score >= 0.65:
        return "High"
    elif score >= 0.40:
        return "Medium"
    return "Low"

def score_dataframe(df, kev_boost=0.20):
    df = df.copy()

    X_new = df.drop(columns=[
        "cve_id",
        "published",
        "description",
        "epss_percentile",
        "epss_score",
        "is_kev"
    ], errors="ignore")

    df["lightgbm_predicted_score"] = model.predict(X_new)

    if "is_kev" not in df.columns:
        df["is_kev"] = 0

    df["final_score"] = (
        df["lightgbm_predicted_score"] +
        df["is_kev"].fillna(0).astype(int) * kev_boost
    ).clip(upper=1.0)

    df["priority"] = df["final_score"].apply(map_priority)

    df = df.sort_values("final_score", ascending=False).reset_index(drop=True)
    df["rank"] = df.index + 1

    return df