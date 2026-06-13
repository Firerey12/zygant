"""
ZYGANT - Sample Monthly Tier 1 Retraining Script

Purpose:
This script is a sample automation workflow for refreshing the Tier 1 model.

Current workflow:
1. Rebuild the training dataset using:
   - cleaned local NVD data
   - latest EPSS data
   - latest CISA KEV catalog

2. Retrain the Tier 1 LightGBM model.

3. Save the updated Tier 1 model artifact.

Important:
- This script does NOT run vulnerability prioritization.
- zygant_prioritization.py separately loads the latest saved artifact during scoring.
- This script only refreshes the training dataset and retrains the model.

Future improvements:
- Pull NVD directly from the NVD API.
- Add model versioning.
- Store evaluation metrics for each retraining run.
- Add logging.
- Schedule monthly execution using automation tools.
"""

import subprocess
import sys
from pathlib import Path


# Script that rebuilds the training dataset using latest EPSS and KEV.
BUILD_DATASET_SCRIPT = Path("build_training_dataset.py")

# Script that trains Tier 1 and saves the latest model artifact.
TRAIN_MODEL_SCRIPT = Path("tier1_ml_model.py")


def run_step(script_path: Path) -> None:
    """
    Run one Python script as part of the retraining workflow.

    If the script fails, the workflow stops.
    """

    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")

    print(f"\nRunning: {script_path}")

    result = subprocess.run([sys.executable, str(script_path)])

    if result.returncode != 0:
        raise RuntimeError(f"{script_path} failed.")

    print(f"Completed: {script_path}")


def main() -> None:
    """
    Run the sample monthly retraining workflow.

    Step 1:
    Refresh the historical training dataset with latest EPSS and KEV.

    Step 2:
    Retrain Tier 1 and save the updated model artifact.
    """

    print("Starting ZYGANT sample monthly retraining workflow...")

    run_step(BUILD_DATASET_SCRIPT)
    run_step(TRAIN_MODEL_SCRIPT)

    print("\nZYGANT monthly retraining workflow completed successfully.")
    print("Latest Tier 1 model artifact is ready for prioritization.")


if __name__ == "__main__":
    main()