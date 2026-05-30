import os
import requests
import psycopg2
import pandas as pd
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from scoring import score_dataframe
import requests
from itertools import islice

load_dotenv()

# =========================
# CONFIG
# =========================

WAZUH_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_USER = os.getenv("WAZUH_INDEXER_USER")
WAZUH_PASS = os.getenv("WAZUH_INDEXER_PASS")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

requests.packages.urllib3.disable_warnings()

def chunked(iterable, size):
    it = iter(iterable)

    while True:
        chunk = list(islice(it, size))

        if not chunk:
            break

        yield chunk


def get_nvd_metrics(cve_ids):
    """
    Returns:
        {
            "CVE-XXXX-YYYY": {
                "base_severity": "...",
                "attack_vector": "...",
                ...
            }
        }
    """

    nvd_lookup = {}

    unique_cves = list(set(cve_ids))

    for chunk in chunked(unique_cves, 100):

        response = requests.get(
            NVD_API_URL,
            params={
                "cveId": None,
                "cveIds": ",".join(chunk)
            },
            timeout=60
        )

        response.raise_for_status()

        data = response.json()

        for vuln in data.get("vulnerabilities", []):

            cve = vuln.get("cve", {})

            cve_id = cve.get("id")

            metrics = cve.get("metrics", {})

            cvss = None

            # Prefer CVSS 3.1
            if metrics.get("cvssMetricV31"):
                cvss = metrics["cvssMetricV31"][0]

            # Fallback CVSS 3.0
            elif metrics.get("cvssMetricV30"):
                cvss = metrics["cvssMetricV30"][0]

            # Last fallback CVSS 2
            elif metrics.get("cvssMetricV2"):
                cvss = metrics["cvssMetricV2"][0]

            if not cvss:
                continue

            cvss_data = cvss.get("cvssData", {})

            nvd_lookup[cve_id] = {
                "baseseverity":
                    cvss_data.get("baseSeverity")
                    or cvss.get("baseSeverity"),

                "attackvector":
                    cvss_data.get("attackVector"),

                "attackcomplexity":
                    cvss_data.get("attackComplexity"),

                "privilegesrequired":
                    cvss_data.get("privilegesRequired"),

                "userinteraction":
                    cvss_data.get("userInteraction"),

                "confidentialityimpact":
                    cvss_data.get("confidentialityImpact"),

                "integrityimpact":
                    cvss_data.get("integrityImpact"),

                "availabilityimpact":
                    cvss_data.get("availabilityImpact"),

                "exploitabilityscore":
                    cvss.get("exploitabilityScore"),

                "impactscore":
                    cvss.get("impactScore")
            }

    return nvd_lookup

# Load EPSS data
epss_df = pd.read_csv("epss_scores.csv")

# Normalize column names just in case
epss_df.columns = epss_df.columns.str.strip().str.lower()

# Create lookup dictionary
epss_lookup = (
    epss_df
    .set_index("cve")[["epss", "percentile"]]
    .to_dict("index")
)

# Load KEV catalog
kev_df = pd.read_csv("kev_catalog.csv")

# Normalize columns
kev_df.columns = kev_df.columns.str.strip().str.lower()

# Create set for O(1) lookup
kev_set = set(kev_df["cve_id"].str.upper())

query = {
    "size": 1000,
    "_source": [
        "agent.id",
        "agent.name",
        "package.name",
        "package.version",
        "vulnerability.id",
        "vulnerability.severity",
        "vulnerability.score.base",
        "vulnerability.published_at"
    ],
    "query": {
        "match_all": {}
    }
}

response = requests.get(
    f"{WAZUH_URL}/wazuh-states-vulnerabilities-*/_search",
    auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASS),
    json=query,
    verify=False
)

response.raise_for_status()

data = response.json()

hits = data["hits"]["hits"]

print(f"[+] Retrieved {len(hits)} vulnerabilities")

# =========================
# PROCESS RESULTS
# =========================

records = []

for item in hits:

    source = item["_source"]

    cve_id = source.get("vulnerability", {}).get("id")

    # Normalize for matching
    cve_key = cve_id.upper() if cve_id else None

    # Lookup EPSS
    epss_data = epss_lookup.get(cve_key, {})

    epss_score = epss_data.get("epss")
    epss_percentile = epss_data.get("percentile")

    # Lookup KEV
    is_kev = cve_key in kev_set if cve_key else False

    record = {
        "agent_id": source.get("agent", {}).get("id"),
        "agent_name": source.get("agent", {}).get("name"),

        "cve_id": cve_id,

        "severity": source.get("vulnerability", {}).get("severity"),

        "cvss_base_score": source.get("vulnerability", {})
                            .get("score", {})
                            .get("base"),

        "package_name": source.get("package", {}).get("name"),

        "package_version": source.get("package", {}).get("version"),

        "published_at": source.get("vulnerability", {})
                            .get("published_at"),

        # New fields
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "is_kev": is_kev
    }

    records.append(record)

# Convert to DataFrame
df = pd.DataFrame(records)

print(df.head())

df["cve_id"] = df["cve_id"].str.upper()
print("Fetching NVD enrichment...")

nvd_lookup = get_nvd_metrics(
    df["cve_id"].dropna().unique().tolist()
)

nvd_df = pd.DataFrame.from_dict(
    nvd_lookup,
    orient="index"
)

nvd_df.index.name = "cve_id"

nvd_df.reset_index(inplace=True)

df = df.merge(
    nvd_df,
    how="left",
    on="cve_id"
)

scored_df = score_dataframe(df)
print(scored_df.head())