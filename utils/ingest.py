"""
Wazuh vulnerability ingest pipeline.

Fetches vulnerability events from the Wazuh Indexer, enriches them with
NVD, EPSS, and KEV data, scores them with the Tier 1+2 model, then upserts
results into PostgreSQL across the agents, cves, and vulnerabilities tables.

Run from the project root:
    python utils/ingest.py

Note: utils/scoring.py loads the model via a CWD-relative path
("../model/lightgbm_pipeline.joblib"). This resolves correctly only when
the process CWD is the project root (zygant/).
"""

import os
import sys
from itertools import islice
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# Make db/ and utils/ importable regardless of invocation directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.connection import get_db
from utils.scoring import score_dataframe

load_dotenv()

# ========================
# CONFIG
# ========================

WAZUH_URL  = os.getenv("WAZUH_INDEXER_URL")
WAZUH_USER = os.getenv("WAZUH_INDEXER_USER")
WAZUH_PASS = os.getenv("WAZUH_INDEXER_PASS")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UTILS_DIR   = Path(__file__).parent

requests.packages.urllib3.disable_warnings()


# ========================
# HELPERS
# ========================

def chunked(iterable, size):
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk


def get_nvd_metrics(cve_ids):
    """Fetch NVD/CVSS metadata for a list of CVE IDs. Returns a dict keyed by CVE ID."""
    nvd_lookup = {}
    for chunk in chunked(list(set(cve_ids)), 100):
        response = requests.get(
            NVD_API_URL,
            params={"cveIds": ",".join(chunk)},
            timeout=60,
        )
        response.raise_for_status()
        for vuln in response.json().get("vulnerabilities", []):
            cve     = vuln.get("cve", {})
            cve_id  = cve.get("id")
            metrics = cve.get("metrics", {})
            cvss    = None
            if metrics.get("cvssMetricV31"):
                cvss = metrics["cvssMetricV31"][0]
            elif metrics.get("cvssMetricV30"):
                cvss = metrics["cvssMetricV30"][0]
            elif metrics.get("cvssMetricV2"):
                cvss = metrics["cvssMetricV2"][0]
            if not cvss:
                continue
            d = cvss.get("cvssData", {})
            nvd_lookup[cve_id] = {
                "published_date":        cve.get("published"),
                "baseseverity":          d.get("baseSeverity") or cvss.get("baseSeverity"),
                "attackvector":          d.get("attackVector"),
                "attackcomplexity":      d.get("attackComplexity"),
                "privilegesrequired":    d.get("privilegesRequired"),
                "userinteraction":       d.get("userInteraction"),
                "scope":                 d.get("scope"),
                "confidentialityimpact": d.get("confidentialityImpact"),
                "integrityimpact":       d.get("integrityImpact"),
                "availabilityimpact":    d.get("availabilityImpact"),
                "exploitabilityscore":   cvss.get("exploitabilityScore"),
                "impactscore":           cvss.get("impactScore"),
            }
    return nvd_lookup


def get_agent_os(agent_id):
    """Fetch OS info for a Wazuh agent."""
    response = requests.get(
        f"{WAZUH_URL}/syscollector/{agent_id}/os",
        auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASS),
        verify=False,
    )
    response.raise_for_status()
    items = response.json()["data"]["affected_items"]
    return items[0] if items else {}


# ========================
# STEP 1: LOAD EPSS + KEV
# ========================

epss_df = pd.read_csv(UTILS_DIR / "epss_scores.csv")
epss_df.columns = epss_df.columns.str.strip().str.lower()
epss_lookup = epss_df.set_index("cve")[["epss", "percentile"]].to_dict("index")

kev_df = pd.read_csv(UTILS_DIR / "kev_catalog.csv")
kev_df.columns = kev_df.columns.str.strip().str.lower()
kev_set = set(kev_df["cve_id"].str.upper())


# ========================
# STEP 2: FETCH FROM WAZUH INDEXER
# ========================

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
        "vulnerability.published_at",
    ],
    "query": {"match_all": {}},
}

response = requests.get(
    f"{WAZUH_URL}/wazuh-states-vulnerabilities-*/_search",
    auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASS),
    json=query,
    verify=False,
)
response.raise_for_status()
hits = response.json()["hits"]["hits"]
print(f"[+] Retrieved {len(hits)} vulnerability events from Wazuh")


# ========================
# STEP 3: BUILD RECORDS + ENRICH WITH EPSS/KEV
# ========================

records = []
for item in hits:
    src     = item["_source"]
    cve_id  = src.get("vulnerability", {}).get("id")
    cve_key = cve_id.upper() if cve_id else None
    epss_data = epss_lookup.get(cve_key, {})

    records.append({
        "agent_id":        src.get("agent", {}).get("id"),
        "agent_name":      src.get("agent", {}).get("name"),
        "cve_id":          cve_key,
        "severity":        src.get("vulnerability", {}).get("severity"),
        "cvss_base_score": src.get("vulnerability", {}).get("score", {}).get("base"),
        "package_name":    src.get("package", {}).get("name"),
        "package_version": src.get("package", {}).get("version"),
        "published_at":    src.get("vulnerability", {}).get("published_at"),
        "epss_score":      epss_data.get("epss"),
        "epss_percentile": epss_data.get("percentile"),
        "is_kev":          cve_key in kev_set if cve_key else False,
    })

df = pd.DataFrame(records)


# ========================
# STEP 4: ENRICH WITH NVD
# ========================

print("[+] Fetching NVD enrichment...")
nvd_lookup = get_nvd_metrics(df["cve_id"].dropna().unique().tolist())

nvd_df = pd.DataFrame.from_dict(nvd_lookup, orient="index")
nvd_df.index.name = "cve_id"
nvd_df.reset_index(inplace=True)

df = df.merge(nvd_df, how="left", on="cve_id")

df["published_date"] = pd.to_datetime(df.get("published_date"), errors="coerce", utc=True)
now = pd.Timestamp.utcnow()
df["days_since_published"] = (now - df["published_date"]).dt.days.fillna(-1).astype(int)


# ========================
# STEP 5: SCORE
# ========================

scored_df = score_dataframe(df)
print(f"[+] Scored {len(scored_df)} records")


# ========================
# STEP 6: FETCH AGENT DETAILS FROM WAZUH API
# ========================

print("[+] Fetching agent OS details from Wazuh...")
agent_response = requests.get(
    f"{WAZUH_URL}/agents",
    auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASS),
    verify=False,
)
agent_response.raise_for_status()
wazuh_agents = agent_response.json()["data"]["affected_items"]

agent_lookup = {}
for agent in wazuh_agents:
    wid     = agent["id"]
    os_info = get_agent_os(wid)
    agent_lookup[wid] = {
        "hostname":      agent.get("name"),
        "ip_address":    agent.get("ip"),
        "agent_status":  agent.get("status"),
        "agent_version": agent.get("version"),
        "os_name":       os_info.get("os", {}).get("name"),
        "os_version":    os_info.get("os", {}).get("version"),
        "architecture":  os_info.get("architecture"),
    }


# ========================
# STEP 7: WRITE TO POSTGRESQL
# ========================

conn = get_db()
try:
    with conn.cursor() as cur:

        # --- Upsert agents ---
        for wid, info in agent_lookup.items():
            cur.execute("""
                INSERT INTO agents (
                    wazuh_agent_id, hostname, ip_address,
                    agent_status, agent_version,
                    os_name, os_version, architecture,
                    last_seen_at
                ) VALUES (%s, %s, %s::inet, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (wazuh_agent_id) DO UPDATE SET
                    hostname      = EXCLUDED.hostname,
                    ip_address    = EXCLUDED.ip_address,
                    agent_status  = EXCLUDED.agent_status,
                    agent_version = EXCLUDED.agent_version,
                    os_name       = EXCLUDED.os_name,
                    os_version    = EXCLUDED.os_version,
                    architecture  = EXCLUDED.architecture,
                    last_seen_at  = NOW(),
                    updated_at    = NOW()
            """, (
                wid,
                info.get("hostname"),
                info.get("ip_address"),
                info.get("agent_status"),
                info.get("agent_version"),
                info.get("os_name"),
                info.get("os_version"),
                info.get("architecture"),
            ))

        # --- Upsert CVEs (one row per unique CVE) ---
        for _, row in scored_df.drop_duplicates("cve_id").iterrows():
            cve_id = row.get("cve_id")
            if not cve_id:
                continue
            cur.execute("""
                INSERT INTO cves (
                    cve_id,
                    base_severity, cvss_base_score,
                    attack_vector, attack_complexity, privileges_required,
                    user_interaction, scope,
                    confidentiality_impact, integrity_impact, availability_impact,
                    exploitability_score, impact_score,
                    epss_score, epss_percentile,
                    is_kev, days_since_published,
                    enriched_at
                ) VALUES (
                    %s,
                    %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s,
                    %s, %s,
                    NOW()
                )
                ON CONFLICT (cve_id) DO UPDATE SET
                    base_severity          = EXCLUDED.base_severity,
                    cvss_base_score        = EXCLUDED.cvss_base_score,
                    attack_vector          = EXCLUDED.attack_vector,
                    attack_complexity      = EXCLUDED.attack_complexity,
                    privileges_required    = EXCLUDED.privileges_required,
                    user_interaction       = EXCLUDED.user_interaction,
                    scope                  = EXCLUDED.scope,
                    confidentiality_impact = EXCLUDED.confidentiality_impact,
                    integrity_impact       = EXCLUDED.integrity_impact,
                    availability_impact    = EXCLUDED.availability_impact,
                    exploitability_score   = EXCLUDED.exploitability_score,
                    impact_score           = EXCLUDED.impact_score,
                    epss_score             = EXCLUDED.epss_score,
                    epss_percentile        = EXCLUDED.epss_percentile,
                    is_kev                 = EXCLUDED.is_kev,
                    days_since_published   = EXCLUDED.days_since_published,
                    enriched_at            = NOW(),
                    updated_at             = NOW()
            """, (
                cve_id,
                row.get("baseseverity"),
                row.get("cvss_base_score"),
                row.get("attackvector"),
                row.get("attackcomplexity"),
                row.get("privilegesrequired"),
                row.get("userinteraction"),
                row.get("scope"),
                row.get("confidentialityimpact"),
                row.get("integrityimpact"),
                row.get("availabilityimpact"),
                row.get("exploitabilityscore"),
                row.get("impactscore"),
                row.get("epss_score"),
                row.get("epss_percentile"),
                bool(row.get("is_kev", False)),
                int(row.get("days_since_published", -1)),
            ))

        # --- Upsert vulnerabilities (one row per agent + CVE pair) ---
        # Uses a SELECT subquery to resolve wazuh_agent_id → agents.id FK.
        for _, row in scored_df.iterrows():
            cve_id   = row.get("cve_id")
            wazuh_id = row.get("agent_id")
            if not cve_id or not wazuh_id:
                continue

            priority = str(row.get("priority", "low")).lower()
            tier1    = row.get("lightgbm_predicted_score")
            # kev_boost mirrors the flat +0.20 logic in utils/scoring.py
            boost    = int(bool(row.get("is_kev", False))) * 0.20
            final    = row.get("final_score")

            cur.execute("""
                INSERT INTO vulnerabilities (
                    agent_id, cve_id, source,
                    package_name, package_version,
                    tier1_ml_score, kev_boost, final_score,
                    priority, scored_at
                )
                SELECT
                    a.id, %s, 'wazuh',
                    %s, %s,
                    %s, %s, %s,
                    %s::criticality_level, NOW()
                FROM agents a
                WHERE a.wazuh_agent_id = %s
                ON CONFLICT (agent_id, cve_id) WHERE agent_id IS NOT NULL
                DO UPDATE SET
                    package_name    = EXCLUDED.package_name,
                    package_version = EXCLUDED.package_version,
                    tier1_ml_score  = EXCLUDED.tier1_ml_score,
                    kev_boost       = EXCLUDED.kev_boost,
                    final_score     = EXCLUDED.final_score,
                    priority        = EXCLUDED.priority,
                    scored_at       = NOW(),
                    updated_at      = NOW()
            """, (
                cve_id,
                row.get("package_name"),
                row.get("package_version"),
                tier1,
                boost,
                final,
                priority,
                wazuh_id,
            ))

    conn.commit()
    print("[+] Upserted agents, CVEs, and vulnerabilities into PostgreSQL.")

except Exception as exc:
    conn.rollback()
    print(f"[!] Database write failed: {exc}", file=sys.stderr)
    raise
finally:
    conn.close()
