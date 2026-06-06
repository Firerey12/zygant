# ZYGANT - AI-Powered Vulnerability Prioritization Engine

## Overview

ZYGANT is an AI-powered vulnerability prioritization engine designed to help organizations identify, rank, and remediate cybersecurity vulnerabilities based on real-world risk.

Traditional vulnerability management programs often rely heavily on CVSS scores, which provide a severity rating but do not account for exploitation likelihood, active threat intelligence, or organization-specific risk factors. As a result, security teams may spend valuable time remediating vulnerabilities that pose little immediate risk while overlooking those that are more likely to be exploited.

ZYGANT addresses this challenge by combining machine learning, threat intelligence, and contextual risk analysis to generate a more meaningful vulnerability prioritization score.

---

## Project Objectives

The primary objectives of ZYGANT are to:

- Improve vulnerability prioritization accuracy
- Reduce reliance on static CVSS scoring
- Incorporate real-world exploitation likelihood
- Integrate threat intelligence sources
- Include business and operational context in risk calculations
- Help security teams focus remediation efforts on the vulnerabilities that matter most

---

## Data Sources

ZYGANT integrates data from multiple industry-standard sources.

### National Vulnerability Database (NVD)

Provides vulnerability metadata including:

- CVE identifiers
- CVSS metrics
- Attack vector information
- Impact ratings
- Vulnerability descriptions

### Exploit Prediction Scoring System (EPSS)

Provides exploitability likelihood information, including:

- EPSS Score
- EPSS Percentile

### CISA Known Exploited Vulnerabilities (KEV)

Provides information on vulnerabilities that have been confirmed as actively exploited in the wild.

---

## Multi-Tier Prioritization Architecture

ZYGANT uses a three-tier prioritization framework.

### Tier 1 - Machine Learning Exploitation Likelihood Scoring

Tier 1 uses a LightGBM Regressor trained on historical NVD and EPSS data.

The model learns relationships between vulnerability characteristics and EPSS percentile in order to estimate exploitation likelihood using vulnerability metadata and CVSS features.

#### Key Functionality

- NVD, EPSS, and KEV dataset integration
- Data preparation and normalization
- Feature preprocessing and encoding
- EPSS percentile prediction
- Model evaluation using MAE, MSE, RMSE, and R² metrics

The output of Tier 1 is an initial machine learning-based exploitation likelihood score.

### Tier 2 - Threat Intelligence Prioritization

Tier 2 incorporates external threat intelligence into the prioritization process.

Currently, this layer is designed to leverage:

- CISA Known Exploited Vulnerabilities (KEV)

Vulnerabilities confirmed as actively exploited receive additional prioritization weight to ensure known threats are elevated above vulnerabilities with similar technical characteristics.

### Tier 3 - Contextual Risk Scoring

Tier 3 incorporates organization-specific context to prioritize vulnerabilities based on business impact and operational risk.

Contextual factors include:

- Asset criticality
- Business impact
- Operational risk
- Network and host exposure
- Data sensitivity
- Compliance requirements
- Asset ownership

Tier 3 is represented using a synthetic enterprise environment called Secure Enterprise Risk Authority (SERA).

---

## Current Project Status

### Completed

- NVD data collection and cleaning
- EPSS integration
- KEV integration
- Dataset preparation workflow
- Tier 1 LightGBM regression model
- Tier 1 model evaluation
- SERA organizational design
- Network architecture design
- Contextual asset inventory development

### In Progress

- Tier 2 threat intelligence scoring implementation
- Tier 3 contextual prioritization engine
- Dashboard integration
- SQLite data storage
- Automated retraining workflow

### Future Enhancements

- Automated EPSS and KEV ingestion
- Scheduled model retraining
- Enhanced contextual scoring
- Analyst reporting capabilities
- LLM-assisted remediation guidance

---

## Technology Stack

- Python
- Pandas
- Scikit-learn
- LightGBM
- SQLite
- GitHub
- HTML
- CSS
- JavaScript

---

## Team

- Glaron Nirel Pinto
- Tanveer Ismail Abdulaziz
- Zoha Zainub Shabudeen
