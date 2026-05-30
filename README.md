# ZYGANT — AI-Powered Vulnerability Prioritization

## Overview
ZYGANT is an AI-driven vulnerability prioritization platform designed to help security teams identify, rank, and remediate the most critical vulnerabilities first. Traditional vulnerability management approaches rely heavily on static severity scores such as CVSS, which often fail to consider real-world exploitability and organization-specific risk context.

Our platform combines machine learning, threat intelligence, and automation to prioritize vulnerabilities based on:
- Real-world exploitability
- Organizational risk
- Threat intelligence correlation
- Vulnerability impact

## The Problem
Most organizations manage hundreds or thousands of vulnerabilities at any given time. Traditional scoring systems like CVSS assign severity based on general characteristics — not on whether a vulnerability is actively being exploited, or how critical the affected asset is to your organization. This leads to wasted remediation effort, misallocated resources, and real threats going unaddressed.

ZYGANT was built to fix that.

## What we built
A full-stack web platform that ingests vulnerability scan data, runs it through a multi-tier AI prioritization engine, and delivers analyst-ready reports through a centralized dashboard.

## Core Features

### Multi-Tier AI Prioritization Engine
The heart of the platform. Every vulnerability is scored across three progressive layers to produce a final risk ranking that reflects reality, not just textbook severity:

- Tier 1 — ML Predicted Score: A machine learning model trained on real-world exploitability data to predict which vulnerabilities pose the greatest immediate risk.
- Tier 2 — KEV Boost: Automatic priority escalation for CVEs confirmed as actively exploited by CISA's Known Exploited Vulnerabilities catalog.
- Tier 3 — Contextual Risk Score: Organization-specific scoring that factors in asset exposure, compliance requirements, and environmental risk.

### Threat Intelligence Integration
The prioritization engine is backed by continuous ingestion and correlation of data from industry-standard sources:

- NVD — National Vulnerability Database
- EPSS — Exploit Prediction Scoring System
- CISA KEV — Known Exploited Vulnerabilities catalog

### LLM-Powered Reporting
Automated, analyst-ready reports generated per vulnerability or scan covering root cause analysis and remediation strategies. Designed to reduce the manual overhead typically placed on security analysts.

### AI Chatbot Assistant
A conversational assistant connected directly to the vulnerability and asset inventory. Analysts can query findings, ask follow-up questions, and explore remediation paths in natural language without digging through raw data.

### Vulnerability Management Dashboard
A centralized web interface that supports the full vulnerability management lifecycle:

- Asset inventory with exposure and risk classification
- Scan triggering and real-time status monitoring
- CVE detail views with severity, status, and remediation tracking
- Pre vs. post prioritization comparison views
- Audit logs and support ticketing

## Built By
- Glaron Nirel Pinto
- Tanveer Ismail Abdulaziz
- Zoha Zainub Shabudeen
