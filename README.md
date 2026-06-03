# Vulnerability Prioritization Engine (EPSS-based)

## Overview
This project is a lightweight vulnerability prioritization tool that enriches CVE data using the FIRST.org EPSS API and computes a basic risk score to help prioritize remediation efforts.

The goal is to simulate a simplified vulnerability management pipeline similar to what is used in SOC / Vulnerability Management workflows.

---

## Features
- CVE ingestion from CSV dataset
- EPSS enrichment via FIRST.org API
- Asset criticality mapping
- Basic risk scoring model
- Prioritized output ranking

---

## Data Sources
- EPSS (Exploit Prediction Scoring System) by FIRST.org
- Local CSV file containing CVE and asset context

---

## Risk Scoring Model
The risk score is calculated using a weighted model:

- CVSS (impact severity)
- EPSS (likelihood of exploitation)
- Asset criticality (business importance)

This is a simplified model for educational and prototyping purposes.

---

## Output Example

Rank 1
CVE: CVE-XXXX-XXXX
Risk Score: 34.50
CVSS: 10.0
EPSS: 0.92
Asset Criticality: critical (5)

---

## Purpose
This project demonstrates:
- Vulnerability data enrichment
- Basic risk-based prioritization
- Early-stage SOC/VM pipeline design thinking

---

## Future Improvements
- Integrate NVD API for CVSS validation
- Add CISA KEV enrichment
- Improve scoring model with threat intelligence signals
- Export results to JSON/CSV formats
