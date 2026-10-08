# Vulnerability Prioritization Engine (v2)

## Overview
A vulnerability prioritization tool that ranks findings by combining severity, exploit likelihood, known-exploitation status and asset criticality, instead of sorting on CVSS alone.

It simulates a simplified risk-based vulnerability management pipeline of the kind used in SOC / VM workflows: ingest findings, enrich them with threat intelligence, score them, and output a ranked remediation list.

---

## What's New in v2
- **CISA KEV enrichment:** CVEs known to be exploited in the wild get a score bonus. The catalog is cached locally for 24h, with offline mode and a `--kev-file` option.
- **Fixed scoring model:** v1 mixed scales, so EPSS could dominate the score. v2 normalizes every input to 0-1 before weighting, and outputs a 0-100 score with P1-P4 priority tiers.
- **Batched EPSS lookups:** CVEs are sent 50 per request instead of one API call per CVE.
- **Honest handling of missing data:** If EPSS or KEV data is unavailable, it is flagged in the output and the remaining weights are renormalized. It is not silently scored as zero.
- **Vendor-neutral input:** Optional `vendor`, `vendor_id` (e.g. a Qualys QID) and `vendor_severity` columns carry scanner data through and feed the score.
- **Robust I/O:** Invalid CSV rows are skipped with a message instead of crashing the run, and results export to CSV or JSON.
- **CLI + tests:** Runs from any directory with argparse options, and ships with a pytest suite (30 tests).

---

## Features
- CVE ingestion from CSV, with validation
- EPSS enrichment via the FIRST.org API
- CISA KEV enrichment
- Normalized, explainable risk scoring (0-100)
- P1-P4 priority tiers
- Optional vendor severity input
- CSV / JSON export

---

## Data Sources
- **EPSS** (Exploit Prediction Scoring System) from FIRST.org
- **CISA KEV** (Known Exploited Vulnerabilities catalog)
- Local CSV file containing CVE and asset context

---

## Usage
```bash
pip install -r requirements.txt

python src/main.py                                    # sample data, live EPSS + KEV
python src/main.py --input findings.csv --output ranked.csv
python src/main.py --offline --kev-file kev.json      # no network
python src/main.py --top 10                           # print only the top 10
```

Run the tests:
```bash
pip install -r requirements-dev.txt
pytest
```

### Input format
| Column | Required | Notes |
|---|---|---|
| `cve_id` | Yes | e.g. CVE-2021-44228 |
| `cvss_score` | Yes | 0-10 |
| `asset_criticality` | Yes | low / medium / high / critical |
| `asset` | No | Hostname or asset name |
| `vendor` | No | e.g. qualys |
| `vendor_id` | No | e.g. a Qualys QID |
| `vendor_severity` | No | 1-5 scale assumed |

---

## Risk Scoring Model
Each input is normalized to 0-1, then combined with these default weights:

| Input | Weight |
|---|---|
| CVSS (impact severity) | 0.30 |
| EPSS (likelihood of exploitation) | 0.30 |
| Asset criticality (business importance) | 0.30 |
| Vendor severity (only if present) | 0.10 |

- **Missing inputs:** If an input is unavailable, the remaining weights are renormalized and the gap is listed in the `Missing` column.
- **KEV bonus:** CVEs in CISA KEV get +25 points, capped at 100. Ties at the cap are broken by the pre-bonus score, then CVSS.
- **Tiers:** P1 >= 75, P2 >= 50, P3 >= 30, otherwise P4.

---

## Output Example
Live run, 8 Oct 2026 (EPSS values change daily):
```
#   CVE              Pri   Score  CVSS    EPSS KEV  Asset     Missing
------------------------------------------------------------------------
1   CVE-2021-44228   P1    100.0  10.0  1.0000 yes  critical  vendor
2   CVE-2017-0144    P1    100.0   8.1  0.9923 yes  critical  vendor
3   CVE-2022-22965   P1    100.0   9.8  0.9964 yes  high      vendor
4   CVE-2021-34527   P1    100.0   8.8  0.9979 yes  high      vendor
5   CVE-2023-44487   P1    100.0   7.5  1.0000 yes  high      vendor
6   CVE-2019-0708    P1    100.0   9.8  1.0000 yes  medium    vendor
7   CVE-2014-0160    P1     90.0   7.5  1.0000 yes  low       vendor
8   CVE-2023-48795   P1     77.5   5.9  0.9355 no   high      vendor
9   CVE-2023-38545   P2     72.2   9.8  0.7848 no   medium    vendor
10  CVE-2024-3094    P2     68.7  10.0  0.8597 no   low       vendor
11  CVE-2022-3602    P2     68.6   7.5  0.9077 no   medium    vendor
12  CVE-2023-48795   P2     57.5   5.9  0.9355 no   low       vendor
13  CVE-2018-15473   P2     57.2   5.3  0.9863 no   low       vendor
14  CVE-2020-8284    P4     20.3   3.7  0.0390 no   low       vendor

```

---

## Limitations
- **Weights are heuristic defaults,** not empirically validated. Tune them for your environment.
- **No vendor-specific parsers yet:** Scanner exports (e.g. Qualys) must be mapped to the generic CSV columns manually.
- **Findings are scored per row:** There is no deduplication across assets.
- **CVSS is taken from the input file,** not validated against NVD.
- **Use sample or synthetic data only.** Do not commit real client or employer scan data.

---

## Roadmap
- Qualys CSV export parser (QID to CVE mapping)
- NVD API cross-check for CVSS
- Context layer: internet exposure and regulatory tags (e.g. RMiT)
- Scanner API connectors
- Weight tuning and validation

---

## Purpose
This project demonstrates:
- Vulnerability data enrichment from multiple threat-intel sources
- Risk-based prioritization beyond CVSS
- Handling of missing and unreliable data in a VM pipeline
- Testable, maintainable pipeline design

---

**Note:** asset names and criticality in `data/sample_cves.csv` are synthetic.
