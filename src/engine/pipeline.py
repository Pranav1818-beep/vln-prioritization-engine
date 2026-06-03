import pandas as pd

from fetchers.epss import get_epss_score
from models.vuln import Vulnerability

from engine.scoring import (
    calculate_risk_score,
    map_asset_criticality
)


def run_pipeline():
    df = pd.read_csv("data/sample_cves.csv")

    print("\n=== Vulnerability EPSS Enrichment ===\n")

    results = []

    for _, row in df.iterrows():

        # Build vulnerability object
        vuln = Vulnerability(row["cve_id"])
        vuln.cvss = float(row["cvss_score"])
        vuln.asset_criticality = row["asset_criticality"]

        # Normalize asset criticality
        asset_criticality_score = map_asset_criticality(
            vuln.asset_criticality
        )

        print(f"Processing {vuln.cve_id}...")

        # Enrichment
        vuln.epss = get_epss_score(vuln.cve_id)

        # Scoring
        vuln.risk_score = calculate_risk_score(
            vuln.cvss,
            vuln.epss,
            asset_criticality_score
        )

        results.append({
            "cve_id": vuln.cve_id,
            "cvss": vuln.cvss,
            "epss": vuln.epss,
            "asset_criticality_label": vuln.asset_criticality,
            "asset_criticality_score": asset_criticality_score,
            "risk_score": vuln.risk_score
        })

    results.sort(
        key=lambda x: x["risk_score"],
        reverse=True
    )

    print("\n=== PRIORITIZED VULNERABILITIES ===\n")

    for i, item in enumerate(results, 1):

        print(
            f"Rank {i}\n"
            f"CVE: {item['cve_id']}\n"
            f"Risk Score: {item['risk_score']:.2f}\n"
            f"CVSS: {item['cvss']}\n"
            f"EPSS: {item['epss']}\n"
            f"Asset Criticality: {item['asset_criticality_label']} "
            f"({item['asset_criticality_score']})\n"
            f"----------------------------\n"
        )
